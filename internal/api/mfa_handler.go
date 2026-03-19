package api

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/hayward-solutions/wireguard-ui/internal/auth"
	"github.com/hayward-solutions/wireguard-ui/internal/database"
	"github.com/hayward-solutions/wireguard-ui/internal/domain"
)

// MFAHandler handles MFA enrollment, management, and login challenge endpoints.
type MFAHandler struct {
	store                  database.Store
	webauthn               *auth.WebAuthnProvider
	totp                   *auth.TOTPProvider
	jwt                    *auth.JWTManager
	secureCookie           bool
	sessionExpiry          time.Duration
	allowPasswordlessLogin bool
}

type MFAHandlerConfig struct {
	Store                  database.Store
	WebAuthn               *auth.WebAuthnProvider
	TOTP                   *auth.TOTPProvider
	JWT                    *auth.JWTManager
	SecureCookie           bool
	SessionExpiry          time.Duration
	AllowPasswordlessLogin bool
}

func NewMFAHandler(cfg MFAHandlerConfig) *MFAHandler {
	return &MFAHandler{
		store:                  cfg.Store,
		webauthn:               cfg.WebAuthn,
		totp:                   cfg.TOTP,
		jwt:                    cfg.JWT,
		secureCookie:           cfg.SecureCookie,
		sessionExpiry:          cfg.SessionExpiry,
		allowPasswordlessLogin: cfg.AllowPasswordlessLogin,
	}
}

// --- Authenticated: MFA Status & Management ---

// HandleMFAStatus godoc
// @Summary Get MFA status
// @Description Returns the user's MFA enrollment status and registered credentials.
// @Tags mfa
// @Security BearerAuth
// @Produce json
// @Success 200 {object} Response{data=MFAStatusResponse}
// @Failure 401 {object} Response
// @Router /api/v1/me/mfa [get]
func (h *MFAHandler) HandleMFAStatus(w http.ResponseWriter, r *http.Request) {
	claims := auth.ClaimsFromContext(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "not authenticated")
		return
	}

	creds, err := h.store.ListWebAuthnCredentials(r.Context(), claims.Subject)
	if err != nil {
		slog.Error("list webauthn credentials", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to load credentials")
		return
	}

	userTOTP, err := h.store.GetUserTOTP(r.Context(), claims.Subject)
	if err != nil {
		slog.Error("get user totp", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to load TOTP status")
		return
	}

	user, err := h.store.GetUser(r.Context(), claims.Subject)
	if err != nil || user == nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "user not found")
		return
	}

	credList := make([]MFACredentialInfo, 0, len(creds))
	for _, c := range creds {
		credList = append(credList, MFACredentialInfo{
			ID:         c.ID,
			Name:       c.Name,
			CreatedAt:  c.CreatedAt,
			LastUsedAt: c.LastUsedAt,
		})
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"mfa_enabled":          user.MFAEnabled,
		"webauthn_credentials": credList,
		"totp_enrolled":        userTOTP != nil && userTOTP.Verified,
	})
}

// --- Authenticated: WebAuthn Registration ---

// HandleWebAuthnRegisterBegin godoc
// @Summary Begin WebAuthn registration
// @Description Starts WebAuthn credential registration for the authenticated user.
// @Tags mfa
// @Security BearerAuth
// @Produce json
// @Success 200 {object} Response{data=WebAuthnRegisterBeginResponse}
// @Failure 401 {object} Response
// @Router /api/v1/me/mfa/webauthn/register/begin [post]
func (h *MFAHandler) HandleWebAuthnRegisterBegin(w http.ResponseWriter, r *http.Request) {
	claims := auth.ClaimsFromContext(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "not authenticated")
		return
	}

	user, err := h.store.GetUser(r.Context(), claims.Subject)
	if err != nil || user == nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "user not found")
		return
	}

	creds, err := h.store.ListWebAuthnCredentials(r.Context(), user.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to load credentials")
		return
	}

	waUser := &auth.WebAuthnUser{User: user, Credentials: creds}
	options, sessionData, err := h.webauthn.BeginRegistration(waUser)
	if err != nil {
		slog.Error("webauthn begin registration", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to start registration")
		return
	}

	challengeID := uuid.New().String()
	h.webauthn.StoreSession(challengeID, sessionData)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"challenge_id": challengeID,
		"options":      options.Response,
	})
}

// HandleWebAuthnRegisterFinish godoc
// @Summary Finish WebAuthn registration
// @Description Completes WebAuthn credential registration.
// @Tags mfa
// @Security BearerAuth
// @Accept json
// @Produce json
// @Success 201 {object} Response{data=WebAuthnCreatedResponse}
// @Failure 400 {object} Response
// @Failure 401 {object} Response
// @Router /api/v1/me/mfa/webauthn/register/finish [post]
func (h *MFAHandler) HandleWebAuthnRegisterFinish(w http.ResponseWriter, r *http.Request) {
	claims := auth.ClaimsFromContext(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "not authenticated")
		return
	}

	var req struct {
		ChallengeID string `json:"challenge_id"`
		Name        string `json:"name"`
	}

	// Parse the challenge_id and name from query params or a wrapper,
	// but the credential response is the raw body the browser sends.
	challengeID := r.URL.Query().Get("challenge_id")
	name := r.URL.Query().Get("name")
	if challengeID == "" {
		// Try reading from a JSON wrapper
		var wrapper struct {
			ChallengeID string          `json:"challenge_id"`
			Name        string          `json:"name"`
			Response    json.RawMessage `json:"response"`
		}
		body := json.NewDecoder(r.Body)
		if err := body.Decode(&wrapper); err != nil {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
			return
		}
		req.ChallengeID = wrapper.ChallengeID
		req.Name = wrapper.Name
		challengeID = wrapper.ChallengeID
		name = wrapper.Name

		// Re-parse the response part as the credential
		parsedResponse, err := protocol.ParseCredentialCreationResponseBody(jsonReader(wrapper.Response))
		if err != nil {
			slog.Error("parse webauthn response", "error", err)
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid credential response")
			return
		}

		h.finishWebAuthnRegistration(w, r, claims.Subject, challengeID, name, parsedResponse)
		return
	}

	// Fallback: raw body is the credential response
	parsedResponse, err := protocol.ParseCredentialCreationResponseBody(r.Body)
	if err != nil {
		slog.Error("parse webauthn response", "error", err)
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid credential response")
		return
	}

	_ = req
	h.finishWebAuthnRegistration(w, r, claims.Subject, challengeID, name, parsedResponse)
}

func (h *MFAHandler) finishWebAuthnRegistration(w http.ResponseWriter, r *http.Request, userID, challengeID, name string, parsedResponse *protocol.ParsedCredentialCreationData) {
	sessionData, ok := h.webauthn.ConsumeSession(challengeID)
	if !ok {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "registration session expired")
		return
	}

	user, err := h.store.GetUser(r.Context(), userID)
	if err != nil || user == nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "user not found")
		return
	}

	creds, _ := h.store.ListWebAuthnCredentials(r.Context(), userID)
	waUser := &auth.WebAuthnUser{User: user, Credentials: creds}

	credential, err := h.webauthn.FinishRegistration(waUser, sessionData, parsedResponse)
	if err != nil {
		slog.Error("webauthn finish registration", "error", err)
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "registration verification failed")
		return
	}

	if name == "" {
		name = "Security Key"
	}

	domainCred := auth.CredentialToDomain(userID, credential, name)
	domainCred.ID = uuid.New().String()

	if err := h.store.CreateWebAuthnCredential(r.Context(), domainCred); err != nil {
		slog.Error("save webauthn credential", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to save credential")
		return
	}

	// Auto-enable MFA
	if !user.MFAEnabled {
		if err := h.store.SetMFAEnabled(r.Context(), userID, true); err != nil {
			slog.Error("enable mfa", "error", err)
		}
	}

	slog.Warn("audit", "action", "webauthn_register", "actor", userID, "credential_name", name)

	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"id":   domainCred.ID,
		"name": domainCred.Name,
	})
}

// HandleWebAuthnDelete godoc
// @Summary Delete WebAuthn credential
// @Description Deletes a WebAuthn credential by ID.
// @Tags mfa
// @Security BearerAuth
// @Produce json
// @Param id path string true "Credential ID"
// @Success 200 {object} Response{data=MessageResponse}
// @Failure 401 {object} Response
// @Failure 404 {object} Response
// @Router /api/v1/me/mfa/webauthn/{id} [delete]
func (h *MFAHandler) HandleWebAuthnDelete(w http.ResponseWriter, r *http.Request) {
	claims := auth.ClaimsFromContext(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "not authenticated")
		return
	}

	credID := chi.URLParam(r, "id")

	// Verify the credential belongs to this user by listing their creds
	creds, err := h.store.ListWebAuthnCredentials(r.Context(), claims.Subject)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to load credentials")
		return
	}

	found := false
	for _, c := range creds {
		if c.ID == credID {
			found = true
			break
		}
	}
	if !found {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "credential not found")
		return
	}

	if err := h.store.DeleteWebAuthnCredential(r.Context(), credID); err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to delete credential")
		return
	}

	// Check if MFA should be disabled
	h.maybeDisableMFA(r, claims.Subject)

	slog.Warn("audit", "action", "webauthn_delete", "actor", claims.Subject, "credential_id", credID)
	writeJSON(w, http.StatusOK, map[string]string{"message": "credential deleted"})
}

// --- Authenticated: TOTP Enrollment ---

// HandleTOTPEnroll godoc
// @Summary Enroll TOTP
// @Description Generates a new TOTP secret for the authenticated user.
// @Tags mfa
// @Security BearerAuth
// @Produce json
// @Success 200 {object} Response{data=TOTPEnrollResponse}
// @Failure 401 {object} Response
// @Router /api/v1/me/mfa/totp/enroll [post]
func (h *MFAHandler) HandleTOTPEnroll(w http.ResponseWriter, r *http.Request) {
	claims := auth.ClaimsFromContext(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "not authenticated")
		return
	}

	key, err := h.totp.GenerateSecret(claims.Email, "WireGuard UI")
	if err != nil {
		slog.Error("generate totp secret", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to generate secret")
		return
	}

	userTOTP := &domain.UserTOTP{
		UserID:    claims.Subject,
		Secret:    key.Secret(),
		Verified:  false,
		CreatedAt: time.Now(),
	}

	if err := h.store.CreateUserTOTP(r.Context(), userTOTP); err != nil {
		slog.Error("save totp secret", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to save secret")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"secret": key.Secret(),
		"qr_uri": key.URL(),
	})
}

// HandleTOTPVerify godoc
// @Summary Verify TOTP enrollment
// @Description Verifies a TOTP code to complete enrollment.
// @Tags mfa
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param body body TOTPVerifyRequest true "TOTP code"
// @Success 200 {object} Response{data=MessageResponse}
// @Failure 400 {object} Response
// @Failure 401 {object} Response
// @Router /api/v1/me/mfa/totp/verify [post]
func (h *MFAHandler) HandleTOTPVerify(w http.ResponseWriter, r *http.Request) {
	claims := auth.ClaimsFromContext(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "not authenticated")
		return
	}

	var req TOTPVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}

	userTOTP, err := h.store.GetUserTOTP(r.Context(), claims.Subject)
	if err != nil || userTOTP == nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "TOTP not enrolled")
		return
	}

	if !h.totp.Validate(req.Code, userTOTP.Secret) {
		writeError(w, http.StatusUnauthorized, "INVALID_CODE", "invalid TOTP code")
		return
	}

	if err := h.store.VerifyUserTOTP(r.Context(), claims.Subject); err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to verify TOTP")
		return
	}

	// Auto-enable MFA
	user, _ := h.store.GetUser(r.Context(), claims.Subject)
	if user != nil && !user.MFAEnabled {
		if err := h.store.SetMFAEnabled(r.Context(), claims.Subject, true); err != nil {
			slog.Error("enable mfa", "error", err)
		}
	}

	slog.Warn("audit", "action", "totp_enroll", "actor", claims.Subject)
	writeJSON(w, http.StatusOK, map[string]string{"message": "TOTP verified and enabled"})
}

// HandleTOTPDelete godoc
// @Summary Delete TOTP enrollment
// @Description Removes TOTP enrollment for the authenticated user.
// @Tags mfa
// @Security BearerAuth
// @Produce json
// @Success 200 {object} Response{data=MessageResponse}
// @Failure 401 {object} Response
// @Router /api/v1/me/mfa/totp [delete]
func (h *MFAHandler) HandleTOTPDelete(w http.ResponseWriter, r *http.Request) {
	claims := auth.ClaimsFromContext(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "not authenticated")
		return
	}

	if err := h.store.DeleteUserTOTP(r.Context(), claims.Subject); err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to delete TOTP")
		return
	}

	h.maybeDisableMFA(r, claims.Subject)

	slog.Warn("audit", "action", "totp_delete", "actor", claims.Subject)
	writeJSON(w, http.StatusOK, map[string]string{"message": "TOTP removed"})
}

// --- Unauthenticated: MFA Login Challenge ---

// HandleMFAVerifyTOTP godoc
// @Summary MFA TOTP challenge
// @Description Verifies a TOTP code during the MFA login step.
// @Tags auth
// @Accept json
// @Produce json
// @Param body body MFAChallengeRequest true "MFA token and TOTP code"
// @Success 200 {object} Response{data=LoginResponse}
// @Failure 400 {object} Response
// @Failure 401 {object} Response
// @Router /auth/mfa/challenge [post]
func (h *MFAHandler) HandleMFAVerifyTOTP(w http.ResponseWriter, r *http.Request) {
	var req MFAChallengeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}

	user, err := h.validateMFAChallenge(r, req.MFAToken)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", err.Error())
		return
	}

	userTOTP, err := h.store.GetUserTOTP(r.Context(), user.ID)
	if err != nil || userTOTP == nil || !userTOTP.Verified {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "TOTP not configured")
		return
	}

	if !h.totp.Validate(req.Code, userTOTP.Secret) {
		writeError(w, http.StatusUnauthorized, "INVALID_CODE", "invalid TOTP code")
		return
	}

	if err := h.store.UseMFAChallenge(r.Context(), req.MFAToken); err != nil {
		slog.Error("use mfa challenge", "error", err)
	}

	h.issueSessionAndToken(w, r, user)

	slog.Warn("audit", "action", "mfa_login_totp", "actor", user.ID, "target_name", user.Username)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"user": map[string]string{
			"id":       user.ID,
			"username": user.Username,
			"name":     user.Name,
			"role":     user.Role,
		},
	})
}

// HandleMFAWebAuthnBegin godoc
// @Summary MFA WebAuthn begin
// @Description Starts a WebAuthn assertion for MFA login.
// @Tags auth
// @Accept json
// @Produce json
// @Param body body MFATokenRequest true "MFA token"
// @Success 200 {object} Response{data=WebAuthnOptionsResponse}
// @Failure 400 {object} Response
// @Failure 401 {object} Response
// @Router /auth/mfa/webauthn/begin [post]
func (h *MFAHandler) HandleMFAWebAuthnBegin(w http.ResponseWriter, r *http.Request) {
	var req MFATokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}

	user, err := h.validateMFAChallenge(r, req.MFAToken)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", err.Error())
		return
	}

	creds, _ := h.store.ListWebAuthnCredentials(r.Context(), user.ID)
	if len(creds) == 0 {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "no WebAuthn credentials registered")
		return
	}

	waUser := &auth.WebAuthnUser{User: user, Credentials: creds}
	options, sessionData, err := h.webauthn.BeginLogin(waUser)
	if err != nil {
		slog.Error("webauthn begin login", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to start authentication")
		return
	}

	h.webauthn.StoreSession(req.MFAToken, sessionData)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"options": options.Response,
	})
}

// HandleMFAWebAuthnFinish godoc
// @Summary MFA WebAuthn finish
// @Description Completes a WebAuthn assertion for MFA login.
// @Tags auth
// @Accept json
// @Produce json
// @Success 200 {object} Response{data=LoginResponse}
// @Failure 400 {object} Response
// @Failure 401 {object} Response
// @Router /auth/mfa/webauthn/finish [post]
func (h *MFAHandler) HandleMFAWebAuthnFinish(w http.ResponseWriter, r *http.Request) {
	var wrapper MFAWebAuthnFinishRequest
	if err := json.NewDecoder(r.Body).Decode(&wrapper); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}

	user, err := h.validateMFAChallenge(r, wrapper.MFAToken)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", err.Error())
		return
	}

	sessionData, ok := h.webauthn.ConsumeSession(wrapper.MFAToken)
	if !ok {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "authentication session expired")
		return
	}

	parsedResponse, err := protocol.ParseCredentialRequestResponseBody(jsonReader(wrapper.Response))
	if err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid credential response")
		return
	}

	creds, _ := h.store.ListWebAuthnCredentials(r.Context(), user.ID)
	waUser := &auth.WebAuthnUser{User: user, Credentials: creds}

	credential, err := h.webauthn.FinishLogin(waUser, sessionData, parsedResponse)
	if err != nil {
		slog.Error("webauthn finish login", "error", err)
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "authentication failed")
		return
	}

	// Update sign count
	credIDEncoded := encodeBase64URL(credential.ID)
	if err := h.store.UpdateWebAuthnSignCount(r.Context(), credIDEncoded, credential.Authenticator.SignCount); err != nil {
		slog.Error("update webauthn sign count", "error", err)
	}

	if err := h.store.UseMFAChallenge(r.Context(), wrapper.MFAToken); err != nil {
		slog.Error("use mfa challenge", "error", err)
	}

	h.issueSessionAndToken(w, r, user)

	slog.Warn("audit", "action", "mfa_login_webauthn", "actor", user.ID, "target_name", user.Username)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"user": map[string]string{
			"id":       user.ID,
			"username": user.Username,
			"name":     user.Name,
			"role":     user.Role,
		},
	})
}

// --- Unauthenticated: Passwordless WebAuthn Login ---

// HandlePasskeyLoginBegin godoc
// @Summary Passkey login begin
// @Description Starts a passwordless WebAuthn (passkey) login flow.
// @Tags auth
// @Produce json
// @Success 200 {object} Response{data=PasskeyLoginBeginResponse}
// @Failure 500 {object} Response
// @Router /auth/passkey/begin [post]
func (h *MFAHandler) HandlePasskeyLoginBegin(w http.ResponseWriter, r *http.Request) {
	if !h.allowPasswordlessLogin {
		writeError(w, http.StatusForbidden, "FORBIDDEN", "passwordless login is disabled")
		return
	}

	options, sessionData, err := h.webauthn.BeginDiscoverableLogin()
	if err != nil {
		slog.Error("webauthn begin discoverable login", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to start authentication")
		return
	}

	challengeID := uuid.New().String()
	h.webauthn.StoreSession(challengeID, sessionData)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"challenge_id": challengeID,
		"options":      options.Response,
	})
}

// HandlePasskeyLoginFinish godoc
// @Summary Passkey login finish
// @Description Completes a passwordless WebAuthn (passkey) login flow.
// @Tags auth
// @Accept json
// @Produce json
// @Success 200 {object} Response{data=LoginResponse}
// @Failure 400 {object} Response
// @Failure 401 {object} Response
// @Router /auth/passkey/finish [post]
func (h *MFAHandler) HandlePasskeyLoginFinish(w http.ResponseWriter, r *http.Request) {
	var wrapper PasskeyLoginFinishRequest
	if err := json.NewDecoder(r.Body).Decode(&wrapper); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}

	sessionData, ok := h.webauthn.ConsumeSession(wrapper.ChallengeID)
	if !ok {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "authentication session expired")
		return
	}

	parsedResponse, err := protocol.ParseCredentialRequestResponseBody(jsonReader(wrapper.Response))
	if err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid credential response")
		return
	}

	// Discoverable login: look up user by user handle from the credential
	handler := func(rawID, userHandle []byte) (webauthn.User, error) {
		userID := string(userHandle)
		user, err := h.store.GetUser(r.Context(), userID)
		if err != nil || user == nil {
			return nil, fmt.Errorf("user not found")
		}
		creds, _ := h.store.ListWebAuthnCredentials(r.Context(), userID)
		return &auth.WebAuthnUser{User: user, Credentials: creds}, nil
	}

	credential, err := h.webauthn.FinishDiscoverableLogin(handler, sessionData, parsedResponse)
	if err != nil {
		slog.Error("webauthn finish discoverable login", "error", err)
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "authentication failed")
		return
	}

	// Find the user from the credential's user handle
	credIDEncoded := encodeBase64URL(credential.ID)
	dbCred, err := h.store.GetWebAuthnCredentialByCredentialID(r.Context(), credIDEncoded)
	if err != nil || dbCred == nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "credential not found")
		return
	}

	user, err := h.store.GetUser(r.Context(), dbCred.UserID)
	if err != nil || user == nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "user not found")
		return
	}

	// Update sign count
	if err := h.store.UpdateWebAuthnSignCount(r.Context(), credIDEncoded, credential.Authenticator.SignCount); err != nil {
		slog.Error("update webauthn sign count", "error", err)
	}

	if err := h.store.UpdateLastLogin(r.Context(), user.ID); err != nil {
		slog.Error("update last login", "error", err)
	}

	h.issueSessionAndToken(w, r, user)

	slog.Warn("audit", "action", "passkey_login", "actor", user.ID, "target_name", user.Username)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"user": map[string]string{
			"id":       user.ID,
			"username": user.Username,
			"name":     user.Name,
			"role":     user.Role,
		},
	})
}

// --- Helpers ---

func (h *MFAHandler) validateMFAChallenge(r *http.Request, mfaToken string) (*domain.User, error) {
	if mfaToken == "" {
		return nil, fmt.Errorf("missing MFA token")
	}

	challenge, err := h.store.GetMFAChallenge(r.Context(), mfaToken)
	if err != nil || challenge == nil {
		return nil, fmt.Errorf("invalid MFA token")
	}

	if challenge.Used {
		return nil, fmt.Errorf("MFA token already used")
	}

	if time.Now().After(challenge.ExpiresAt) {
		return nil, fmt.Errorf("MFA token expired")
	}

	user, err := h.store.GetUser(r.Context(), challenge.UserID)
	if err != nil || user == nil {
		return nil, fmt.Errorf("user not found")
	}

	return user, nil
}

func (h *MFAHandler) issueSessionAndToken(w http.ResponseWriter, r *http.Request, user *domain.User) {
	now := time.Now()
	sess := &domain.Session{
		ID:        uuid.New().String(),
		UserID:    user.ID,
		CreatedAt: now,
		ExpiresAt: now.Add(h.sessionExpiry),
	}
	if err := h.store.CreateSession(r.Context(), sess); err != nil {
		slog.Error("failed to create session", "error", err)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    sess.ID,
		Path:     "/",
		MaxAge:   int(h.sessionExpiry.Seconds()),
		HttpOnly: true,
		Secure:   h.secureCookie,
		SameSite: http.SameSiteLaxMode,
	})

	token, err := h.jwt.Issue(user.ID, user.Username, user.Name, user.Role)
	if err != nil {
		slog.Error("jwt issue failed", "error", err)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    token,
		Path:     "/",
		MaxAge:   int(h.jwt.Expiry().Seconds()),
		HttpOnly: true,
		Secure:   h.secureCookie,
		SameSite: http.SameSiteLaxMode,
	})

	// Set CSRF token
	csrfToken, err := GenerateCSRFToken()
	if err != nil {
		slog.Error("failed to generate CSRF token", "error", err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    csrfToken,
		Path:     "/",
		MaxAge:   int(h.sessionExpiry.Seconds()),
		HttpOnly: false,
		Secure:   h.secureCookie,
		SameSite: http.SameSiteLaxMode,
	})
}

// maybeDisableMFA checks if user still has any MFA credentials and disables MFA if not.
func (h *MFAHandler) maybeDisableMFA(r *http.Request, userID string) {
	creds, _ := h.store.ListWebAuthnCredentials(r.Context(), userID)
	userTOTP, _ := h.store.GetUserTOTP(r.Context(), userID)

	hasCreds := len(creds) > 0
	hasTOTP := userTOTP != nil && userTOTP.Verified

	if !hasCreds && !hasTOTP {
		if err := h.store.SetMFAEnabled(r.Context(), userID, false); err != nil {
			slog.Error("disable mfa", "error", err)
		}
	}
}

// getMFAMethods returns which MFA methods the user has configured.
func getMFAMethods(r *http.Request, store database.Store, userID string) []string {
	var methods []string

	creds, _ := store.ListWebAuthnCredentials(r.Context(), userID)
	if len(creds) > 0 {
		methods = append(methods, "webauthn")
	}

	userTOTP, _ := store.GetUserTOTP(r.Context(), userID)
	if userTOTP != nil && userTOTP.Verified {
		methods = append(methods, "totp")
	}

	return methods
}
