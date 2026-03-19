package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"
	"unicode"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/hayward-solutions/wireguard-ui/internal/auth"
	"github.com/hayward-solutions/wireguard-ui/internal/database"
	"github.com/hayward-solutions/wireguard-ui/internal/domain"
	"golang.org/x/crypto/bcrypt"
)

const minPasswordLength = 8

// validatePassword enforces minimum length and basic strength rules.
// Requires at least one uppercase letter, one lowercase letter, and one digit.
func validatePassword(password string) error {
	if len(password) < minPasswordLength {
		return fmt.Errorf("password must be at least %d characters", minPasswordLength)
	}
	var hasUpper, hasLower, hasDigit bool
	for _, r := range password {
		switch {
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsDigit(r):
			hasDigit = true
		}
	}
	if !hasUpper || !hasLower || !hasDigit {
		return fmt.Errorf("password must contain at least one uppercase letter, one lowercase letter, and one digit")
	}
	return nil
}

type UserHandler struct {
	store database.Store
}

func NewUserHandler(store database.Store) *UserHandler {
	return &UserHandler{store: store}
}

// HandleList godoc
// @Summary List users
// @Description Returns all users.
// @Tags users
// @Security BearerAuth
// @Produce json
// @Success 200 {array} domain.User
// @Failure 500 {object} Response
// @Router /api/v1/users [get]
func (h *UserHandler) HandleList(w http.ResponseWriter, r *http.Request) {
	users, err := h.store.ListUsers(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to list users")
		return
	}
	writeJSON(w, http.StatusOK, users)
}

// HandleGet godoc
// @Summary Get user
// @Description Returns a single user by ID.
// @Tags users
// @Security BearerAuth
// @Produce json
// @Param id path string true "User ID"
// @Success 200 {object} domain.User
// @Failure 404 {object} Response
// @Router /api/v1/users/{id} [get]
func (h *UserHandler) HandleGet(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	user, err := h.store.GetUser(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to get user")
		return
	}
	if user == nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "user not found")
		return
	}
	writeJSON(w, http.StatusOK, user)
}

// HandleCreate godoc
// @Summary Create user
// @Description Creates a new local user. Requires admin role.
// @Tags users
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param body body CreateUserRequest true "User details"
// @Success 201 {object} domain.User
// @Failure 400 {object} Response
// @Failure 403 {object} Response
// @Failure 409 {object} Response
// @Router /api/v1/users [post]
func (h *UserHandler) HandleCreate(w http.ResponseWriter, r *http.Request) {
	claims := auth.ClaimsFromContext(r.Context())
	if claims == nil || claims.Role != domain.RoleAdmin {
		writeError(w, http.StatusForbidden, "FORBIDDEN", "admin access required")
		return
	}

	var req CreateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}

	if req.Username == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "username and password are required")
		return
	}
	if err := validatePassword(req.Password); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", err.Error())
		return
	}

	if req.Role == "" {
		req.Role = domain.RoleViewer
	}
	if req.Role != domain.RoleAdmin && req.Role != domain.RoleEditor && req.Role != domain.RoleViewer {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "role must be admin, editor, or viewer")
		return
	}

	existing, _ := h.store.GetUserByUsername(r.Context(), req.Username)
	if existing != nil {
		writeError(w, http.StatusConflict, "CONFLICT", "username already exists")
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to hash password")
		return
	}

	user := &domain.User{
		ID:           uuid.New().String(),
		Username:     req.Username,
		PasswordHash: string(hash),
		Name:         req.Name,
		Role:         req.Role,
	}

	if user.Name == "" {
		user.Name = user.Username
	}

	if err := h.store.CreateUser(r.Context(), user); err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to create user")
		return
	}

	slog.Warn("audit", "action", "user_created", "actor", claims.Subject, "target_id", user.ID, "target_name", user.Username, "role", user.Role)

	writeJSON(w, http.StatusCreated, user)
}

// HandleUpdate godoc
// @Summary Update user
// @Description Updates an existing user. Requires admin role.
// @Tags users
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param id path string true "User ID"
// @Param body body UpdateUserRequest true "Fields to update"
// @Success 200 {object} domain.User
// @Failure 400 {object} Response
// @Failure 403 {object} Response
// @Failure 404 {object} Response
// @Router /api/v1/users/{id} [put]
func (h *UserHandler) HandleUpdate(w http.ResponseWriter, r *http.Request) {
	claims := auth.ClaimsFromContext(r.Context())
	if claims == nil || claims.Role != domain.RoleAdmin {
		writeError(w, http.StatusForbidden, "FORBIDDEN", "admin access required")
		return
	}

	id := chi.URLParam(r, "id")
	user, err := h.store.GetUser(r.Context(), id)
	if err != nil || user == nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "user not found")
		return
	}

	var req UpdateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}

	oldRole := user.Role

	if req.Username != "" {
		user.Username = req.Username
	}
	if req.Name != "" {
		user.Name = req.Name
	}
	if req.Role != "" {
		if req.Role != domain.RoleAdmin && req.Role != domain.RoleEditor && req.Role != domain.RoleViewer {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "role must be admin, editor, or viewer")
			return
		}
		user.Role = req.Role
	}

	if err := h.store.UpdateUser(r.Context(), user); err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to update user")
		return
	}

	if oldRole != user.Role {
		slog.Warn("audit", "action", "role_changed", "actor", claims.Subject, "target_id", user.ID,
			"target_name", user.Username, "old_role", oldRole, "new_role", user.Role)
	}
	slog.Warn("audit", "action", "user_updated", "actor", claims.Subject, "target_id", user.ID, "target_name", user.Username)

	writeJSON(w, http.StatusOK, user)
}

// HandleDelete godoc
// @Summary Delete user
// @Description Deletes a user by ID. Requires admin role. Cannot delete yourself.
// @Tags users
// @Security BearerAuth
// @Produce json
// @Param id path string true "User ID"
// @Success 200 {object} Response{data=MessageResponse}
// @Failure 400 {object} Response
// @Failure 403 {object} Response
// @Router /api/v1/users/{id} [delete]
func (h *UserHandler) HandleDelete(w http.ResponseWriter, r *http.Request) {
	claims := auth.ClaimsFromContext(r.Context())
	if claims == nil || claims.Role != domain.RoleAdmin {
		writeError(w, http.StatusForbidden, "FORBIDDEN", "admin access required")
		return
	}

	id := chi.URLParam(r, "id")

	if claims.Subject == id {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "cannot delete yourself")
		return
	}

	if err := h.store.DeleteUser(r.Context(), id); err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to delete user")
		return
	}

	slog.Warn("audit", "action", "user_deleted", "actor", claims.Subject, "target_id", id)

	writeJSON(w, http.StatusOK, map[string]string{"message": "user deleted"})
}

// HandleResetPassword godoc
// @Summary Reset user password
// @Description Resets a user's password. Requires admin role. Revokes all sessions.
// @Tags users
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param id path string true "User ID"
// @Param body body ResetPasswordRequest true "New password"
// @Success 200 {object} Response{data=MessageResponse}
// @Failure 400 {object} Response
// @Failure 403 {object} Response
// @Router /api/v1/users/{id}/reset-password [post]
func (h *UserHandler) HandleResetPassword(w http.ResponseWriter, r *http.Request) {
	claims := auth.ClaimsFromContext(r.Context())
	if claims == nil || claims.Role != domain.RoleAdmin {
		writeError(w, http.StatusForbidden, "FORBIDDEN", "admin access required")
		return
	}

	id := chi.URLParam(r, "id")
	var req ResetPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Password == "" {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "password is required")
		return
	}
	if err := validatePassword(req.Password); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", err.Error())
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to hash password")
		return
	}

	if err := h.store.UpdateUserPassword(r.Context(), id, string(hash)); err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to reset password")
		return
	}

	if err := h.store.RevokeUserSessions(r.Context(), id); err != nil {
		slog.Error("failed to revoke sessions after password reset", "error", err, "target_id", id)
	}

	slog.Warn("audit", "action", "password_reset", "actor", claims.Subject, "target_id", id)

	writeJSON(w, http.StatusOK, map[string]string{"message": "password reset"})
}

// HandleChangePassword godoc
// @Summary Change own password
// @Description Allows the authenticated user to change their own password. Revokes all sessions.
// @Tags self-service
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param body body ChangePasswordRequest true "Current and new password"
// @Success 200 {object} Response{data=MessageResponse}
// @Failure 400 {object} Response
// @Failure 401 {object} Response
// @Router /api/v1/me/password [post]
func (h *UserHandler) HandleChangePassword(w http.ResponseWriter, r *http.Request) {
	claims := auth.ClaimsFromContext(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "not authenticated")
		return
	}

	var req ChangePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}
	if req.CurrentPassword == "" || req.NewPassword == "" {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "current_password and new_password are required")
		return
	}
	if err := validatePassword(req.NewPassword); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", err.Error())
		return
	}

	user, err := h.store.GetUser(r.Context(), claims.Subject)
	if err != nil || user == nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "user not found")
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.CurrentPassword)); err != nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "current password is incorrect")
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to hash password")
		return
	}

	if err := h.store.UpdateUserPassword(r.Context(), user.ID, string(hash)); err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to change password")
		return
	}

	if err := h.store.RevokeUserSessions(r.Context(), user.ID); err != nil {
		slog.Error("failed to revoke sessions after password change", "error", err, "user_id", user.ID)
	}

	slog.Warn("audit", "action", "password_changed", "actor", claims.Subject)

	writeJSON(w, http.StatusOK, map[string]string{"message": "password changed"})
}

// ensureDefaultAdmin creates the default admin user on startup if no users exist.
func EnsureDefaultAdmin(ctx context.Context, store database.Store, username, password string) error {
	users, err := store.ListUsers(ctx)
	if err != nil {
		return err
	}
	if len(users) > 0 {
		return nil
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	return store.CreateUser(ctx, &domain.User{
		ID:           uuid.New().String(),
		Username:     username,
		PasswordHash: string(hash),
		Name:         username,
		Role:         domain.RoleAdmin,
		CreatedAt:    time.Now(),
	})
}
