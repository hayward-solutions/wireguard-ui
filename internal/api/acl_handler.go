package api

import (
	"encoding/json"
	"log/slog"
	"net"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/hayward-solutions/wireguard-ui/internal/acl"
	"github.com/hayward-solutions/wireguard-ui/internal/database"
	"github.com/hayward-solutions/wireguard-ui/internal/domain"
)

type ACLHandler struct {
	store  database.Store
	engine *acl.PolicyEngine
}

func NewACLHandler(store database.Store, engine *acl.PolicyEngine) *ACLHandler {
	return &ACLHandler{store: store, engine: engine}
}

func (h *ACLHandler) HandleList(w http.ResponseWriter, r *http.Request) {
	rules, err := h.store.ListACLRules(r.Context())
	if err != nil {
		slog.Error("list acl rules", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to list rules")
		return
	}
	if rules == nil {
		rules = []domain.ACLRule{}
	}
	writeJSON(w, http.StatusOK, rules)
}

func (h *ACLHandler) HandleGet(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	rule, err := h.store.GetACLRule(r.Context(), id)
	if err != nil {
		slog.Error("get acl rule", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to get rule")
		return
	}
	if rule == nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "rule not found")
		return
	}
	writeJSON(w, http.StatusOK, rule)
}

func (h *ACLHandler) HandleCreate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string  `json:"name"`
		Description string  `json:"description"`
		Priority    int     `json:"priority"`
		Protocol    string  `json:"protocol"`
		DstCIDR     string  `json:"dst_cidr"`
		DstPorts    string  `json:"dst_ports"`
		GroupID     *string `json:"group_id"`
		UserID      *string `json:"user_id"`
		Enabled     *bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}

	if err := validateACLRequest(req.Name, req.DstCIDR, req.Protocol, req.GroupID, req.UserID); err != "" {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", err)
		return
	}

	if req.Protocol == "" {
		req.Protocol = domain.ACLProtocolAny
	}
	if req.Priority == 0 {
		req.Priority = 100
	}

	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	rule := &domain.ACLRule{
		ID:          uuid.New().String(),
		Name:        req.Name,
		Description: req.Description,
		Priority:    req.Priority,
		Action:      domain.ACLActionAllow,
		Protocol:    req.Protocol,
		DstCIDR:     req.DstCIDR,
		DstPorts:    req.DstPorts,
		GroupID:     req.GroupID,
		UserID:      req.UserID,
		Enabled:     enabled,
	}

	if err := h.store.CreateACLRule(r.Context(), rule); err != nil {
		slog.Error("create acl rule", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to create rule")
		return
	}

	h.reloadACL(r)
	writeJSON(w, http.StatusCreated, rule)
}

func (h *ACLHandler) HandleUpdate(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	rule, err := h.store.GetACLRule(r.Context(), id)
	if err != nil {
		slog.Error("get acl rule", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to get rule")
		return
	}
	if rule == nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "rule not found")
		return
	}

	var req struct {
		Name        *string `json:"name"`
		Description *string `json:"description"`
		Priority    *int    `json:"priority"`
		Protocol    *string `json:"protocol"`
		DstCIDR     *string `json:"dst_cidr"`
		DstPorts    *string `json:"dst_ports"`
		GroupID     *string `json:"group_id"`
		UserID      *string `json:"user_id"`
		Enabled     *bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}

	if req.Name != nil {
		rule.Name = *req.Name
	}
	if req.Description != nil {
		rule.Description = *req.Description
	}
	if req.Priority != nil {
		rule.Priority = *req.Priority
	}
	if req.Protocol != nil {
		rule.Protocol = *req.Protocol
	}
	if req.DstCIDR != nil {
		rule.DstCIDR = *req.DstCIDR
	}
	if req.DstPorts != nil {
		rule.DstPorts = *req.DstPorts
	}
	if req.GroupID != nil {
		rule.GroupID = req.GroupID
	}
	if req.UserID != nil {
		rule.UserID = req.UserID
	}
	if req.Enabled != nil {
		rule.Enabled = *req.Enabled
	}

	// Re-validate after applying updates
	groupID := rule.GroupID
	userID := rule.UserID
	if errMsg := validateACLRequest(rule.Name, rule.DstCIDR, rule.Protocol, groupID, userID); errMsg != "" {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", errMsg)
		return
	}

	if err := h.store.UpdateACLRule(r.Context(), rule); err != nil {
		slog.Error("update acl rule", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to update rule")
		return
	}

	h.reloadACL(r)
	writeJSON(w, http.StatusOK, rule)
}

func (h *ACLHandler) HandleDelete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	rule, err := h.store.GetACLRule(r.Context(), id)
	if err != nil {
		slog.Error("get acl rule", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to get rule")
		return
	}
	if rule == nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "rule not found")
		return
	}

	if err := h.store.DeleteACLRule(r.Context(), id); err != nil {
		slog.Error("delete acl rule", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to delete rule")
		return
	}

	h.reloadACL(r)
	writeJSON(w, http.StatusOK, map[string]string{"message": "rule deleted"})
}

func (h *ACLHandler) HandleEffective(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "userID")
	rules, err := h.store.GetEffectiveACLRules(r.Context(), userID)
	if err != nil {
		slog.Error("get effective acl rules", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to get effective rules")
		return
	}
	if rules == nil {
		rules = []domain.ACLRule{}
	}
	writeJSON(w, http.StatusOK, rules)
}

func (h *ACLHandler) HandleReload(w http.ResponseWriter, r *http.Request) {
	if h.engine == nil {
		writeJSON(w, http.StatusOK, map[string]string{"message": "no policy engine configured"})
		return
	}
	if err := h.engine.Reload(r.Context(), h.store); err != nil {
		slog.Error("acl reload failed", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to reload ACL engine")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "ACL engine reloaded"})
}

func (h *ACLHandler) reloadACL(r *http.Request) {
	if h.engine != nil {
		if err := h.engine.Reload(r.Context(), h.store); err != nil {
			slog.Error("acl reload failed", "error", err)
		}
	}
}

func validateACLRequest(name, dstCIDR, protocol string, groupID, userID *string) string {
	if name == "" {
		return "name is required"
	}
	if dstCIDR == "" {
		return "dst_cidr is required"
	}
	if _, _, err := net.ParseCIDR(dstCIDR); err != nil {
		return "dst_cidr must be a valid CIDR (e.g., 10.0.0.0/24)"
	}
	if protocol != "" && protocol != domain.ACLProtocolAny &&
		protocol != domain.ACLProtocolTCP && protocol != domain.ACLProtocolUDP {
		return "protocol must be 'any', 'tcp', or 'udp'"
	}
	if groupID != nil && *groupID != "" && userID != nil && *userID != "" {
		return "group_id and user_id are mutually exclusive"
	}
	return ""
}
