package api

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/hayward-solutions/wireguard-ui/internal/acl"
	"github.com/hayward-solutions/wireguard-ui/internal/database"
	"github.com/hayward-solutions/wireguard-ui/internal/domain"
)

type GroupHandler struct {
	store  database.Store
	engine *acl.PolicyEngine
}

func NewGroupHandler(store database.Store, engine *acl.PolicyEngine) *GroupHandler {
	return &GroupHandler{store: store, engine: engine}
}

func (h *GroupHandler) HandleList(w http.ResponseWriter, r *http.Request) {
	groups, err := h.store.ListGroups(r.Context())
	if err != nil {
		slog.Error("list groups", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to list groups")
		return
	}
	if groups == nil {
		groups = []domain.Group{}
	}
	writeJSON(w, http.StatusOK, groups)
}

func (h *GroupHandler) HandleGet(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	group, err := h.store.GetGroup(r.Context(), id)
	if err != nil {
		slog.Error("get group", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to get group")
		return
	}
	if group == nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "group not found")
		return
	}
	writeJSON(w, http.StatusOK, group)
}

func (h *GroupHandler) HandleCreate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "name is required")
		return
	}

	existing, _ := h.store.GetGroupByName(r.Context(), req.Name)
	if existing != nil {
		writeError(w, http.StatusConflict, "CONFLICT", "group name already exists")
		return
	}

	group := &domain.Group{
		ID:     uuid.New().String(),
		Name:   req.Name,
		Source: domain.GroupSourceLocal,
	}
	if err := h.store.CreateGroup(r.Context(), group); err != nil {
		slog.Error("create group", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to create group")
		return
	}

	writeJSON(w, http.StatusCreated, group)
}

func (h *GroupHandler) HandleUpdate(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	group, err := h.store.GetGroup(r.Context(), id)
	if err != nil {
		slog.Error("get group", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to get group")
		return
	}
	if group == nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "group not found")
		return
	}

	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}
	if req.Name != "" {
		group.Name = req.Name
	}

	if err := h.store.UpdateGroup(r.Context(), group); err != nil {
		slog.Error("update group", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to update group")
		return
	}

	writeJSON(w, http.StatusOK, group)
}

func (h *GroupHandler) HandleDelete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	group, err := h.store.GetGroup(r.Context(), id)
	if err != nil {
		slog.Error("get group", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to get group")
		return
	}
	if group == nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "group not found")
		return
	}

	if err := h.store.DeleteGroup(r.Context(), id); err != nil {
		slog.Error("delete group", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to delete group")
		return
	}

	h.reloadACL(r)
	writeJSON(w, http.StatusOK, map[string]string{"message": "group deleted"})
}

func (h *GroupHandler) HandleMembers(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	group, err := h.store.GetGroup(r.Context(), id)
	if err != nil {
		slog.Error("get group", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to get group")
		return
	}
	if group == nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "group not found")
		return
	}

	members, err := h.store.GetGroupMembers(r.Context(), id)
	if err != nil {
		slog.Error("get group members", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to get members")
		return
	}
	if members == nil {
		members = []domain.User{}
	}
	writeJSON(w, http.StatusOK, members)
}

func (h *GroupHandler) HandleSetUserGroups(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "id")
	user, err := h.store.GetUser(r.Context(), userID)
	if err != nil {
		slog.Error("get user", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to get user")
		return
	}
	if user == nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "user not found")
		return
	}

	var req struct {
		GroupIDs []string `json:"group_ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}

	if err := h.store.SetUserGroups(r.Context(), userID, req.GroupIDs); err != nil {
		slog.Error("set user groups", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to set groups")
		return
	}

	h.reloadACL(r)

	groups, _ := h.store.GetUserGroups(r.Context(), userID)
	if groups == nil {
		groups = []domain.Group{}
	}
	writeJSON(w, http.StatusOK, groups)
}

func (h *GroupHandler) reloadACL(r *http.Request) {
	if h.engine != nil {
		if err := h.engine.Reload(r.Context(), h.store); err != nil {
			slog.Error("acl reload failed", "error", err)
		}
	}
}
