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

// HandleList godoc
// @Summary List groups
// @Description Returns all groups.
// @Tags groups
// @Security BearerAuth
// @Produce json
// @Success 200 {array} domain.Group
// @Failure 500 {object} Response
// @Router /api/v1/groups [get]
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

// HandleGet godoc
// @Summary Get group
// @Description Returns a single group by ID.
// @Tags groups
// @Security BearerAuth
// @Produce json
// @Param id path string true "Group ID"
// @Success 200 {object} domain.Group
// @Failure 404 {object} Response
// @Router /api/v1/groups/{id} [get]
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

// HandleCreate godoc
// @Summary Create group
// @Description Creates a new group.
// @Tags groups
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param body body CreateGroupRequest true "Group details"
// @Success 201 {object} domain.Group
// @Failure 400 {object} Response
// @Failure 409 {object} Response
// @Router /api/v1/groups [post]
func (h *GroupHandler) HandleCreate(w http.ResponseWriter, r *http.Request) {
	var req CreateGroupRequest
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

	slog.Warn("audit", "action", "group_created", "actor", actorFromRequest(r), "target_id", group.ID, "target_name", group.Name)

	writeJSON(w, http.StatusCreated, group)
}

// HandleUpdate godoc
// @Summary Update group
// @Description Updates an existing group.
// @Tags groups
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param id path string true "Group ID"
// @Param body body UpdateGroupRequest true "Fields to update"
// @Success 200 {object} domain.Group
// @Failure 400 {object} Response
// @Failure 404 {object} Response
// @Router /api/v1/groups/{id} [put]
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

	var req UpdateGroupRequest
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

	slog.Warn("audit", "action", "group_updated", "actor", actorFromRequest(r), "target_id", group.ID, "target_name", group.Name)

	writeJSON(w, http.StatusOK, group)
}

// HandleDelete godoc
// @Summary Delete group
// @Description Deletes a group by ID.
// @Tags groups
// @Security BearerAuth
// @Produce json
// @Param id path string true "Group ID"
// @Success 200 {object} Response{data=MessageResponse}
// @Failure 404 {object} Response
// @Router /api/v1/groups/{id} [delete]
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

	slog.Warn("audit", "action", "group_deleted", "actor", actorFromRequest(r), "target_id", id, "target_name", group.Name)

	h.reloadACL(r)
	writeJSON(w, http.StatusOK, map[string]string{"message": "group deleted"})
}

// HandleMembers godoc
// @Summary List group members
// @Description Returns the members of a group.
// @Tags groups
// @Security BearerAuth
// @Produce json
// @Param id path string true "Group ID"
// @Success 200 {array} domain.User
// @Failure 404 {object} Response
// @Router /api/v1/groups/{id}/members [get]
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

// HandleSetUserGroups godoc
// @Summary Set user groups
// @Description Sets the group memberships for a user.
// @Tags users
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param id path string true "User ID"
// @Param body body SetUserGroupsRequest true "Group IDs"
// @Success 200 {array} domain.Group
// @Failure 400 {object} Response
// @Failure 404 {object} Response
// @Router /api/v1/users/{id}/groups [put]
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

	var req SetUserGroupsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}

	if err := h.store.SetUserGroups(r.Context(), userID, req.GroupIDs); err != nil {
		slog.Error("set user groups", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to set groups")
		return
	}

	slog.Warn("audit", "action", "user_groups_changed", "actor", actorFromRequest(r), "target_id", userID, "group_ids", req.GroupIDs)

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
