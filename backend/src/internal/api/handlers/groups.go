package handlers

import (
	"net/http"
	"strings"

	"backend/internal/store"

	"github.com/google/uuid"
)

type groupRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

func ListGroupsHandler(st store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userCtx, project, resolveErr := resolveActiveProject(r, st)
		if resolveErr != nil {
			writeProblem(w, r, resolveErr.status, resolveErr.title, resolveErr.detail, resolveErr.err)
			return
		}
		if authzErr := requireProjectRole(userCtx, st, project.ID, store.ProjectRoleReader); authzErr != nil {
			writeProblem(w, r, authzErr.status, authzErr.title, authzErr.detail, authzErr.err)
			return
		}

		page, pageSize, err := parsePagination(r)
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid pagination parameters.", err)
			return
		}

		items, err := st.ListGroupsByProject(project.ID)
		if err == store.ErrNotFound {
			writeProblem(w, r, http.StatusNotFound, "Not Found", "Project not found.", nil)
			return
		}
		if err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to list groups.", err)
			return
		}
		writeJSON(w, http.StatusOK, paginate(items, page, pageSize))
	}
}

func CreateGroupHandler(st store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userCtx, project, resolveErr := resolveActiveProject(r, st)
		if resolveErr != nil {
			writeProblem(w, r, resolveErr.status, resolveErr.title, resolveErr.detail, resolveErr.err)
			return
		}
		if authzErr := requireProjectRole(userCtx, st, project.ID, store.ProjectRoleWriter); authzErr != nil {
			writeProblem(w, r, authzErr.status, authzErr.title, authzErr.detail, authzErr.err)
			return
		}

		var req groupRequest
		if err := decodeJSON(r, &req); err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid JSON body.", err)
			return
		}
		name, err := validateName("name", req.Name, true)
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", err.Error(), nil)
			return
		}

		group, err := st.CreateGroupInProject(project.ID, name, sanitizePlainText(req.Description), userCtx.ID)
		if err == store.ErrAlreadyExists {
			writeProblem(w, r, http.StatusConflict, "Conflict", "Group already exists.", nil)
			return
		}
		if err == store.ErrNotFound {
			writeProblem(w, r, http.StatusNotFound, "Not Found", "Project or user not found.", nil)
			return
		}
		if err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to create group.", err)
			return
		}
		writeJSON(w, http.StatusCreated, group)
	}
}

func ListGroupMembersHandler(st store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userCtx, project, resolveErr := resolveActiveProject(r, st)
		if resolveErr != nil {
			writeProblem(w, r, resolveErr.status, resolveErr.title, resolveErr.detail, resolveErr.err)
			return
		}
		if authzErr := requireProjectRole(userCtx, st, project.ID, store.ProjectRoleReader); authzErr != nil {
			writeProblem(w, r, authzErr.status, authzErr.title, authzErr.detail, authzErr.err)
			return
		}

		groupID, err := uuid.Parse(strings.TrimSpace(r.PathValue("groupId")))
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid groupId.", err)
			return
		}

		items, err := st.ListGroupMembers(project.ID, groupID)
		if err == store.ErrNotFound {
			writeProblem(w, r, http.StatusNotFound, "Not Found", "Group not found.", nil)
			return
		}
		if err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to list group members.", err)
			return
		}
		writeJSON(w, http.StatusOK, items)
	}
}
