package handlers

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"backend/internal/store"

	"github.com/google/uuid"
)

type jiraMappingsResponse struct {
	Items      []store.JiraIssueMapping `json:"items"`
	Page       int                      `json:"page"`
	PageSize   int                      `json:"pageSize"`
	Total      int                      `json:"total"`
	TotalPages int                      `json:"totalPages"`
}

type jiraDeliveriesResponse struct {
	Items      []store.JiraDeliveryAttempt `json:"items"`
	Page       int                         `json:"page"`
	PageSize   int                         `json:"pageSize"`
	Total      int                         `json:"total"`
	TotalPages int                         `json:"totalPages"`
}

type jiraManualRetryRequest struct {
	AlertGroupID string `json:"alertGroupId"`
}

type jiraManualRetryResponse struct {
	JobID         string `json:"jobId"`
	AlertGroupID  string `json:"alertGroupId"`
	EventState    string `json:"eventState"`
	QueueState    string `json:"queueState"`
	AttemptCount  int    `json:"attemptCount"`
	NextAttemptAt string `json:"nextAttemptAt"`
}

func normalizeJiraIssuesStatus(raw string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "open":
		return "OPEN", true
	case "closed":
		return "CLOSED", true
	case "all":
		return "ALL", true
	default:
		return "", false
	}
}

func getJiraIssuesByEntityHandler(st store.Store, level store.JiraConfigLevel, resolveTarget func(*http.Request, store.Store, uuid.UUID) (uuid.UUID, *resolveError)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, project, resolveErr := resolveActiveProject(r, st)
		if resolveErr != nil {
			writeProblem(w, r, resolveErr.status, resolveErr.title, resolveErr.detail, resolveErr.err)
			return
		}
		targetID, targetErr := resolveTarget(r, st, project.ID)
		if targetErr != nil {
			writeProblem(w, r, targetErr.status, targetErr.title, targetErr.detail, targetErr.err)
			return
		}
		page, pageSize, err := parsePagination(r)
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid pagination parameters.", err)
			return
		}
		offset := (page - 1) * pageSize
		status, ok := normalizeJiraIssuesStatus(r.URL.Query().Get("status"))
		if !ok {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid Jira issues status filter.", nil)
			return
		}
		items, total, err := st.ListJiraIssueMappingsByEntity(project.ID, level, targetID, store.JiraIssueMappingsListFilter{
			Limit:     pageSize,
			Offset:    offset,
			Status:    status,
			Component: r.URL.Query().Get("component"),
			JiraKey:   r.URL.Query().Get("jiraKey"),
		})
		if err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to list Jira mappings.", err)
			return
		}
		totalPages := 0
		if pageSize > 0 {
			totalPages = (total + pageSize - 1) / pageSize
		}
		writeJSON(w, http.StatusOK, jiraMappingsResponse{
			Items:      items,
			Page:       page,
			PageSize:   pageSize,
			Total:      total,
			TotalPages: totalPages,
		})
	}
}

func getJiraDeliveriesByEntityHandler(st store.Store, level store.JiraConfigLevel, resolveTarget func(*http.Request, store.Store, uuid.UUID) (uuid.UUID, *resolveError)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, project, resolveErr := resolveActiveProject(r, st)
		if resolveErr != nil {
			writeProblem(w, r, resolveErr.status, resolveErr.title, resolveErr.detail, resolveErr.err)
			return
		}
		targetID, targetErr := resolveTarget(r, st, project.ID)
		if targetErr != nil {
			writeProblem(w, r, targetErr.status, targetErr.title, targetErr.detail, targetErr.err)
			return
		}
		page, pageSize, err := parsePagination(r)
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid pagination parameters.", err)
			return
		}
		offset := (page - 1) * pageSize
		items, total, err := st.ListJiraDeliveryAttemptsByEntity(project.ID, level, targetID, pageSize, offset)
		if err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to list Jira delivery attempts.", err)
			return
		}
		totalPages := 0
		if pageSize > 0 {
			totalPages = (total + pageSize - 1) / pageSize
		}
		writeJSON(w, http.StatusOK, jiraDeliveriesResponse{
			Items:      items,
			Page:       page,
			PageSize:   pageSize,
			Total:      total,
			TotalPages: totalPages,
		})
	}
}

func postJiraRetryByEntityHandler(
	st store.Store,
	level store.JiraConfigLevel,
	resolveTargetAndOwner func(*http.Request, store.Store, uuid.UUID) (uuid.UUID, uuid.UUID, *resolveError),
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userCtx, project, resolveErr := resolveActiveProject(r, st)
		if resolveErr != nil {
			writeProblem(w, r, resolveErr.status, resolveErr.title, resolveErr.detail, resolveErr.err)
			return
		}
		targetID, productID, targetErr := resolveTargetAndOwner(r, st, project.ID)
		if targetErr != nil {
			writeProblem(w, r, targetErr.status, targetErr.title, targetErr.detail, targetErr.err)
			return
		}
		if authzErr := requireProductOwnerForJiraSettings(st, project.ID, productID, userCtx); authzErr != nil {
			writeProblem(w, r, authzErr.status, authzErr.title, authzErr.detail, authzErr.err)
			return
		}

		var req jiraManualRetryRequest
		if err := decodeJSON(r, &req); err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid JSON body.", err)
			return
		}
		groupID, err := uuid.Parse(strings.TrimSpace(req.AlertGroupID))
		if err != nil || groupID == uuid.Nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid alertGroupId.", err)
			return
		}

		group, err := st.GetAlertGroup(project.ID, groupID)
		if errors.Is(err, store.ErrNotFound) {
			writeProblem(w, r, http.StatusNotFound, "Not Found", "Alert group not found.", nil)
			return
		}
		if err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to load alert group.", err)
			return
		}

		occCtx, occErr := st.GetLatestAlertOccurrenceContext(project.ID, groupID)
		if errors.Is(occErr, store.ErrNotFound) || occCtx == nil {
			writeProblem(w, r, http.StatusConflict, "Conflict", "Cannot retry Jira dispatch because alert context is missing.", nil)
			return
		}
		if occErr != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to load alert context.", occErr)
			return
		}

		switch level {
		case store.JiraConfigLevelProduct:
			if occCtx.ProductID == nil || *occCtx.ProductID != targetID {
				writeProblem(w, r, http.StatusForbidden, "Forbidden", "Alert group does not belong to selected product.", nil)
				return
			}
		case store.JiraConfigLevelScope:
			if occCtx.ScopeID == nil || *occCtx.ScopeID != targetID {
				writeProblem(w, r, http.StatusForbidden, "Forbidden", "Alert group does not belong to selected scope.", nil)
				return
			}
		case store.JiraConfigLevelTest:
			if occCtx.TestID == nil || *occCtx.TestID != targetID {
				writeProblem(w, r, http.StatusForbidden, "Forbidden", "Alert group does not belong to selected test.", nil)
				return
			}
		default:
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid Jira config level.", nil)
			return
		}

		eventState := store.AlertDispatchEventStateFiring
		if strings.EqualFold(strings.TrimSpace(group.Status), string(store.AlertGroupStatusClosed)) {
			eventState = store.AlertDispatchEventStateResolve
		}
		projectID := project.ID
		queued, enqueueErr := st.EnqueueAlertDispatchJob(store.AlertDispatchEnqueueInput{
			MessageType: store.AlertDispatchMessageTypeAlertEvent,
			EventState:  &eventState,
			ProjectID:   &projectID,
			GroupID:     &groupID,
			PayloadJSON: []byte(`{"reason":"manual_jira_retry"}`),
		})
		if enqueueErr != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to enqueue Jira retry.", enqueueErr)
			return
		}

		writeJSON(w, http.StatusAccepted, jiraManualRetryResponse{
			JobID:         queued.ID.String(),
			AlertGroupID:  groupID.String(),
			EventState:    string(eventState),
			QueueState:    string(queued.State),
			AttemptCount:  queued.AttemptCount,
			NextAttemptAt: queued.NextAttemptAt.UTC().Format(time.RFC3339Nano),
		})
	}
}

func GetProductJiraIssuesHandler(st store.Store) http.HandlerFunc {
	return getJiraIssuesByEntityHandler(st, store.JiraConfigLevelProduct, func(r *http.Request, st store.Store, projectID uuid.UUID) (uuid.UUID, *resolveError) {
		return getProductJiraTarget(r, st, projectID)
	})
}

func GetScopeJiraIssuesHandler(st store.Store) http.HandlerFunc {
	return getJiraIssuesByEntityHandler(st, store.JiraConfigLevelScope, func(r *http.Request, st store.Store, projectID uuid.UUID) (uuid.UUID, *resolveError) {
		scopeID, _, resolveErr := getScopeJiraTarget(r, st, projectID)
		return scopeID, resolveErr
	})
}

func GetTestJiraIssuesHandler(st store.Store) http.HandlerFunc {
	return getJiraIssuesByEntityHandler(st, store.JiraConfigLevelTest, func(r *http.Request, st store.Store, projectID uuid.UUID) (uuid.UUID, *resolveError) {
		testID, _, _, resolveErr := getTestJiraTarget(r, st, projectID)
		return testID, resolveErr
	})
}

func GetProductJiraDeliveriesHandler(st store.Store) http.HandlerFunc {
	return getJiraDeliveriesByEntityHandler(st, store.JiraConfigLevelProduct, func(r *http.Request, st store.Store, projectID uuid.UUID) (uuid.UUID, *resolveError) {
		return getProductJiraTarget(r, st, projectID)
	})
}

func PostProductJiraRetryHandler(st store.Store) http.HandlerFunc {
	return postJiraRetryByEntityHandler(st, store.JiraConfigLevelProduct, func(r *http.Request, st store.Store, projectID uuid.UUID) (uuid.UUID, uuid.UUID, *resolveError) {
		productID, resolveErr := getProductJiraTarget(r, st, projectID)
		return productID, productID, resolveErr
	})
}

func GetScopeJiraDeliveriesHandler(st store.Store) http.HandlerFunc {
	return getJiraDeliveriesByEntityHandler(st, store.JiraConfigLevelScope, func(r *http.Request, st store.Store, projectID uuid.UUID) (uuid.UUID, *resolveError) {
		scopeID, _, resolveErr := getScopeJiraTarget(r, st, projectID)
		return scopeID, resolveErr
	})
}

func PostScopeJiraRetryHandler(st store.Store) http.HandlerFunc {
	return postJiraRetryByEntityHandler(st, store.JiraConfigLevelScope, func(r *http.Request, st store.Store, projectID uuid.UUID) (uuid.UUID, uuid.UUID, *resolveError) {
		scopeID, productID, resolveErr := getScopeJiraTarget(r, st, projectID)
		return scopeID, productID, resolveErr
	})
}

func GetTestJiraDeliveriesHandler(st store.Store) http.HandlerFunc {
	return getJiraDeliveriesByEntityHandler(st, store.JiraConfigLevelTest, func(r *http.Request, st store.Store, projectID uuid.UUID) (uuid.UUID, *resolveError) {
		testID, _, _, resolveErr := getTestJiraTarget(r, st, projectID)
		return testID, resolveErr
	})
}

func PostTestJiraRetryHandler(st store.Store) http.HandlerFunc {
	return postJiraRetryByEntityHandler(st, store.JiraConfigLevelTest, func(r *http.Request, st store.Store, projectID uuid.UUID) (uuid.UUID, uuid.UUID, *resolveError) {
		testID, _, productID, resolveErr := getTestJiraTarget(r, st, projectID)
		return testID, productID, resolveErr
	})
}
