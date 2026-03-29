package alerting

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"strings"
	"sync"
	"time"

	"backend/internal/eventmeta"
	"backend/internal/store"

	"github.com/google/uuid"
)

type jiraMetadataLocks struct {
	mu    sync.Mutex
	locks map[string]*sync.Mutex
}

var jiraMetaLocks = jiraMetadataLocks{
	locks: make(map[string]*sync.Mutex),
}

func withJiraMetadataLock(key string, fn func() error) error {
	jiraMetaLocks.mu.Lock()
	lock, ok := jiraMetaLocks.locks[key]
	if !ok {
		lock = &sync.Mutex{}
		jiraMetaLocks.locks[key] = lock
	}
	jiraMetaLocks.mu.Unlock()

	lock.Lock()
	defer lock.Unlock()
	return fn()
}

func jiraMetadataBaseURLHash(baseURL string) string {
	normalized := strings.TrimSpace(strings.ToLower(baseURL))
	sum := sha1.Sum([]byte(normalized))
	return hex.EncodeToString(sum[:])
}

func emitJiraMetadataRefreshFailed(
	st store.Store,
	projectID uuid.UUID,
	metadataType store.JiraMetadataType,
	metadataScopeKey string,
	err error,
) {
	if st == nil || err == nil {
		return
	}
	if status, ok := ParseHTTPStatusCode(err); ok && status == 404 && metadataType == store.JiraMetadataTypeTransitions {
		// Transition metadata is issue-scoped. 404 is expected when the selected issue
		// was deleted/moved or became inaccessible; do not spam system events.
		return
	}
	emitJiraSyncEvent(st, projectID, nil, "alerting.jira.metadata_refresh_failed", eventmeta.SeverityError, "Jira metadata refresh failed", "Jira metadata refresh failed.", map[string]any{
		"metadataType":     string(metadataType),
		"metadataScopeKey": strings.TrimSpace(metadataScopeKey),
		"error":            err.Error(),
	})
}

func loadJiraMetadataJSON(
	ctx context.Context,
	st store.Store,
	projectID uuid.UUID,
	cfg *JiraConnectorProfile,
	metadataType store.JiraMetadataType,
	metadataScopeKey string,
	forceRefresh bool,
	fetch func(context.Context, *JiraConnectorProfile) ([]byte, error),
) ([]byte, bool, error) {
	baseURLHash := jiraMetadataBaseURLHash(cfg.BaseURL)
	scopeKey := strings.TrimSpace(metadataScopeKey)
	if !forceRefresh {
		entry, err := st.GetJiraMetadataCache(projectID, baseURLHash, metadataType, scopeKey)
		if err == nil && entry != nil && len(entry.PayloadJSON) > 0 {
			return entry.PayloadJSON, true, nil
		}
	}

	lockKey := projectID.String() + "|" + baseURLHash + "|" + string(metadataType) + "|" + scopeKey
	var payload []byte
	var fromCache bool
	err := withJiraMetadataLock(lockKey, func() error {
		if !forceRefresh {
			entry, err := st.GetJiraMetadataCache(projectID, baseURLHash, metadataType, scopeKey)
			if err == nil && entry != nil && len(entry.PayloadJSON) > 0 {
				payload = entry.PayloadJSON
				fromCache = true
				return nil
			}
		}
		fetched, err := fetch(ctx, cfg)
		if err != nil {
			emitJiraMetadataRefreshFailed(st, projectID, metadataType, scopeKey, err)
			return err
		}
		now := time.Now().UTC()
		entry, err := st.UpsertJiraMetadataCache(store.JiraMetadataCacheUpsertInput{
			ProjectID:        projectID,
			BaseURLHash:      baseURLHash,
			MetadataType:     metadataType,
			MetadataScopeKey: scopeKey,
			PayloadJSON:      fetched,
			FetchedAt:        &now,
		})
		if err != nil {
			emitJiraMetadataRefreshFailed(st, projectID, metadataType, scopeKey, err)
			return err
		}
		payload = entry.PayloadJSON
		fromCache = false
		return nil
	})
	if err != nil {
		return nil, false, err
	}
	return payload, fromCache, nil
}

func LoadJiraProjectsWithCache(ctx context.Context, st store.Store, projectID uuid.UUID, cfg *JiraConnectorProfile, forceRefresh bool) ([]JiraMetadataProject, bool, error) {
	payload, fromCache, err := loadJiraMetadataJSON(ctx, st, projectID, cfg, store.JiraMetadataTypeProjects, "", forceRefresh, func(ctx context.Context, cfg *JiraConnectorProfile) ([]byte, error) {
		items, err := JiraListProjects(ctx, cfg)
		if err != nil {
			return nil, err
		}
		return json.Marshal(items)
	})
	if err != nil {
		return nil, false, err
	}
	out := make([]JiraMetadataProject, 0)
	if err := json.Unmarshal(payload, &out); err != nil {
		return nil, false, err
	}
	if !forceRefresh && fromCache && len(out) == 0 {
		return LoadJiraProjectsWithCache(ctx, st, projectID, cfg, true)
	}
	return out, fromCache, nil
}

func LoadJiraIssueTypesWithCache(ctx context.Context, st store.Store, projectID uuid.UUID, cfg *JiraConnectorProfile, projectKey string, forceRefresh bool) ([]JiraMetadataIssueType, bool, error) {
	scopeKey := strings.TrimSpace(projectKey)
	payload, fromCache, err := loadJiraMetadataJSON(ctx, st, projectID, cfg, store.JiraMetadataTypeIssueTypes, scopeKey, forceRefresh, func(ctx context.Context, cfg *JiraConnectorProfile) ([]byte, error) {
		items, err := JiraListIssueTypes(ctx, cfg, scopeKey)
		if err != nil {
			return nil, err
		}
		return json.Marshal(items)
	})
	if err != nil {
		return nil, false, err
	}
	out := make([]JiraMetadataIssueType, 0)
	if err := json.Unmarshal(payload, &out); err != nil {
		return nil, false, err
	}
	return out, fromCache, nil
}

func LoadJiraProjectComponentsWithCache(ctx context.Context, st store.Store, projectID uuid.UUID, cfg *JiraConnectorProfile, projectKey string, forceRefresh bool) ([]JiraMetadataComponent, bool, error) {
	scopeKey := strings.TrimSpace(projectKey)
	payload, fromCache, err := loadJiraMetadataJSON(ctx, st, projectID, cfg, store.JiraMetadataTypeComponents, scopeKey, forceRefresh, func(ctx context.Context, cfg *JiraConnectorProfile) ([]byte, error) {
		items, err := JiraListProjectComponents(ctx, cfg, scopeKey)
		if err != nil {
			return nil, err
		}
		return json.Marshal(items)
	})
	if err != nil {
		return nil, false, err
	}
	out := make([]JiraMetadataComponent, 0)
	if err := json.Unmarshal(payload, &out); err != nil {
		return nil, false, err
	}
	return out, fromCache, nil
}

func LoadJiraIssuesWithCache(
	ctx context.Context,
	st store.Store,
	projectID uuid.UUID,
	cfg *JiraConnectorProfile,
	projectKey string,
	issueTypeName string,
	forceRefresh bool,
) ([]JiraMetadataIssue, bool, error) {
	scopeKey := strings.TrimSpace(projectKey)
	if issueType := strings.TrimSpace(issueTypeName); issueType != "" {
		scopeKey += "|" + strings.ToLower(issueType)
	}
	payload, fromCache, err := loadJiraMetadataJSON(ctx, st, projectID, cfg, store.JiraMetadataTypeIssues, scopeKey, forceRefresh, func(ctx context.Context, cfg *JiraConnectorProfile) ([]byte, error) {
		items, err := JiraListProjectIssues(ctx, cfg, projectKey, 100, issueTypeName)
		if err != nil {
			return nil, err
		}
		return json.Marshal(items)
	})
	if err != nil {
		return nil, false, err
	}
	out := make([]JiraMetadataIssue, 0)
	if err := json.Unmarshal(payload, &out); err != nil {
		return nil, false, err
	}
	if !forceRefresh && fromCache && len(out) == 0 {
		return LoadJiraIssuesWithCache(ctx, st, projectID, cfg, projectKey, issueTypeName, true)
	}
	return out, fromCache, nil
}

func LoadJiraPrioritiesWithCache(ctx context.Context, st store.Store, projectID uuid.UUID, cfg *JiraConnectorProfile, forceRefresh bool) ([]JiraMetadataPriority, bool, error) {
	payload, fromCache, err := loadJiraMetadataJSON(ctx, st, projectID, cfg, store.JiraMetadataTypePriorities, "", forceRefresh, func(ctx context.Context, cfg *JiraConnectorProfile) ([]byte, error) {
		items, err := JiraListPriorities(ctx, cfg)
		if err != nil {
			return nil, err
		}
		return json.Marshal(items)
	})
	if err != nil {
		return nil, false, err
	}
	out := make([]JiraMetadataPriority, 0)
	if err := json.Unmarshal(payload, &out); err != nil {
		return nil, false, err
	}
	return out, fromCache, nil
}

func loadJiraTransitionsWithCache(ctx context.Context, st store.Store, projectID uuid.UUID, cfg *JiraConnectorProfile, issueIDOrKey string, forceRefresh bool) ([]jiraTransition, bool, error) {
	scopeKey := strings.TrimSpace(issueIDOrKey)
	payload, fromCache, err := loadJiraMetadataJSON(ctx, st, projectID, cfg, store.JiraMetadataTypeTransitions, scopeKey, forceRefresh, func(ctx context.Context, cfg *JiraConnectorProfile) ([]byte, error) {
		items, _, err := jiraListTransitions(ctx, cfg, scopeKey)
		if err != nil {
			return nil, err
		}
		return json.Marshal(items)
	})
	if err != nil {
		return nil, false, err
	}
	out := make([]jiraTransition, 0)
	if err := json.Unmarshal(payload, &out); err != nil {
		return nil, false, err
	}
	return out, fromCache, nil
}

func LoadJiraTransitionsWithCache(ctx context.Context, st store.Store, projectID uuid.UUID, cfg *JiraConnectorProfile, issueIDOrKey string, forceRefresh bool) ([]JiraMetadataTransition, bool, error) {
	items, fromCache, err := loadJiraTransitionsWithCache(ctx, st, projectID, cfg, issueIDOrKey, forceRefresh)
	if err != nil {
		return nil, false, err
	}
	out := make([]JiraMetadataTransition, 0, len(items))
	for _, item := range items {
		transition := JiraMetadataTransition{
			ID:   strings.TrimSpace(item.ID),
			Name: strings.TrimSpace(item.Name),
		}
		if transition.ID == "" || transition.Name == "" {
			continue
		}
		out = append(out, transition)
	}
	return out, fromCache, nil
}

func LoadJiraIssueFieldsWithCache(
	ctx context.Context,
	st store.Store,
	projectID uuid.UUID,
	cfg *JiraConnectorProfile,
	projectKey string,
	issueTypeID string,
	forceRefresh bool,
) ([]JiraMetadataIssueField, bool, error) {
	scopeKey := strings.TrimSpace(projectKey) + "|" + strings.TrimSpace(issueTypeID)
	payload, fromCache, err := loadJiraMetadataJSON(ctx, st, projectID, cfg, store.JiraMetadataTypeIssueFields, scopeKey, forceRefresh, func(ctx context.Context, cfg *JiraConnectorProfile) ([]byte, error) {
		items, err := JiraListRequiredIssueFields(ctx, cfg, projectKey, issueTypeID)
		if err != nil {
			return nil, err
		}
		return json.Marshal(items)
	})
	if err != nil {
		return nil, false, err
	}
	out := make([]JiraMetadataIssueField, 0)
	if err := json.Unmarshal(payload, &out); err != nil {
		return nil, false, err
	}
	return out, fromCache, nil
}
