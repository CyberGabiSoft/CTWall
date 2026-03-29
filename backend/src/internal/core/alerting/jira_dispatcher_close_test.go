package alerting

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"backend/internal/store"

	"github.com/google/uuid"
)

type jiraCloseMappingStoreStub struct {
	store.Store
	upsertIssueMappingCalls int
	deliveryAttempts        []store.JiraDeliveryAttemptInput
	auditEntries            []store.AuditLogEntry
}

func (s *jiraCloseMappingStoreStub) GetJiraEntitySettings(_ uuid.UUID, _ store.JiraConfigLevel, _ uuid.UUID) (*store.JiraEntitySettings, error) {
	return nil, store.ErrNotFound
}

func (s *jiraCloseMappingStoreStub) GetJiraMetadataCache(_ uuid.UUID, _ string, _ store.JiraMetadataType, _ string) (*store.JiraMetadataCacheEntry, error) {
	return nil, store.ErrNotFound
}

func (s *jiraCloseMappingStoreStub) UpsertJiraMetadataCache(input store.JiraMetadataCacheUpsertInput) (*store.JiraMetadataCacheEntry, error) {
	fetchedAt := time.Now().UTC()
	if input.FetchedAt != nil {
		fetchedAt = *input.FetchedAt
	}
	return &store.JiraMetadataCacheEntry{
		ID:               uuid.New(),
		ProjectID:        input.ProjectID,
		BaseURLHash:      strings.TrimSpace(input.BaseURLHash),
		MetadataType:     input.MetadataType,
		MetadataScopeKey: strings.TrimSpace(input.MetadataScopeKey),
		PayloadJSON:      append([]byte(nil), input.PayloadJSON...),
		FetchedAt:        fetchedAt,
		CreatedAt:        fetchedAt,
		UpdatedAt:        fetchedAt,
	}, nil
}

func (s *jiraCloseMappingStoreStub) UpsertJiraIssueMapping(input store.JiraIssueMappingUpsertInput) (*store.JiraIssueMapping, error) {
	s.upsertIssueMappingCalls++
	now := time.Now().UTC()
	return &store.JiraIssueMapping{
		ID:             uuid.New(),
		ProjectID:      input.ProjectID,
		ConfigLevel:    input.ConfigLevel,
		ConfigTargetID: input.ConfigTargetID,
		AlertGroupID:   input.AlertGroupID,
		DedupRuleID:    input.DedupRuleID,
		TestID:         input.TestID,
		ComponentPURL:  input.ComponentPURL,
		JiraIssueKey:   input.JiraIssueKey,
		JiraIssueID:    input.JiraIssueID,
		Status:         input.Status,
		LastSyncedAt:   input.LastSyncedAt,
		LastError:      input.LastError,
		ClosedAt:       input.ClosedAt,
		CreatedAt:      now,
		UpdatedAt:      now,
	}, nil
}

func (s *jiraCloseMappingStoreStub) InsertJiraDeliveryAttempt(input store.JiraDeliveryAttemptInput) error {
	s.deliveryAttempts = append(s.deliveryAttempts, input)
	return nil
}

func (s *jiraCloseMappingStoreStub) CreateAuditLog(entry store.AuditLogEntry) error {
	s.auditEntries = append(s.auditEntries, entry)
	return nil
}

func TestCloseJiraMapping_DoesNotCloseMappingWhenResolveReturnsNotFound(t *testing.T) {
	t.Parallel()

	jiraServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"errorMessages":["Issue does not exist or you do not have permission to see it."],"errors":{}}`))
	}))
	defer jiraServer.Close()

	projectID := uuid.New()
	configTargetID := uuid.New()
	groupID := uuid.New()
	mappingID := uuid.New()

	st := &jiraCloseMappingStoreStub{}
	cfg := &JiraConnectorProfile{
		BaseURL:               jiraServer.URL,
		AuthMode:              JiraAuthModeBasic,
		Username:              "svc",
		Password:              "secret",
		RequestTimeoutSeconds: 5,
		DeploymentMode:        JiraDeploymentAuto,
	}
	job := store.AlertDispatchJob{
		ID:           uuid.New(),
		AttemptCount: 1,
	}
	mapping := store.JiraIssueMapping{
		ID:             mappingID,
		ProjectID:      projectID,
		ConfigLevel:    store.JiraConfigLevelProduct,
		ConfigTargetID: configTargetID,
		AlertGroupID:   groupID,
		JiraIssueKey:   "KAN-131",
		Status:         store.JiraIssueMappingStatusOpen,
	}

	err := closeJiraMapping(context.Background(), st, job, cfg, mapping, store.JiraIssueMappingStatusClosed, store.JiraDeliveryActionResolve)
	if err == nil {
		t.Fatalf("expected resolve failure for 404 response")
	}
	if st.upsertIssueMappingCalls != 0 {
		t.Fatalf("expected no local mapping close on resolve error; got upsert calls=%d", st.upsertIssueMappingCalls)
	}
	if len(st.deliveryAttempts) != 1 {
		t.Fatalf("expected one delivery attempt, got %d", len(st.deliveryAttempts))
	}
	attempt := st.deliveryAttempts[0]
	if attempt.Outcome != store.JiraDeliveryOutcomeFailed {
		t.Fatalf("expected FAILED outcome, got %s", attempt.Outcome)
	}
	if attempt.HTTPStatus == nil || *attempt.HTTPStatus != http.StatusNotFound {
		t.Fatalf("expected HTTP status 404 in attempt, got %#v", attempt.HTTPStatus)
	}
}
