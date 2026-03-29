package alerting

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"backend/internal/models"
	"backend/internal/store"

	"github.com/google/uuid"
)

type connectorDispatchStoreStub struct {
	store.Store
	settingsByProject  map[uuid.UUID][]store.AlertConnectorSettings
	connectorsByConfig map[string]*store.ConnectorConfig
	alertGroups        map[string]*models.AlertGroup
	projects           map[uuid.UUID]*models.Project
	products           map[string]*models.Product
	scopes             map[string]*models.Scope
	tests              map[string]*models.Test
	doneJobIDs         []uuid.UUID
	retriedJobIDs      []uuid.UUID
	deadJobIDs         []uuid.UUID
	lastNotifiedAt     map[string]time.Time
	auditEntries       []store.AuditLogEntry
}

func (s connectorDispatchStoreStub) GetAlertConnectorSettings(projectID uuid.UUID) ([]store.AlertConnectorSettings, error) {
	return append([]store.AlertConnectorSettings(nil), s.settingsByProject[projectID]...), nil
}

func (s connectorDispatchStoreStub) GetProjectConnectorConfig(projectID uuid.UUID, connectorType store.ConnectorType) (*store.ConnectorConfig, error) {
	item := s.connectorsByConfig[connectorKey(projectID, connectorType)]
	if item == nil {
		return nil, store.ErrNotFound
	}
	return item, nil
}

func alertGroupKey(projectID, groupID uuid.UUID) string {
	return projectID.String() + "::" + groupID.String()
}

func projectEntityKey(projectID, entityID uuid.UUID) string {
	return projectID.String() + "::" + entityID.String()
}

func (s *connectorDispatchStoreStub) GetAlertGroup(projectID, id uuid.UUID) (*models.AlertGroup, error) {
	item := s.alertGroups[alertGroupKey(projectID, id)]
	if item == nil {
		return nil, store.ErrNotFound
	}
	copied := *item
	return &copied, nil
}

func (s *connectorDispatchStoreStub) MarkAlertDispatchJobDone(id uuid.UUID) error {
	s.doneJobIDs = append(s.doneJobIDs, id)
	return nil
}

func (s *connectorDispatchStoreStub) MarkAlertDispatchJobRetry(id uuid.UUID, _ time.Time, _, _ string) error {
	s.retriedJobIDs = append(s.retriedJobIDs, id)
	return nil
}

func (s *connectorDispatchStoreStub) MarkAlertDispatchJobDead(id uuid.UUID, _, _ string) error {
	s.deadJobIDs = append(s.deadJobIDs, id)
	return nil
}

func (s *connectorDispatchStoreStub) UpdateAlertGroupLastNotifiedAt(projectID, groupID uuid.UUID, notifiedAt time.Time) error {
	if s.lastNotifiedAt == nil {
		s.lastNotifiedAt = make(map[string]time.Time)
	}
	s.lastNotifiedAt[alertGroupKey(projectID, groupID)] = notifiedAt
	return nil
}

func (s *connectorDispatchStoreStub) CreateAuditLog(entry store.AuditLogEntry) error {
	s.auditEntries = append(s.auditEntries, entry)
	return nil
}

func (s connectorDispatchStoreStub) GetProject(id uuid.UUID) (*models.Project, error) {
	item := s.projects[id]
	if item == nil {
		return nil, store.ErrNotFound
	}
	copied := *item
	return &copied, nil
}

func (s connectorDispatchStoreStub) GetProductInProject(projectID, productID uuid.UUID) (*models.Product, error) {
	item := s.products[projectEntityKey(projectID, productID)]
	if item == nil {
		return nil, store.ErrNotFound
	}
	copied := *item
	return &copied, nil
}

func (s connectorDispatchStoreStub) GetScopeInProject(projectID, scopeID uuid.UUID) (*models.Scope, error) {
	item := s.scopes[projectEntityKey(projectID, scopeID)]
	if item == nil {
		return nil, store.ErrNotFound
	}
	copied := *item
	return &copied, nil
}

func (s connectorDispatchStoreStub) GetTestInProject(projectID, testID uuid.UUID) (*models.Test, error) {
	item := s.tests[projectEntityKey(projectID, testID)]
	if item == nil {
		return nil, store.ErrNotFound
	}
	copied := *item
	return &copied, nil
}

func (s connectorDispatchStoreStub) GetLatestAlertOccurrenceContext(_, _ uuid.UUID) (*store.AlertOccurrenceContext, error) {
	return nil, store.ErrNotFound
}

func TestMatchingConnectorTypesForDispatch_AllowsJiraWithoutExplicitConnectorDedupRule(t *testing.T) {
	projectID := uuid.New()
	groupID := uuid.New()
	st := connectorDispatchStoreStub{
		settingsByProject: map[uuid.UUID][]store.AlertConnectorSettings{
			projectID: {
				{
					ProjectID:     projectID,
					ConnectorType: store.ConnectorTypeJira,
					IsEnabled:     true,
					// JiraDedupRuleID intentionally unset - dispatcher should still route Jira.
				},
			},
		},
		connectorsByConfig: map[string]*store.ConnectorConfig{
			connectorKey(projectID, store.ConnectorTypeJira): {
				ConnectorType: store.ConnectorTypeJira,
				IsEnabled:     true,
				ConfigJSON: json.RawMessage(`{
					"baseUrl":"https://jira.example.local",
					"authMode":"api_token",
					"email":"svc@example.local",
					"apiToken":"secret"
				}`),
			},
		},
	}

	selected, err := matchingConnectorTypesForDispatch(&st, projectID, groupID, store.AlertDispatchEventStateFiring)
	if err != nil {
		t.Fatalf("matchingConnectorTypesForDispatch returned error: %v", err)
	}
	if len(selected) != 1 || selected[0] != store.ConnectorTypeJira {
		t.Fatalf("expected jira connector to be selected, got: %#v", selected)
	}
}

func TestMatchingConnectorTypesForDispatch_ImplicitExternalAlertmanagerWhenConfigured(t *testing.T) {
	projectID := uuid.New()
	groupID := uuid.New()

	st := connectorDispatchStoreStub{
		settingsByProject: map[uuid.UUID][]store.AlertConnectorSettings{
			projectID: {},
		},
		connectorsByConfig: map[string]*store.ConnectorConfig{
			connectorKey(projectID, store.ConnectorTypeAlertmanagerExternal): {
				ConnectorType: store.ConnectorTypeAlertmanagerExternal,
				IsEnabled:     true,
				ConfigJSON: json.RawMessage(`{
					"baseUrl":"https://am.example.local",
					"authMode":"none",
					"timeoutSeconds":10
				}`),
			},
		},
	}

	selected, err := matchingConnectorTypesForDispatch(&st, projectID, groupID, store.AlertDispatchEventStateFiring)
	if err != nil {
		t.Fatalf("matchingConnectorTypesForDispatch returned error: %v", err)
	}
	if len(selected) != 1 || selected[0] != store.ConnectorTypeAlertmanagerExternal {
		t.Fatalf("expected implicit external alertmanager connector, got: %#v", selected)
	}
}

func TestMatchingConnectorTypesForDispatch_ExplicitDisabledExternalAlertmanagerWins(t *testing.T) {
	projectID := uuid.New()
	groupID := uuid.New()

	st := connectorDispatchStoreStub{
		settingsByProject: map[uuid.UUID][]store.AlertConnectorSettings{
			projectID: {
				{
					ProjectID:     projectID,
					ConnectorType: store.ConnectorTypeAlertmanagerExternal,
					IsEnabled:     false,
				},
			},
		},
		connectorsByConfig: map[string]*store.ConnectorConfig{
			connectorKey(projectID, store.ConnectorTypeAlertmanagerExternal): {
				ConnectorType: store.ConnectorTypeAlertmanagerExternal,
				IsEnabled:     true,
				ConfigJSON: json.RawMessage(`{
					"baseUrl":"https://am.example.local",
					"authMode":"none",
					"timeoutSeconds":10
				}`),
			},
		},
	}

	selected, err := matchingConnectorTypesForDispatch(&st, projectID, groupID, store.AlertDispatchEventStateFiring)
	if err != nil {
		t.Fatalf("matchingConnectorTypesForDispatch returned error: %v", err)
	}
	if len(selected) != 0 {
		t.Fatalf("expected explicit disabled setting to skip connector, got: %#v", selected)
	}
}

func TestMatchingConnectorTypesForDispatch_ImplicitConnectorWhenConfigured(t *testing.T) {
	projectID := uuid.New()
	groupID := uuid.New()

	st := connectorDispatchStoreStub{
		settingsByProject: map[uuid.UUID][]store.AlertConnectorSettings{
			projectID: {},
		},
		connectorsByConfig: map[string]*store.ConnectorConfig{
			connectorKey(projectID, store.ConnectorTypeSlack): {
				ConnectorType: store.ConnectorTypeSlack,
				IsEnabled:     true,
				ConfigJSON: json.RawMessage(`{
					"webhookUrl":"https://hooks.slack.com/services/a/b/c"
				}`),
			},
		},
	}

	selected, err := matchingConnectorTypesForDispatch(&st, projectID, groupID, store.AlertDispatchEventStateFiring)
	if err != nil {
		t.Fatalf("matchingConnectorTypesForDispatch returned error: %v", err)
	}
	if len(selected) != 1 || selected[0] != store.ConnectorTypeSlack {
		t.Fatalf("expected implicit slack connector, got: %#v", selected)
	}
}

func TestMatchingConnectorTypesForDispatch_ExplicitDisabledConnectorWinsOverImplicit(t *testing.T) {
	projectID := uuid.New()
	groupID := uuid.New()

	st := connectorDispatchStoreStub{
		settingsByProject: map[uuid.UUID][]store.AlertConnectorSettings{
			projectID: {
				{
					ProjectID:     projectID,
					ConnectorType: store.ConnectorTypeSlack,
					IsEnabled:     false,
				},
			},
		},
		connectorsByConfig: map[string]*store.ConnectorConfig{
			connectorKey(projectID, store.ConnectorTypeSlack): {
				ConnectorType: store.ConnectorTypeSlack,
				IsEnabled:     true,
				ConfigJSON: json.RawMessage(`{
					"webhookUrl":"https://hooks.slack.com/services/a/b/c"
				}`),
			},
		},
	}

	selected, err := matchingConnectorTypesForDispatch(&st, projectID, groupID, store.AlertDispatchEventStateFiring)
	if err != nil {
		t.Fatalf("matchingConnectorTypesForDispatch returned error: %v", err)
	}
	if len(selected) != 0 {
		t.Fatalf("expected no selected connectors when explicit setting is disabled, got: %#v", selected)
	}
}

func TestDispatchExternalAlertmanagerConnectors_SendsAlert(t *testing.T) {
	t.Setenv("ALERTING_ALLOW_HTTP_TARGETS", "true")
	t.Setenv("ALERTING_ALLOW_LOCALHOST_TARGETS", "true")

	projectID := uuid.New()
	groupID := uuid.New()
	var gotPayload []AlertmanagerAlert
	var callCount int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2/alerts" {
			http.NotFound(w, r)
			return
		}
		callCount++
		defer r.Body.Close()
		if err := json.NewDecoder(r.Body).Decode(&gotPayload); err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	st := connectorDispatchStoreStub{
		connectorsByConfig: map[string]*store.ConnectorConfig{
			connectorKey(projectID, store.ConnectorTypeAlertmanagerExternal): {
				ConnectorType: store.ConnectorTypeAlertmanagerExternal,
				IsEnabled:     true,
				ConfigJSON: json.RawMessage(`{
					"baseUrl":"` + srv.URL + `",
					"authMode":"none",
					"timeoutSeconds":10,
					"sendResolved":true
				}`),
			},
		},
	}
	group := models.AlertGroup{
		ID:          groupID,
		ProjectID:   projectID,
		Severity:    "ERROR",
		Category:    "system",
		Type:        "malware.detected",
		GroupKey:    "g-1",
		Title:       "malware detected",
		FirstSeenAt: time.Now().UTC(),
	}
	if err := dispatchExternalAlertmanagerConnectors(
		context.Background(),
		&st,
		"https://ctwall.local",
		projectID,
		group,
		store.AlertDispatchEventStateFiring,
		nil,
		[]store.ConnectorType{store.ConnectorTypeAlertmanagerExternal},
	); err != nil {
		t.Fatalf("dispatch external connector: %v", err)
	}
	if callCount != 1 {
		t.Fatalf("expected one POST call, got %d", callCount)
	}
	if len(gotPayload) != 1 {
		t.Fatalf("expected one alert payload, got %d", len(gotPayload))
	}
	if gotPayload[0].Labels["connector_type"] != "alertmanager_external" {
		t.Fatalf("unexpected connector_type label: %#v", gotPayload[0].Labels["connector_type"])
	}
}

func TestDispatchExternalAlertmanagerConnectors_ResolveSkippedWhenSendResolvedDisabled(t *testing.T) {
	t.Setenv("ALERTING_ALLOW_HTTP_TARGETS", "true")
	t.Setenv("ALERTING_ALLOW_LOCALHOST_TARGETS", "true")

	projectID := uuid.New()
	var callCount int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	st := connectorDispatchStoreStub{
		connectorsByConfig: map[string]*store.ConnectorConfig{
			connectorKey(projectID, store.ConnectorTypeAlertmanagerExternal): {
				ConnectorType: store.ConnectorTypeAlertmanagerExternal,
				IsEnabled:     true,
				ConfigJSON: json.RawMessage(`{
					"baseUrl":"` + srv.URL + `",
					"authMode":"none",
					"timeoutSeconds":10,
					"sendResolved":false
				}`),
			},
		},
	}
	group := models.AlertGroup{
		ProjectID:   projectID,
		Severity:    "INFO",
		Category:    "system",
		Type:        "test",
		GroupKey:    "g-2",
		Title:       "resolved",
		FirstSeenAt: time.Now().UTC(),
	}
	if err := dispatchExternalAlertmanagerConnectors(
		context.Background(),
		&st,
		"https://ctwall.local",
		projectID,
		group,
		store.AlertDispatchEventStateResolve,
		nil,
		[]store.ConnectorType{store.ConnectorTypeAlertmanagerExternal},
	); err != nil {
		t.Fatalf("dispatch external connector: %v", err)
	}
	if callCount != 0 {
		t.Fatalf("expected no POST for resolved event when sendResolved=false, got %d", callCount)
	}
}

func TestProcessAlertEventJob_ContinuesWhenExternalAlertmanagerFailsButSlackSucceeds(t *testing.T) {
	t.Setenv("ALERTING_ALLOW_HTTP_TARGETS", "false")
	t.Setenv("ALERTING_ALLOW_LOCALHOST_TARGETS", "false")

	projectID := uuid.New()
	groupID := uuid.New()
	jobID := uuid.New()
	now := time.Now().UTC()
	eventState := store.AlertDispatchEventStateFiring

	var postAlertsCalls int
	internalAlertmanager := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2/alerts" {
			http.NotFound(w, r)
			return
		}
		postAlertsCalls++
		w.WriteHeader(http.StatusAccepted)
	}))
	defer internalAlertmanager.Close()

	client, err := NewAlertmanagerClient(internalAlertmanager.URL, "", "", 2*time.Second)
	if err != nil {
		t.Fatalf("create internal alertmanager client: %v", err)
	}

	st := &connectorDispatchStoreStub{
		settingsByProject: map[uuid.UUID][]store.AlertConnectorSettings{
			projectID: {},
		},
		connectorsByConfig: map[string]*store.ConnectorConfig{
			connectorKey(projectID, store.ConnectorTypeSlack): {
				ConnectorType: store.ConnectorTypeSlack,
				IsEnabled:     true,
				ConfigJSON:    json.RawMessage(`{"webhookUrl":"https://hooks.slack.com/services/a/b/c"}`),
			},
			connectorKey(projectID, store.ConnectorTypeAlertmanagerExternal): {
				ConnectorType: store.ConnectorTypeAlertmanagerExternal,
				IsEnabled:     true,
				ConfigJSON:    json.RawMessage(`{"baseUrl":"http://127.0.0.1:9093","authMode":"none","timeoutSeconds":5}`),
			},
		},
		alertGroups: map[string]*models.AlertGroup{
			alertGroupKey(projectID, groupID): {
				ID:             groupID,
				ProjectID:      projectID,
				Severity:       "ERROR",
				Category:       "system",
				Type:           "malware.detected",
				GroupKey:       "grp-1",
				Title:          "Malware detected",
				FirstSeenAt:    now.Add(-time.Minute),
				LastSeenAt:     now,
				LastNotifiedAt: &now,
			},
		},
	}
	job := store.AlertDispatchJob{
		ID:           jobID,
		MessageType:  store.AlertDispatchMessageTypeAlertEvent,
		EventState:   &eventState,
		ProjectID:    &projectID,
		GroupID:      &groupID,
		AttemptCount: 1,
		CreatedAt:    now.Add(-2 * time.Minute),
	}
	cfg := DefaultAlertmanagerIntegrationConfig()
	cfg.PublicBaseURL = "https://ctwall.local"

	if err := processAlertEventJob(context.Background(), st, client, cfg, job, slog.Default()); err != nil {
		t.Fatalf("processAlertEventJob returned error: %v", err)
	}
	if postAlertsCalls != 1 {
		t.Fatalf("expected one internal alertmanager POST, got %d", postAlertsCalls)
	}
	if len(st.doneJobIDs) != 1 || st.doneJobIDs[0] != jobID {
		t.Fatalf("expected job to be marked done exactly once, got %#v", st.doneJobIDs)
	}
	if len(st.retriedJobIDs) != 0 {
		t.Fatalf("expected no retry scheduling, got %#v", st.retriedJobIDs)
	}
	if len(st.deadJobIDs) != 0 {
		t.Fatalf("expected no dead-letter mark, got %#v", st.deadJobIDs)
	}
	if _, ok := st.lastNotifiedAt[alertGroupKey(projectID, groupID)]; !ok {
		t.Fatalf("expected last_notified_at update for alert group")
	}
	if len(st.auditEntries) == 0 {
		t.Fatalf("expected audit event for external alertmanager failure")
	}
}

func TestProcessAlertEventJob_SkipsResolveWhenGroupIsOpen(t *testing.T) {
	projectID := uuid.New()
	groupID := uuid.New()
	jobID := uuid.New()
	now := time.Now().UTC()
	eventState := store.AlertDispatchEventStateResolve

	var postAlertsCalls int
	internalAlertmanager := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2/alerts" {
			http.NotFound(w, r)
			return
		}
		postAlertsCalls++
		w.WriteHeader(http.StatusAccepted)
	}))
	defer internalAlertmanager.Close()

	client, err := NewAlertmanagerClient(internalAlertmanager.URL, "", "", 2*time.Second)
	if err != nil {
		t.Fatalf("create internal alertmanager client: %v", err)
	}

	st := &connectorDispatchStoreStub{
		settingsByProject: map[uuid.UUID][]store.AlertConnectorSettings{
			projectID: {},
		},
		connectorsByConfig: map[string]*store.ConnectorConfig{
			connectorKey(projectID, store.ConnectorTypeSlack): {
				ConnectorType: store.ConnectorTypeSlack,
				IsEnabled:     true,
				ConfigJSON:    json.RawMessage(`{"webhookUrl":"https://hooks.slack.com/services/a/b/c"}`),
			},
		},
		alertGroups: map[string]*models.AlertGroup{
			alertGroupKey(projectID, groupID): {
				ID:             groupID,
				ProjectID:      projectID,
				Severity:       "ERROR",
				Category:       "system",
				Type:           "malware.detected",
				Status:         "OPEN",
				GroupKey:       "grp-open",
				Title:          "Malware detected",
				FirstSeenAt:    now.Add(-time.Minute),
				LastSeenAt:     now,
				LastNotifiedAt: &now,
			},
		},
	}

	job := store.AlertDispatchJob{
		ID:           jobID,
		MessageType:  store.AlertDispatchMessageTypeAlertEvent,
		EventState:   &eventState,
		ProjectID:    &projectID,
		GroupID:      &groupID,
		AttemptCount: 1,
		CreatedAt:    now.Add(-2 * time.Minute),
	}
	cfg := DefaultAlertmanagerIntegrationConfig()

	if err := processAlertEventJob(context.Background(), st, client, cfg, job, slog.Default()); err != nil {
		t.Fatalf("processAlertEventJob returned error: %v", err)
	}
	if postAlertsCalls != 0 {
		t.Fatalf("expected no resolve dispatch when group is OPEN, got %d calls", postAlertsCalls)
	}
	if len(st.doneJobIDs) != 1 || st.doneJobIDs[0] != jobID {
		t.Fatalf("expected job to be marked done exactly once, got %#v", st.doneJobIDs)
	}
	if len(st.retriedJobIDs) != 0 {
		t.Fatalf("expected no retry scheduling, got %#v", st.retriedJobIDs)
	}
	if len(st.deadJobIDs) != 0 {
		t.Fatalf("expected no dead-letter mark, got %#v", st.deadJobIDs)
	}
}

func TestProcessAlertEventJob_SkipsResolveWhenGroupIsAcknowledged(t *testing.T) {
	projectID := uuid.New()
	groupID := uuid.New()
	jobID := uuid.New()
	now := time.Now().UTC()
	eventState := store.AlertDispatchEventStateResolve

	var postAlertsCalls int
	internalAlertmanager := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2/alerts" {
			http.NotFound(w, r)
			return
		}
		postAlertsCalls++
		w.WriteHeader(http.StatusAccepted)
	}))
	defer internalAlertmanager.Close()

	client, err := NewAlertmanagerClient(internalAlertmanager.URL, "", "", 2*time.Second)
	if err != nil {
		t.Fatalf("create internal alertmanager client: %v", err)
	}

	st := &connectorDispatchStoreStub{
		settingsByProject: map[uuid.UUID][]store.AlertConnectorSettings{
			projectID: {},
		},
		connectorsByConfig: map[string]*store.ConnectorConfig{
			connectorKey(projectID, store.ConnectorTypeSlack): {
				ConnectorType: store.ConnectorTypeSlack,
				IsEnabled:     true,
				ConfigJSON:    json.RawMessage(`{"webhookUrl":"https://hooks.slack.com/services/a/b/c"}`),
			},
		},
		alertGroups: map[string]*models.AlertGroup{
			alertGroupKey(projectID, groupID): {
				ID:             groupID,
				ProjectID:      projectID,
				Severity:       "ERROR",
				Category:       "system",
				Type:           "malware.detected",
				Status:         "ACKNOWLEDGED",
				GroupKey:       "grp-ack",
				Title:          "Malware detected",
				FirstSeenAt:    now.Add(-time.Minute),
				LastSeenAt:     now,
				LastNotifiedAt: &now,
			},
		},
	}

	job := store.AlertDispatchJob{
		ID:           jobID,
		MessageType:  store.AlertDispatchMessageTypeAlertEvent,
		EventState:   &eventState,
		ProjectID:    &projectID,
		GroupID:      &groupID,
		AttemptCount: 1,
		CreatedAt:    now.Add(-2 * time.Minute),
	}
	cfg := DefaultAlertmanagerIntegrationConfig()

	if err := processAlertEventJob(context.Background(), st, client, cfg, job, slog.Default()); err != nil {
		t.Fatalf("processAlertEventJob returned error: %v", err)
	}
	if postAlertsCalls != 0 {
		t.Fatalf("expected no resolve dispatch when group is ACKNOWLEDGED, got %d calls", postAlertsCalls)
	}
	if len(st.doneJobIDs) != 1 || st.doneJobIDs[0] != jobID {
		t.Fatalf("expected job to be marked done exactly once, got %#v", st.doneJobIDs)
	}
	if len(st.retriedJobIDs) != 0 {
		t.Fatalf("expected no retry scheduling, got %#v", st.retriedJobIDs)
	}
	if len(st.deadJobIDs) != 0 {
		t.Fatalf("expected no dead-letter mark, got %#v", st.deadJobIDs)
	}
}

func TestProcessAlertEventJob_DispatchesResolveWhenGroupIsClosed(t *testing.T) {
	projectID := uuid.New()
	groupID := uuid.New()
	jobID := uuid.New()
	now := time.Now().UTC()
	eventState := store.AlertDispatchEventStateResolve

	var postAlertsCalls int
	internalAlertmanager := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2/alerts" {
			http.NotFound(w, r)
			return
		}
		postAlertsCalls++
		w.WriteHeader(http.StatusAccepted)
	}))
	defer internalAlertmanager.Close()

	client, err := NewAlertmanagerClient(internalAlertmanager.URL, "", "", 2*time.Second)
	if err != nil {
		t.Fatalf("create internal alertmanager client: %v", err)
	}

	st := &connectorDispatchStoreStub{
		settingsByProject: map[uuid.UUID][]store.AlertConnectorSettings{
			projectID: {},
		},
		connectorsByConfig: map[string]*store.ConnectorConfig{
			connectorKey(projectID, store.ConnectorTypeSlack): {
				ConnectorType: store.ConnectorTypeSlack,
				IsEnabled:     true,
				ConfigJSON:    json.RawMessage(`{"webhookUrl":"https://hooks.slack.com/services/a/b/c"}`),
			},
		},
		alertGroups: map[string]*models.AlertGroup{
			alertGroupKey(projectID, groupID): {
				ID:             groupID,
				ProjectID:      projectID,
				Severity:       "ERROR",
				Category:       "system",
				Type:           "malware.detected",
				Status:         "CLOSED",
				GroupKey:       "grp-closed",
				Title:          "Malware detected",
				FirstSeenAt:    now.Add(-time.Minute),
				LastSeenAt:     now,
				LastNotifiedAt: &now,
			},
		},
	}

	job := store.AlertDispatchJob{
		ID:           jobID,
		MessageType:  store.AlertDispatchMessageTypeAlertEvent,
		EventState:   &eventState,
		ProjectID:    &projectID,
		GroupID:      &groupID,
		AttemptCount: 1,
		CreatedAt:    now.Add(-2 * time.Minute),
	}
	cfg := DefaultAlertmanagerIntegrationConfig()

	if err := processAlertEventJob(context.Background(), st, client, cfg, job, slog.Default()); err != nil {
		t.Fatalf("processAlertEventJob returned error: %v", err)
	}
	if postAlertsCalls != 1 {
		t.Fatalf("expected resolve dispatch when group is CLOSED, got %d calls", postAlertsCalls)
	}
	if len(st.doneJobIDs) != 1 || st.doneJobIDs[0] != jobID {
		t.Fatalf("expected job to be marked done exactly once, got %#v", st.doneJobIDs)
	}
	if len(st.retriedJobIDs) != 0 {
		t.Fatalf("expected no retry scheduling, got %#v", st.retriedJobIDs)
	}
	if len(st.deadJobIDs) != 0 {
		t.Fatalf("expected no dead-letter mark, got %#v", st.deadJobIDs)
	}
}

func TestLoadAlertEntityNames_UsesNamesAndFallsBackToIDs(t *testing.T) {
	projectID := uuid.New()
	productID := uuid.New()
	scopeID := uuid.New()
	testID := uuid.New()

	st := connectorDispatchStoreStub{
		projects: map[uuid.UUID]*models.Project{
			projectID: {
				ID:   projectID,
				Name: "Project Alpha",
			},
		},
		products: map[string]*models.Product{
			projectEntityKey(projectID, productID): {
				ID:   productID,
				Name: "Online Banking",
			},
		},
		tests: map[string]*models.Test{
			projectEntityKey(projectID, testID): {
				ID:   testID,
				Name: "API Payments",
			},
		},
	}
	occCtx := &store.AlertOccurrenceContext{
		ProductID: &productID,
		ScopeID:   &scopeID,
		TestID:    &testID,
	}

	names := loadAlertEntityNames(&st, projectID, occCtx)
	if names.project != "Project Alpha" {
		t.Fatalf("expected project name, got %q", names.project)
	}
	if names.product != "Online Banking" {
		t.Fatalf("expected product name, got %q", names.product)
	}
	if names.scope != scopeID.String() {
		t.Fatalf("expected scope ID fallback, got %q", names.scope)
	}
	if names.test != "API Payments" {
		t.Fatalf("expected test name, got %q", names.test)
	}
}

func TestBuildAlertmanagerAlert_UsesNameLabelsAndKeepsIDLabels(t *testing.T) {
	projectID := uuid.New()
	productID := uuid.New()
	scopeID := uuid.New()
	testID := uuid.New()

	group := models.AlertGroup{
		ProjectID:   projectID,
		Severity:    "ERROR",
		Category:    "system",
		Type:        "malware.detected",
		GroupKey:    "grp-123",
		Occurrences: 3,
		FirstSeenAt: time.Now().UTC(),
		Title:       "Malware detected",
	}
	occCtx := &store.AlertOccurrenceContext{
		ProductID: &productID,
		ScopeID:   &scopeID,
		TestID:    &testID,
	}
	names := alertEntityNames{
		project: "Project Name",
		product: "Product Name",
		scope:   "Scope Name",
		test:    "Test Name",
	}

	alert := buildAlertmanagerAlert(group, store.AlertDispatchEventStateFiring, "https://ctwall.local", store.ConnectorTypeSlack, occCtx, names)
	if alert.Labels["project"] != "Project Name" {
		t.Fatalf("expected project name label, got %q", alert.Labels["project"])
	}
	if alert.Labels["product"] != "Product Name" || alert.Labels["scope"] != "Scope Name" || alert.Labels["test"] != "Test Name" {
		t.Fatalf("expected name labels for product/scope/test, got %#v", alert.Labels)
	}
	if alert.Labels["project_id"] != projectID.String() {
		t.Fatalf("expected project_id label, got %q", alert.Labels["project_id"])
	}
	if alert.Labels["product_id"] != productID.String() || alert.Labels["scope_id"] != scopeID.String() || alert.Labels["test_id"] != testID.String() {
		t.Fatalf("expected *_id labels for product/scope/test, got %#v", alert.Labels)
	}
	if alert.Annotations["alert_url"] != "https://ctwall.local/security/alerts" {
		t.Fatalf("expected alert_url annotation, got %#v", alert.Annotations["alert_url"])
	}
	if alert.GeneratorURL != "https://ctwall.local/security/alerts" {
		t.Fatalf("expected generatorURL to point to CTWall alerts page, got %#v", alert.GeneratorURL)
	}
	description := alert.Annotations["description"]
	if !strings.Contains(description, "Project: Project Name") {
		t.Fatalf("expected project name in description, got %q", description)
	}
	if !strings.Contains(description, "Product: Product Name") || !strings.Contains(description, "Scope: Scope Name") || !strings.Contains(description, "Test: Test Name") {
		t.Fatalf("expected product/scope/test names in description, got %q", description)
	}
	if !strings.Contains(description, "Open in CTWall: https://ctwall.local/security/alerts") {
		t.Fatalf("expected CTWall URL in description, got %q", description)
	}
}

func TestBuildAlertmanagerAlert_FiringUsesLongEndsAtHorizon(t *testing.T) {
	group := models.AlertGroup{
		ProjectID:   uuid.New(),
		Severity:    "ERROR",
		Category:    "system",
		Type:        "malware.detected",
		GroupKey:    "grp-firing-horizon",
		Occurrences: 1,
		FirstSeenAt: time.Now().UTC(),
		Title:       "Malware detected",
	}

	now := time.Now().UTC()
	alert := buildAlertmanagerAlert(group, store.AlertDispatchEventStateFiring, "", store.ConnectorTypeSlack, nil, alertEntityNames{})
	if alert.EndsAt == "" {
		t.Fatalf("expected endsAt for FIRING alert")
	}
	endsAt, err := time.Parse(time.RFC3339, alert.EndsAt)
	if err != nil {
		t.Fatalf("parse endsAt: %v", err)
	}
	if !endsAt.After(now.Add(9 * 365 * 24 * time.Hour)) {
		t.Fatalf("expected long endsAt horizon, got %s", endsAt.Format(time.RFC3339))
	}
}

func TestBuildAlertmanagerAlert_ResolveUsesImmediateEndsAt(t *testing.T) {
	group := models.AlertGroup{
		ProjectID:   uuid.New(),
		Severity:    "ERROR",
		Category:    "system",
		Type:        "malware.detected",
		GroupKey:    "grp-resolve-immediate",
		Occurrences: 1,
		FirstSeenAt: time.Now().UTC(),
		Title:       "Malware detected",
	}

	before := time.Now().UTC()
	alert := buildAlertmanagerAlert(group, store.AlertDispatchEventStateResolve, "", store.ConnectorTypeSlack, nil, alertEntityNames{})
	if alert.EndsAt == "" {
		t.Fatalf("expected endsAt for RESOLVED alert")
	}
	endsAt, err := time.Parse(time.RFC3339, alert.EndsAt)
	if err != nil {
		t.Fatalf("parse endsAt: %v", err)
	}
	if endsAt.Before(before.Add(-2*time.Second)) || endsAt.After(time.Now().UTC().Add(2*time.Second)) {
		t.Fatalf("expected immediate endsAt around now, got %s", endsAt.Format(time.RFC3339))
	}
}
