package store_test

import (
	"encoding/json"
	"testing"

	"backend/internal/eventmeta"
	"backend/internal/store"
	"backend/internal/tests"
)

func TestResolveEffectiveJiraSettings_Precedence(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)

	project, err := pgStore.CreateProject("jira-precedence-"+t.Name(), "", nil)
	if err != nil {
		t.Fatalf("create project: %v", err)
	}
	product, err := pgStore.CreateProductInProject(project.ID, "jira-product-"+t.Name(), "")
	if err != nil {
		t.Fatalf("create product: %v", err)
	}
	scope, err := pgStore.CreateScope(product.ID, "jira-scope-"+t.Name(), "")
	if err != nil {
		t.Fatalf("create scope: %v", err)
	}
	testEntity, _, err := pgStore.EnsureTest(scope.ID, "jira-test-"+t.Name(), "cyclonedx", "1.6")
	if err != nil {
		t.Fatalf("create test: %v", err)
	}

	if _, err := pgStore.UpsertJiraEntitySettings(store.JiraEntitySettingsUpsertInput{
		ProjectID:             project.ID,
		ConfigLevel:           store.JiraConfigLevelProduct,
		ConfigTargetID:        product.ID,
		IsEnabled:             true,
		JiraProjectKey:        "PROD",
		IssueType:             "Task",
		TicketSummaryTemplate: "product-template",
	}); err != nil {
		t.Fatalf("upsert product settings: %v", err)
	}

	effective, err := pgStore.ResolveEffectiveJiraSettings(store.JiraEffectiveSettingsResolveInput{
		ProjectID: project.ID,
		ProductID: &product.ID,
		ScopeID:   &scope.ID,
		TestID:    &testEntity.ID,
	})
	if err != nil {
		t.Fatalf("resolve effective from product: %v", err)
	}
	if effective.ResolvedFromLevel != store.JiraConfigLevelProduct {
		t.Fatalf("expected PRODUCT precedence, got %s", effective.ResolvedFromLevel)
	}

	if _, err := pgStore.UpsertJiraEntitySettings(store.JiraEntitySettingsUpsertInput{
		ProjectID:             project.ID,
		ConfigLevel:           store.JiraConfigLevelScope,
		ConfigTargetID:        scope.ID,
		IsEnabled:             true,
		JiraProjectKey:        "SCOPE",
		IssueType:             "Bug",
		TicketSummaryTemplate: "scope-template",
	}); err != nil {
		t.Fatalf("upsert scope settings: %v", err)
	}

	effective, err = pgStore.ResolveEffectiveJiraSettings(store.JiraEffectiveSettingsResolveInput{
		ProjectID: project.ID,
		ProductID: &product.ID,
		ScopeID:   &scope.ID,
		TestID:    &testEntity.ID,
	})
	if err != nil {
		t.Fatalf("resolve effective from scope: %v", err)
	}
	if effective.ResolvedFromLevel != store.JiraConfigLevelScope {
		t.Fatalf("expected SCOPE precedence, got %s", effective.ResolvedFromLevel)
	}

	if _, err := pgStore.UpsertJiraEntitySettings(store.JiraEntitySettingsUpsertInput{
		ProjectID:             project.ID,
		ConfigLevel:           store.JiraConfigLevelTest,
		ConfigTargetID:        testEntity.ID,
		IsEnabled:             true,
		JiraProjectKey:        "TEST",
		IssueType:             "Incident",
		TicketSummaryTemplate: "test-template",
	}); err != nil {
		t.Fatalf("upsert test settings: %v", err)
	}

	effective, err = pgStore.ResolveEffectiveJiraSettings(store.JiraEffectiveSettingsResolveInput{
		ProjectID: project.ID,
		ProductID: &product.ID,
		ScopeID:   &scope.ID,
		TestID:    &testEntity.ID,
	})
	if err != nil {
		t.Fatalf("resolve effective from test: %v", err)
	}
	if effective.ResolvedFromLevel != store.JiraConfigLevelTest {
		t.Fatalf("expected TEST precedence, got %s", effective.ResolvedFromLevel)
	}
}

func TestUpsertJiraIssueMapping_AllowsMultipleComponentMappingsPerSameGroupIdentity(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)

	project, err := pgStore.CreateProject("jira-mappings-"+t.Name(), "", nil)
	if err != nil {
		t.Fatalf("create project: %v", err)
	}
	product, err := pgStore.CreateProductInProject(project.ID, "jira-product-"+t.Name(), "")
	if err != nil {
		t.Fatalf("create product: %v", err)
	}
	scope, err := pgStore.CreateScope(product.ID, "jira-scope-"+t.Name(), "")
	if err != nil {
		t.Fatalf("create scope: %v", err)
	}
	testEntity, _, err := pgStore.EnsureTest(scope.ID, "jira-test-"+t.Name(), "cyclonedx", "1.6")
	if err != nil {
		t.Fatalf("create test: %v", err)
	}

	group, err := pgStore.UpsertAlertGroupAndInsertOccurrence(
		store.AlertGroupUpsert{
			ProjectID: project.ID,
			Severity:  eventmeta.SeverityError,
			Category:  eventmeta.CategoryMalware,
			Type:      "malware.detected",
			GroupKey:  "group-" + t.Name(),
			Title:     "Malware detected in active revision",
		},
		store.AlertOccurrenceInsert{
			ProjectID: project.ID,
			ProductID: &product.ID,
			ScopeID:   &scope.ID,
			TestID:    &testEntity.ID,
			Details:   json.RawMessage(`{"source":"integration_test"}`),
		},
	)
	if err != nil {
		t.Fatalf("upsert alert group: %v", err)
	}

	// Same project/config/group identity, different component PURLs must be allowed.
	first, err := pgStore.UpsertJiraIssueMapping(store.JiraIssueMappingUpsertInput{
		ProjectID:      project.ID,
		ConfigLevel:    store.JiraConfigLevelProduct,
		ConfigTargetID: product.ID,
		AlertGroupID:   group.ID,
		TestID:         &testEntity.ID,
		ComponentPURL:  "pkg:npm/a@1.0.0",
		Status:         store.JiraIssueMappingStatusOpen,
	})
	if err != nil {
		t.Fatalf("upsert first mapping: %v", err)
	}
	if first == nil || first.ID == [16]byte{} {
		t.Fatalf("expected first mapping to be created")
	}

	second, err := pgStore.UpsertJiraIssueMapping(store.JiraIssueMappingUpsertInput{
		ProjectID:      project.ID,
		ConfigLevel:    store.JiraConfigLevelProduct,
		ConfigTargetID: product.ID,
		AlertGroupID:   group.ID,
		TestID:         &testEntity.ID,
		ComponentPURL:  "pkg:npm/b@2.0.0",
		Status:         store.JiraIssueMappingStatusOpen,
	})
	if err != nil {
		t.Fatalf("upsert second mapping: %v", err)
	}
	if second == nil || second.ID == [16]byte{} {
		t.Fatalf("expected second mapping to be created")
	}
	if second.ID == first.ID {
		t.Fatalf("expected different mappings for different component purls")
	}

	openMappings, err := pgStore.ListOpenJiraIssueMappings(project.ID, group.ID, nil)
	if err != nil {
		t.Fatalf("list open mappings: %v", err)
	}
	if len(openMappings) != 2 {
		t.Fatalf("expected 2 open mappings, got %d", len(openMappings))
	}
}
