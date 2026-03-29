package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"backend/internal/core/auth"
	"backend/internal/store"
	"backend/internal/tests"

	"github.com/google/uuid"
)

func withAuthedAdminAndProject(t *testing.T, st store.Store, req *http.Request) (*http.Request, uuid.UUID, uuid.UUID) {
	t.Helper()

	user, err := st.CreateUser("dedup-rules-admin-"+uuid.NewString()+"@example.com", "hash", "ADMIN", "USER", "Dedup Admin")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	projectID, err := st.GetSelectedProjectID(user.ID)
	if err != nil {
		t.Fatalf("get selected project: %v", err)
	}
	if projectID == nil || *projectID == uuid.Nil {
		t.Fatalf("expected selected project id")
	}

	ctx := auth.WithUser(req.Context(), auth.UserContext{
		ID:          user.ID,
		Email:       user.Email,
		Role:        auth.RoleAdmin,
		AccountType: auth.AccountTypeUser,
	})
	return req.WithContext(ctx), user.ID, *projectID
}

func TestParseAlertDedupRuleType(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/alerts/dedup-rules", nil)
	if got := parseAlertDedupRuleType(req); got != defaultAlertDedupRuleType {
		t.Fatalf("expected default type, got %q", got)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/alerts/dedup-rules?alertType=custom.type", nil)
	if got := parseAlertDedupRuleType(req); got != "custom.type" {
		t.Fatalf("expected custom type, got %q", got)
	}
}

func TestListAlertDedupRulesHandler_RequiresAuth(t *testing.T) {
	st, _ := tests.NewPostgresTestStore(t)
	handler := ListAlertDedupRulesHandler(st)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/alerts/dedup-rules", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without auth, got %d", rec.Code)
	}
}

func TestListAlertDedupRulesHandler_DefaultFallback(t *testing.T) {
	st, _ := tests.NewPostgresTestStore(t)
	handler := ListAlertDedupRulesHandler(st)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/alerts/dedup-rules", nil)
	req, _, projectID := withAuthedAdminAndProject(t, st, req)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var payload alertDedupRuleResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(payload.Items) != 1 {
		t.Fatalf("expected 1 fallback item, got %d", len(payload.Items))
	}
	if payload.Items[0].ProjectID != projectID {
		t.Fatalf("unexpected project id in fallback row")
	}
	if payload.Items[0].DedupScope != string(store.AlertDedupScopeTest) {
		t.Fatalf("expected TEST fallback scope for malware.detected, got %q", payload.Items[0].DedupScope)
	}
}

func TestPutAlertDedupRulesHandler_InvalidPayload(t *testing.T) {
	st, _ := tests.NewPostgresTestStore(t)
	handler := PutAlertDedupRulesHandler(st, nil)

	req := httptest.NewRequest(http.MethodPut, "/api/v1/alerts/dedup-rules", bytes.NewBufferString(`{"rules":[{"dedupScope":"PRODUCT","productId":"bad-uuid"}]}`))
	req, _, _ = withAuthedAdminAndProject(t, st, req)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid UUID payload, got %d", rec.Code)
	}
}

func TestPutAlertDedupRulesHandler_ReplaceAndList(t *testing.T) {
	st, _ := tests.NewPostgresTestStore(t)
	putHandler := PutAlertDedupRulesHandler(st, nil)
	listHandler := ListAlertDedupRulesHandler(st)

	product, err := st.CreateProduct("dedup-product-"+uuid.NewString(), "")
	if err != nil {
		t.Fatalf("create product: %v", err)
	}

	body := map[string]any{
		"rules": []map[string]any{
			{
				"dedupScope": "PRODUCT",
				"productId":  product.ID.String(),
				"enabled":    true,
			},
		},
	}
	raw, _ := json.Marshal(body)
	putReq := httptest.NewRequest(http.MethodPut, "/api/v1/alerts/dedup-rules?alertType=malware.detected", bytes.NewReader(raw))
	putReq, _, _ = withAuthedAdminAndProject(t, st, putReq)
	putRec := httptest.NewRecorder()
	putHandler.ServeHTTP(putRec, putReq)

	if putRec.Code != http.StatusOK {
		t.Fatalf("expected 200 on put, got %d; body=%s", putRec.Code, putRec.Body.String())
	}
	var putPayload alertDedupRuleResponse
	if err := json.Unmarshal(putRec.Body.Bytes(), &putPayload); err != nil {
		t.Fatalf("decode put response: %v", err)
	}
	if len(putPayload.Items) < 1 {
		t.Fatalf("expected at least one saved rule, got %d", len(putPayload.Items))
	}

	listReq := httptest.NewRequest(http.MethodGet, "/api/v1/alerts/dedup-rules?alertType=malware.detected", nil)
	listReq, _, _ = withAuthedAdminAndProject(t, st, listReq)
	listRec := httptest.NewRecorder()
	listHandler.ServeHTTP(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("expected 200 on list, got %d", listRec.Code)
	}
	var listPayload alertDedupRuleResponse
	if err := json.Unmarshal(listRec.Body.Bytes(), &listPayload); err != nil {
		t.Fatalf("decode list response: %v", err)
	}
	if len(listPayload.Items) == 0 {
		t.Fatalf("expected dedup rules in list")
	}
}
