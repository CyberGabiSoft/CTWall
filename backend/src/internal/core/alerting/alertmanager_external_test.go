package alerting

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestParseExternalAlertmanagerConnectorConfig(t *testing.T) {
	t.Setenv("ALERTING_ALLOW_HTTP_TARGETS", "true")
	t.Setenv("ALERTING_ALLOW_LOCALHOST_TARGETS", "true")

	cfg, err := ParseExternalAlertmanagerConnectorConfig([]byte(`{
		"baseUrl":"http://127.0.0.1:9093",
		"authMode":"basic",
		"username":"svc",
		"password":"secret",
		"timeoutSeconds":15,
		"sendResolved":false,
		"allowSelfSigned":true
	}`))
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	if cfg.BaseURL != "http://127.0.0.1:9093" {
		t.Fatalf("unexpected base url: %s", cfg.BaseURL)
	}
	if cfg.AuthMode != ExternalAlertmanagerAuthBasic {
		t.Fatalf("unexpected auth mode: %s", cfg.AuthMode)
	}
	if cfg.TimeoutSeconds != 15 {
		t.Fatalf("unexpected timeout: %d", cfg.TimeoutSeconds)
	}
	if cfg.SendResolved {
		t.Fatalf("expected sendResolved=false")
	}
	if !cfg.AllowSelfSigned {
		t.Fatalf("expected allowSelfSigned=true")
	}
}

func TestParseExternalAlertmanagerConnectorConfig_AuthValidation(t *testing.T) {
	t.Setenv("ALERTING_ALLOW_HTTP_TARGETS", "true")
	t.Setenv("ALERTING_ALLOW_LOCALHOST_TARGETS", "true")

	if _, err := ParseExternalAlertmanagerConnectorConfig([]byte(`{
		"baseUrl":"http://127.0.0.1:9093",
		"authMode":"basic",
		"username":"svc"
	}`)); err == nil {
		t.Fatalf("expected missing password error for basic auth")
	}

	if _, err := ParseExternalAlertmanagerConnectorConfig([]byte(`{
		"baseUrl":"http://127.0.0.1:9093",
		"authMode":"bearer"
	}`)); err == nil {
		t.Fatalf("expected missing token error for bearer auth")
	}
}

func TestExternalAlertmanagerConnection_ReadyOrStatus(t *testing.T) {
	t.Setenv("ALERTING_ALLOW_HTTP_TARGETS", "true")
	t.Setenv("ALERTING_ALLOW_LOCALHOST_TARGETS", "true")

	var readyCalls int
	var statusCalls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/-/ready":
			readyCalls++
			w.WriteHeader(http.StatusServiceUnavailable)
		case "/api/v2/status":
			statusCalls++
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	cfg, err := ParseExternalAlertmanagerConnectorConfig([]byte(`{
		"baseUrl":"` + srv.URL + `",
		"authMode":"none",
		"timeoutSeconds":10
	}`))
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := TestExternalAlertmanagerConnection(ctx, cfg); err != nil {
		t.Fatalf("expected connection test to succeed via /api/v2/status fallback: %v", err)
	}
	if readyCalls != 1 {
		t.Fatalf("expected one ready call, got %d", readyCalls)
	}
	if statusCalls != 1 {
		t.Fatalf("expected one status call, got %d", statusCalls)
	}
}
