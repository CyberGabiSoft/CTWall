package alerting

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewAlertmanagerClientValidation(t *testing.T) {
	t.Run("requires url", func(t *testing.T) {
		if _, err := NewAlertmanagerClient("", "user", "pass", time.Second); err == nil {
			t.Fatalf("expected url validation error")
		}
	})

	t.Run("rejects invalid url", func(t *testing.T) {
		if _, err := NewAlertmanagerClient("://bad", "user", "pass", time.Second); err == nil {
			t.Fatalf("expected invalid url error")
		}
	})

	t.Run("rejects password without username", func(t *testing.T) {
		if _, err := NewAlertmanagerClient("http://127.0.0.1:9093", "", "pass", time.Second); err == nil {
			t.Fatalf("expected credential validation error")
		}
	})
}

func TestAlertmanagerClientPostAlerts(t *testing.T) {
	var gotAuth string
	var gotPath string
	var gotMethod string
	var gotPayload []AlertmanagerAlert

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotMethod = r.Method
		gotAuth = r.Header.Get("Authorization")
		defer r.Body.Close()
		if err := json.NewDecoder(r.Body).Decode(&gotPayload); err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	client, err := NewAlertmanagerClient(srv.URL, "ctwall_backend", "secret", 2*time.Second)
	if err != nil {
		t.Fatalf("client init: %v", err)
	}

	alerts := []AlertmanagerAlert{
		{
			Labels: map[string]string{
				"alertname":  "MALWARE",
				"project_id": "project-1",
			},
		},
	}
	if err := client.PostAlerts(context.Background(), alerts); err != nil {
		t.Fatalf("post alerts: %v", err)
	}

	if gotPath != "/api/v2/alerts" {
		t.Fatalf("unexpected path: %s", gotPath)
	}
	if gotMethod != http.MethodPost {
		t.Fatalf("unexpected method: %s", gotMethod)
	}
	if len(gotPayload) != 1 || gotPayload[0].Labels["alertname"] != "MALWARE" {
		t.Fatalf("unexpected payload: %#v", gotPayload)
	}
	wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("ctwall_backend:secret"))
	if gotAuth != wantAuth {
		t.Fatalf("unexpected authorization header: %s", gotAuth)
	}
}

func TestAlertmanagerClientReloadErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "reload failed", http.StatusInternalServerError)
	}))
	defer srv.Close()

	client, err := NewAlertmanagerClient(srv.URL, "ctwall_backend", "secret", 2*time.Second)
	if err != nil {
		t.Fatalf("client init: %v", err)
	}
	err = client.Reload(context.Background())
	if err == nil {
		t.Fatalf("expected reload error")
	}
	if ok := strings.Contains(err.Error(), "500"); !ok {
		t.Fatalf("expected status code in error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "reload failed") {
		t.Fatalf("expected body in error, got: %v", err)
	}
}

func TestAlertmanagerClientPostAlerts_BearerAuth(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	client, err := NewAlertmanagerClientWithOptions(AlertmanagerClientOptions{
		BaseURL:     srv.URL,
		AuthMode:    "bearer",
		BearerToken: "token-123",
		Timeout:     2 * time.Second,
	})
	if err != nil {
		t.Fatalf("client init: %v", err)
	}
	if err := client.PostAlerts(context.Background(), []AlertmanagerAlert{{Labels: map[string]string{"alertname": "TEST"}}}); err != nil {
		t.Fatalf("post alerts: %v", err)
	}
	if gotAuth != "Bearer token-123" {
		t.Fatalf("unexpected bearer auth header: %s", gotAuth)
	}
}

func TestAlertmanagerClientReadyAndStatus(t *testing.T) {
	var readyCalls int
	var statusCalls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/-/ready":
			readyCalls++
			w.WriteHeader(http.StatusOK)
		case "/api/v2/status":
			statusCalls++
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	client, err := NewAlertmanagerClient(srv.URL, "", "", 2*time.Second)
	if err != nil {
		t.Fatalf("client init: %v", err)
	}
	if err := client.Ready(context.Background()); err != nil {
		t.Fatalf("ready check failed: %v", err)
	}
	if err := client.Status(context.Background()); err != nil {
		t.Fatalf("status check failed: %v", err)
	}
	if readyCalls != 1 {
		t.Fatalf("expected one ready call, got %d", readyCalls)
	}
	if statusCalls != 1 {
		t.Fatalf("expected one status call, got %d", statusCalls)
	}
}
