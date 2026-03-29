package alerting

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseSlackConfig(t *testing.T) {
	t.Run("webhook only", func(t *testing.T) {
		cfg, err := ParseSlackConfig(json.RawMessage(`{"webhookUrl":"https://hooks.slack.com/services/a/b/c"}`))
		if err != nil {
			t.Fatalf("parse config: %v", err)
		}
		if cfg.WebhookURL == "" {
			t.Fatalf("expected webhook url")
		}
	})

	t.Run("bot token requires default channel", func(t *testing.T) {
		if _, err := ParseSlackConfig(json.RawMessage(`{"botToken":"xoxb-123"}`)); err == nil {
			t.Fatalf("expected missing defaultChannel error")
		}
	})
}

func TestSendSlackWebhook(t *testing.T) {
	var gotPath string
	var gotAuth string
	var gotPayload map[string]any

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		defer r.Body.Close()
		if err := json.NewDecoder(r.Body).Decode(&gotPayload); err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	cfg, err := ParseSlackConfig(json.RawMessage(`{"webhookUrl":"` + srv.URL + `/hook","username":"CTWall Bot"}`))
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	if err := SendSlack(t.Context(), cfg, SendSlackRequest{Text: "connector test"}); err != nil {
		t.Fatalf("send webhook: %v", err)
	}
	if gotPath != "/hook" {
		t.Fatalf("unexpected path: %s", gotPath)
	}
	if gotAuth != "" {
		t.Fatalf("webhook send should not include bearer auth")
	}
	if strings.TrimSpace(gotPayload["text"].(string)) != "connector test" {
		t.Fatalf("unexpected text payload: %#v", gotPayload["text"])
	}
}

func TestSendSlackBotToken(t *testing.T) {
	originalURL := slackChatPostMessageURL
	defer func() { slackChatPostMessageURL = originalURL }()

	var gotAuth string
	var gotPayload map[string]any

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		defer r.Body.Close()
		if err := json.NewDecoder(r.Body).Decode(&gotPayload); err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()
	slackChatPostMessageURL = srv.URL + "/api/chat.postMessage"

	cfg, err := ParseSlackConfig(json.RawMessage(`{"botToken":"xoxb-123","defaultChannel":"#alerts"}`))
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	if err := SendSlack(t.Context(), cfg, SendSlackRequest{Text: "connector test"}); err != nil {
		t.Fatalf("send bot token: %v", err)
	}
	if gotAuth != "Bearer xoxb-123" {
		t.Fatalf("unexpected auth header: %s", gotAuth)
	}
	if gotPayload["channel"] != "#alerts" {
		t.Fatalf("expected default channel, got %#v", gotPayload["channel"])
	}
}
