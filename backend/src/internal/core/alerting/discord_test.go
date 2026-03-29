package alerting

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseDiscordConfig(t *testing.T) {
	t.Setenv("ALERTING_ALLOW_HTTP_TARGETS", "true")
	t.Setenv("ALERTING_ALLOW_LOCALHOST_TARGETS", "true")

	cfg, err := ParseDiscordConfig(json.RawMessage(`{"webhookUrl":"http://127.0.0.1:8080/discord","timeoutSeconds":12}`))
	if err != nil {
		t.Fatalf("parse discord config: %v", err)
	}
	if cfg.WebhookURL != "http://127.0.0.1:8080/discord" {
		t.Fatalf("unexpected webhook url: %s", cfg.WebhookURL)
	}
	if cfg.TimeoutSeconds != 12 {
		t.Fatalf("unexpected timeout: %d", cfg.TimeoutSeconds)
	}
}

func TestSendDiscord(t *testing.T) {
	var gotPath string
	var gotPayload map[string]any

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		defer r.Body.Close()
		if err := json.NewDecoder(r.Body).Decode(&gotPayload); err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	cfg := &DiscordConfig{
		WebhookURL:     srv.URL + "/hook",
		Username:       "CTWall Bot",
		TimeoutSeconds: 10,
	}
	if err := SendDiscord(t.Context(), cfg, SendDiscordRequest{
		Content: "connector test",
	}); err != nil {
		t.Fatalf("send discord webhook: %v", err)
	}

	if gotPath != "/hook" {
		t.Fatalf("unexpected path: %s", gotPath)
	}
	if strings.TrimSpace(gotPayload["content"].(string)) != "connector test" {
		t.Fatalf("unexpected content payload: %#v", gotPayload["content"])
	}
	if strings.TrimSpace(gotPayload["username"].(string)) != "CTWall Bot" {
		t.Fatalf("unexpected username payload: %#v", gotPayload["username"])
	}
}
