package alerting

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"backend/internal/store"
)

type DiscordConfig struct {
	WebhookURL      string
	Username        string
	AvatarURL       string
	MessageTemplate string
	TimeoutSeconds  int
}

type SendDiscordRequest struct {
	Content   string
	Username  string
	AvatarURL string
}

func ParseDiscordConfig(raw json.RawMessage) (*DiscordConfig, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "{}" {
		return nil, errors.New("discord config is empty")
	}

	if err := ValidateAlertmanagerConnectorConfig(store.ConnectorTypeDiscord, raw); err != nil {
		return nil, err
	}
	cfgMap, err := normalizeReceiverConfigObject(store.ConnectorTypeDiscord, raw)
	if err != nil {
		return nil, err
	}

	cfg := &DiscordConfig{
		WebhookURL:      strings.TrimSpace(asString(cfgMap["webhook_url"])),
		Username:        strings.TrimSpace(asString(cfgMap["username"])),
		AvatarURL:       strings.TrimSpace(asString(cfgMap["avatar_url"])),
		MessageTemplate: strings.TrimSpace(asString(cfgMap["message_template"])),
	}
	cfg.TimeoutSeconds = discordReadTimeoutSeconds(cfgMap)
	if cfg.TimeoutSeconds <= 0 {
		cfg.TimeoutSeconds = 10
	}
	if cfg.TimeoutSeconds > 30 {
		cfg.TimeoutSeconds = 30
	}

	return cfg, nil
}

func SendDiscord(ctx context.Context, cfg *DiscordConfig, req SendDiscordRequest) error {
	if cfg == nil {
		return errors.New("discord config is nil")
	}

	req.Content = strings.TrimSpace(req.Content)
	req.Username = strings.TrimSpace(req.Username)
	req.AvatarURL = strings.TrimSpace(req.AvatarURL)
	if req.Content == "" {
		return errors.New("discord content is required")
	}
	// Discord hard-limits message content to 2000 characters.
	if len(req.Content) > 2_000 {
		req.Content = req.Content[:2_000]
	}
	if req.Username == "" {
		req.Username = cfg.Username
	}
	if req.AvatarURL == "" {
		req.AvatarURL = cfg.AvatarURL
	}

	payload := map[string]string{
		"content": req.Content,
	}
	if req.Username != "" {
		payload["username"] = req.Username
	}
	if req.AvatarURL != "" {
		payload["avatar_url"] = req.AvatarURL
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	timeout := time.Duration(cfg.TimeoutSeconds) * time.Second
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           (&net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			MaxIdleConnsPerHost:   32,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   5 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}

	sendCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(sendCtx, http.MethodPost, cfg.WebhookURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(httpReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	return HTTPStatusError{StatusCode: resp.StatusCode, Body: string(respBody)}
}

func discordReadTimeoutSeconds(cfg map[string]any) int {
	readInt := func(key string) (int, bool) {
		value, ok := cfg[key]
		if !ok {
			return 0, false
		}
		switch typed := value.(type) {
		case float64:
			return int(typed), true
		case int:
			return typed, true
		case string:
			trimmed := strings.TrimSpace(typed)
			if trimmed == "" {
				return 0, false
			}
			if parsed, err := strconv.Atoi(trimmed); err == nil {
				return parsed, true
			}
		}
		return 0, false
	}

	if value, ok := readInt("timeout_seconds"); ok {
		return value
	}
	if value, ok := readInt("timeout"); ok {
		return value
	}
	return 0
}
