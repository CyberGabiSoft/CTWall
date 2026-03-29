package alerting

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type SlackConfig struct {
	WebhookURL      string `json:"webhookUrl"`
	BotToken        string `json:"botToken"`
	DefaultChannel  string `json:"defaultChannel"`
	Username        string `json:"username"`
	MessageTemplate string `json:"messageTemplate"`
	TimeoutSeconds  int    `json:"timeoutSeconds"`
}

type SendSlackRequest struct {
	Text     string
	Channel  string
	Username string
}

var slackChatPostMessageURL = "https://slack.com/api/chat.postMessage"

func ParseSlackConfig(raw json.RawMessage) (*SlackConfig, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "{}" {
		return nil, errors.New("slack config is empty")
	}

	var cfg SlackConfig
	if err := json.Unmarshal([]byte(trimmed), &cfg); err != nil {
		return nil, fmt.Errorf("invalid slack config json: %w", err)
	}

	cfg.WebhookURL = strings.TrimSpace(cfg.WebhookURL)
	cfg.BotToken = strings.TrimSpace(cfg.BotToken)
	cfg.DefaultChannel = strings.TrimSpace(cfg.DefaultChannel)
	cfg.Username = strings.TrimSpace(cfg.Username)
	cfg.MessageTemplate = strings.TrimSpace(cfg.MessageTemplate)

	var rawMap map[string]any
	if err := json.Unmarshal([]byte(trimmed), &rawMap); err == nil {
		normalized := normalizeMapKeys(rawMap)
		if cfg.MessageTemplate == "" {
			cfg.MessageTemplate = strings.TrimSpace(asString(normalized["message_template"]))
		}
	}

	if cfg.WebhookURL == "" && cfg.BotToken == "" {
		return nil, errors.New("slack requires either webhookUrl or botToken")
	}
	if cfg.WebhookURL != "" {
		parsed, err := url.Parse(cfg.WebhookURL)
		if err != nil || parsed == nil || parsed.Host == "" {
			return nil, errors.New("slack webhookUrl must be a valid URL")
		}
		if parsed.Scheme != "https" && parsed.Scheme != "http" {
			return nil, errors.New("slack webhookUrl scheme must be http or https")
		}
	}
	if cfg.WebhookURL == "" && cfg.DefaultChannel == "" {
		return nil, errors.New("slack defaultChannel is required when botToken is used")
	}
	if cfg.TimeoutSeconds <= 0 {
		cfg.TimeoutSeconds = 10
	}
	if cfg.TimeoutSeconds > 30 {
		cfg.TimeoutSeconds = 30
	}
	return &cfg, nil
}

func SendSlack(ctx context.Context, cfg *SlackConfig, req SendSlackRequest) error {
	if cfg == nil {
		return errors.New("slack config is nil")
	}
	req.Text = strings.TrimSpace(req.Text)
	req.Channel = strings.TrimSpace(req.Channel)
	req.Username = strings.TrimSpace(req.Username)
	if req.Text == "" {
		return errors.New("slack message text is required")
	}
	if len(req.Text) > 5_000 {
		req.Text = req.Text[:5_000]
	}
	if req.Username == "" {
		req.Username = cfg.Username
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
	if cfg.WebhookURL != "" {
		return sendSlackWebhook(sendCtx, client, cfg, req)
	}
	return sendSlackBotMessage(sendCtx, client, cfg, req)
}

func sendSlackWebhook(ctx context.Context, client *http.Client, cfg *SlackConfig, req SendSlackRequest) error {
	payload := map[string]string{
		"text": req.Text,
	}
	channel := req.Channel
	if channel == "" {
		channel = cfg.DefaultChannel
	}
	if channel != "" {
		payload["channel"] = channel
	}
	if req.Username != "" {
		payload["username"] = req.Username
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.WebhookURL, bytes.NewReader(body))
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
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	return HTTPStatusError{StatusCode: resp.StatusCode, Body: string(data)}
}

func sendSlackBotMessage(ctx context.Context, client *http.Client, cfg *SlackConfig, req SendSlackRequest) error {
	channel := req.Channel
	if channel == "" {
		channel = cfg.DefaultChannel
	}
	channel = strings.TrimSpace(channel)
	if channel == "" {
		return errors.New("slack channel is required for bot token send")
	}

	payload := map[string]string{
		"channel": channel,
		"text":    req.Text,
	}
	if req.Username != "" {
		payload["username"] = req.Username
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, slackChatPostMessageURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json; charset=utf-8")
	httpReq.Header.Set("Authorization", "Bearer "+cfg.BotToken)

	resp, err := client.Do(httpReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return HTTPStatusError{StatusCode: resp.StatusCode, Body: string(bodyBytes)}
	}
	var slackResp struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(bodyBytes, &slackResp); err != nil {
		return fmt.Errorf("invalid slack api response: %w", err)
	}
	if !slackResp.OK {
		reason := strings.TrimSpace(slackResp.Error)
		if reason == "" {
			reason = "unknown_error"
		}
		return fmt.Errorf("slack api error: %s", reason)
	}
	return nil
}
