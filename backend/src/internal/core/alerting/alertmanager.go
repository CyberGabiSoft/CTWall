package alerting

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type AlertmanagerAlert struct {
	Labels       map[string]string `json:"labels"`
	Annotations  map[string]string `json:"annotations,omitempty"`
	StartsAt     string            `json:"startsAt,omitempty"`
	EndsAt       string            `json:"endsAt,omitempty"`
	GeneratorURL string            `json:"generatorURL,omitempty"`
}

type HTTPStatusError struct {
	StatusCode int
	Body       string
}

func (e HTTPStatusError) Error() string {
	if strings.TrimSpace(e.Body) == "" {
		return fmt.Sprintf("unexpected status code: %d", e.StatusCode)
	}
	return fmt.Sprintf("unexpected status code: %d (%s)", e.StatusCode, strings.TrimSpace(e.Body))
}

type AlertmanagerClient struct {
	baseURL         string
	authMode        string
	username        string
	password        string
	bearerToken     string
	allowSelfSigned bool
	httpClient      *http.Client
}

type AlertmanagerClientOptions struct {
	BaseURL         string
	AuthMode        string
	Username        string
	Password        string
	BearerToken     string
	AllowSelfSigned bool
	Timeout         time.Duration
}

func NewAlertmanagerClient(baseURL, username, password string, timeout time.Duration) (*AlertmanagerClient, error) {
	authMode := "none"
	if strings.TrimSpace(username) != "" || strings.TrimSpace(password) != "" {
		authMode = "basic"
	}
	return NewAlertmanagerClientWithOptions(AlertmanagerClientOptions{
		BaseURL:  baseURL,
		AuthMode: authMode,
		Username: username,
		Password: password,
		Timeout:  timeout,
	})
}

func NewAlertmanagerClientWithOptions(options AlertmanagerClientOptions) (*AlertmanagerClient, error) {
	baseURL := strings.TrimSpace(options.BaseURL)
	if baseURL == "" {
		return nil, fmt.Errorf("alertmanager url is required")
	}
	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("invalid alertmanager url")
	}
	authMode := strings.ToLower(strings.TrimSpace(options.AuthMode))
	if authMode == "" {
		authMode = "none"
	}
	username := strings.TrimSpace(options.Username)
	password := strings.TrimSpace(options.Password)
	bearerToken := strings.TrimSpace(options.BearerToken)
	switch authMode {
	case "none":
		// No auth.
	case "basic":
		if username == "" {
			return nil, fmt.Errorf("alertmanager username is required for basic auth")
		}
		if password == "" {
			return nil, fmt.Errorf("alertmanager password is required for basic auth")
		}
		if bearerToken != "" {
			return nil, fmt.Errorf("alertmanager bearer token cannot be used with basic auth")
		}
	case "bearer":
		if bearerToken == "" {
			return nil, fmt.Errorf("alertmanager bearer token is required for bearer auth")
		}
		if username != "" || password != "" {
			return nil, fmt.Errorf("alertmanager username/password cannot be used with bearer auth")
		}
	default:
		return nil, fmt.Errorf("alertmanager auth mode must be one of: none, basic, bearer")
	}

	timeout := options.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   32,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	if options.AllowSelfSigned {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec
	}
	return &AlertmanagerClient{
		baseURL:         strings.TrimRight(parsed.String(), "/"),
		authMode:        authMode,
		username:        username,
		password:        password,
		bearerToken:     bearerToken,
		allowSelfSigned: options.AllowSelfSigned,
		httpClient: &http.Client{
			Timeout:   timeout,
			Transport: transport,
		},
	}, nil
}

func (c *AlertmanagerClient) PostAlerts(ctx context.Context, alerts []AlertmanagerAlert) error {
	if c == nil {
		return fmt.Errorf("alertmanager client is nil")
	}
	if len(alerts) == 0 {
		return nil
	}
	body, err := json.Marshal(alerts)
	if err != nil {
		return fmt.Errorf("marshal alert payload: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/v2/alerts", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	c.applyAuth(req)
	return c.do(req, http.StatusOK, http.StatusAccepted)
}

func (c *AlertmanagerClient) Reload(ctx context.Context) error {
	if c == nil {
		return fmt.Errorf("alertmanager client is nil")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/-/reload", nil)
	if err != nil {
		return err
	}
	c.applyAuth(req)
	return c.do(req, http.StatusOK, http.StatusAccepted)
}

func (c *AlertmanagerClient) Ready(ctx context.Context) error {
	if c == nil {
		return fmt.Errorf("alertmanager client is nil")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/-/ready", nil)
	if err != nil {
		return err
	}
	c.applyAuth(req)
	return c.do(req, http.StatusOK)
}

func (c *AlertmanagerClient) Status(ctx context.Context) error {
	if c == nil {
		return fmt.Errorf("alertmanager client is nil")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/api/v2/status", nil)
	if err != nil {
		return err
	}
	c.applyAuth(req)
	return c.do(req, http.StatusOK)
}

func (c *AlertmanagerClient) applyAuth(req *http.Request) {
	if c == nil || req == nil {
		return
	}
	switch c.authMode {
	case "basic":
		req.SetBasicAuth(c.username, c.password)
	case "bearer":
		req.Header.Set("Authorization", "Bearer "+c.bearerToken)
	}
}

func (c *AlertmanagerClient) do(req *http.Request, okStatuses ...int) error {
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	for _, okStatus := range okStatuses {
		if resp.StatusCode == okStatus {
			return nil
		}
	}
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	return HTTPStatusError{
		StatusCode: resp.StatusCode,
		Body:       string(data),
	}
}
