package alerting

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"os"
	"strconv"
	"strings"
	"time"
)

// SMTPConfig is the minimal SMTP connector config supported by CTWall (MVP).
// It is stored as JSON in connector_configs.config_json for connector_type=SMTP.
type SMTPConfig struct {
	Host            string `json:"host"`
	Port            int    `json:"port"`
	Username        string `json:"username"`
	Password        string `json:"password"`
	AuthIdentity    string `json:"authIdentity"`
	AuthSecret      string `json:"authSecret"`
	FromEmail       string `json:"fromEmail"`
	FromName        string `json:"fromName"`
	ReplyTo         string `json:"replyTo"`
	Domain          string `json:"domain"`
	CAFile          string `json:"caFile"`
	ServerName      string `json:"serverName"`
	Auth            string `json:"auth"`       // login|plain|cram_md5|none
	Encryption      string `json:"encryption"` // starttls|tls|none
	VerifyMode      string `json:"verifyMode"` // peer|none
	MessageTemplate string `json:"messageTemplate"`
	TimeoutSeconds  int    `json:"timeoutSeconds"`
	SendResolved    bool   `json:"sendResolved"`
}

func ParseSMTPConfig(raw json.RawMessage) (*SMTPConfig, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "{}" {
		return nil, errors.New("smtp config is empty")
	}
	cfg := SMTPConfig{SendResolved: true}
	if err := json.Unmarshal([]byte(trimmed), &cfg); err != nil {
		return nil, fmt.Errorf("invalid smtp config json: %w", err)
	}
	var rawMap map[string]any
	if err := json.Unmarshal([]byte(trimmed), &rawMap); err == nil {
		normalized := normalizeMapKeys(rawMap)
		if rawSendResolved, exists := normalized["send_resolved"]; exists {
			value, ok := parseBoolConfigValue(rawSendResolved)
			if !ok {
				return nil, errors.New("smtp sendResolved must be a boolean")
			}
			cfg.SendResolved = value
		}
		if cfg.MessageTemplate == "" {
			cfg.MessageTemplate = strings.TrimSpace(asString(normalized["message_template"]))
		}
	}
	cfg.Host = strings.TrimSpace(cfg.Host)
	cfg.Username = strings.TrimSpace(cfg.Username)
	cfg.AuthIdentity = strings.TrimSpace(cfg.AuthIdentity)
	cfg.AuthSecret = strings.TrimSpace(cfg.AuthSecret)
	cfg.FromEmail = strings.TrimSpace(cfg.FromEmail)
	cfg.FromName = strings.TrimSpace(cfg.FromName)
	cfg.ReplyTo = strings.TrimSpace(cfg.ReplyTo)
	cfg.Domain = strings.TrimSpace(cfg.Domain)
	cfg.CAFile = strings.TrimSpace(cfg.CAFile)
	cfg.ServerName = strings.TrimSpace(cfg.ServerName)
	cfg.Auth = strings.ToLower(strings.TrimSpace(cfg.Auth))
	cfg.Encryption = strings.ToLower(strings.TrimSpace(cfg.Encryption))
	cfg.VerifyMode = strings.ToLower(strings.TrimSpace(cfg.VerifyMode))
	cfg.MessageTemplate = strings.TrimSpace(cfg.MessageTemplate)

	if cfg.Host == "" {
		return nil, errors.New("smtp host is required")
	}
	if cfg.Port <= 0 || cfg.Port > 65535 {
		return nil, errors.New("smtp port must be between 1 and 65535")
	}
	if cfg.TimeoutSeconds <= 0 {
		cfg.TimeoutSeconds = 10
	}
	if cfg.TimeoutSeconds > 60 {
		cfg.TimeoutSeconds = 60
	}
	if cfg.Auth == "" {
		cfg.Auth = "login"
	}
	if cfg.Encryption == "" {
		// Safe default for port 587.
		cfg.Encryption = "starttls"
	}
	if cfg.VerifyMode == "" {
		cfg.VerifyMode = "peer"
	}

	switch cfg.Encryption {
	case "starttls", "tls", "none":
	default:
		return nil, errors.New("smtp encryption must be one of: starttls, tls, none")
	}
	switch cfg.VerifyMode {
	case "peer", "none":
	default:
		return nil, errors.New("smtp verifyMode must be one of: peer, none")
	}
	switch cfg.Auth {
	case "login", "plain", "cram_md5", "none":
	default:
		return nil, errors.New("smtp auth must be one of: login, plain, cram_md5, none")
	}
	switch cfg.Auth {
	case "none":
		// No auth required.
	case "login", "plain":
		if cfg.Username == "" || cfg.Password == "" {
			return nil, errors.New("smtp username/password required for selected auth mode")
		}
	case "cram_md5":
		if cfg.Username == "" {
			return nil, errors.New("smtp username is required for cram_md5 auth")
		}
		if cfg.AuthSecret == "" && cfg.Password == "" {
			return nil, errors.New("smtp authSecret or password is required for cram_md5 auth")
		}
	}

	if cfg.Encryption == "none" && !allowInsecureSMTP() {
		return nil, errors.New("insecure smtp is disabled (set ALERTING_ALLOW_INSECURE_SMTP=true for local dev only)")
	}

	// Port/encryption sanity (GitLab-compatible).
	if cfg.Port == 587 && cfg.Encryption == "tls" {
		return nil, errors.New("smtp encryption=tls is not valid for port 587 (use starttls)")
	}
	if cfg.Port == 465 && cfg.Encryption == "starttls" {
		return nil, errors.New("smtp encryption=starttls is not valid for port 465 (use tls)")
	}

	if cfg.FromEmail == "" {
		cfg.FromEmail = cfg.Username
	}
	if cfg.FromEmail == "" {
		return nil, errors.New("smtp fromEmail is required")
	}

	return &cfg, nil
}

func parseBoolConfigValue(value any) (bool, bool) {
	switch typed := value.(type) {
	case bool:
		return typed, true
	case string:
		switch strings.ToLower(strings.TrimSpace(typed)) {
		case "1", "true", "yes", "on":
			return true, true
		case "0", "false", "no", "off":
			return false, true
		default:
			return false, false
		}
	case float64:
		if typed == 1 {
			return true, true
		}
		if typed == 0 {
			return false, true
		}
	}
	return false, false
}

// AlertmanagerRequireTLS maps CTWall SMTP transport policy to Alertmanager v0.28.1 behavior.
// - starttls => require STARTTLS
// - tls+465  => implicit TLS path, must not require STARTTLS
// - none     => no TLS requirement
func (cfg *SMTPConfig) AlertmanagerRequireTLS() bool {
	if cfg == nil {
		return false
	}
	switch cfg.Encryption {
	case "starttls":
		return true
	case "tls":
		return cfg.Port != 465
	default:
		return false
	}
}

func allowInsecureSMTP() bool {
	raw := strings.TrimSpace(os.Getenv("ALERTING_ALLOW_INSECURE_SMTP"))
	raw = strings.ToLower(raw)
	return raw == "1" || raw == "true" || raw == "yes" || raw == "on"
}

type SendEmailRequest struct {
	ToEmail string
	Subject string
	Body    string // plain text (MVP)
}

func SendSMTP(ctx context.Context, cfg *SMTPConfig, req SendEmailRequest) error {
	if cfg == nil {
		return errors.New("smtp config is nil")
	}
	req.ToEmail = strings.TrimSpace(req.ToEmail)
	req.Subject = strings.TrimSpace(req.Subject)
	if req.ToEmail == "" || req.Subject == "" {
		return errors.New("missing toEmail or subject")
	}
	// Defensive limits: avoid huge payloads / log spam.
	if len(req.Subject) > 200 {
		req.Subject = req.Subject[:200]
	}
	if len(req.Body) > 100_000 {
		req.Body = req.Body[:100_000]
	}

	timeout := time.Duration(cfg.TimeoutSeconds) * time.Second
	dialer := &net.Dialer{Timeout: timeout}

	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))

	tlsConfig := &tls.Config{
		ServerName: cfg.Host,
		MinVersion: tls.VersionTLS12,
	}
	if cfg.VerifyMode == "none" {
		tlsConfig.InsecureSkipVerify = true // local dev only; gated by config/env validation.
	}

	var c *smtp.Client
	var conn net.Conn
	var err error

	switch cfg.Encryption {
	case "tls":
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, tlsConfig)
		if err != nil {
			return fmt.Errorf("smtp tls dial: %w", err)
		}
		c, err = smtp.NewClient(conn, cfg.Host)
		if err != nil {
			_ = conn.Close()
			return fmt.Errorf("smtp client: %w", err)
		}
	case "starttls", "none":
		conn, err = dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			return fmt.Errorf("smtp dial: %w", err)
		}
		c, err = smtp.NewClient(conn, cfg.Host)
		if err != nil {
			_ = conn.Close()
			return fmt.Errorf("smtp client: %w", err)
		}
		if cfg.Encryption == "starttls" {
			if err := c.StartTLS(tlsConfig); err != nil {
				_ = c.Close()
				return fmt.Errorf("smtp starttls: %w", err)
			}
		}
	default:
		return errors.New("unsupported smtp encryption")
	}
	defer func() { _ = c.Close() }()

	auth, err := buildSMTPAuth(cfg)
	if err != nil {
		return err
	}
	if auth != nil {
		if err := c.Auth(auth); err != nil {
			return fmt.Errorf("smtp auth: %w", err)
		}
	}

	if err := c.Mail(cfg.FromEmail); err != nil {
		return fmt.Errorf("smtp MAIL FROM: %w", err)
	}
	if err := c.Rcpt(req.ToEmail); err != nil {
		return fmt.Errorf("smtp RCPT TO: %w", err)
	}

	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("smtp DATA: %w", err)
	}
	defer func() { _ = w.Close() }()

	msg := buildPlainEmailMessage(cfg, req)
	// Apply a soft write deadline to avoid hanging.
	_ = conn.SetWriteDeadline(time.Now().Add(timeout))
	if _, err := w.Write([]byte(msg)); err != nil {
		return fmt.Errorf("smtp write: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("smtp data close: %w", err)
	}
	if err := c.Quit(); err != nil {
		// Treat quit failure as non-fatal: message already delivered to server.
		return nil
	}
	return nil
}

func buildPlainEmailMessage(cfg *SMTPConfig, req SendEmailRequest) string {
	from := cfg.FromEmail
	if cfg.FromName != "" {
		// Minimal header escaping: strip CR/LF (header injection).
		cleanName := strings.NewReplacer("\r", "", "\n", "").Replace(cfg.FromName)
		cleanFrom := strings.NewReplacer("\r", "", "\n", "").Replace(cfg.FromEmail)
		from = fmt.Sprintf("%s <%s>", cleanName, cleanFrom)
	}
	to := strings.NewReplacer("\r", "", "\n", "").Replace(req.ToEmail)
	subject := strings.NewReplacer("\r", "", "\n", "").Replace(req.Subject)

	var b strings.Builder
	b.WriteString("From: " + from + "\r\n")
	b.WriteString("To: " + to + "\r\n")
	if cfg.ReplyTo != "" {
		replyTo := strings.NewReplacer("\r", "", "\n", "").Replace(cfg.ReplyTo)
		b.WriteString("Reply-To: " + replyTo + "\r\n")
	}
	b.WriteString("Subject: " + subject + "\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	b.WriteString("\r\n")
	b.WriteString(req.Body)
	if !strings.HasSuffix(req.Body, "\n") {
		b.WriteString("\n")
	}
	return b.String()
}

func buildSMTPAuth(cfg *SMTPConfig) (smtp.Auth, error) {
	if cfg == nil || cfg.Auth == "none" {
		return nil, nil
	}
	switch cfg.Auth {
	case "login", "plain":
		if cfg.Username == "" || cfg.Password == "" {
			return nil, errors.New("smtp username/password required for auth")
		}
		identity := ""
		if cfg.Auth == "plain" {
			identity = cfg.AuthIdentity
		}
		return smtp.PlainAuth(identity, cfg.Username, cfg.Password, cfg.Host), nil
	case "cram_md5":
		if cfg.Username == "" {
			return nil, errors.New("smtp username is required for cram_md5 auth")
		}
		secret := cfg.AuthSecret
		if secret == "" {
			secret = cfg.Password
		}
		if secret == "" {
			return nil, errors.New("smtp authSecret or password is required for cram_md5 auth")
		}
		return smtp.CRAMMD5Auth(cfg.Username, secret), nil
	default:
		return nil, errors.New("unsupported smtp auth mode")
	}
}
