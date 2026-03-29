package alerting

import (
	"encoding/json"
	"testing"
)

func TestParseSMTPConfig_ExtendedFields(t *testing.T) {
	raw := json.RawMessage(`{
		"host":" smtp.example.local ",
		"port":587,
		"username":" user@example.local ",
		"password":" secret ",
		"auth":"plain",
		"authIdentity":" relay-identity ",
		"fromEmail":" alerts@example.local ",
		"fromName":" CTWall Alerts ",
		"replyTo":" noreply@example.local ",
		"domain":" ctwall.local ",
		"caFile":" /etc/ssl/certs/custom-ca.pem ",
		"serverName":" smtp.example.local ",
		"encryption":"starttls",
		"verifyMode":"peer"
	}`)

	cfg, err := ParseSMTPConfig(raw)
	if err != nil {
		t.Fatalf("parse smtp config: %v", err)
	}

	if cfg.Host != "smtp.example.local" {
		t.Fatalf("unexpected host: %q", cfg.Host)
	}
	if cfg.Auth != "plain" {
		t.Fatalf("unexpected auth mode: %q", cfg.Auth)
	}
	if cfg.AuthIdentity != "relay-identity" {
		t.Fatalf("unexpected auth identity: %q", cfg.AuthIdentity)
	}
	if cfg.Domain != "ctwall.local" {
		t.Fatalf("unexpected domain: %q", cfg.Domain)
	}
	if cfg.CAFile != "/etc/ssl/certs/custom-ca.pem" {
		t.Fatalf("unexpected caFile: %q", cfg.CAFile)
	}
	if cfg.ServerName != "smtp.example.local" {
		t.Fatalf("unexpected serverName: %q", cfg.ServerName)
	}
	if cfg.TimeoutSeconds != 10 {
		t.Fatalf("expected default timeout=10, got %d", cfg.TimeoutSeconds)
	}
	if cfg.SendResolved != true {
		t.Fatalf("expected default sendResolved=true, got %v", cfg.SendResolved)
	}
}

func TestParseSMTPConfig_ReadsSendResolvedSnakeCase(t *testing.T) {
	raw := json.RawMessage(`{
		"host":"smtp.example.local",
		"port":587,
		"username":"mailer",
		"password":"secret",
		"auth":"login",
		"fromEmail":"alerts@example.local",
		"encryption":"starttls",
		"send_resolved":false
	}`)

	cfg, err := ParseSMTPConfig(raw)
	if err != nil {
		t.Fatalf("parse smtp config: %v", err)
	}
	if cfg.SendResolved != false {
		t.Fatalf("expected sendResolved=false, got %v", cfg.SendResolved)
	}
}

func TestParseSMTPConfig_AllowsCRAMMD5WithAuthSecret(t *testing.T) {
	raw := json.RawMessage(`{
		"host":"smtp.example.local",
		"port":465,
		"username":"mailer",
		"auth":"cram_md5",
		"authSecret":"very-secret",
		"fromEmail":"alerts@example.local",
		"encryption":"tls"
	}`)

	cfg, err := ParseSMTPConfig(raw)
	if err != nil {
		t.Fatalf("parse smtp config: %v", err)
	}
	if cfg.Auth != "cram_md5" {
		t.Fatalf("unexpected auth mode: %q", cfg.Auth)
	}
	if cfg.AuthSecret != "very-secret" {
		t.Fatalf("unexpected auth secret")
	}
}

func TestParseSMTPConfig_RejectsMissingCredentialsForAuth(t *testing.T) {
	raw := json.RawMessage(`{
		"host":"smtp.example.local",
		"port":587,
		"username":"mailer",
		"auth":"login",
		"fromEmail":"alerts@example.local",
		"encryption":"starttls"
	}`)

	if _, err := ParseSMTPConfig(raw); err == nil {
		t.Fatalf("expected validation error")
	}
}

func TestParseSMTPConfig_RejectsInvalidPortEncryptionPairs(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{
			name: "port 587 with tls",
			raw: `{
				"host":"smtp.example.local",
				"port":587,
				"username":"mailer",
				"password":"secret",
				"auth":"login",
				"fromEmail":"alerts@example.local",
				"encryption":"tls"
			}`,
		},
		{
			name: "port 465 with starttls",
			raw: `{
				"host":"smtp.example.local",
				"port":465,
				"username":"mailer",
				"password":"secret",
				"auth":"login",
				"fromEmail":"alerts@example.local",
				"encryption":"starttls"
			}`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseSMTPConfig(json.RawMessage(tc.raw)); err == nil {
				t.Fatalf("expected validation error")
			}
		})
	}
}

func TestSMTPConfigAlertmanagerRequireTLS(t *testing.T) {
	tests := []struct {
		name     string
		cfg      *SMTPConfig
		expected bool
	}{
		{
			name:     "starttls on 587 requires tls",
			cfg:      &SMTPConfig{Port: 587, Encryption: "starttls"},
			expected: true,
		},
		{
			name:     "tls wrapper on 465 disables require tls",
			cfg:      &SMTPConfig{Port: 465, Encryption: "tls"},
			expected: false,
		},
		{
			name:     "tls on non-465 requires tls",
			cfg:      &SMTPConfig{Port: 2525, Encryption: "tls"},
			expected: true,
		},
		{
			name:     "none disables require tls",
			cfg:      &SMTPConfig{Port: 25, Encryption: "none"},
			expected: false,
		},
		{
			name:     "nil config",
			cfg:      nil,
			expected: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.cfg.AlertmanagerRequireTLS(); got != tc.expected {
				t.Fatalf("expected %v, got %v", tc.expected, got)
			}
		})
	}
}
