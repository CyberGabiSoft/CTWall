package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validConfig = `
server:
  port: "8080"
  read_timeout: "10s"
  write_timeout: "10s"
  idle_timeout: "60s"
storage:
  path: "data/blob_storage"
logging:
  level: "info"
database:
  url: "postgres://appuser:password@localhost:5432/appdb?sslmode=disable"
  ping_timeout: "5s"
secrets:
  jwt_secret_key: "test-jwt"
  app_encryption_passphrase: "test-passphrase"
  app_encryption_salt: "base64:MDEyMzQ1Njc4OWFiY2RlZg=="
  alertmanager_username: "ctwall_backend"
  alertmanager_password: "test-alertmanager-password"
auth:
  jwt_issuer: "ctwall-backend"
  access_token_ttl: "30m"
  refresh_token_ttl: "72h"
  cookie_name: "__Host-CTWALL_SESSION"
  refresh_cookie_name: "__Secure-CTWALL_REFRESH"
  cookie_secure: true
  allow_insecure_cookies: false
malware:
  osv:
    enabled: true
    base_url: "https://storage.googleapis.com/osv-vulnerabilities"
    all_zip_url: "https://storage.googleapis.com/osv-vulnerabilities/all.zip"
    modified_csv_url: "https://storage.googleapis.com/osv-vulnerabilities/modified_id.csv"
    data_path: "osv"
    full_sync_interval: "168h"
    latest_sync_interval: "1h"
    timeout: "2m"
workers:
  ingest_workers: "auto"
  malware_input_workers: "auto"
  malware_component_analysis_workers: "auto"
  malware_test_revision_summary_workers: "auto"
  malware_test_revision_diff_workers: "auto"
  malware_component_analysis_claim_batch_size: 5
  malware_component_analysis_scheduler_enqueue_limit: 1000
`

func writeTempConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(strings.TrimSpace(content)), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func TestLoadConfig(t *testing.T) {
	path := writeTempConfig(t, validConfig)
	if _, err := Load(path); err != nil {
		t.Fatalf("expected load success: %v", err)
	}
}

func TestLoadConfigMissing(t *testing.T) {
	if _, err := Load(" "); err == nil {
		t.Fatalf("expected missing path error")
	}
	if _, err := Load(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Fatalf("expected read error")
	}
}

func TestLoadConfigInvalidYAML(t *testing.T) {
	path := writeTempConfig(t, "server: [")
	if _, err := Load(path); err == nil {
		t.Fatalf("expected parse error")
	}
}

func TestLoadConfigValidation(t *testing.T) {
	path := writeTempConfig(t, `
server:
  port: ""
  read_timeout: "10s"
  write_timeout: "10s"
  idle_timeout: "60s"
storage:
  path: "data"
logging:
  level: "info"
database:
  url: "postgres://appuser:password@localhost:5432/appdb?sslmode=disable"
  ping_timeout: "5s"
secrets:
  jwt_secret_key: "test-jwt"
  app_encryption_passphrase: "test-passphrase"
  app_encryption_salt: "base64:MDEyMzQ1Njc4OWFiY2RlZg=="
  alertmanager_username: "ctwall_backend"
  alertmanager_password: "test-alertmanager-password"
auth:
  jwt_issuer: "issuer"
  access_token_ttl: "30m"
  refresh_token_ttl: "72h"
  cookie_name: "__Host-CTWALL_SESSION"
  refresh_cookie_name: "__Secure-CTWALL_REFRESH"
  cookie_secure: true
  allow_insecure_cookies: false
workers:
  ingest_workers: "auto"
  malware_input_workers: "auto"
  malware_component_analysis_workers: "auto"
  malware_test_revision_summary_workers: "auto"
  malware_test_revision_diff_workers: "auto"
  malware_component_analysis_claim_batch_size: 5
  malware_component_analysis_scheduler_enqueue_limit: 1000
`)
	if _, err := Load(path); err == nil {
		t.Fatalf("expected validation error")
	}
}

func TestLoadConfigValidationMigrationsPathRequiredWhenEnabled(t *testing.T) {
	path := writeTempConfig(t, `
server:
  port: "8080"
  read_timeout: "10s"
  write_timeout: "10s"
  idle_timeout: "60s"
storage:
  path: "data"
logging:
  level: "info"
database:
  url: "postgres://appuser:password@localhost:5432/appdb?sslmode=disable"
  ping_timeout: "5s"
  auto_apply_on_start: true
secrets:
  jwt_secret_key: "test-jwt"
  app_encryption_passphrase: "test-passphrase"
  app_encryption_salt: "base64:MDEyMzQ1Njc4OWFiY2RlZg=="
  alertmanager_username: "ctwall_backend"
  alertmanager_password: "test-alertmanager-password"
auth:
  jwt_issuer: "issuer"
  access_token_ttl: "30m"
  refresh_token_ttl: "72h"
  cookie_name: "__Host-CTWALL_SESSION"
  refresh_cookie_name: "__Secure-CTWALL_REFRESH"
  cookie_secure: true
  allow_insecure_cookies: false
workers:
  ingest_workers: "auto"
  malware_input_workers: "auto"
  malware_component_analysis_workers: "auto"
  malware_test_revision_summary_workers: "auto"
  malware_test_revision_diff_workers: "auto"
  malware_component_analysis_claim_batch_size: 5
  malware_component_analysis_scheduler_enqueue_limit: 1000
`)
	if _, err := Load(path); err == nil {
		t.Fatalf("expected migrations path validation error")
	}
}

func TestLoadConfigCookiePrefixValidation(t *testing.T) {
	t.Run("__Host session requires secure", func(t *testing.T) {
		path := writeTempConfig(t, strings.ReplaceAll(validConfig, "cookie_secure: true", "cookie_secure: false"))
		if _, err := Load(path); err == nil {
			t.Fatalf("expected prefix/secure validation error")
		}
	})

	t.Run("__Host refresh is not allowed", func(t *testing.T) {
		cfg := strings.ReplaceAll(validConfig, `refresh_cookie_name: "__Secure-CTWALL_REFRESH"`, `refresh_cookie_name: "__Host-CTWALL_REFRESH"`)
		path := writeTempConfig(t, cfg)
		if _, err := Load(path); err == nil {
			t.Fatalf("expected refresh __Host prefix validation error")
		}
	})
}
