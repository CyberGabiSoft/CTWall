package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"backend/internal/config"
	"backend/internal/store"

	"github.com/DATA-DOG/go-sqlmock"
)

const testConfigTemplate = `
server:
  port: "%s"
  read_timeout: "10s"
  write_timeout: "10s"
  idle_timeout: "60s"
storage:
  path: "%s"
logging:
  level: "info"
database:
  url: "postgres://user@localhost/db"
  ping_timeout: "5s"
secrets:
  jwt_secret_key: "test-secret"
  app_encryption_passphrase: "test-passphrase"
  app_encryption_salt: "base64:MDEyMzQ1Njc4OWFiY2RlZg=="
  alertmanager_username: "ctwall_backend"
  alertmanager_password: "test-alertmanager-password"
auth:
  jwt_issuer: "ctwall-backend"
  access_token_ttl: "15m"
  refresh_token_ttl: "72h"
  cookie_name: "__Host-CTWALL_SESSION"
  refresh_cookie_name: "__Secure-CTWALL_REFRESH"
  cookie_secure: true
  allow_insecure_cookies: false
workers:
  ingest_workers: "auto"
  malware_input_workers: "auto"
  malware_component_analysis_workers: "0"
  malware_test_revision_summary_workers: "0"
  malware_test_revision_diff_workers: "0"
  malware_component_analysis_claim_batch_size: 5
  malware_component_analysis_scheduler_enqueue_limit: 1000
`

func setupConfig(t *testing.T, port string) string {
	t.Helper()
	setupRuntimeStubs(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	storagePath := filepath.Join(dir, "storage")
	content := fmt.Sprintf(testConfigTemplate, port, storagePath)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv("CTWALL_CONFIG_PATH", path)
	t.Setenv(runtimeEnvPrimary, "development")
	return storagePath
}

func setupRuntimeStubs(t *testing.T) {
	t.Helper()

	origEnsureBootstrapAdmin := ensureBootstrapAdmin
	ensureBootstrapAdmin = func(store.Store) (*adminBootstrapResult, error) {
		return nil, nil
	}

	origConfigureAlertmanager := configureAlertmanager
	configureAlertmanager = func(context.Context, store.Store, config.Config, string, *slog.Logger) error {
		return nil
	}

	t.Cleanup(func() {
		ensureBootstrapAdmin = origEnsureBootstrapAdmin
		configureAlertmanager = origConfigureAlertmanager
	})
}

func setupMockDB(t *testing.T) sqlmock.Sqlmock {
	t.Helper()
	t.Setenv("DB_URL", "postgres://user@localhost/db")
	t.Setenv("JWT_SECRET_KEY", "test-secret")
	storagePath := setupConfig(t, "0")
	t.Setenv("STORAGE_PATH", storagePath)

	db, mock, err := sqlmock.New(sqlmock.MonitorPingsOption(true))
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	mock.ExpectPing()
	mock.ExpectQuery(`SELECT id, config_json FROM connector_configs`).
		WillReturnRows(sqlmock.NewRows([]string{"id", "config_json"}))
	mock.ExpectClose()

	origOpenDB := openDB
	openDB = func(string, string) (*sql.DB, error) {
		return db, nil
	}
	t.Cleanup(func() {
		openDB = origOpenDB
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("expectations: %v", err)
		}
	})

	return mock
}

func TestRunGracefulShutdown(t *testing.T) {
	t.Setenv("PORT", "0")
	setupMockDB(t)

	done := make(chan error, 1)
	go func() {
		done <- run()
	}()

	select {
	case err := <-done:
		t.Fatalf("server returned before shutdown signal: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	_ = syscall.Kill(os.Getpid(), syscall.SIGTERM)

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for shutdown")
	}

}

func TestRunDefaultPort(t *testing.T) {
	t.Setenv("PORT", "")
	setupMockDB(t)

	done := make(chan error, 1)
	go func() {
		done <- run()
	}()

	select {
	case err := <-done:
		t.Fatalf("server returned before shutdown signal: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	_ = syscall.Kill(os.Getpid(), syscall.SIGTERM)

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for shutdown")
	}
}

func TestMainErrorExit(t *testing.T) {
	originalExit := exitFunc
	exitCode := 0
	exitFunc = func(code int) {
		exitCode = code
	}
	defer func() {
		exitFunc = originalExit
	}()

	setupConfig(t, "0")
	t.Setenv("PORT", "bad")
	main()

	if exitCode != 1 {
		t.Fatalf("expected exit code 1, got %d", exitCode)
	}
}

func TestRunShutdownError(t *testing.T) {
	t.Setenv("PORT", "0")
	setupMockDB(t)

	originalShutdown := shutdownServer
	shutdownServer = func(_ context.Context, _ *http.Server) error {
		return errors.New("boom")
	}
	defer func() {
		shutdownServer = originalShutdown
	}()

	done := make(chan error, 1)
	go func() {
		done <- run()
	}()

	select {
	case err := <-done:
		t.Fatalf("server returned before shutdown signal: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	_ = syscall.Kill(os.Getpid(), syscall.SIGTERM)

	select {
	case err := <-done:
		if err == nil {
			t.Fatalf("expected shutdown error")
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for shutdown error")
	}
}

func TestRunServerError(t *testing.T) {
	t.Setenv("PORT", "bad")
	setupMockDB(t)

	if err := run(); err == nil {
		t.Fatalf("expected server error")
	}
}

func TestRunInitStoreError(t *testing.T) {
	setupConfig(t, "0")
	t.Setenv("PORT", "0")
	t.Setenv("DB_URL", "postgres://user@localhost/db")
	t.Setenv("JWT_SECRET_KEY", "test-secret")

	origOpenDB := openDB
	openDB = func(string, string) (*sql.DB, error) {
		return nil, errors.New("open boom")
	}
	defer func() { openDB = origOpenDB }()

	if err := run(); err == nil {
		t.Fatalf("expected initStore error")
	}
}

type closeErrStore struct {
	store.Store
}

func (c closeErrStore) Close() error {
	return errors.New("close boom")
}

func TestRunCloseError(t *testing.T) {
	t.Setenv("PORT", "0")
	t.Setenv("DB_URL", "postgres://user@localhost/db")
	t.Setenv("JWT_SECRET_KEY", "test-secret")
	storagePath := setupConfig(t, "0")
	t.Setenv("STORAGE_PATH", storagePath)

	db, mock, err := sqlmock.New(sqlmock.MonitorPingsOption(true))
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	mock.ExpectPing()
	mock.ExpectQuery(`SELECT id, config_json FROM connector_configs`).
		WillReturnRows(sqlmock.NewRows([]string{"id", "config_json"}))

	origOpenDB := openDB
	openDB = func(string, string) (*sql.DB, error) {
		return db, nil
	}
	defer func() { openDB = origOpenDB }()

	origNewStore := newPostgresStore
	newPostgresStore = func(db *sql.DB, storagePath string) (store.Store, error) {
		ps, err := store.NewPostgresStore(db, storagePath)
		if err != nil {
			return nil, err
		}
		return closeErrStore{Store: ps}, nil
	}
	defer func() { newPostgresStore = origNewStore }()

	done := make(chan error, 1)
	go func() {
		done <- run()
	}()
	select {
	case err := <-done:
		t.Fatalf("server returned before shutdown signal: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	_ = syscall.Kill(os.Getpid(), syscall.SIGTERM)

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for shutdown")
	}

	mock.ExpectClose()
	if err := db.Close(); err != nil {
		t.Fatalf("close db: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}

func TestInitStore(t *testing.T) {
	t.Setenv(appEncryptionKeyEnv, "")
	testDBCfg := config.DatabaseConfig{PingTimeout: "5s"}

	t.Run("missing db url", func(t *testing.T) {
		t.Setenv("DB_URL", "")
		if _, err := initStore(testDBCfg, t.TempDir(), ""); err == nil {
			t.Fatalf("expected db url error")
		}
	})

	t.Run("open error", func(t *testing.T) {
		t.Setenv("DB_URL", "postgres://user@localhost/db")
		origOpenDB := openDB
		openDB = func(string, string) (*sql.DB, error) {
			return nil, errors.New("open boom")
		}
		defer func() { openDB = origOpenDB }()

		if _, err := initStore(testDBCfg, t.TempDir(), ""); err == nil {
			t.Fatalf("expected open error")
		}
	})

	t.Run("ping error", func(t *testing.T) {
		t.Setenv("DB_URL", "postgres://user@localhost/db")
		db, mock, err := sqlmock.New(sqlmock.MonitorPingsOption(true))
		if err != nil {
			t.Fatalf("sqlmock: %v", err)
		}
		mock.ExpectPing().WillReturnError(errors.New("ping boom"))
		mock.ExpectClose()

		origOpenDB := openDB
		openDB = func(string, string) (*sql.DB, error) {
			return db, nil
		}
		defer func() { openDB = origOpenDB }()

		if _, err := initStore(testDBCfg, t.TempDir(), ""); err == nil {
			t.Fatalf("expected ping error")
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatalf("expectations: %v", err)
		}
	})

	t.Run("new store error", func(t *testing.T) {
		t.Setenv("DB_URL", "postgres://user@localhost/db")
		db, mock, err := sqlmock.New(sqlmock.MonitorPingsOption(true))
		if err != nil {
			t.Fatalf("sqlmock: %v", err)
		}
		mock.ExpectPing()
		mock.ExpectClose()

		origOpenDB := openDB
		openDB = func(string, string) (*sql.DB, error) {
			return db, nil
		}
		defer func() { openDB = origOpenDB }()

		origNewStore := newPostgresStore
		newPostgresStore = func(*sql.DB, string) (store.Store, error) {
			return nil, errors.New("store boom")
		}
		defer func() { newPostgresStore = origNewStore }()

		if _, err := initStore(testDBCfg, t.TempDir(), ""); err == nil {
			t.Fatalf("expected store init error")
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatalf("expectations: %v", err)
		}
	})

	t.Run("success", func(t *testing.T) {
		t.Setenv("DB_URL", "postgres://user@localhost/db")
		db, mock, err := sqlmock.New(sqlmock.MonitorPingsOption(true))
		if err != nil {
			t.Fatalf("sqlmock: %v", err)
		}
		mock.ExpectPing()
		mock.ExpectClose()

		origOpenDB := openDB
		openDB = func(string, string) (*sql.DB, error) {
			return db, nil
		}
		defer func() { openDB = origOpenDB }()

		origNewStore := newPostgresStore
		newPostgresStore = func(db *sql.DB, storagePath string) (store.Store, error) {
			return store.NewPostgresStore(db, storagePath)
		}
		defer func() { newPostgresStore = origNewStore }()

		got, err := initStore(testDBCfg, t.TempDir(), "")
		if err != nil {
			t.Fatalf("expected store, got %v", err)
		}
		_ = got.Close()

		if err := db.Close(); err != nil {
			t.Fatalf("close db: %v", err)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatalf("expectations: %v", err)
		}
	})
}

func TestNewPostgresStoreWrapper(t *testing.T) {
	t.Setenv(appEncryptionKeyEnv, "")
	db, mock, err := sqlmock.New(sqlmock.MonitorPingsOption(true))
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	mock.ExpectClose()

	store, err := newPostgresStore(db, t.TempDir())
	if err != nil {
		t.Fatalf("expected store, got %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}

func TestLoadConfigOverrides(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	content := fmt.Sprintf(testConfigTemplate, "8080", filepath.Join(t.TempDir(), "storage"))
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv("CTWALL_CONFIG_PATH", path)
	t.Setenv("PORT", "9090")
	t.Setenv("STORAGE_PATH", "/tmp/storage")
	t.Setenv("LOG_LEVEL", "debug")
	t.Setenv("JWT_ISSUER", "override-issuer")

	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.Server.Port != "9090" || cfg.Storage.Path != "/tmp/storage" {
		t.Fatalf("expected overrides applied")
	}
	if cfg.Logging.Level != "debug" || cfg.Auth.JWTIssuer != "override-issuer" {
		t.Fatalf("expected logging/auth overrides applied")
	}
}

func TestLoadConfigMissingFile(t *testing.T) {
	t.Setenv("CTWALL_CONFIG_PATH", filepath.Join(t.TempDir(), "missing.yaml"))
	if _, err := loadConfig(); err == nil {
		t.Fatalf("expected missing config error")
	}
}

func TestParseDuration(t *testing.T) {
	if _, err := parseDuration("field", " "); err == nil {
		t.Fatalf("expected required error")
	}
	if _, err := parseDuration("field", "not-a-duration"); err == nil {
		t.Fatalf("expected parse error")
	}
	if got, err := parseDuration("field", "1s"); err != nil || got != time.Second {
		t.Fatalf("expected duration parse")
	}
}

func TestLoadAuthConfig(t *testing.T) {
	t.Setenv("JWT_SECRET_KEY", "secret")
	cfg := config.AuthConfig{
		JWTIssuer:            "issuer",
		AccessTokenTTL:       "15m",
		RefreshTokenTTL:      "72h",
		CookieName:           "__Host-CTWALL_SESSION",
		RefreshCookieName:    "__Secure-CTWALL_REFRESH",
		CookieSecure:         true,
		AllowInsecureCookies: false,
	}
	if _, err := loadAuthConfig(cfg); err != nil {
		t.Fatalf("expected auth config to load: %v", err)
	}
	cfg.CookieSecure = false
	if _, err := loadAuthConfig(cfg); err == nil {
		t.Fatalf("expected insecure cookie error")
	}
	cfg.CookieSecure = true
	cfg.AccessTokenTTL = "bad"
	if _, err := loadAuthConfig(cfg); err == nil {
		t.Fatalf("expected access token ttl error")
	}
	cfg.AccessTokenTTL = "15m"
	cfg.RefreshTokenTTL = "bad"
	if _, err := loadAuthConfig(cfg); err == nil {
		t.Fatalf("expected refresh token ttl error")
	}
}

func TestConfigureAlertmanagerIntegration(t *testing.T) {
	baseCfg := config.Config{
		Alerting: config.AlertingConfig{
			Alertmanager: config.AlertmanagerConfig{
				Enabled:        true,
				URL:            "http://127.0.0.1:9093",
				ConfigFilePath: "test-alertmanager.yml",
			},
		},
	}

	t.Run("missing url is rejected", func(t *testing.T) {
		cfg := baseCfg
		cfg.Alerting.Alertmanager.URL = ""
		t.Setenv("ALERTMANAGER_URL", "")
		t.Setenv("ALERTMANAGER_ENABLED", "")
		if err := configureAlertmanagerIntegration(context.Background(), nil, cfg, "", slog.Default()); err == nil {
			t.Fatalf("expected missing url error")
		}
	})

	t.Run("explicitly disabled is rejected", func(t *testing.T) {
		cfg := baseCfg
		cfg.Alerting.Alertmanager.Enabled = false
		t.Setenv("ALERTMANAGER_ENABLED", "")
		t.Setenv("ALERTMANAGER_USERNAME", "")
		t.Setenv("ALERTMANAGER_PASSWORD", "")
		if err := configureAlertmanagerIntegration(context.Background(), nil, cfg, "", slog.Default()); err == nil {
			t.Fatalf("expected explicit disabled error")
		}
	})

	t.Run("missing credentials when enabled", func(t *testing.T) {
		cfg := baseCfg
		t.Setenv("ALERTMANAGER_URL", "")
		t.Setenv("ALERTMANAGER_ENABLED", "true")
		t.Setenv("ALERTMANAGER_USERNAME", "")
		t.Setenv("ALERTMANAGER_PASSWORD", "")
		err := configureAlertmanagerIntegration(context.Background(), nil, cfg, "", slog.Default())
		if err == nil {
			t.Fatalf("expected credentials error")
		}
	})

	t.Run("invalid url when enabled", func(t *testing.T) {
		cfg := baseCfg
		cfg.Alerting.Alertmanager.URL = "://bad"
		t.Setenv("ALERTMANAGER_URL", "")
		t.Setenv("ALERTMANAGER_ENABLED", "true")
		t.Setenv("ALERTMANAGER_USERNAME", "user")
		t.Setenv("ALERTMANAGER_PASSWORD", "pass")
		if err := configureAlertmanagerIntegration(context.Background(), nil, cfg, "", slog.Default()); err == nil {
			t.Fatalf("expected invalid url error")
		}
	})

	t.Run("enabled with credentials and nil store", func(t *testing.T) {
		cfg := baseCfg
		t.Setenv("ALERTMANAGER_URL", "")
		t.Setenv("ALERTMANAGER_ENABLED", "true")
		t.Setenv("ALERTMANAGER_USERNAME", "user")
		t.Setenv("ALERTMANAGER_PASSWORD", "pass")
		if err := configureAlertmanagerIntegration(context.Background(), nil, cfg, "", slog.Default()); err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
	})
}

func TestValidateConnectorSecretRuntimePolicy(t *testing.T) {
	t.Run("passes when encryption key is configured", func(t *testing.T) {
		t.Setenv(runtimeEnvPrimary, "production")
		t.Setenv(appEncryptionKeyEnv, "base64:MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=")
		if err := validateConnectorSecretRuntimePolicy(); err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
	})

	t.Run("passes in explicit development runtime without key", func(t *testing.T) {
		t.Setenv(runtimeEnvPrimary, "development")
		t.Setenv(appEncryptionKeyEnv, "")
		if err := validateConnectorSecretRuntimePolicy(); err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
	})

	t.Run("fails in production runtime without key", func(t *testing.T) {
		t.Setenv(runtimeEnvPrimary, "production")
		t.Setenv(appEncryptionKeyEnv, "")
		if err := validateConnectorSecretRuntimePolicy(); err == nil {
			t.Fatalf("expected policy error")
		}
	})
}
