package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"backend/internal/config"
	"backend/internal/models"
	"backend/internal/store"

	"github.com/google/uuid"
)

const runtimeBootstrapTemplate = `
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
  url: "postgres://appuser:change-me-postgres@ctwall-postgres:5432/appdb?sslmode=disable"
  ping_timeout: "5s"
auth:
  jwt_issuer: "ctwall-backend"
  access_token_ttl: "30m"
  refresh_token_ttl: "72h"
  cookie_name: "__Host-CTWALL_SESSION"
  refresh_cookie_name: "__Secure-CTWALL_REFRESH"
  cookie_secure: true
  allow_insecure_cookies: false
workers:
  ingest_workers: "2"
  malware_input_workers: "2"
  malware_component_analysis_workers: "2"
  malware_test_revision_summary_workers: "2"
  malware_test_revision_diff_workers: "2"
  malware_component_analysis_claim_batch_size: 5
  malware_component_analysis_scheduler_enqueue_limit: 1000
secrets:
  jwt_secret_key: ""
  app_encryption_passphrase: ""
  app_encryption_salt: ""
  alertmanager_username: ""
  alertmanager_password: ""
`

func TestBootstrapRuntimeConfigFromTemplate_GeneratesMissingSecrets(t *testing.T) {
	dir := t.TempDir()
	templatePath := filepath.Join(dir, "config.template.yaml")
	if err := os.WriteFile(templatePath, []byte(runtimeBootstrapTemplate), 0o600); err != nil {
		t.Fatalf("write template: %v", err)
	}

	t.Setenv(runtimeConfigTemplateEnv, templatePath)
	t.Setenv("JWT_SECRET_KEY", "")
	t.Setenv(appEncryptionKeyEnv, "")
	t.Setenv(appEncryptionPassphraseEnv, "")
	t.Setenv(appEncryptionSaltEnv, "")
	t.Setenv("ALERTMANAGER_USERNAME", "")
	t.Setenv("ALERTMANAGER_PASSWORD", "")

	configPath := filepath.Join(dir, "runtime", "config.yaml")
	result, err := bootstrapRuntimeConfig(configPath)
	if err != nil {
		t.Fatalf("bootstrap config: %v", err)
	}
	if !result.ConfigUpdated {
		t.Fatalf("expected config creation from template")
	}
	if !result.SecretsUpdated {
		t.Fatalf("expected secrets update for generated runtime secrets")
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("load generated config: %v", err)
	}
	if cfg.Secrets.JWTSecretKey != "" {
		t.Fatalf("expected config secrets to remain unchanged")
	}
	if result.Secrets.JWTSecretKey == "" {
		t.Fatalf("expected generated jwt_secret_key")
	}
	if result.Secrets.AppEncryptionPassphrase == "" {
		t.Fatalf("expected generated app_encryption_passphrase")
	}
	if result.Secrets.AppEncryptionSalt == "" {
		t.Fatalf("expected generated app_encryption_salt")
	}
	if result.Secrets.AlertmanagerUsername == "" {
		t.Fatalf("expected generated alertmanager_username")
	}
	if result.Secrets.AlertmanagerPassword == "" {
		t.Fatalf("expected generated alertmanager_password")
	}
	if _, err := os.Stat(result.SecretsPath); err != nil {
		t.Fatalf("expected runtime secrets file: %v", err)
	}
}

func TestBootstrapRuntimeConfigFromTemplate_MissingTemplateEnv(t *testing.T) {
	t.Setenv(runtimeConfigTemplateEnv, "")
	configPath := filepath.Join(t.TempDir(), "runtime", "config.yaml")
	if _, err := bootstrapRuntimeConfig(configPath); err == nil {
		t.Fatalf("expected error when runtime config is missing and template env is not set")
	}
}

func TestBootstrapRuntimeConfig_NoChangesWhenConfigComplete(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	content := `
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
  url: "postgres://appuser:change-me-postgres@ctwall-postgres:5432/appdb?sslmode=disable"
  ping_timeout: "5s"
auth:
  jwt_issuer: "ctwall-backend"
  access_token_ttl: "30m"
  refresh_token_ttl: "72h"
  cookie_name: "__Host-CTWALL_SESSION"
  refresh_cookie_name: "__Secure-CTWALL_REFRESH"
  cookie_secure: true
  allow_insecure_cookies: false
workers:
  ingest_workers: "2"
  malware_input_workers: "2"
  malware_component_analysis_workers: "2"
  malware_test_revision_summary_workers: "2"
  malware_test_revision_diff_workers: "2"
  malware_component_analysis_claim_batch_size: 5
  malware_component_analysis_scheduler_enqueue_limit: 1000
secrets:
  jwt_secret_key: "jwt"
  app_encryption_passphrase: "test-passphrase"
  app_encryption_salt: "base64:MDEyMzQ1Njc4OWFiY2RlZg=="
  alertmanager_username: "ctwall_backend"
  alertmanager_password: "topsecret"
`
	if err := os.WriteFile(configPath, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv(runtimeConfigTemplateEnv, "")

	result, err := bootstrapRuntimeConfig(configPath)
	if err != nil {
		t.Fatalf("bootstrap complete config: %v", err)
	}
	if result.ConfigUpdated {
		t.Fatalf("expected no config update when all runtime fields are already set")
	}
	if !result.SecretsUpdated {
		t.Fatalf("expected migration of legacy config secrets into dedicated secrets file")
	}
	if strings.TrimSpace(result.Secrets.JWTSecretKey) == "" {
		t.Fatalf("expected secrets loaded from legacy config")
	}
}

func TestBootstrapRuntimeSecretsWithPolicy_NoGenerateOnInitializedDB(t *testing.T) {
	t.Setenv("JWT_SECRET_KEY", "")
	t.Setenv(appEncryptionKeyEnv, "")
	t.Setenv(appEncryptionPassphraseEnv, "")
	t.Setenv(appEncryptionSaltEnv, "")
	t.Setenv("ALERTMANAGER_USERNAME", "")
	t.Setenv("ALERTMANAGER_PASSWORD", "")

	configPath := filepath.Join(t.TempDir(), "config.yaml")
	_, _, _, err := bootstrapRuntimeSecretsWithPolicy(configPath, config.SecretsConfig{}, false)
	if err == nil {
		t.Fatalf("expected error when secrets are missing and generation is disabled")
	}
	if !strings.Contains(err.Error(), "JWT_SECRET_KEY is required") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBootstrapRuntimeSecretsWithPolicy_UsesLegacyWithoutGeneration(t *testing.T) {
	t.Setenv("JWT_SECRET_KEY", "")
	t.Setenv(appEncryptionKeyEnv, "")
	t.Setenv("ALERTMANAGER_USERNAME", "")
	t.Setenv("ALERTMANAGER_PASSWORD", "")

	configPath := filepath.Join(t.TempDir(), "config.yaml")
	legacy := config.SecretsConfig{
		JWTSecretKey:            "legacy-jwt",
		AppEncryptionPassphrase: "legacy-passphrase",
		AppEncryptionSalt:       "base64:MDEyMzQ1Njc4OWFiY2RlZg==",
		AlertmanagerUsername:    "legacy-user",
		AlertmanagerPassword:    "legacy-pass",
	}

	secrets, updated, _, err := bootstrapRuntimeSecretsWithPolicy(configPath, legacy, false)
	if err != nil {
		t.Fatalf("bootstrap runtime secrets without generation: %v", err)
	}
	if !updated {
		t.Fatalf("expected secrets file update from legacy values")
	}
	if secrets.JWTSecretKey != legacy.JWTSecretKey {
		t.Fatalf("expected jwt from legacy config")
	}
	if secrets.AppEncryptionPassphrase != legacy.AppEncryptionPassphrase {
		t.Fatalf("expected app encryption passphrase from legacy config")
	}
	if secrets.AppEncryptionSalt != legacy.AppEncryptionSalt {
		t.Fatalf("expected app encryption salt from legacy config")
	}
	if secrets.AlertmanagerUsername != legacy.AlertmanagerUsername {
		t.Fatalf("expected alertmanager username from legacy config")
	}
}

func TestDeriveAppEncryptionKeyDeterministic(t *testing.T) {
	const passphrase = "integration-test-passphrase"
	const salt = "base64:MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="

	first, err := deriveAppEncryptionKey(passphrase, salt)
	if err != nil {
		t.Fatalf("derive first key: %v", err)
	}
	second, err := deriveAppEncryptionKey(passphrase, salt)
	if err != nil {
		t.Fatalf("derive second key: %v", err)
	}
	if first != second {
		t.Fatalf("expected deterministic key derivation")
	}

	decoded, err := decodeBase64Secret(first)
	if err != nil {
		t.Fatalf("decode derived key: %v", err)
	}
	if len(decoded) != 32 {
		t.Fatalf("expected 32-byte derived key, got %d", len(decoded))
	}
}

func TestDeriveAppEncryptionKeyChangesWithSalt(t *testing.T) {
	const passphrase = "integration-test-passphrase"
	const saltA = "base64:MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
	const saltB = "base64:ZmVkY2JhOTg3NjU0MzIxMGFiY2RlZmVkY2JhOTg3NjU="

	keyA, err := deriveAppEncryptionKey(passphrase, saltA)
	if err != nil {
		t.Fatalf("derive key A: %v", err)
	}
	keyB, err := deriveAppEncryptionKey(passphrase, saltB)
	if err != nil {
		t.Fatalf("derive key B: %v", err)
	}
	if keyA == keyB {
		t.Fatalf("expected different derived keys for different salt")
	}
}

func TestApplyRuntimeSecretsToEnv_PrefersExistingDBURL(t *testing.T) {
	envDBURL := "postgres://env-user:env-pass@env-host:5432/env-db?sslmode=disable"
	fileDBURL := "postgres://file-user:file-pass@file-host:5432/file-db?sslmode=disable"

	t.Setenv("DB_URL", envDBURL)

	cfg := config.Config{
		Database: config.DatabaseConfig{URL: fileDBURL},
		Secrets: config.SecretsConfig{
			JWTSecretKey:            "jwt-from-secrets",
			AppEncryptionPassphrase: "passphrase-from-secrets",
			AppEncryptionSalt:       "base64:MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
			AlertmanagerUsername:    "alert-user",
			AlertmanagerPassword:    "alert-password",
		},
	}
	if err := applyRuntimeSecretsToEnv(cfg); err != nil {
		t.Fatalf("applyRuntimeSecretsToEnv: %v", err)
	}
	if got := strings.TrimSpace(os.Getenv("DB_URL")); got != envDBURL {
		t.Fatalf("expected DB_URL from env, got %q", got)
	}
}

func TestApplyRuntimeSecretsToEnv_FallsBackToConfigDBURL(t *testing.T) {
	fileDBURL := "postgres://file-user:file-pass@file-host:5432/file-db?sslmode=disable"

	t.Setenv("DB_URL", "")

	cfg := config.Config{
		Database: config.DatabaseConfig{URL: fileDBURL},
		Secrets: config.SecretsConfig{
			JWTSecretKey:            "jwt-from-secrets",
			AppEncryptionPassphrase: "passphrase-from-secrets",
			AppEncryptionSalt:       "base64:MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
			AlertmanagerUsername:    "alert-user",
			AlertmanagerPassword:    "alert-password",
		},
	}
	if err := applyRuntimeSecretsToEnv(cfg); err != nil {
		t.Fatalf("applyRuntimeSecretsToEnv: %v", err)
	}
	if got := strings.TrimSpace(os.Getenv("DB_URL")); got != fileDBURL {
		t.Fatalf("expected DB_URL from config, got %q", got)
	}
}

type bootstrapAdminStoreStub struct {
	store.Store

	getErr          error
	getCreds        *store.UserCredentials
	createUser      *models.User
	createErr       error
	updateErr       error
	updateUserID    uuid.UUID
	updateHashValue string
}

func (s *bootstrapAdminStoreStub) GetUserByEmail(email string) (*store.UserCredentials, error) {
	if s.getErr != nil {
		return nil, s.getErr
	}
	if s.getCreds != nil {
		return s.getCreds, nil
	}
	return nil, store.ErrNotFound
}

func (s *bootstrapAdminStoreStub) CreateUser(email, passwordHash, role, accountType string, profile ...string) (*models.User, error) {
	if s.createErr != nil {
		return nil, s.createErr
	}
	if s.createUser != nil {
		return s.createUser, nil
	}
	return &models.User{ID: uuid.New(), Email: email}, nil
}

func (s *bootstrapAdminStoreStub) UpdateUserPassword(userID uuid.UUID, passwordHash string) error {
	s.updateUserID = userID
	s.updateHashValue = passwordHash
	if s.updateErr != nil {
		return s.updateErr
	}
	return nil
}

func TestEnsureBootstrapAdminUserCreatesCredentialsFile(t *testing.T) {
	credentialsPath := filepath.Join(t.TempDir(), "bootstrap-admin-credentials.json")
	t.Setenv(bootstrapAdminCredentialsPathEnv, credentialsPath)

	stub := &bootstrapAdminStoreStub{
		getErr: store.ErrNotFound,
	}
	result, err := ensureBootstrapAdminUser(stub)
	if err != nil {
		t.Fatalf("ensure bootstrap admin: %v", err)
	}
	if result == nil {
		t.Fatalf("expected bootstrap admin credentials result")
	}
	if strings.TrimSpace(result.Email) != defaultBootstrapAdminEmail {
		t.Fatalf("unexpected bootstrap email: %q", result.Email)
	}
	if strings.TrimSpace(result.Password) == "" {
		t.Fatalf("expected generated bootstrap password")
	}

	stored, readErr := readBootstrapAdminCredentials(credentialsPath)
	if readErr != nil {
		t.Fatalf("read stored bootstrap credentials: %v", readErr)
	}
	if stored == nil {
		t.Fatalf("expected stored bootstrap credentials")
	}
	if stored.Password != result.Password {
		t.Fatalf("stored password does not match generated password")
	}
}

func TestEnsureBootstrapAdminUserRotatesPasswordWhenLegacyCredentialsFileMissing(t *testing.T) {
	credentialsPath := filepath.Join(t.TempDir(), "bootstrap-admin-credentials.json")
	t.Setenv(bootstrapAdminCredentialsPathEnv, credentialsPath)

	adminID := uuid.New()
	stub := &bootstrapAdminStoreStub{
		getCreds: &store.UserCredentials{
			User: models.User{
				ID:    adminID,
				Email: defaultBootstrapAdminEmail,
			},
			PasswordHash: "existing-hash",
		},
	}

	result, err := ensureBootstrapAdminUser(stub)
	if err != nil {
		t.Fatalf("ensure bootstrap admin: %v", err)
	}
	if result == nil {
		t.Fatalf("expected password rotation result when credentials file is missing")
	}
	if stub.updateUserID != adminID {
		t.Fatalf("expected password rotation for admin id %s, got %s", adminID, stub.updateUserID)
	}
	if !strings.HasPrefix(strings.TrimSpace(stub.updateHashValue), "$argon2id$") {
		t.Fatalf("expected argon2id password hash update")
	}
}

func TestEnsureBootstrapAdminUserNoRotationWhenCredentialsFileExists(t *testing.T) {
	credentialsPath := filepath.Join(t.TempDir(), "bootstrap-admin-credentials.json")
	t.Setenv(bootstrapAdminCredentialsPathEnv, credentialsPath)
	if err := writeBootstrapAdminCredentials(credentialsPath, adminBootstrapResult{
		Email:    defaultBootstrapAdminEmail,
		Password: "existing-password",
	}); err != nil {
		t.Fatalf("write bootstrap credentials fixture: %v", err)
	}

	stub := &bootstrapAdminStoreStub{
		getCreds: &store.UserCredentials{
			User: models.User{
				ID:    uuid.New(),
				Email: defaultBootstrapAdminEmail,
			},
			PasswordHash: "existing-hash",
		},
	}
	result, err := ensureBootstrapAdminUser(stub)
	if err != nil {
		t.Fatalf("ensure bootstrap admin: %v", err)
	}
	if result != nil {
		t.Fatalf("expected nil result when admin and credentials file already exist")
	}
	if stub.updateUserID != uuid.Nil {
		t.Fatalf("expected no password rotation update")
	}
}

func TestReadBootstrapAdminCredentialsInvalidJSONReturnsError(t *testing.T) {
	credentialsPath := filepath.Join(t.TempDir(), "bootstrap-admin-credentials.json")
	if err := os.WriteFile(credentialsPath, []byte("{invalid"), 0o600); err != nil {
		t.Fatalf("write invalid file: %v", err)
	}

	_, err := readBootstrapAdminCredentials(credentialsPath)
	if err == nil {
		t.Fatalf("expected decode error for invalid credentials file")
	}
	if !strings.Contains(err.Error(), "decode bootstrap admin credentials") {
		t.Fatalf("unexpected error: %v", err)
	}
}
