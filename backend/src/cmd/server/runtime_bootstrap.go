package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"backend/internal/config"
	"backend/internal/core/auth"
	"backend/internal/store"

	"github.com/google/uuid"
	"go.yaml.in/yaml/v3"
	"golang.org/x/crypto/argon2"
)

const (
	defaultBootstrapAdminEmail           = "admin@ctwall"
	defaultBootstrapAdminCredentialsPath = "/app/data/bootstrap-admin-credentials.json"
	runtimeConfigTemplateEnv             = "CTWALL_CONFIG_TEMPLATE_PATH"
	runtimeSecretsPathEnv                = "CTWALL_SECRETS_PATH"
	bootstrapAdminCredentialsPathEnv     = "CTWALL_BOOTSTRAP_ADMIN_CREDENTIALS_PATH"
	appEncryptionPassphraseEnv           = "APP_ENCRYPTION_PASSPHRASE"
	appEncryptionSaltEnv                 = "APP_ENCRYPTION_SALT"
	appEncryptionKDFVersion              = "argon2id-v1"
)

type runtimeBootstrapResult struct {
	ConfigUpdated  bool
	SecretsUpdated bool
	SecretsPath    string
	Secrets        config.SecretsConfig
}

type adminBootstrapResult struct {
	Email        string
	Password     string
	FirstStartup bool
}

type bootstrapAdminCredentialsRecord struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func bootstrapRuntimeConfig(configPath string) (runtimeBootstrapResult, error) {
	path := strings.TrimSpace(configPath)
	if path == "" {
		return runtimeBootstrapResult{}, fmt.Errorf("config path required")
	}
	configCreated, err := ensureRuntimeConfigFileExists(path)
	if err != nil {
		return runtimeBootstrapResult{}, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return runtimeBootstrapResult{}, fmt.Errorf("read config: %w", err)
	}

	var cfg config.Config
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return runtimeBootstrapResult{}, fmt.Errorf("parse config: %w", err)
	}

	secrets, secretsUpdated, secretsPath, err := bootstrapRuntimeSecrets(path, cfg.Secrets)
	if err != nil {
		return runtimeBootstrapResult{}, err
	}

	return runtimeBootstrapResult{
		ConfigUpdated:  configCreated,
		SecretsUpdated: secretsUpdated,
		SecretsPath:    secretsPath,
		Secrets:        secrets,
	}, nil
}

func ensureRuntimeConfigFileExists(path string) (bool, error) {
	info, err := os.Stat(path)
	if err == nil {
		if info.IsDir() {
			return false, fmt.Errorf("config path %q is a directory", path)
		}
		return false, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("stat config: %w", err)
	}

	templatePath := strings.TrimSpace(os.Getenv(runtimeConfigTemplateEnv))
	if templatePath == "" {
		return false, fmt.Errorf("config file %q not found and %s is not set", path, runtimeConfigTemplateEnv)
	}
	templateRaw, err := os.ReadFile(templatePath)
	if err != nil {
		return false, fmt.Errorf("read config template: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return false, fmt.Errorf("create config directory: %w", err)
	}
	if err := os.WriteFile(path, templateRaw, 0o600); err != nil {
		return false, fmt.Errorf("write initial config from template: %w", err)
	}
	return true, nil
}

func bootstrapRuntimeSecrets(configPath string, legacy config.SecretsConfig) (config.SecretsConfig, bool, string, error) {
	return bootstrapRuntimeSecretsWithPolicy(configPath, legacy, true)
}

func bootstrapRuntimeSecretsWithPolicy(
	configPath string,
	legacy config.SecretsConfig,
	allowGenerate bool,
) (config.SecretsConfig, bool, string, error) {
	secretsPath := resolveRuntimeSecretsPath(configPath)
	current, found, err := readRuntimeSecrets(secretsPath)
	if err != nil {
		return config.SecretsConfig{}, false, "", err
	}

	updated := !found

	jwtSecret, changed, err := resolveOrGenerateSecret(
		current.JWTSecretKey,
		firstNonEmpty(legacy.JWTSecretKey, os.Getenv("JWT_SECRET_KEY")),
		func() (string, error) { return generateOpaqueSecret(48) },
		allowGenerate,
		"JWT_SECRET_KEY",
	)
	if err != nil {
		return config.SecretsConfig{}, false, "", err
	}
	if changed {
		current.JWTSecretKey = jwtSecret
		updated = true
	}

	appPassphrase, changed, err := resolveOrGenerateSecret(
		current.AppEncryptionPassphrase,
		firstNonEmpty(legacy.AppEncryptionPassphrase, os.Getenv(appEncryptionPassphraseEnv)),
		func() (string, error) { return generateOpaqueSecret(48) },
		allowGenerate,
		appEncryptionPassphraseEnv,
	)
	if err != nil {
		return config.SecretsConfig{}, false, "", err
	}
	if changed {
		current.AppEncryptionPassphrase = appPassphrase
		updated = true
	}

	appSalt, changed, err := resolveOrGenerateSecret(
		current.AppEncryptionSalt,
		firstNonEmpty(legacy.AppEncryptionSalt, os.Getenv(appEncryptionSaltEnv)),
		generateAppEncryptionSalt,
		allowGenerate,
		appEncryptionSaltEnv,
	)
	if err != nil {
		return config.SecretsConfig{}, false, "", err
	}
	if changed {
		current.AppEncryptionSalt = appSalt
		updated = true
	}

	alertUser, changed, err := resolveOrGenerateSecret(
		current.AlertmanagerUsername,
		firstNonEmpty(legacy.AlertmanagerUsername, os.Getenv("ALERTMANAGER_USERNAME")),
		generateAlertmanagerUsername,
		allowGenerate,
		"ALERTMANAGER_USERNAME",
	)
	if err != nil {
		return config.SecretsConfig{}, false, "", err
	}
	if changed {
		current.AlertmanagerUsername = alertUser
		updated = true
	}

	alertPass, changed, err := resolveOrGenerateSecret(
		current.AlertmanagerPassword,
		firstNonEmpty(legacy.AlertmanagerPassword, os.Getenv("ALERTMANAGER_PASSWORD")),
		func() (string, error) { return generateOpaqueSecret(24) },
		allowGenerate,
		"ALERTMANAGER_PASSWORD",
	)
	if err != nil {
		return config.SecretsConfig{}, false, "", err
	}
	if changed {
		current.AlertmanagerPassword = alertPass
		updated = true
	}

	if updated {
		if err := writeRuntimeSecrets(secretsPath, current); err != nil {
			return config.SecretsConfig{}, false, "", err
		}
	}

	return current, updated, secretsPath, nil
}

func resolveRuntimeSecretsPath(configPath string) string {
	if configured := strings.TrimSpace(os.Getenv(runtimeSecretsPathEnv)); configured != "" {
		return configured
	}
	baseDir := strings.TrimSpace(filepath.Dir(configPath))
	if baseDir == "" || baseDir == "." {
		return "secrets.yaml"
	}
	return filepath.Join(baseDir, "secrets.yaml")
}

func readRuntimeSecrets(path string) (config.SecretsConfig, bool, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return config.SecretsConfig{}, false, nil
		}
		return config.SecretsConfig{}, false, fmt.Errorf("read runtime secrets: %w", err)
	}

	var direct config.SecretsConfig
	if err := yaml.Unmarshal(raw, &direct); err != nil {
		return config.SecretsConfig{}, false, fmt.Errorf("parse runtime secrets: %w", err)
	}
	if !isEmptySecretsConfig(direct) {
		return direct, true, nil
	}

	var wrapped struct {
		Secrets config.SecretsConfig `yaml:"secrets"`
	}
	if err := yaml.Unmarshal(raw, &wrapped); err != nil {
		return config.SecretsConfig{}, false, fmt.Errorf("parse runtime secrets wrapper: %w", err)
	}
	return wrapped.Secrets, true, nil
}

func writeRuntimeSecrets(path string, secrets config.SecretsConfig) error {
	encoded, err := yaml.Marshal(&secrets)
	if err != nil {
		return fmt.Errorf("encode runtime secrets: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("create runtime secrets directory: %w", err)
	}

	mode := os.FileMode(0o600)
	if info, statErr := os.Stat(path); statErr == nil {
		mode = info.Mode().Perm()
	}
	if err := os.WriteFile(path, encoded, mode); err != nil {
		return fmt.Errorf("write runtime secrets: %w", err)
	}
	return nil
}

func isEmptySecretsConfig(s config.SecretsConfig) bool {
	return strings.TrimSpace(s.JWTSecretKey) == "" &&
		strings.TrimSpace(s.AppEncryptionPassphrase) == "" &&
		strings.TrimSpace(s.AppEncryptionSalt) == "" &&
		strings.TrimSpace(s.AlertmanagerUsername) == "" &&
		strings.TrimSpace(s.AlertmanagerPassword) == ""
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func applyRuntimeSecretsToEnv(cfg config.Config) error {
	derivedAppKey, err := deriveAppEncryptionKey(
		cfg.Secrets.AppEncryptionPassphrase,
		cfg.Secrets.AppEncryptionSalt,
	)
	if err != nil {
		return err
	}
	dbURL := firstNonEmpty(
		os.Getenv("DB_URL"),
		cfg.Database.URL,
	)

	required := map[string]string{
		"DB_URL":                dbURL,
		"JWT_SECRET_KEY":        strings.TrimSpace(cfg.Secrets.JWTSecretKey),
		appEncryptionKeyEnv:     strings.TrimSpace(derivedAppKey),
		"ALERTMANAGER_USERNAME": strings.TrimSpace(cfg.Secrets.AlertmanagerUsername),
		"ALERTMANAGER_PASSWORD": strings.TrimSpace(cfg.Secrets.AlertmanagerPassword),
	}
	for key, value := range required {
		if value == "" {
			return fmt.Errorf("%s is required after runtime secrets bootstrap", key)
		}
		if err := os.Setenv(key, value); err != nil {
			return fmt.Errorf("set %s: %w", key, err)
		}
	}
	return nil
}

func ensureBootstrapAdminUser(memStore store.Store) (*adminBootstrapResult, error) {
	if memStore == nil {
		return nil, nil
	}
	credentialsPath := resolveBootstrapAdminCredentialsPath()
	bootstrapCredentials, readErr := readBootstrapAdminCredentials(credentialsPath)
	if readErr != nil {
		slog.Warn(
			"bootstrap admin credentials read failed; credential rotation fallback will be used",
			"component", "bootstrap",
			"path", credentialsPath,
			"error", readErr,
		)
	}

	creds, err := memStore.GetUserByEmail(defaultBootstrapAdminEmail)
	if err == nil {
		if bootstrapCredentials != nil {
			return nil, nil
		}

		if creds.User.ID == uuid.Nil {
			return nil, fmt.Errorf("bootstrap admin account exists but user id is empty")
		}
		adminPassword, genErr := generateOpaqueSecret(24)
		if genErr != nil {
			return nil, genErr
		}
		passwordHash, hashErr := auth.HashPassword(adminPassword)
		if hashErr != nil {
			return nil, hashErr
		}
		if updateErr := memStore.UpdateUserPassword(creds.User.ID, passwordHash); updateErr != nil {
			return nil, updateErr
		}
		result := &adminBootstrapResult{
			Email:        defaultBootstrapAdminEmail,
			Password:     adminPassword,
			FirstStartup: false,
		}
		if writeErr := writeBootstrapAdminCredentials(credentialsPath, *result); writeErr != nil {
			return nil, writeErr
		}
		return result, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}

	adminPassword, err := generateOpaqueSecret(24)
	if err != nil {
		return nil, err
	}
	passwordHash, err := auth.HashPassword(adminPassword)
	if err != nil {
		return nil, err
	}

	_, err = memStore.CreateUser(defaultBootstrapAdminEmail, passwordHash, "ADMIN", "USER", "admin", "CTWall Admin")
	if err != nil {
		if errors.Is(err, store.ErrAlreadyExists) {
			return nil, nil
		}
		return nil, err
	}

	result := &adminBootstrapResult{
		Email:        defaultBootstrapAdminEmail,
		Password:     adminPassword,
		FirstStartup: true,
	}
	if err := writeBootstrapAdminCredentials(credentialsPath, *result); err != nil {
		return nil, err
	}

	return result, nil
}

func resolveBootstrapAdminCredentialsPath() string {
	if value := strings.TrimSpace(os.Getenv(bootstrapAdminCredentialsPathEnv)); value != "" {
		return value
	}
	return defaultBootstrapAdminCredentialsPath
}

func readBootstrapAdminCredentials(path string) (*adminBootstrapResult, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read bootstrap admin credentials: %w", err)
	}

	var payload bootstrapAdminCredentialsRecord
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, fmt.Errorf("decode bootstrap admin credentials: %w", err)
	}

	email := strings.TrimSpace(payload.Email)
	if email == "" {
		email = defaultBootstrapAdminEmail
	}
	password := strings.TrimSpace(payload.Password)
	if password == "" {
		return nil, nil
	}

	return &adminBootstrapResult{
		Email:        email,
		Password:     password,
		FirstStartup: false,
	}, nil
}

func writeBootstrapAdminCredentials(path string, creds adminBootstrapResult) error {
	record := bootstrapAdminCredentialsRecord{
		Email:    strings.TrimSpace(creds.Email),
		Password: strings.TrimSpace(creds.Password),
	}
	if record.Email == "" {
		record.Email = defaultBootstrapAdminEmail
	}
	if record.Password == "" {
		return fmt.Errorf("bootstrap admin password cannot be empty")
	}

	encoded, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return fmt.Errorf("encode bootstrap admin credentials: %w", err)
	}
	encoded = append(encoded, '\n')

	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("create bootstrap credentials directory: %w", err)
	}
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		return fmt.Errorf("write bootstrap admin credentials: %w", err)
	}

	return nil
}

func resolveOrGenerateSecret(
	existing string,
	fromEnv string,
	generator func() (string, error),
	allowGenerate bool,
	name string,
) (value string, changed bool, err error) {
	if current := strings.TrimSpace(existing); current != "" {
		return current, false, nil
	}
	if legacy := strings.TrimSpace(fromEnv); legacy != "" {
		return legacy, true, nil
	}
	if !allowGenerate {
		return "", false, fmt.Errorf("%s is required in runtime secrets when database is already initialized", strings.TrimSpace(name))
	}
	generated, err := generator()
	if err != nil {
		return "", false, err
	}
	return generated, true, nil
}

func generateOpaqueSecret(size int) (string, error) {
	if size <= 0 {
		return "", fmt.Errorf("secret size must be > 0")
	}
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func generateAppEncryptionSalt() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return "base64:" + base64.StdEncoding.EncodeToString(buf), nil
}

func deriveAppEncryptionKey(passphraseRaw, saltRaw string) (string, error) {
	passphrase := strings.TrimSpace(passphraseRaw)
	if passphrase == "" {
		return "", fmt.Errorf("%s is required after runtime secrets bootstrap", appEncryptionPassphraseEnv)
	}
	salt, err := decodeBase64Secret(saltRaw)
	if err != nil {
		return "", fmt.Errorf("%s invalid: %w", appEncryptionSaltEnv, err)
	}
	if len(salt) < 16 {
		return "", fmt.Errorf("%s must decode to at least 16 bytes", appEncryptionSaltEnv)
	}

	derived := argon2.IDKey([]byte(passphrase), salt, 3, 64*1024, 4, 32)
	if len(derived) != 32 {
		return "", fmt.Errorf("%s key derivation failed (%s)", appEncryptionKeyEnv, appEncryptionKDFVersion)
	}
	return "base64:" + base64.StdEncoding.EncodeToString(derived), nil
}

func decodeBase64Secret(raw string) ([]byte, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return nil, fmt.Errorf("value is empty")
	}
	if strings.HasPrefix(value, "base64:") {
		value = strings.TrimSpace(strings.TrimPrefix(value, "base64:"))
	}
	if value == "" {
		return nil, fmt.Errorf("value is empty")
	}
	if decoded, err := base64.StdEncoding.DecodeString(value); err == nil {
		return decoded, nil
	}
	if decoded, err := base64.RawStdEncoding.DecodeString(value); err == nil {
		return decoded, nil
	}
	return nil, fmt.Errorf("expected base64 or raw base64 payload")
}

func generateAlertmanagerUsername() (string, error) {
	buf := make([]byte, 4)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return "ctwall_backend_" + hex.EncodeToString(buf), nil
}
