package main

import (
	"fmt"
	"log/slog"

	"backend/internal/config"
	"backend/internal/store"
)

type runtimeInitializerResult struct {
	Storage        store.Store
	AdminBootstrap *adminBootstrapResult
	FirstStartup   bool
	SecretsUpdated bool
	SecretsPath    string
}

// runRuntimeInitializer executes startup initialization flow for both Docker Compose and Helm:
// 1) applies/validates DB migrations,
// 2) detects first startup by creating bootstrap admin account if missing,
// 3) generates runtime secrets only on first startup,
// 4) on subsequent starts requires existing secrets and only performs validation checks.
func runRuntimeInitializer(cfg *config.Config, configPath string) (runtimeInitializerResult, error) {
	if cfg == nil {
		return runtimeInitializerResult{}, fmt.Errorf("config is required")
	}

	// Load existing runtime secrets without generation before store initialization.
	// This keeps derived APP_ENCRYPTION_KEY available for connector secret decryption on already initialized databases.
	if preSecrets, _, _, err := bootstrapRuntimeSecretsWithPolicy(configPath, cfg.Secrets, false); err == nil {
		cfg.Secrets = preSecrets
		if err := applyRuntimeSecretsToEnv(*cfg); err != nil {
			return runtimeInitializerResult{}, err
		}
	}

	storage, err := initStore(cfg.Database, cfg.Storage.Path, configPath)
	if err != nil {
		return runtimeInitializerResult{}, err
	}
	closeOnError := true
	defer func() {
		if closeOnError {
			if closeErr := storage.Close(); closeErr != nil {
				slog.Warn("runtime initializer store close failed", "error", closeErr)
			}
		}
	}()

	adminBootstrap, err := ensureBootstrapAdmin(storage)
	if err != nil {
		return runtimeInitializerResult{}, err
	}
	firstStartup := adminBootstrap != nil && adminBootstrap.FirstStartup

	secrets, secretsUpdated, secretsPath, err := bootstrapRuntimeSecretsWithPolicy(configPath, cfg.Secrets, firstStartup)
	if err != nil {
		return runtimeInitializerResult{}, err
	}
	cfg.Secrets = secrets

	if err := applyRuntimeSecretsToEnv(*cfg); err != nil {
		return runtimeInitializerResult{}, err
	}
	if err := validateConnectorSecretRuntimePolicy(); err != nil {
		return runtimeInitializerResult{}, err
	}

	if firstStartup {
		slog.Info("runtime initializer finished", "component", "initializer", "first_startup", true)
	} else {
		slog.Info("runtime initializer finished", "component", "initializer", "first_startup", false)
	}

	closeOnError = false
	return runtimeInitializerResult{
		Storage:        storage,
		AdminBootstrap: adminBootstrap,
		FirstStartup:   firstStartup,
		SecretsUpdated: secretsUpdated,
		SecretsPath:    secretsPath,
	}, nil
}
