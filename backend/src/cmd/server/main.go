package main

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"backend/internal/api/middleware"
	"backend/internal/api/router"
	"backend/internal/audit"
	"backend/internal/config"
	"backend/internal/core/alerting"
	"backend/internal/core/componentanalysis"
	"backend/internal/core/malware"
	"backend/internal/observability"
	"backend/internal/store"

	_ "github.com/jackc/pgx/v5/stdlib"
)

var exitFunc = os.Exit

var shutdownServer = func(ctx context.Context, srv *http.Server) error {
	return srv.Shutdown(ctx)
}

var openDB = sql.Open
var newPostgresStore = func(db *sql.DB, storagePath string) (store.Store, error) {
	return store.NewPostgresStore(db, storagePath)
}
var ensureBootstrapAdmin = ensureBootstrapAdminUser
var configureAlertmanager = configureAlertmanagerIntegration

const (
	appEncryptionKeyEnv = "APP_ENCRYPTION_KEY"
	runtimeEnvPrimary   = "CTWALL_RUNTIME_ENV"
	runtimeEnvFallback  = "APP_ENV"
)

func main() {
	// Baseline logger (may be reconfigured after loading config).
	baseLevel := parseLogLevel(os.Getenv("LOG_LEVEL"))
	baseLogger := slog.New(observability.NewSplitHandler(
		slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: baseLevel}),
		slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: baseLevel}),
	))
	baseLogger = baseLogger.With("app", "ctwall-backend")
	slog.SetDefault(baseLogger)

	initOnlyMode, err := parseBoolEnv("CTWALL_INIT_ONLY", false)
	if err != nil {
		baseLogger.Error("application startup failed", "error", err)
		exitFunc(1)
		return
	}
	if initOnlyMode {
		if err := runInitializerOnly(); err != nil {
			baseLogger.Error("initializer mode failed", "error", err)
			exitFunc(1)
		}
		return
	}

	if err := run(); err != nil {
		baseLogger.Error("application startup failed", "error", err)
		exitFunc(1)
	}
}

func runInitializerOnly() error {
	configPath := resolveConfigPath()
	configCreated, err := ensureRuntimeConfigFileExists(configPath)
	if err != nil {
		return err
	}

	cfg, err := loadConfigAtPath(configPath)
	if err != nil {
		return err
	}

	logLevel := parseLogLevel(cfg.Logging.Level)
	logger := slog.New(observability.NewSplitHandler(
		slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel}),
		slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel}),
	))
	logger = logger.With("app", "ctwall-backend")
	slog.SetDefault(logger)

	if configCreated {
		slog.Info("runtime bootstrap updated config file", "component", "bootstrap", "config_path", configPath)
	}

	initResult, err := runRuntimeInitializer(&cfg, configPath)
	if err != nil {
		return err
	}
	if initResult.Storage != nil {
		defer func() {
			if closeErr := initResult.Storage.Close(); closeErr != nil {
				slog.Error("store shutdown failed", "error", closeErr)
			}
		}()
	}

	if initResult.SecretsUpdated {
		slog.Info("runtime bootstrap updated secrets file", "component", "bootstrap", "secrets_path", initResult.SecretsPath)
	}
	if initResult.AdminBootstrap != nil {
		logBootstrapAdminCreated(initResult.AdminBootstrap, cfg.Secrets)
	} else {
		slog.Info(
			"bootstrap admin account not created",
			"component", "bootstrap",
			"reason", "admin account already exists",
			"email", defaultBootstrapAdminEmail,
		)
	}
	slog.Info("initializer mode completed", "component", "initializer", "first_startup", initResult.FirstStartup)
	return nil
}

func run() error {
	configPath := resolveConfigPath()
	configCreated, err := ensureRuntimeConfigFileExists(configPath)
	if err != nil {
		return err
	}

	cfg, err := loadConfigAtPath(configPath)
	if err != nil {
		return err
	}

	// Reconfigure logger based on config (env overrides still supported).
	logLevel := parseLogLevel(cfg.Logging.Level)
	logger := slog.New(observability.NewSplitHandler(
		slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel}),
		slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel}),
	))
	logger = logger.With("app", "ctwall-backend")
	slog.SetDefault(logger)

	slog.Debug("configuration loaded", "component", "bootstrap", "port", cfg.Server.Port, "storage_path", cfg.Storage.Path)
	if configCreated {
		slog.Info("runtime bootstrap updated config file", "component", "bootstrap", "config_path", configPath)
	}

	initResult, err := runRuntimeInitializer(&cfg, configPath)
	if err != nil {
		return err
	}
	storage := initResult.Storage
	defer func() {
		if closeErr := storage.Close(); closeErr != nil {
			slog.Error("store shutdown failed", "error", closeErr)
		}
	}()

	if initResult.SecretsUpdated {
		slog.Info("runtime bootstrap updated secrets file", "component", "bootstrap", "secrets_path", initResult.SecretsPath)
	}
	if initResult.AdminBootstrap != nil {
		logBootstrapAdminCreated(initResult.AdminBootstrap, cfg.Secrets)
	}

	workers, err := resolveWorkerRuntimeConfig(cfg.Workers)
	if err != nil {
		return err
	}
	slog.Info(
		"worker config loaded",
		"ingest_workers", workers.IngestWorkers,
		"malware_input_workers", workers.MalwareInputWorkers,
		"malware_component_analysis_workers", workers.ComponentAnalysisWorkers,
		"malware_test_revision_summary_workers", workers.RevisionSummaryWorkers,
		"malware_test_revision_diff_workers", workers.RevisionDiffWorkers,
		"malware_component_analysis_claim_batch_size", cfg.Workers.MalwareComponentAnalysisClaimBatchSize,
		"malware_component_analysis_scheduler_enqueue_limit", cfg.Workers.MalwareComponentAnalysisSchedulerEnqueueLimit,
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := configureAlertmanager(ctx, storage, cfg, configPath, logger); err != nil {
		return err
	}

	storeAllLogs, err := parseBoolEnv("DB_STORE_ALL_LOGS", false)
	if err != nil {
		return err
	}
	storeConfidentialLogs, err := parseBoolEnv("DB_STORE_CONFIDENTIAL_LOGS", true)
	if err != nil {
		return err
	}
	auditWriter := audit.NewWriter(storage, audit.Config{
		StoreAllLogs:          storeAllLogs,
		StoreConfidentialLogs: storeConfidentialLogs,
	}, logger)
	slog.Info("audit storage config loaded", "store_all", storeAllLogs, "store_confidential", storeConfidentialLogs)

	var osvSyncer *malware.OSVSyncService
	if cfg.Malware.OSV.Enabled {
		osvTimeout, err := parseDuration("malware.osv.timeout", cfg.Malware.OSV.Timeout)
		if err != nil {
			return err
		}
		osvSyncer, err = malware.NewOSVSyncService(storage, malware.OSVConfig{
			BaseURL:        cfg.Malware.OSV.BaseURL,
			AllZipURL:      cfg.Malware.OSV.AllZipURL,
			ModifiedCSVURL: cfg.Malware.OSV.ModifiedCSVURL,
			StoragePath:    cfg.Storage.Path,
			DataPath:       cfg.Malware.OSV.DataPath,
			Timeout:        osvTimeout,
			InputWorkers:   workers.MalwareInputWorkers,
		}, auditWriter, logger)
		if err != nil {
			return err
		}
		source, scanner, err := osvSyncer.EnsureSourceScanner(ctx)
		if err != nil {
			return err
		}
		if source != nil && scanner != nil {
			slog.Info("osv source initialized", "source_id", source.ID, "scanner_id", scanner.ID, "active", source.IsActive)
		}

		fullInterval, err := parseDuration("malware.osv.full_sync_interval", cfg.Malware.OSV.FullSyncInterval)
		if err != nil {
			return err
		}
		latestInterval, err := parseDuration("malware.osv.latest_sync_interval", cfg.Malware.OSV.LatestSyncInterval)
		if err != nil {
			return err
		}
		seedStateFromStoreOnStart := true
		if cfg.Malware.OSV.BootstrapOnStart.SeedStateFromStoreOnStart != nil {
			seedStateFromStoreOnStart = *cfg.Malware.OSV.BootstrapOnStart.SeedStateFromStoreOnStart
		}
		malware.StartOSVScheduler(ctx, osvSyncer, fullInterval, latestInterval, seedStateFromStoreOnStart, logger)
	}

	componentAnalysis := componentanalysis.NewService(storage, logger)
	componentAnalysis.SetClaimBatchSize(cfg.Workers.MalwareComponentAnalysisClaimBatchSize)
	componentAnalysis.SetSchedulerEnqueueLimit(cfg.Workers.MalwareComponentAnalysisSchedulerEnqueueLimit)
	if osvSyncer != nil {
		// Wake summary/component-analysis workers after OSV sync enqueues follow-up work.
		osvSyncer.SetComponentAnalysisNotifier(componentAnalysis)
	}
	var componentAnalysisScheduler *componentanalysis.Scheduler
	if workers.ComponentAnalysisWorkers > 0 {
		schedule, err := storage.GetComponentAnalysisMalwareSchedule()
		if err != nil {
			return err
		}
		componentAnalysis.SetSchedule(schedule.Enabled, time.Duration(schedule.IntervalSeconds)*time.Second)
		componentAnalysis.SetScheduleAnchor(schedule.UpdatedAt)

		componentAnalysisScheduler = componentanalysis.NewScheduler(componentAnalysis, logger)
		componentAnalysisScheduler.Start(ctx)
		componentAnalysis.StartWorkers(ctx, workers.ComponentAnalysisWorkers)
	}
	if workers.RevisionSummaryWorkers > 0 {
		componentAnalysis.StartSummaryWorkers(ctx, workers.RevisionSummaryWorkers)
	}
	if workers.RevisionDiffWorkers > 0 {
		componentAnalysis.StartRevisionDiffWorkers(ctx, workers.RevisionDiffWorkers)
	}

	// Router setup
	authCfg, err := loadAuthConfig(cfg.Auth)
	if err != nil {
		return err
	}
	authCfg.AuditWriter = auditWriter
	mux, err := router.NewRouter(storage, router.Config{
		Auth:                       authCfg,
		Malware:                    osvSyncer,
		AuditWriter:                auditWriter,
		IngestWorkers:              workers.IngestWorkers,
		ComponentAnalysisService:   componentAnalysis,
		ComponentAnalysisScheduler: componentAnalysisScheduler,
		RuntimeConfig:              cfg,
		RuntimeConfigPath:          configPath,
		RuntimeConfigSources:       configOverrideSources(),
	})
	if err != nil {
		return err
	}
	handler := middleware.WithSecurityHeaders(mux)

	readTimeout, err := parseDuration("server.read_timeout", cfg.Server.ReadTimeout)
	if err != nil {
		return err
	}
	writeTimeout, err := parseDuration("server.write_timeout", cfg.Server.WriteTimeout)
	if err != nil {
		return err
	}
	idleTimeout, err := parseDuration("server.idle_timeout", cfg.Server.IdleTimeout)
	if err != nil {
		return err
	}

	// Server setup
	srv := &http.Server{
		Addr:         ":" + cfg.Server.Port,
		Handler:      handler,
		ReadTimeout:  readTimeout,
		WriteTimeout: writeTimeout,
		IdleTimeout:  idleTimeout,
	}

	// Server start in goroutine
	serverErrors := make(chan error, 1)
	go func() {
		slog.Info("server starting", "port", cfg.Server.Port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			serverErrors <- fmt.Errorf("server init: %w", err)
		}
	}()

	// Graceful shutdown
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-serverErrors:
		return err
	case sig := <-shutdown:
		slog.Info("server shutdown started", "signal", sig)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := shutdownServer(ctx, srv); err != nil {
			return fmt.Errorf("server forced to shutdown: %w", err)
		}
	}

	slog.Info("server shutdown completed")
	return nil
}

// logBootstrapAdminCreated must always emit credentials on first bootstrap, even if configured log level hides WARN.
func logBootstrapAdminCreated(adminBootstrap *adminBootstrapResult, secrets config.SecretsConfig) {
	if adminBootstrap == nil {
		return
	}
	if slog.Default().Enabled(context.Background(), slog.LevelWarn) {
		slog.Warn(
			"bootstrap admin account created",
			"component", "bootstrap",
			"email", adminBootstrap.Email,
			"password", adminBootstrap.Password,
			"alertmanager_username", secrets.AlertmanagerUsername,
			"alertmanager_password", secrets.AlertmanagerPassword,
		)
		return
	}
	// Fallback path for high log levels (e.g. ERROR) so first-run credentials are not lost.
	fmt.Fprintf(
		os.Stderr,
		`{"level":"WARN","msg":"bootstrap admin account created","component":"bootstrap","email":%q,"password":%q,"alertmanager_username":%q,"alertmanager_password":%q}`+"\n",
		adminBootstrap.Email,
		adminBootstrap.Password,
		secrets.AlertmanagerUsername,
		secrets.AlertmanagerPassword,
	)
}

type workerRuntimeConfig struct {
	IngestWorkers            int
	MalwareInputWorkers      int
	ComponentAnalysisWorkers int
	RevisionSummaryWorkers   int
	RevisionDiffWorkers      int
}

func resolveWorkerRuntimeConfig(cfg config.WorkersConfig) (workerRuntimeConfig, error) {
	ingestWorkers, err := resolveWorkerCount("workers.ingest_workers", cfg.IngestWorkers)
	if err != nil {
		return workerRuntimeConfig{}, err
	}
	malwareInputWorkers, err := resolveWorkerCount("workers.malware_input_workers", cfg.MalwareInputWorkers)
	if err != nil {
		return workerRuntimeConfig{}, err
	}
	componentAnalysisWorkers, err := resolveWorkerCount("workers.malware_component_analysis_workers", cfg.MalwareComponentAnalysisWorkers)
	if err != nil {
		return workerRuntimeConfig{}, err
	}
	revisionSummaryWorkers, err := resolveWorkerCount("workers.malware_test_revision_summary_workers", cfg.MalwareTestRevisionSummaryWorkers)
	if err != nil {
		return workerRuntimeConfig{}, err
	}
	revisionDiffWorkers, err := resolveWorkerCount("workers.malware_test_revision_diff_workers", cfg.MalwareTestRevisionDiffWorkers)
	if err != nil {
		return workerRuntimeConfig{}, err
	}
	return workerRuntimeConfig{
		IngestWorkers:            ingestWorkers,
		MalwareInputWorkers:      malwareInputWorkers,
		ComponentAnalysisWorkers: componentAnalysisWorkers,
		RevisionSummaryWorkers:   revisionSummaryWorkers,
		RevisionDiffWorkers:      revisionDiffWorkers,
	}, nil
}

func loadAuthConfig(cfg config.AuthConfig) (middleware.AuthConfig, error) {
	secret := strings.TrimSpace(os.Getenv("JWT_SECRET_KEY"))
	if secret == "" {
		return middleware.AuthConfig{}, fmt.Errorf("JWT_SECRET_KEY is required")
	}
	issuer := strings.TrimSpace(os.Getenv("JWT_ISSUER"))
	if issuer == "" {
		issuer = strings.TrimSpace(cfg.JWTIssuer)
	}
	if issuer == "" {
		return middleware.AuthConfig{}, fmt.Errorf("auth.jwt_issuer is required")
	}
	accessTTL, err := parseDuration("auth.access_token_ttl", cfg.AccessTokenTTL)
	if err != nil {
		return middleware.AuthConfig{}, err
	}
	refreshTTL, err := parseDuration("auth.refresh_token_ttl", cfg.RefreshTokenTTL)
	if err != nil {
		return middleware.AuthConfig{}, err
	}
	if !cfg.CookieSecure && !cfg.AllowInsecureCookies {
		return middleware.AuthConfig{}, fmt.Errorf("insecure cookies are disabled; set auth.allow_insecure_cookies=true for local dev")
	}
	if strings.HasPrefix(strings.TrimSpace(cfg.CookieName), "__Host-") && !cfg.CookieSecure {
		return middleware.AuthConfig{}, fmt.Errorf("auth.cookie_name with __Host- prefix requires auth.cookie_secure=true")
	}
	if strings.HasPrefix(strings.TrimSpace(cfg.CookieName), "__Secure-") && !cfg.CookieSecure {
		return middleware.AuthConfig{}, fmt.Errorf("auth.cookie_name with __Secure- prefix requires auth.cookie_secure=true")
	}
	if strings.HasPrefix(strings.TrimSpace(cfg.RefreshCookieName), "__Secure-") && !cfg.CookieSecure {
		return middleware.AuthConfig{}, fmt.Errorf("auth.refresh_cookie_name with __Secure- prefix requires auth.cookie_secure=true")
	}
	if strings.HasPrefix(strings.TrimSpace(cfg.RefreshCookieName), "__Host-") {
		return middleware.AuthConfig{}, fmt.Errorf("auth.refresh_cookie_name with __Host- prefix is not supported for refresh path scope")
	}
	return middleware.AuthConfig{
		JWTSecret:         []byte(secret),
		JWTIssuer:         issuer,
		AccessTokenTTL:    accessTTL,
		RefreshTokenTTL:   refreshTTL,
		CookieName:        cfg.CookieName,
		RefreshCookieName: cfg.RefreshCookieName,
		CookieSecure:      cfg.CookieSecure,
	}, nil
}

func initStore(dbCfg config.DatabaseConfig, storagePath string, configPath string) (store.Store, error) {
	dbURL := strings.TrimSpace(os.Getenv("DB_URL"))
	if dbURL == "" {
		return nil, fmt.Errorf("DB_URL is required")
	}
	slog.Debug("initializing store", "component", "bootstrap", "storage_path", storagePath)

	db, err := openDB("pgx", dbURL)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	maxOpenConnsDefault := 20
	if dbCfg.MaxOpenConns != nil {
		maxOpenConnsDefault = *dbCfg.MaxOpenConns
	}
	// Guard against exhausting PostgreSQL global connection slots.
	maxOpenConns, err := parseIntEnvWithDefault("DB_MAX_OPEN_CONNS", maxOpenConnsDefault)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	if maxOpenConns < 1 {
		_ = db.Close()
		return nil, fmt.Errorf("DB_MAX_OPEN_CONNS must be >= 1")
	}

	maxIdleConnsDefault := 10
	if dbCfg.MaxIdleConns != nil {
		maxIdleConnsDefault = *dbCfg.MaxIdleConns
	}
	maxIdleConns, err := parseIntEnvWithDefault("DB_MAX_IDLE_CONNS", maxIdleConnsDefault)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	if maxIdleConns < 0 {
		_ = db.Close()
		return nil, fmt.Errorf("DB_MAX_IDLE_CONNS must be >= 0")
	}
	if maxIdleConns > maxOpenConns {
		maxIdleConns = maxOpenConns
	}

	connMaxLifetimeDefault := 30 * time.Minute
	if raw := strings.TrimSpace(dbCfg.ConnMaxLifetime); raw != "" {
		connMaxLifetimeDefault, err = parseDuration("database.conn_max_lifetime", raw)
		if err != nil {
			_ = db.Close()
			return nil, err
		}
	}
	connMaxLifetime, err := parseDurationEnvWithDefault("DB_CONN_MAX_LIFETIME", connMaxLifetimeDefault)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	if connMaxLifetime <= 0 {
		_ = db.Close()
		return nil, fmt.Errorf("DB_CONN_MAX_LIFETIME must be > 0")
	}

	connMaxIdleTimeDefault := 10 * time.Minute
	if raw := strings.TrimSpace(dbCfg.ConnMaxIdleTime); raw != "" {
		connMaxIdleTimeDefault, err = parseDuration("database.conn_max_idle_time", raw)
		if err != nil {
			_ = db.Close()
			return nil, err
		}
	}
	connMaxIdleTime, err := parseDurationEnvWithDefault("DB_CONN_MAX_IDLE_TIME", connMaxIdleTimeDefault)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	if connMaxIdleTime <= 0 {
		_ = db.Close()
		return nil, fmt.Errorf("DB_CONN_MAX_IDLE_TIME must be > 0")
	}
	db.SetMaxOpenConns(maxOpenConns)
	db.SetMaxIdleConns(maxIdleConns)
	db.SetConnMaxLifetime(connMaxLifetime)
	db.SetConnMaxIdleTime(connMaxIdleTime)

	pingTimeout, err := parseDuration("database.ping_timeout", dbCfg.PingTimeout)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), pingTimeout)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping db: %w", err)
	}
	migrationCfg, err := resolveStartupMigrationConfig(dbCfg, configPath)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := applyStartupMigrations(context.Background(), db, migrationCfg); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("startup db migrations: %w", err)
	}

	pgStore, err := newPostgresStore(db, storagePath)
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("init store: %w", err)
	}
	return pgStore, nil
}

func parseLogLevel(raw string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func loadConfig() (config.Config, error) {
	return loadConfigAtPath(resolveConfigPath())
}

func loadConfigAtPath(configPath string) (config.Config, error) {
	cfg, err := config.Load(configPath)
	if err != nil {
		return config.Config{}, err
	}
	if override := strings.TrimSpace(os.Getenv("PORT")); override != "" {
		cfg.Server.Port = override
	}
	if override := strings.TrimSpace(os.Getenv("STORAGE_PATH")); override != "" {
		cfg.Storage.Path = override
	}
	if override := strings.TrimSpace(os.Getenv("LOG_LEVEL")); override != "" {
		cfg.Logging.Level = override
	}
	if override := strings.TrimSpace(os.Getenv("JWT_ISSUER")); override != "" {
		cfg.Auth.JWTIssuer = override
	}
	return cfg, nil
}

func resolveConfigPath() string {
	configPath := strings.TrimSpace(os.Getenv("CTWALL_CONFIG_PATH"))
	if configPath == "" {
		configPath = "config.yaml"
	}
	return configPath
}

func sourceFromEnv(envName string) string {
	if strings.TrimSpace(os.Getenv(envName)) != "" {
		return "env"
	}
	return "file"
}

func configOverrideSources() map[string]string {
	return map[string]string{
		"server.port":     sourceFromEnv("PORT"),
		"storage.path":    sourceFromEnv("STORAGE_PATH"),
		"logging.level":   sourceFromEnv("LOG_LEVEL"),
		"auth.jwt_issuer": sourceFromEnv("JWT_ISSUER"),
	}
}

func runtimeEnvironment() string {
	if value := strings.TrimSpace(os.Getenv(runtimeEnvPrimary)); value != "" {
		return strings.ToLower(value)
	}
	if value := strings.TrimSpace(os.Getenv(runtimeEnvFallback)); value != "" {
		return strings.ToLower(value)
	}
	return "production"
}

func isExplicitDevRuntime(env string) bool {
	switch strings.ToLower(strings.TrimSpace(env)) {
	case "dev", "development", "local", "test":
		return true
	default:
		return false
	}
}

func validateConnectorSecretRuntimePolicy() error {
	if strings.TrimSpace(os.Getenv(appEncryptionKeyEnv)) != "" {
		return nil
	}
	env := runtimeEnvironment()
	if isExplicitDevRuntime(env) {
		return nil
	}
	return fmt.Errorf("%s is required when runtime env is %q (set %s=development only for local dev)", appEncryptionKeyEnv, env, runtimeEnvPrimary)
}

func parseDuration(field string, raw string) (time.Duration, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return 0, fmt.Errorf("%s is required", field)
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("%s invalid: %w", field, err)
	}
	return parsed, nil
}

func parseBoolEnv(key string, defaultValue bool) (bool, error) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return defaultValue, nil
	}
	parsed, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("%s invalid: %w", key, err)
	}
	return parsed, nil
}

func parseDurationEnvWithDefault(key string, defaultValue time.Duration) (time.Duration, error) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return defaultValue, nil
	}
	return parseDuration(key, raw)
}

func parseIntEnvWithDefault(key string, defaultValue int) (int, error) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return defaultValue, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("%s invalid: %w", key, err)
	}
	return value, nil
}

func splitCSV(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		value := strings.TrimSpace(part)
		if value == "" {
			continue
		}
		out = append(out, value)
	}
	return out
}

func configureAlertmanagerIntegration(ctx context.Context, st store.Store, cfg config.Config, configPath string, logger *slog.Logger) error {
	alertCfg := cfg.Alerting.Alertmanager
	enabled := alertCfg.Enabled
	rawEnabledOverride := strings.TrimSpace(os.Getenv("ALERTMANAGER_ENABLED"))
	if rawEnabled, ok := os.LookupEnv("ALERTMANAGER_ENABLED"); ok && strings.TrimSpace(rawEnabled) != "" {
		value, err := strconv.ParseBool(strings.TrimSpace(rawEnabled))
		if err != nil {
			return fmt.Errorf("ALERTMANAGER_ENABLED invalid: %w", err)
		}
		enabled = value
	}
	if !enabled && rawEnabledOverride == "" && strings.TrimSpace(os.Getenv("ALERTMANAGER_URL")) != "" {
		// Backward compatibility for deployments that still rely on ALERTMANAGER_URL only.
		enabled = true
	}
	if !enabled {
		return fmt.Errorf("alerting.alertmanager.enabled=false is not supported; internal Alertmanager is required")
	}

	url := strings.TrimSpace(alertCfg.URL)
	if override := strings.TrimSpace(os.Getenv("ALERTMANAGER_URL")); override != "" {
		url = override
	}
	if url == "" {
		return fmt.Errorf("alerting.alertmanager.url is required")
	}

	requestTimeout, err := parseDurationConfigWithDefault("alerting.alertmanager.request_timeout", alertCfg.RequestTimeout, 10*time.Second)
	if err != nil {
		return err
	}
	requestTimeout, err = parseDurationEnvWithDefault("ALERTMANAGER_REQUEST_TIMEOUT", requestTimeout)
	if err != nil {
		return err
	}
	username := strings.TrimSpace(os.Getenv("ALERTMANAGER_USERNAME"))
	password := strings.TrimSpace(os.Getenv("ALERTMANAGER_PASSWORD"))
	if username == "" || password == "" {
		return fmt.Errorf("ALERTMANAGER_USERNAME and ALERTMANAGER_PASSWORD are required")
	}

	client, err := alerting.NewAlertmanagerClient(url, username, password, requestTimeout)
	if err != nil {
		return err
	}

	integrationCfg := alerting.DefaultAlertmanagerIntegrationConfig()
	integrationCfg.ConfigFilePath = resolvePathRelativeToConfig(configPath, alertCfg.ConfigFilePath)
	if override := strings.TrimSpace(os.Getenv("ALERTMANAGER_CONFIG_FILE_PATH")); override != "" {
		integrationCfg.ConfigFilePath = override
	}
	integrationCfg.PublicBaseURL = strings.TrimSpace(alertCfg.PublicBaseURL)
	if override := strings.TrimSpace(os.Getenv("ALERTING_PUBLIC_BASE_URL")); override != "" {
		integrationCfg.PublicBaseURL = override
	}
	if integrationCfg.PublicBaseURL == "" {
		integrationCfg.PublicBaseURL = strings.TrimSpace(os.Getenv("PUBLIC_BASE_URL"))
	}
	if strings.TrimSpace(integrationCfg.ConfigFilePath) == "" {
		return fmt.Errorf("alerting.alertmanager.config_file_path is required")
	}

	if integrationCfg.ControlPollInterval, err = parseDurationConfigWithDefault("alerting.alertmanager.control_poll_interval", alertCfg.ControlPollInterval, integrationCfg.ControlPollInterval); err != nil {
		return err
	}
	if integrationCfg.DispatchPollInterval, err = parseDurationConfigWithDefault("alerting.alertmanager.dispatch_poll_interval", alertCfg.DispatchPollInterval, integrationCfg.DispatchPollInterval); err != nil {
		return err
	}
	if integrationCfg.HeartbeatInterval, err = parseDurationConfigWithDefault("alerting.alertmanager.heartbeat_interval", alertCfg.HeartbeatInterval, integrationCfg.HeartbeatInterval); err != nil {
		return err
	}
	if integrationCfg.RetryMaxWindow, err = parseDurationConfigWithDefault("alerting.alertmanager.retry_max_window", alertCfg.RetryMaxWindow, integrationCfg.RetryMaxWindow); err != nil {
		return err
	}
	if integrationCfg.RouteGroupWait, err = parseDurationConfigWithDefault("alerting.alertmanager.route_group_wait", alertCfg.RouteGroupWait, integrationCfg.RouteGroupWait); err != nil {
		return err
	}
	if integrationCfg.RouteGroupInterval, err = parseDurationConfigWithDefault("alerting.alertmanager.route_group_interval", alertCfg.RouteGroupInterval, integrationCfg.RouteGroupInterval); err != nil {
		return err
	}
	if integrationCfg.RouteRepeatInterval, err = parseDurationConfigWithDefault("alerting.alertmanager.route_repeat_interval", alertCfg.RouteRepeatInterval, integrationCfg.RouteRepeatInterval); err != nil {
		return err
	}

	if integrationCfg.DispatchWorkers, err = parseIntConfigWithDefault("alerting.alertmanager.dispatch_workers", alertCfg.DispatchWorkers, integrationCfg.DispatchWorkers); err != nil {
		return err
	}
	if integrationCfg.ClaimBatchSize, err = parseIntConfigWithDefault("alerting.alertmanager.claim_batch_size", alertCfg.ClaimBatchSize, integrationCfg.ClaimBatchSize); err != nil {
		return err
	}
	if integrationCfg.RetryMaxAttempts, err = parseIntConfigWithDefault("alerting.alertmanager.retry_max_attempts", alertCfg.RetryMaxAttempts, integrationCfg.RetryMaxAttempts); err != nil {
		return err
	}
	if groupBy := normalizeCSVValues(alertCfg.RouteGroupBy); len(groupBy) > 0 {
		integrationCfg.RouteGroupBy = groupBy
	}

	if integrationCfg.ControlPollInterval, err = parseDurationEnvWithDefault("ALERTMANAGER_CONTROL_POLL_INTERVAL", integrationCfg.ControlPollInterval); err != nil {
		return err
	}
	if integrationCfg.DispatchPollInterval, err = parseDurationEnvWithDefault("ALERTMANAGER_DISPATCH_POLL_INTERVAL", integrationCfg.DispatchPollInterval); err != nil {
		return err
	}
	if integrationCfg.HeartbeatInterval, err = parseDurationEnvWithDefault("ALERTMANAGER_HEARTBEAT_INTERVAL", integrationCfg.HeartbeatInterval); err != nil {
		return err
	}
	if integrationCfg.RetryMaxWindow, err = parseDurationEnvWithDefault("ALERTMANAGER_RETRY_MAX_WINDOW", integrationCfg.RetryMaxWindow); err != nil {
		return err
	}
	if integrationCfg.RouteGroupWait, err = parseDurationEnvWithDefault("ALERTMANAGER_ROUTE_GROUP_WAIT", integrationCfg.RouteGroupWait); err != nil {
		return err
	}
	if integrationCfg.RouteGroupInterval, err = parseDurationEnvWithDefault("ALERTMANAGER_ROUTE_GROUP_INTERVAL", integrationCfg.RouteGroupInterval); err != nil {
		return err
	}
	if integrationCfg.RouteRepeatInterval, err = parseDurationEnvWithDefault("ALERTMANAGER_ROUTE_REPEAT_INTERVAL", integrationCfg.RouteRepeatInterval); err != nil {
		return err
	}

	if integrationCfg.DispatchWorkers, err = parseIntEnvWithDefault("ALERTMANAGER_DISPATCH_WORKERS", integrationCfg.DispatchWorkers); err != nil {
		return err
	}
	if integrationCfg.ClaimBatchSize, err = parseIntEnvWithDefault("ALERTMANAGER_CLAIM_BATCH_SIZE", integrationCfg.ClaimBatchSize); err != nil {
		return err
	}
	if integrationCfg.RetryMaxAttempts, err = parseIntEnvWithDefault("ALERTMANAGER_RETRY_MAX_ATTEMPTS", integrationCfg.RetryMaxAttempts); err != nil {
		return err
	}

	if groupByRaw := strings.TrimSpace(os.Getenv("ALERTMANAGER_ROUTE_GROUP_BY")); groupByRaw != "" {
		groupBy := splitCSV(groupByRaw)
		if len(groupBy) == 0 {
			return fmt.Errorf("ALERTMANAGER_ROUTE_GROUP_BY is empty after parsing")
		}
		integrationCfg.RouteGroupBy = groupBy
	}

	alerting.StartAlertmanagerIntegration(ctx, st, client, integrationCfg, logger)
	logger.Info(
		"alertmanager integration enabled",
		"url", url,
		"basic_auth_enabled", username != "",
		"request_timeout", requestTimeout.String(),
		"config_file_path", integrationCfg.ConfigFilePath,
		"dispatch_workers", integrationCfg.DispatchWorkers,
		"claim_batch_size", integrationCfg.ClaimBatchSize,
	)
	return nil
}

func parseDurationConfigWithDefault(field string, raw string, defaultValue time.Duration) (time.Duration, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return defaultValue, nil
	}
	return parseDuration(field, value)
}

func parseIntConfigWithDefault(field string, value int, defaultValue int) (int, error) {
	if value == 0 {
		return defaultValue, nil
	}
	if value < 0 {
		return 0, fmt.Errorf("%s must be >= 0", field)
	}
	return value, nil
}

func normalizeCSVValues(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		out = append(out, trimmed)
	}
	return out
}

func resolvePathRelativeToConfig(configPath string, configuredPath string) string {
	path := strings.TrimSpace(configuredPath)
	if path == "" {
		return ""
	}
	if filepath.IsAbs(path) {
		return path
	}
	baseDir := strings.TrimSpace(filepath.Dir(configPath))
	if baseDir == "" || baseDir == "." {
		return path
	}
	return filepath.Join(baseDir, path)
}

func resolveWorkerCount(field string, raw string) (int, error) {
	value := strings.TrimSpace(raw)
	if value == "" || strings.EqualFold(value, "auto") {
		return autoWorkers(), nil
	}
	count, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("%s invalid: %w", field, err)
	}
	if count < 0 {
		return 0, fmt.Errorf("%s must be >= 0 or auto", field)
	}
	return count, nil
}

// autoWorkers uses 2x vCPU with bounds to balance I/O and DB pressure.
func autoWorkers() int {
	vcpu := runtime.NumCPU()
	workers := vcpu * 2
	if workers < 2 {
		workers = 2
	}
	if workers > 8 {
		workers = 8
	}
	return workers
}
