package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// Config defines the backend runtime configuration loaded from YAML.
type Config struct {
	Server   ServerConfig   `yaml:"server"`
	Storage  StorageConfig  `yaml:"storage"`
	Logging  LoggingConfig  `yaml:"logging"`
	Database DatabaseConfig `yaml:"database"`
	Secrets  SecretsConfig  `yaml:"secrets"`
	Auth     AuthConfig     `yaml:"auth"`
	Alerting AlertingConfig `yaml:"alerting"`
	Malware  MalwareConfig  `yaml:"malware"`
	Workers  WorkersConfig  `yaml:"workers"`
}

type ServerConfig struct {
	Port         string `yaml:"port"`
	ReadTimeout  string `yaml:"read_timeout"`
	WriteTimeout string `yaml:"write_timeout"`
	IdleTimeout  string `yaml:"idle_timeout"`
}

type StorageConfig struct {
	Path string `yaml:"path"`
}

type LoggingConfig struct {
	Level string `yaml:"level"`
}

type DatabaseConfig struct {
	URL             string `yaml:"url"`
	PingTimeout     string `yaml:"ping_timeout"`
	MaxOpenConns    *int   `yaml:"max_open_conns"`
	MaxIdleConns    *int   `yaml:"max_idle_conns"`
	ConnMaxLifetime string `yaml:"conn_max_lifetime"`
	ConnMaxIdleTime string `yaml:"conn_max_idle_time"`
	// AutoApplyOnStart enables SQL migration execution at backend startup.
	AutoApplyOnStart bool `yaml:"auto_apply_on_start"`
	// MigrationsPath points to a directory with *.up.sql migration files.
	// Relative paths are resolved against the config file directory.
	MigrationsPath string `yaml:"migrations_path"`
}

type SecretsConfig struct {
	JWTSecretKey            string `yaml:"jwt_secret_key"`
	AppEncryptionPassphrase string `yaml:"app_encryption_passphrase"`
	AppEncryptionSalt       string `yaml:"app_encryption_salt"`
	AlertmanagerUsername    string `yaml:"alertmanager_username"`
	AlertmanagerPassword    string `yaml:"alertmanager_password"`
}

type AuthConfig struct {
	JWTIssuer            string `yaml:"jwt_issuer"`
	AccessTokenTTL       string `yaml:"access_token_ttl"`
	RefreshTokenTTL      string `yaml:"refresh_token_ttl"`
	CookieName           string `yaml:"cookie_name"`
	RefreshCookieName    string `yaml:"refresh_cookie_name"`
	CookieSecure         bool   `yaml:"cookie_secure"`
	AllowInsecureCookies bool   `yaml:"allow_insecure_cookies"`
}

type AlertingConfig struct {
	Alertmanager AlertmanagerConfig `yaml:"alertmanager"`
}

type AlertmanagerConfig struct {
	Enabled              bool     `yaml:"enabled"`
	URL                  string   `yaml:"url"`
	RequestTimeout       string   `yaml:"request_timeout"`
	ConfigFilePath       string   `yaml:"config_file_path"`
	PublicBaseURL        string   `yaml:"public_base_url"`
	ControlPollInterval  string   `yaml:"control_poll_interval"`
	DispatchPollInterval string   `yaml:"dispatch_poll_interval"`
	HeartbeatInterval    string   `yaml:"heartbeat_interval"`
	DispatchWorkers      int      `yaml:"dispatch_workers"`
	ClaimBatchSize       int      `yaml:"claim_batch_size"`
	RetryMaxAttempts     int      `yaml:"retry_max_attempts"`
	RetryMaxWindow       string   `yaml:"retry_max_window"`
	RouteGroupBy         []string `yaml:"route_group_by"`
	RouteGroupWait       string   `yaml:"route_group_wait"`
	RouteGroupInterval   string   `yaml:"route_group_interval"`
	RouteRepeatInterval  string   `yaml:"route_repeat_interval"`
}

type MalwareConfig struct {
	OSV OSVConfig `yaml:"osv"`
}

type OSVBootstrapConfig struct {
	SeedStateFromStoreOnStart *bool `yaml:"seed_state_from_store_on_start"`
}

type OSVConfig struct {
	Enabled            bool               `yaml:"enabled"`
	BaseURL            string             `yaml:"base_url"`
	AllZipURL          string             `yaml:"all_zip_url"`
	ModifiedCSVURL     string             `yaml:"modified_csv_url"`
	DataPath           string             `yaml:"data_path"`
	FullSyncInterval   string             `yaml:"full_sync_interval"`
	LatestSyncInterval string             `yaml:"latest_sync_interval"`
	Timeout            string             `yaml:"timeout"`
	BootstrapOnStart   OSVBootstrapConfig `yaml:"bootstrap_on_start"`
}

type WorkersConfig struct {
	IngestWorkers                     string `yaml:"ingest_workers"`
	MalwareInputWorkers               string `yaml:"malware_input_workers"`
	MalwareComponentAnalysisWorkers   string `yaml:"malware_component_analysis_workers"`
	MalwareTestRevisionSummaryWorkers string `yaml:"malware_test_revision_summary_workers"`
	MalwareTestRevisionDiffWorkers    string `yaml:"malware_test_revision_diff_workers"`
	// MalwareComponentAnalysisClaimBatchSize caps how many queue items a single worker claims per poll cycle.
	// This is a backpressure control to avoid locking too many rows at once (especially at startup).
	MalwareComponentAnalysisClaimBatchSize int `yaml:"malware_component_analysis_claim_batch_size"`
	// MalwareComponentAnalysisSchedulerEnqueueLimit caps how many stale components are enqueued per scheduler tick.
	// This prevents a single scheduled run from inserting an unbounded backlog.
	MalwareComponentAnalysisSchedulerEnqueueLimit int `yaml:"malware_component_analysis_scheduler_enqueue_limit"`
}

// Load reads and validates configuration from the given YAML path.
func Load(path string) (Config, error) {
	rawPath := strings.TrimSpace(path)
	if rawPath == "" {
		return Config{}, fmt.Errorf("config path required")
	}
	data, err := os.ReadFile(rawPath)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Validate checks for required config fields.
func (c Config) Validate() error {
	if strings.TrimSpace(c.Server.Port) == "" {
		return fmt.Errorf("server.port is required")
	}
	if strings.TrimSpace(c.Server.ReadTimeout) == "" {
		return fmt.Errorf("server.read_timeout is required")
	}
	if strings.TrimSpace(c.Server.WriteTimeout) == "" {
		return fmt.Errorf("server.write_timeout is required")
	}
	if strings.TrimSpace(c.Server.IdleTimeout) == "" {
		return fmt.Errorf("server.idle_timeout is required")
	}
	if strings.TrimSpace(c.Storage.Path) == "" {
		return fmt.Errorf("storage.path is required")
	}
	if strings.TrimSpace(c.Logging.Level) == "" {
		return fmt.Errorf("logging.level is required")
	}
	if strings.TrimSpace(c.Database.URL) == "" {
		return fmt.Errorf("database.url is required")
	}
	if strings.TrimSpace(c.Database.PingTimeout) == "" {
		return fmt.Errorf("database.ping_timeout is required")
	}
	if c.Database.MaxOpenConns != nil && *c.Database.MaxOpenConns < 1 {
		return fmt.Errorf("database.max_open_conns must be >= 1")
	}
	if c.Database.MaxIdleConns != nil && *c.Database.MaxIdleConns < 0 {
		return fmt.Errorf("database.max_idle_conns must be >= 0")
	}
	if strings.TrimSpace(c.Database.ConnMaxLifetime) != "" {
		if err := parsePositiveDuration("database.conn_max_lifetime", c.Database.ConnMaxLifetime); err != nil {
			return err
		}
	}
	if strings.TrimSpace(c.Database.ConnMaxIdleTime) != "" {
		if err := parsePositiveDuration("database.conn_max_idle_time", c.Database.ConnMaxIdleTime); err != nil {
			return err
		}
	}
	if c.Database.AutoApplyOnStart && strings.TrimSpace(c.Database.MigrationsPath) == "" {
		return fmt.Errorf("database.migrations_path is required when database.auto_apply_on_start is enabled")
	}
	if strings.TrimSpace(c.Auth.JWTIssuer) == "" {
		return fmt.Errorf("auth.jwt_issuer is required")
	}
	if strings.TrimSpace(c.Auth.AccessTokenTTL) == "" {
		return fmt.Errorf("auth.access_token_ttl is required")
	}
	if strings.TrimSpace(c.Auth.RefreshTokenTTL) == "" {
		return fmt.Errorf("auth.refresh_token_ttl is required")
	}
	if strings.TrimSpace(c.Auth.CookieName) == "" {
		return fmt.Errorf("auth.cookie_name is required")
	}
	if strings.TrimSpace(c.Auth.RefreshCookieName) == "" {
		return fmt.Errorf("auth.refresh_cookie_name is required")
	}
	if err := validateCookiePrefixCompatibility(c.Auth); err != nil {
		return err
	}
	if c.Alerting.Alertmanager.Enabled {
		if strings.TrimSpace(c.Alerting.Alertmanager.URL) == "" {
			return fmt.Errorf("alerting.alertmanager.url is required when alerting.alertmanager.enabled is true")
		}
		if strings.TrimSpace(c.Alerting.Alertmanager.ConfigFilePath) == "" {
			return fmt.Errorf("alerting.alertmanager.config_file_path is required when alerting.alertmanager.enabled is true")
		}
		if strings.TrimSpace(c.Alerting.Alertmanager.RequestTimeout) != "" {
			if err := parsePositiveDuration("alerting.alertmanager.request_timeout", c.Alerting.Alertmanager.RequestTimeout); err != nil {
				return err
			}
		}
		if strings.TrimSpace(c.Alerting.Alertmanager.ControlPollInterval) != "" {
			if err := parsePositiveDuration("alerting.alertmanager.control_poll_interval", c.Alerting.Alertmanager.ControlPollInterval); err != nil {
				return err
			}
		}
		if strings.TrimSpace(c.Alerting.Alertmanager.DispatchPollInterval) != "" {
			if err := parsePositiveDuration("alerting.alertmanager.dispatch_poll_interval", c.Alerting.Alertmanager.DispatchPollInterval); err != nil {
				return err
			}
		}
		if strings.TrimSpace(c.Alerting.Alertmanager.HeartbeatInterval) != "" {
			if err := parsePositiveDuration("alerting.alertmanager.heartbeat_interval", c.Alerting.Alertmanager.HeartbeatInterval); err != nil {
				return err
			}
		}
		if strings.TrimSpace(c.Alerting.Alertmanager.RetryMaxWindow) != "" {
			if err := parsePositiveDuration("alerting.alertmanager.retry_max_window", c.Alerting.Alertmanager.RetryMaxWindow); err != nil {
				return err
			}
		}
		if strings.TrimSpace(c.Alerting.Alertmanager.RouteGroupWait) != "" {
			if err := parsePositiveDuration("alerting.alertmanager.route_group_wait", c.Alerting.Alertmanager.RouteGroupWait); err != nil {
				return err
			}
		}
		if strings.TrimSpace(c.Alerting.Alertmanager.RouteGroupInterval) != "" {
			if err := parsePositiveDuration("alerting.alertmanager.route_group_interval", c.Alerting.Alertmanager.RouteGroupInterval); err != nil {
				return err
			}
		}
		if strings.TrimSpace(c.Alerting.Alertmanager.RouteRepeatInterval) != "" {
			if err := parsePositiveDuration("alerting.alertmanager.route_repeat_interval", c.Alerting.Alertmanager.RouteRepeatInterval); err != nil {
				return err
			}
		}
		if c.Alerting.Alertmanager.DispatchWorkers < 0 {
			return fmt.Errorf("alerting.alertmanager.dispatch_workers must be >= 0")
		}
		if c.Alerting.Alertmanager.ClaimBatchSize < 0 {
			return fmt.Errorf("alerting.alertmanager.claim_batch_size must be >= 0")
		}
		if c.Alerting.Alertmanager.RetryMaxAttempts < 0 {
			return fmt.Errorf("alerting.alertmanager.retry_max_attempts must be >= 0")
		}
		for i, item := range c.Alerting.Alertmanager.RouteGroupBy {
			if strings.TrimSpace(item) == "" {
				return fmt.Errorf("alerting.alertmanager.route_group_by[%d] must not be empty", i)
			}
		}
	}
	if strings.TrimSpace(c.Workers.IngestWorkers) == "" {
		return fmt.Errorf("workers.ingest_workers is required")
	}
	if strings.TrimSpace(c.Workers.MalwareInputWorkers) == "" {
		return fmt.Errorf("workers.malware_input_workers is required")
	}
	if strings.TrimSpace(c.Workers.MalwareComponentAnalysisWorkers) == "" {
		return fmt.Errorf("workers.malware_component_analysis_workers is required")
	}
	if strings.TrimSpace(c.Workers.MalwareTestRevisionSummaryWorkers) == "" {
		return fmt.Errorf("workers.malware_test_revision_summary_workers is required")
	}
	if strings.TrimSpace(c.Workers.MalwareTestRevisionDiffWorkers) == "" {
		return fmt.Errorf("workers.malware_test_revision_diff_workers is required")
	}
	if c.Workers.MalwareComponentAnalysisClaimBatchSize < 1 {
		return fmt.Errorf("workers.malware_component_analysis_claim_batch_size must be >= 1")
	}
	if c.Workers.MalwareComponentAnalysisSchedulerEnqueueLimit < 1 {
		return fmt.Errorf("workers.malware_component_analysis_scheduler_enqueue_limit must be >= 1")
	}
	if c.Malware.OSV.Enabled {
		if strings.TrimSpace(c.Malware.OSV.BaseURL) == "" {
			return fmt.Errorf("malware.osv.base_url is required")
		}
		if strings.TrimSpace(c.Malware.OSV.DataPath) == "" {
			return fmt.Errorf("malware.osv.data_path is required")
		}
		if strings.TrimSpace(c.Malware.OSV.FullSyncInterval) == "" {
			return fmt.Errorf("malware.osv.full_sync_interval is required")
		}
		if strings.TrimSpace(c.Malware.OSV.LatestSyncInterval) == "" {
			return fmt.Errorf("malware.osv.latest_sync_interval is required")
		}
		if strings.TrimSpace(c.Malware.OSV.Timeout) == "" {
			return fmt.Errorf("malware.osv.timeout is required")
		}
	}
	return nil
}

func parsePositiveDuration(field, raw string) error {
	value := strings.TrimSpace(raw)
	if value == "" {
		return fmt.Errorf("%s is required", field)
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return fmt.Errorf("%s invalid: %w", field, err)
	}
	if parsed <= 0 {
		return fmt.Errorf("%s must be > 0", field)
	}
	return nil
}

func validateCookiePrefixCompatibility(authCfg AuthConfig) error {
	cookieName := strings.TrimSpace(authCfg.CookieName)
	refreshCookieName := strings.TrimSpace(authCfg.RefreshCookieName)

	if strings.HasPrefix(cookieName, "__Host-") && !authCfg.CookieSecure {
		return fmt.Errorf("auth.cookie_name with __Host- prefix requires auth.cookie_secure=true")
	}
	if strings.HasPrefix(cookieName, "__Secure-") && !authCfg.CookieSecure {
		return fmt.Errorf("auth.cookie_name with __Secure- prefix requires auth.cookie_secure=true")
	}
	if strings.HasPrefix(refreshCookieName, "__Secure-") && !authCfg.CookieSecure {
		return fmt.Errorf("auth.refresh_cookie_name with __Secure- prefix requires auth.cookie_secure=true")
	}
	// Refresh cookie is intentionally scoped to /api/v1/auth/refresh, so __Host- is invalid.
	if strings.HasPrefix(refreshCookieName, "__Host-") {
		return fmt.Errorf("auth.refresh_cookie_name with __Host- prefix is not supported for refresh path scope")
	}
	return nil
}
