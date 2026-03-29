package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"backend/internal/config"
)

const (
	startupMigrationAdvisoryLockID int64 = 90422031
)

type startupMigrationConfig struct {
	Enabled bool
	DirPath string
}

type existingSchemaState struct {
	productsTableExists bool
}

type appliedMigration struct {
	Filename string
	Checksum string
}

func resolveStartupMigrationConfig(dbCfg config.DatabaseConfig, configPath string) (startupMigrationConfig, error) {
	if !dbCfg.AutoApplyOnStart {
		return startupMigrationConfig{Enabled: false}, nil
	}
	rawPath := strings.TrimSpace(dbCfg.MigrationsPath)
	if rawPath == "" {
		return startupMigrationConfig{}, fmt.Errorf("database.migrations_path is required when database.auto_apply_on_start is enabled")
	}
	if filepath.IsAbs(rawPath) {
		return startupMigrationConfig{Enabled: true, DirPath: filepath.Clean(rawPath)}, nil
	}
	baseDir := "."
	configPath = strings.TrimSpace(configPath)
	if configPath != "" {
		baseDir = filepath.Dir(configPath)
	}
	resolvedDir := filepath.Clean(filepath.Join(baseDir, rawPath))
	if dirExists(resolvedDir) {
		return startupMigrationConfig{
			Enabled: true,
			DirPath: resolvedDir,
		}, nil
	}

	// Container config is usually mounted to /app/config while SQL migrations live in /app/src/migrations.
	// If "<config-dir>/<rawPath>" does not exist, try one level above config dir.
	parentResolvedDir := filepath.Clean(filepath.Join(filepath.Dir(baseDir), rawPath))
	if parentResolvedDir != resolvedDir && dirExists(parentResolvedDir) {
		return startupMigrationConfig{
			Enabled: true,
			DirPath: parentResolvedDir,
		}, nil
	}

	return startupMigrationConfig{
		Enabled: true,
		DirPath: resolvedDir,
	}, nil
}

func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func applyStartupMigrations(ctx context.Context, db *sql.DB, cfg startupMigrationConfig) error {
	if !cfg.Enabled {
		return nil
	}
	if db == nil {
		return fmt.Errorf("db is nil")
	}
	if strings.TrimSpace(cfg.DirPath) == "" {
		return fmt.Errorf("startup migrations path is empty")
	}

	if _, err := db.ExecContext(ctx, `SELECT pg_advisory_lock($1)`, startupMigrationAdvisoryLockID); err != nil {
		return fmt.Errorf("acquire startup migration lock: %w", err)
	}
	defer func() {
		if _, err := db.ExecContext(context.Background(), `SELECT pg_advisory_unlock($1)`, startupMigrationAdvisoryLockID); err != nil {
			slog.Warn("failed to release startup migration lock", "error", err)
		}
	}()

	if err := ensureSchemaMigrationsTable(ctx, db); err != nil {
		return err
	}

	files, err := listMigrationFiles(cfg.DirPath)
	if err != nil {
		return err
	}
	if len(files) == 0 {
		slog.Info("startup migrations: no migration files found", "path", cfg.DirPath)
		return nil
	}

	applied, err := loadAppliedMigrations(ctx, db)
	if err != nil {
		return err
	}

	state, err := loadExistingSchemaState(ctx, db)
	if err != nil {
		return err
	}

	for _, filename := range files {
		migrationPath := filepath.Join(cfg.DirPath, filename)
		migrationSQL, err := os.ReadFile(migrationPath)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", filename, err)
		}
		checksum := computeMigrationChecksum(migrationSQL)

		if existingChecksum, ok := applied[filename]; ok {
			if !strings.EqualFold(strings.TrimSpace(existingChecksum), checksum) {
				return fmt.Errorf("migration %s checksum mismatch: applied=%s current=%s", filename, existingChecksum, checksum)
			}
			continue
		}

		shouldSkip, skipReason := shouldSkipMigration(filename, state)
		if shouldSkip {
			if err := markMigrationApplied(ctx, db, appliedMigration{Filename: filename, Checksum: checksum}); err != nil {
				return err
			}
			slog.Info("startup migration marked as applied without execution", "migration", filename, "reason", skipReason)
			continue
		}

		if len(strings.TrimSpace(string(migrationSQL))) == 0 {
			if err := markMigrationApplied(ctx, db, appliedMigration{Filename: filename, Checksum: checksum}); err != nil {
				return err
			}
			slog.Info("startup migration is empty; marked as applied", "migration", filename)
			continue
		}

		slog.Info("applying startup migration", "migration", filename)
		if _, err := db.ExecContext(ctx, string(migrationSQL)); err != nil {
			return fmt.Errorf("exec migration %s: %w", filename, err)
		}
		if err := markMigrationApplied(ctx, db, appliedMigration{Filename: filename, Checksum: checksum}); err != nil {
			return err
		}
	}

	slog.Info("startup migrations completed", "path", cfg.DirPath, "files", len(files))
	return nil
}

func ensureSchemaMigrationsTable(ctx context.Context, db *sql.DB) error {
	const query = `
CREATE TABLE IF NOT EXISTS schema_migrations (
    filename TEXT PRIMARY KEY,
    checksum TEXT NOT NULL,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`
	if _, err := db.ExecContext(ctx, query); err != nil {
		return fmt.Errorf("ensure schema_migrations table: %w", err)
	}
	return nil
}

func listMigrationFiles(dirPath string) ([]string, error) {
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return nil, fmt.Errorf("read migrations dir %s: %w", dirPath, err)
	}
	out := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasSuffix(name, ".up.sql") {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out, nil
}

func loadAppliedMigrations(ctx context.Context, db *sql.DB) (map[string]string, error) {
	rows, err := db.QueryContext(ctx, `SELECT filename, checksum FROM schema_migrations`)
	if err != nil {
		return nil, fmt.Errorf("load applied migrations: %w", err)
	}
	defer rows.Close()

	applied := map[string]string{}
	for rows.Next() {
		var row appliedMigration
		if err := rows.Scan(&row.Filename, &row.Checksum); err != nil {
			return nil, fmt.Errorf("scan applied migration: %w", err)
		}
		applied[row.Filename] = row.Checksum
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate applied migrations: %w", err)
	}
	return applied, nil
}

func markMigrationApplied(ctx context.Context, db *sql.DB, migration appliedMigration) error {
	if strings.TrimSpace(migration.Filename) == "" {
		return fmt.Errorf("migration filename is required")
	}
	if strings.TrimSpace(migration.Checksum) == "" {
		return fmt.Errorf("migration checksum is required")
	}
	if _, err := db.ExecContext(
		ctx,
		`INSERT INTO schema_migrations (filename, checksum, applied_at)
		 VALUES ($1, $2, NOW())
		 ON CONFLICT (filename) DO UPDATE SET checksum = EXCLUDED.checksum`,
		migration.Filename,
		migration.Checksum,
	); err != nil {
		return fmt.Errorf("mark migration %s as applied: %w", migration.Filename, err)
	}
	return nil
}

func loadExistingSchemaState(ctx context.Context, db *sql.DB) (existingSchemaState, error) {
	productsTableExists, err := tableExistsByRegclass(ctx, db, "public.products")
	if err != nil {
		return existingSchemaState{}, err
	}
	return existingSchemaState{
		productsTableExists: productsTableExists,
	}, nil
}

func tableExistsByRegclass(ctx context.Context, db *sql.DB, regclass string) (bool, error) {
	var value sql.NullString
	if err := db.QueryRowContext(ctx, `SELECT to_regclass($1)`, regclass).Scan(&value); err != nil {
		return false, fmt.Errorf("table existence check %s: %w", regclass, err)
	}
	return value.Valid && strings.TrimSpace(value.String) != "", nil
}

func shouldSkipMigration(filename string, state existingSchemaState) (bool, string) {
	if filename == "001_init_schema.up.sql" && state.productsTableExists {
		return true, "schema already initialized (products table exists)"
	}
	return false, ""
}

func computeMigrationChecksum(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}
