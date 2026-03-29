package tests

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"backend/internal/store"

	"github.com/jackc/pgx/v5"
	_ "github.com/jackc/pgx/v5/stdlib"
)

const defaultTestDBURL = "postgres://appuser:test12345@127.0.0.1:5432/appdb_test?sslmode=disable"

var (
	dbMu        sync.Mutex
	migrateOnce sync.Once
	migrateErr  error
)

const advisoryLockID int64 = 7483921

// NewPostgresTestStore provides a Postgres-backed store with migrations applied.
func NewPostgresTestStore(t *testing.T) (*store.PostgresStore, *sql.DB) {
	t.Helper()

	dbMu.Lock()

	dbURL := normalizeDBURL(strings.TrimSpace(os.Getenv("TEST_DB_URL")))
	if dbURL == "" {
		dbURL = normalizeDBURL(defaultTestDBURL)
	}

	db, err := sql.Open("pgx", dbURL)
	if err != nil {
		dbMu.Unlock()
		t.Fatalf("open db: %v", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	pingCtx, pingCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer pingCancel()
	if err := db.PingContext(pingCtx); err != nil {
		_ = db.Close()
		dbMu.Unlock()
		t.Fatalf("ping db: %v", err)
	}

	// Advisory lock ensures cross-package test binaries do not share the same DB concurrently.
	// Under -race, test binaries can be significantly slower, so keep the timeout generous.
	lockTimeout := 60 * time.Second
	if deadline, ok := t.Deadline(); ok {
		// Leave some buffer for cleanup and test assertions.
		remaining := time.Until(deadline) - 5*time.Second
		if remaining > 0 && remaining < lockTimeout {
			lockTimeout = remaining
		}
		if lockTimeout < 10*time.Second {
			lockTimeout = 10 * time.Second
		}
	}
	lockCtx, lockCancel := context.WithTimeout(context.Background(), lockTimeout)
	defer lockCancel()
	if _, err := db.ExecContext(lockCtx, "SELECT pg_advisory_lock($1)", advisoryLockID); err != nil {
		_ = db.Close()
		dbMu.Unlock()
		t.Fatalf("advisory lock: %v", err)
	}

	migrateOnce.Do(func() {
		migrateErr = applyMigrations(db, dbURL)
	})
	if migrateErr != nil {
		_ = db.Close()
		dbMu.Unlock()
		t.Fatalf("migrations: %v", migrateErr)
	}
	if err := truncateAllTables(db); err != nil {
		_ = db.Close()
		dbMu.Unlock()
		t.Fatalf("truncate tables: %v", err)
	}

	storeInstance, err := store.NewPostgresStore(db, t.TempDir())
	if err != nil {
		_ = db.Close()
		dbMu.Unlock()
		t.Fatalf("new store: %v", err)
	}

	t.Cleanup(func() {
		if err := truncateAllTables(db); err != nil {
			t.Errorf("truncate tables: %v", err)
		}
		_, _ = db.Exec("SELECT pg_advisory_unlock($1)", advisoryLockID)
		_ = db.Close()
		dbMu.Unlock()
	})

	return storeInstance, db
}

func normalizeDBURL(dbURL string) string {
	if dbURL == "" {
		return ""
	}
	parsed, err := url.Parse(dbURL)
	if err != nil {
		return dbURL
	}
	query := parsed.Query()
	if query.Get("sslmode") == "" {
		query.Set("sslmode", "disable")
	}
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

func applyMigrations(db *sql.DB, dbURL string) error {
	if db == nil {
		return fmt.Errorf("db is nil")
	}
	if strings.TrimSpace(dbURL) == "" {
		return fmt.Errorf("db url is empty")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cfg, err := pgx.ParseConfig(dbURL)
	if err != nil {
		return fmt.Errorf("parse db url: %w", err)
	}
	cfg.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return fmt.Errorf("connect for migrations: %w", err)
	}
	defer func() {
		_ = conn.Close(context.Background())
	}()

	root, err := backendRoot()
	if err != nil {
		return err
	}
	migrationsDir := filepath.Join(root, "migrations")
	entries, err := os.ReadDir(migrationsDir)
	if err != nil {
		return fmt.Errorf("read migrations dir: %w", err)
	}
	var files []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasSuffix(name, ".up.sql") {
			files = append(files, name)
		}
	}
	sort.Strings(files)
	exists, err := tableExists(db, "products")
	if err != nil {
		return err
	}
	if exists {
		needsReset := false
		if hasTable, err := tableExists(db, "component_analysis_malware_findings"); err != nil {
			return err
		} else if !hasTable {
			needsReset = true
		}
		if hasColumn, err := columnExists(db, "tests", "sbom_standard"); err != nil {
			return err
		} else if !hasColumn {
			needsReset = true
		}
		if hasColumn, err := columnExists(db, "components", "pkg_name"); err != nil {
			return err
		} else if !hasColumn {
			needsReset = true
		}
		if hasColumn, err := columnExists(db, "ingest_queue", "sbom_standard"); err != nil {
			return err
		} else if !hasColumn {
			needsReset = true
		}
		if hasColumn, err := columnExists(db, "test_revisions", "sbom_producer"); err != nil {
			return err
		} else if !hasColumn {
			needsReset = true
		}
		if needsReset {
			if err := resetSchema(ctx, conn); err != nil {
				return err
			}
			exists = false
		}
	}
	for _, name := range files {
		if name == "001_init_schema.up.sql" && exists {
			continue
		}
		if err := execMigrationFile(conn, name); err != nil {
			return err
		}
	}
	return nil
}

func execMigrationFile(conn *pgx.Conn, filename string) error {
	root, err := backendRoot()
	if err != nil {
		return err
	}
	path := filepath.Join(root, "migrations", filename)
	content, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read migration %s: %w", filename, err)
	}
	if len(strings.TrimSpace(string(content))) == 0 {
		return nil
	}
	if _, err := conn.Exec(context.Background(), string(content)); err != nil {
		return fmt.Errorf("exec migration %s: %w", filename, err)
	}
	return nil
}

func backendRoot() (string, error) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("resolve tests path")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	return root, nil
}

func tableExists(db *sql.DB, name string) (bool, error) {
	var result sql.NullString
	if err := db.QueryRow(`SELECT to_regclass($1)`, "public."+name).Scan(&result); err != nil {
		return false, fmt.Errorf("table check %s: %w", name, err)
	}
	return result.Valid, nil
}

func columnExists(db *sql.DB, tableName, columnName string) (bool, error) {
	var exists bool
	if err := db.QueryRow(
		`SELECT EXISTS (
			 SELECT 1
			 FROM information_schema.columns
			 WHERE table_schema = 'public'
			   AND table_name = $1
			   AND column_name = $2
		 )`,
		tableName,
		columnName,
	).Scan(&exists); err != nil {
		return false, fmt.Errorf("column check %s.%s: %w", tableName, columnName, err)
	}
	return exists, nil
}

func resetSchema(ctx context.Context, conn *pgx.Conn) error {
	rows, err := conn.Query(ctx, `SELECT tablename FROM pg_tables WHERE schemaname = 'public'`)
	if err != nil {
		return fmt.Errorf("list tables: %w", err)
	}
	defer rows.Close()

	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return fmt.Errorf("scan table name: %w", err)
		}
		tables = append(tables, name)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("list tables: %w", err)
	}
	for _, table := range tables {
		if _, err := conn.Exec(ctx, fmt.Sprintf(`DROP TABLE IF EXISTS "%s" CASCADE`, table)); err != nil {
			return fmt.Errorf("drop table %s: %w", table, err)
		}
	}
	return nil
}

func truncateAllTables(db *sql.DB) error {
	tables := []string{
		"audit_logs",
		"refresh_tokens",
		"api_tokens",
		"connector_configs",
		"product_group_grants",
		"user_group_members",
		"project_memberships",
		"user_settings",
		"component_analysis_malware_findings",
		"component_analysis_malware_queue",
		"component_analysis_malware_component_state",
		"source_malware_input_component_results",
		"source_malware_input_queue",
		"source_malware_input_results",
		"source_scanners",
		"scan_malware_source",
		"component_overrides",
		"components",
		"test_revisions",
		"ingest_queue",
		"sbom_objects",
		"tests",
		"scopes",
		"products",
		"user_groups",
		"projects",
		"users",
	}
	for _, table := range tables {
		exists, err := tableExists(db, table)
		if err != nil {
			return err
		}
		if !exists {
			continue
		}
		if _, err := db.Exec("DELETE FROM " + table); err != nil {
			return err
		}
	}

	// Keep runtime config tables in a deterministic state for tests.
	if exists, err := tableExists(db, "component_analysis_malware_schedule"); err != nil {
		return err
	} else if exists {
		if _, err := db.Exec(`
UPDATE component_analysis_malware_schedule
SET enabled = TRUE,
    interval_seconds = 21600,
    updated_at = NOW()
WHERE id = 1;`); err != nil {
			return err
		}
		if _, err := db.Exec(`
INSERT INTO component_analysis_malware_schedule (id)
VALUES (1)
ON CONFLICT (id) DO NOTHING;`); err != nil {
			return err
		}
	}

	// Keep project-scoped model deterministic for tests.
	if exists, err := tableExists(db, "projects"); err != nil {
		return err
	} else if exists {
		if _, err := db.Exec(`
INSERT INTO projects (name, description, created_at, updated_at)
VALUES ('Default Project', 'Default workspace for tests.', NOW(), NOW())
ON CONFLICT DO NOTHING;`); err != nil {
			return err
		}
	}
	return nil
}
