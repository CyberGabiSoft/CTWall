package main

import (
	"os"
	"path/filepath"
	"testing"

	"backend/internal/config"
)

func TestResolveStartupMigrationConfig(t *testing.T) {
	t.Run("disabled", func(t *testing.T) {
		got, err := resolveStartupMigrationConfig(config.DatabaseConfig{
			AutoApplyOnStart: false,
		}, "/tmp/config.yaml")
		if err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
		if got.Enabled {
			t.Fatalf("expected migrations disabled")
		}
	})

	t.Run("enabled missing path", func(t *testing.T) {
		_, err := resolveStartupMigrationConfig(config.DatabaseConfig{
			AutoApplyOnStart: true,
			MigrationsPath:   " ",
		}, "/tmp/config.yaml")
		if err == nil {
			t.Fatalf("expected error for missing migrations path")
		}
	})

	t.Run("absolute path", func(t *testing.T) {
		got, err := resolveStartupMigrationConfig(config.DatabaseConfig{
			AutoApplyOnStart: true,
			MigrationsPath:   "/var/lib/ctwall/migrations",
		}, "/tmp/config.yaml")
		if err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
		if !got.Enabled {
			t.Fatalf("expected migrations enabled")
		}
		if got.DirPath != "/var/lib/ctwall/migrations" {
			t.Fatalf("unexpected dir path: %s", got.DirPath)
		}
	})

	t.Run("relative to config dir", func(t *testing.T) {
		got, err := resolveStartupMigrationConfig(config.DatabaseConfig{
			AutoApplyOnStart: true,
			MigrationsPath:   "src/migrations",
		}, "/opt/ctwall/config/backend.yaml")
		if err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
		expected := filepath.Clean("/opt/ctwall/config/src/migrations")
		if got.DirPath != expected {
			t.Fatalf("expected %s, got %s", expected, got.DirPath)
		}
	})
}

func TestListMigrationFiles(t *testing.T) {
	dir := t.TempDir()
	mustWriteFile(t, filepath.Join(dir, "002_add.up.sql"), "SELECT 1;")
	mustWriteFile(t, filepath.Join(dir, "001_init_schema.up.sql"), "SELECT 1;")
	mustWriteFile(t, filepath.Join(dir, "README.md"), "ignore")
	mustWriteFile(t, filepath.Join(dir, "003_down.down.sql"), "ignore")

	got, err := listMigrationFiles(dir)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 migration files, got %d", len(got))
	}
	if got[0] != "001_init_schema.up.sql" || got[1] != "002_add.up.sql" {
		t.Fatalf("unexpected migration order: %v", got)
	}
}

func TestShouldSkipMigration(t *testing.T) {
	if skip, _ := shouldSkipMigration("001_init_schema.up.sql", existingSchemaState{productsTableExists: true}); !skip {
		t.Fatalf("expected 001 skip for existing schema")
	}
	if skip, _ := shouldSkipMigration("099_future.up.sql", existingSchemaState{productsTableExists: true}); skip {
		t.Fatalf("did not expect skip for non-legacy migration")
	}
}

func TestComputeMigrationChecksum(t *testing.T) {
	left := computeMigrationChecksum([]byte("SELECT 1;"))
	right := computeMigrationChecksum([]byte("SELECT 1;"))
	diff := computeMigrationChecksum([]byte("SELECT 2;"))
	if left != right {
		t.Fatalf("expected same checksum for same content")
	}
	if left == diff {
		t.Fatalf("expected different checksum for different content")
	}
}

func mustWriteFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
