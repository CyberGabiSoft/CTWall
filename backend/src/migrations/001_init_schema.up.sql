-- CTWall baseline schema migration
-- Generated on 2026-03-28 by consolidating historical migrations 001..036
-- Keep this as a single baseline for fresh database initialization.


-- ---------------------------------------------------------------------
-- BEGIN 001_init_schema.up.sql
-- ---------------------------------------------------------------------
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE products (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    description TEXT,
    archived_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
COMMENT ON TABLE products IS 'Root entity for organizing projects (e.g. "Banking Ecosystem").';
CREATE UNIQUE INDEX uq_products_name ON products (LOWER(name));

CREATE TABLE scopes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    product_id UUID NOT NULL REFERENCES products(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    description TEXT,
    archived_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
COMMENT ON TABLE scopes IS 'Sub-grouping within Product (e.g. "Backend Team" or "Payments Module").';
CREATE UNIQUE INDEX uq_scopes_name ON scopes (product_id, LOWER(name));

CREATE TABLE tests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scope_id UUID NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    is_public BOOLEAN NOT NULL DEFAULT FALSE,
    public_token TEXT,
    archived_at TIMESTAMPTZ,
    sbom_standard TEXT NOT NULL,
    sbom_spec_version TEXT NOT NULL DEFAULT 'unknown',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
COMMENT ON TABLE tests IS 'Logical representation of an Application/Service. Holds configuration and permissions, effectively a container for SBOM history.';
CREATE UNIQUE INDEX uq_tests_name_type ON tests (scope_id, LOWER(name), sbom_standard, sbom_spec_version);
CREATE UNIQUE INDEX uq_tests_public_token ON tests (public_token) WHERE public_token IS NOT NULL;

CREATE TABLE sbom_objects (
    sha256 CHAR(64) PRIMARY KEY,
    storage_path TEXT NOT NULL,
    size_bytes BIGINT NOT NULL,
    format TEXT NOT NULL,
    content_type TEXT NOT NULL DEFAULT '',
    is_gzip BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
COMMENT ON TABLE sbom_objects IS 'Physical file storage metadata. Content is deduplicated by SHA256.';

CREATE TABLE ingest_queue (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    product_id UUID,
    scope_id UUID,
    test_id UUID,
    sbom_sha256 CHAR(64) NOT NULL,
    sbom_standard TEXT NOT NULL,
    sbom_spec_version TEXT NOT NULL DEFAULT 'unknown',
    sbom_producer TEXT NOT NULL DEFAULT 'other',
    tags JSONB NOT NULL DEFAULT '[]'::jsonb,
    metadata_json JSONB,
    content_type TEXT NOT NULL DEFAULT '',
    is_gzip BOOLEAN NOT NULL DEFAULT FALSE,
    components_count INT NOT NULL DEFAULT 0,
    processing_stage TEXT NOT NULL DEFAULT 'RECEIVED'
        CHECK (processing_stage IN ('RECEIVED', 'VALIDATING', 'PARSING', 'ANALYZING', 'STORING', 'REVISIONING', 'COMPLETED', 'FAILED')),
    status TEXT NOT NULL CHECK (status IN ('PENDING', 'PROCESSING', 'COMPLETED', 'FAILED')),
    error_message TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);
COMMENT ON TABLE ingest_queue IS 'Durable ingest buffer for SBOM uploads and retry.';
CREATE INDEX idx_ingest_queue_status ON ingest_queue(status, created_at);

CREATE TABLE test_revisions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    test_id UUID NOT NULL REFERENCES tests(id) ON DELETE CASCADE,
    sbom_sha256 CHAR(64) NOT NULL REFERENCES sbom_objects(sha256),
    sbom_producer TEXT NOT NULL DEFAULT 'other',
    sbom_metadata_json JSONB,
    is_active BOOLEAN DEFAULT TRUE,
    components_count INT DEFAULT 0,
    tags JSONB NOT NULL DEFAULT '[]'::jsonb,
    metadata_json JSONB,
    last_modified_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
COMMENT ON TABLE test_revisions IS 'Immutable snapshot of an uploaded SBOM file linked to a Test.';
CREATE INDEX idx_revisions_test_created ON test_revisions(test_id, created_at DESC);
CREATE UNIQUE INDEX uq_revisions_active_per_test ON test_revisions(test_id) WHERE is_active = TRUE;
CREATE INDEX idx_revisions_tags_gin ON test_revisions USING GIN (tags);

CREATE TABLE components (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    revision_id UUID NOT NULL REFERENCES test_revisions(id) ON DELETE CASCADE,
    purl TEXT NOT NULL,
    pkg_name TEXT NOT NULL,
    version TEXT NOT NULL,
    pkg_type TEXT NOT NULL,
    pkg_namespace TEXT,
    sbom_type TEXT NOT NULL,
    publisher TEXT,
    supplier TEXT,
    licenses JSONB,
    properties JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX idx_components_revision ON components(revision_id);
CREATE INDEX idx_components_purl ON components(purl);
CREATE INDEX idx_components_licenses ON components USING GIN (licenses);

CREATE TABLE component_overrides (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    test_id UUID NOT NULL REFERENCES tests(id) ON DELETE CASCADE,
    purl_pattern TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('APPROVED', 'WARNING', 'REJECTED')),
    reason TEXT,
    comment TEXT,
    author_id UUID,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT uq_override_target UNIQUE (test_id, purl_pattern)
);
COMMENT ON TABLE component_overrides IS 'Stores triage decisions (Approved/Rejected) that persist across SBOM uploads for a Test.';

CREATE TABLE scan_malware_source (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    source_type TEXT NOT NULL CHECK (source_type IN ('OSV_API', 'OSV_MIRROR', 'GITHUB_ADVISORIES')),
    base_url TEXT NOT NULL,
    config_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
COMMENT ON TABLE scan_malware_source IS 'Configuration for malware data sources (OSV API/mirror, GitHub advisories, etc.).';

CREATE TABLE source_scanners (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_id UUID NOT NULL REFERENCES scan_malware_source(id) ON DELETE RESTRICT,
    name TEXT NOT NULL,
    scanner_type TEXT NOT NULL,
    version TEXT,
    results_path TEXT,
    config_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
COMMENT ON TABLE source_scanners IS 'Registered scanners with type/name/version tied to a malware source.';

CREATE TABLE source_malware_input_queue (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    component_purl TEXT NOT NULL,
    scanner_id UUID NOT NULL REFERENCES source_scanners(id) ON DELETE CASCADE,
    status TEXT NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'PROCESSING', 'COMPLETED', 'FAILED')),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT uq_analysis_queue_target UNIQUE (component_purl, scanner_id)
);
CREATE INDEX idx_queue_poll ON source_malware_input_queue(status, created_at);

CREATE TABLE source_malware_input_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    component_purl TEXT NOT NULL,
    component_hash TEXT,
    verdict TEXT NOT NULL CHECK (verdict IN ('MALWARE', 'CLEAN', 'UNKNOWN')),
    findings_count INT DEFAULT 0,
    summary TEXT,
    scanned_at TIMESTAMPTZ DEFAULT NOW(),
    valid_until TIMESTAMPTZ,
    CONSTRAINT uq_result_target UNIQUE (component_purl)
);
CREATE INDEX idx_results_lookup ON source_malware_input_results(component_purl, verdict);
COMMENT ON TABLE source_malware_input_results IS 'Persistent storage for analysis results (Malware/Heuristics). Decoupled from specific SBOMs via PURL.';

CREATE TABLE source_malware_input_component_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    component_purl TEXT NOT NULL,
    component_hash TEXT,
    analysis_result_id UUID REFERENCES source_malware_input_results(id) ON DELETE CASCADE,
    scan_id UUID NOT NULL REFERENCES source_malware_input_queue(id) ON DELETE CASCADE,
    source_id UUID NOT NULL,
    result_filename TEXT,
    evidence TEXT,
    details_json JSONB NOT NULL,
    published_at TIMESTAMPTZ,
    modified_at TIMESTAMPTZ,
    detect_version TEXT,
    fixed_version TEXT,
    is_malware BOOLEAN NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT uq_scan_component_result UNIQUE (component_purl, source_id, result_filename)
);
CREATE INDEX idx_scan_component_results_purl_created ON source_malware_input_component_results(component_purl, created_at DESC);
CREATE INDEX idx_scan_component_results_source_created ON source_malware_input_component_results(source_id, created_at DESC);
COMMENT ON TABLE source_malware_input_component_results IS 'Raw malware/heuristics findings per component PURL (hash may be unavailable).';

CREATE TABLE component_analysis_malware_queue (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    component_purl TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'PROCESSING', 'COMPLETED', 'FAILED')),
    reason TEXT NOT NULL DEFAULT 'SCHEDULED' CHECK (reason IN ('SCHEDULED', 'MANUAL', 'BACKFILL')),
    attempts INT NOT NULL DEFAULT 0,
    last_error TEXT,
    locked_at TIMESTAMPTZ,
    locked_by TEXT,
    scheduled_for TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);
CREATE UNIQUE INDEX uq_component_analysis_malware_queue_active
    ON component_analysis_malware_queue(component_purl)
    WHERE status IN ('PENDING', 'PROCESSING');
CREATE INDEX idx_component_analysis_malware_queue_status ON component_analysis_malware_queue(status, created_at);
CREATE INDEX idx_component_analysis_malware_queue_component ON component_analysis_malware_queue(component_purl, created_at DESC);
COMMENT ON TABLE component_analysis_malware_queue IS 'Queue of component PURL mapping runs to malware input results.';

CREATE TABLE component_analysis_malware_findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    component_purl TEXT NOT NULL,
    malware_purl TEXT NOT NULL,
    source_malware_input_result_id UUID NOT NULL REFERENCES source_malware_input_results(id) ON DELETE CASCADE,
    match_type TEXT NOT NULL CHECK (match_type IN ('EXACT', 'CONTAINS_PREFIX')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_component_analysis_malware_findings UNIQUE (component_purl, malware_purl)
);
CREATE INDEX idx_component_analysis_malware_findings_component ON component_analysis_malware_findings(component_purl);
CREATE INDEX idx_component_analysis_malware_findings_malware ON component_analysis_malware_findings(malware_purl);
COMMENT ON TABLE component_analysis_malware_findings IS 'Mapping between SBOM component PURLs and malware input PURLs.';

CREATE TABLE integrations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    product_id UUID REFERENCES products(id) ON DELETE CASCADE,
    scope_id UUID REFERENCES scopes(id) ON DELETE CASCADE,
    test_id UUID REFERENCES tests(id) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    config JSONB NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT chk_provider CHECK (provider IN ('JIRA', 'SLACK', 'WEBHOOK', 'EMAIL'))
);

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT DEFAULT 'WRITER' CHECK (role IN ('ADMIN', 'WRITER', 'READER')),
    account_type TEXT DEFAULT 'USER' CHECK (account_type IN ('USER', 'SERVICE_ACCOUNT')),
    full_name TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE api_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    token_hash TEXT NOT NULL,
    last_used_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE refresh_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    replaced_by_id UUID REFERENCES refresh_tokens(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,
    user_agent TEXT,
    ip_address TEXT
);
CREATE INDEX idx_refresh_tokens_user ON refresh_tokens(user_id);
CREATE INDEX idx_refresh_tokens_expires ON refresh_tokens(expires_at);

CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_id UUID REFERENCES users(id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id UUID,
    details JSONB,
    ip_address TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_audit_created ON audit_logs USING BRIN (created_at);

-- END 001_init_schema.up.sql

-- ---------------------------------------------------------------------
-- BEGIN 002_component_analysis_schedule_state.up.sql
-- ---------------------------------------------------------------------
-- Component analysis malware schedule + per-component state.
-- This prevents repeated re-analysis when there are no findings (clean components),
-- and enables controlled, scheduled re-analysis.

CREATE TABLE IF NOT EXISTS component_analysis_malware_schedule (
    id INT PRIMARY KEY CHECK (id = 1),
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    interval_seconds INT NOT NULL DEFAULT 86400 CHECK (interval_seconds >= 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
COMMENT ON TABLE component_analysis_malware_schedule IS 'Runtime configuration for scheduled component malware mapping re-analysis.';

INSERT INTO component_analysis_malware_schedule (id)
VALUES (1)
ON CONFLICT (id) DO NOTHING;

CREATE TABLE IF NOT EXISTS component_analysis_malware_component_state (
    component_purl TEXT PRIMARY KEY,
    scanned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    valid_until TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
COMMENT ON TABLE component_analysis_malware_component_state IS 'Tracks the latest component malware mapping run per component PURL (even if no findings).';
CREATE INDEX IF NOT EXISTS idx_component_analysis_malware_component_state_valid_until
    ON component_analysis_malware_component_state(valid_until);

-- END 002_component_analysis_schedule_state.up.sql

-- ---------------------------------------------------------------------
-- BEGIN 003_test_revision_malware_summary.up.sql
-- ---------------------------------------------------------------------
-- Materialized malware summary per TestRevision (active revision is used by UI).
-- The summary is recomputed asynchronously when component analysis results change.

CREATE TABLE IF NOT EXISTS test_revision_malware_summary (
    revision_id UUID PRIMARY KEY REFERENCES test_revisions(id) ON DELETE CASCADE,
    malware_component_count INT NOT NULL DEFAULT 0 CHECK (malware_component_count >= 0),
    computed_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
COMMENT ON TABLE test_revision_malware_summary IS 'Materialized malware summary per TestRevision. Source of truth remains mappings/results; this is a cached read model.';

-- Queue of revision summary recomputation jobs. One active job per revision_id.
CREATE TABLE IF NOT EXISTS test_revision_malware_summary_queue (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    revision_id UUID NOT NULL REFERENCES test_revisions(id) ON DELETE CASCADE,
    CONSTRAINT uq_test_revision_malware_summary_queue_revision UNIQUE (revision_id),
    status TEXT NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'PROCESSING', 'COMPLETED', 'FAILED')),
    reason TEXT NOT NULL DEFAULT 'BACKFILL' CHECK (reason IN ('BACKFILL', 'INGEST', 'COMPONENT_ANALYSIS_UPDATE')),
    attempts INT NOT NULL DEFAULT 0,
    last_error TEXT,
    locked_at TIMESTAMPTZ,
    locked_by TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);
COMMENT ON TABLE test_revision_malware_summary_queue IS 'Queue of recomputation jobs for test_revision_malware_summary.';

CREATE INDEX IF NOT EXISTS idx_test_revision_malware_summary_queue_status
    ON test_revision_malware_summary_queue(status, created_at);
CREATE INDEX IF NOT EXISTS idx_test_revision_malware_summary_queue_revision
    ON test_revision_malware_summary_queue(revision_id, created_at DESC);

-- Backfill summary rows for existing revisions.
INSERT INTO test_revision_malware_summary (revision_id)
SELECT id
FROM test_revisions
ON CONFLICT (revision_id) DO NOTHING;

-- Enqueue active revisions for initial compute.
INSERT INTO test_revision_malware_summary_queue (revision_id, status, reason)
SELECT id, 'PENDING', 'BACKFILL'
FROM test_revisions
WHERE is_active = TRUE
ON CONFLICT (revision_id) DO UPDATE SET
    status = 'PENDING',
    reason = EXCLUDED.reason,
    updated_at = NOW(),
    completed_at = NULL,
    last_error = NULL;

-- END 003_test_revision_malware_summary.up.sql

-- ---------------------------------------------------------------------
-- BEGIN 004_test_revision_malware_summary_queue_manual_reason.up.sql
-- ---------------------------------------------------------------------
-- Allow manual recomputation reason for test revision malware summary queue.

DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conrelid = 'public.test_revision_malware_summary_queue'::regclass
      AND conname = 'test_revision_malware_summary_queue_reason_check'
  ) THEN
    ALTER TABLE test_revision_malware_summary_queue
      DROP CONSTRAINT test_revision_malware_summary_queue_reason_check;
  END IF;
END $$;

ALTER TABLE test_revision_malware_summary_queue
  ADD CONSTRAINT test_revision_malware_summary_queue_reason_check
  CHECK (reason IN ('BACKFILL', 'INGEST', 'COMPONENT_ANALYSIS_UPDATE', 'MANUAL'));


-- END 004_test_revision_malware_summary_queue_manual_reason.up.sql

-- ---------------------------------------------------------------------
-- BEGIN 005_components_search_trgm.up.sql
-- ---------------------------------------------------------------------
-- Enable fast substring search for Components PURL.
-- pg_trgm is an official PostgreSQL extension (contrib) widely used for ILIKE/contains search.

CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- Accelerate `purl ILIKE '%' || q || '%'` queries.
CREATE INDEX IF NOT EXISTS idx_components_purl_trgm
  ON components
  USING GIN (purl gin_trgm_ops);


-- END 005_components_search_trgm.up.sql

-- ---------------------------------------------------------------------
-- BEGIN 006_events_indexes.up.sql
-- ---------------------------------------------------------------------
-- Indexes for Events UI queries derived from audit_logs (append-only).
-- NOTE: We intentionally scope indexes to rows with details.event_key to keep them small.

CREATE INDEX IF NOT EXISTS idx_audit_events_event_key_created
  ON audit_logs ((details->>'event_key'), created_at DESC)
  WHERE action <> 'EVENT_ACK' AND details ? 'event_key' AND COALESCE(details->>'event_key','') <> '';

CREATE INDEX IF NOT EXISTS idx_audit_events_severity_category_created
  ON audit_logs ((details->>'severity'), (details->>'category'), created_at DESC)
  WHERE action <> 'EVENT_ACK' AND details ? 'event_key' AND COALESCE(details->>'event_key','') <> '';

CREATE INDEX IF NOT EXISTS idx_audit_events_ack_event_key_created
  ON audit_logs ((details->>'event_key'), created_at DESC)
  WHERE action = 'EVENT_ACK' AND details ? 'event_key' AND COALESCE(details->>'event_key','') <> '';


-- END 006_events_indexes.up.sql

-- ---------------------------------------------------------------------
-- BEGIN 007_try_jsonb_helper.up.sql
-- ---------------------------------------------------------------------
-- Helper to safely parse legacy audit_logs.details values when the column is not JSONB
-- (or contains invalid JSON due to historic data). This prevents Events queries from 500-ing.
--
-- Note: returning NULL for invalid payloads intentionally excludes such rows from Events,
-- because they cannot participate in event_key-based aggregation anyway.
CREATE OR REPLACE FUNCTION ctwall_try_jsonb(input_text TEXT)
RETURNS JSONB
LANGUAGE plpgsql
IMMUTABLE
AS $$
BEGIN
  IF input_text IS NULL OR BTRIM(input_text) = '' THEN
    RETURN NULL;
  END IF;
  RETURN input_text::jsonb;
EXCEPTION WHEN others THEN
  RETURN NULL;
END;
$$;


-- END 007_try_jsonb_helper.up.sql

-- ---------------------------------------------------------------------
-- BEGIN 008_audit_logs_backfill_event_key.up.sql
-- ---------------------------------------------------------------------
-- Backfill audit_logs.details.event_key for legacy rows.
-- event_key is required for Events aggregation and for consistent auditing.
--
-- NOTE: This uses a conservative, low-cardinality derivation: "<category>.<normalized_action>".
-- It intentionally does not include dynamic identifiers, URLs, UUIDs, etc.

UPDATE audit_logs
SET details = jsonb_set(
  details,
  '{event_key}',
  to_jsonb(
    left(
      coalesce(nullif(details->>'category', ''), 'system')
      || '.'
      || coalesce(
        nullif(
          btrim(regexp_replace(lower(action), '[^a-z0-9]+', '_', 'g'), '_'),
          ''
        ),
        'unknown_action'
      ),
      240
    )
  ),
  true
)
WHERE details IS NOT NULL
  AND (NOT (details ? 'event_key') OR btrim(coalesce(details->>'event_key', '')) = '');


-- END 008_audit_logs_backfill_event_key.up.sql

-- ---------------------------------------------------------------------
-- BEGIN 009_projects_workspace_selector.up.sql
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS projects (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    description TEXT,
    archived_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_projects_name ON projects (LOWER(name));

CREATE TABLE IF NOT EXISTS project_memberships (
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    PRIMARY KEY (project_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_project_memberships_user_project ON project_memberships (user_id, project_id);
CREATE INDEX IF NOT EXISTS idx_project_memberships_project_user ON project_memberships (project_id, user_id);

CREATE TABLE IF NOT EXISTS user_settings (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    selected_project_id UUID REFERENCES projects(id) ON DELETE SET NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_user_settings_selected_project ON user_settings (selected_project_id);

ALTER TABLE products
    ADD COLUMN IF NOT EXISTS project_id UUID;

INSERT INTO projects (name, description)
VALUES ('Default Project', 'Default workspace created by migration.')
ON CONFLICT (LOWER(name)) DO NOTHING;

CREATE OR REPLACE FUNCTION ctwall_default_project_id()
RETURNS UUID
LANGUAGE sql
STABLE
AS $$
    SELECT id
    FROM projects
    WHERE LOWER(name) = LOWER('Default Project')
    LIMIT 1
$$;

ALTER TABLE products
    ALTER COLUMN project_id SET DEFAULT ctwall_default_project_id();

WITH default_project AS (
    SELECT id
    FROM projects
    WHERE LOWER(name) = LOWER('Default Project')
    LIMIT 1
)
UPDATE products p
SET project_id = dp.id
FROM default_project dp
WHERE p.project_id IS NULL;

ALTER TABLE products
    ALTER COLUMN project_id SET NOT NULL;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'fk_products_project_id'
    ) THEN
        ALTER TABLE products
            ADD CONSTRAINT fk_products_project_id
            FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE;
    END IF;
END $$;

DROP INDEX IF EXISTS uq_products_name;
CREATE UNIQUE INDEX IF NOT EXISTS uq_products_project_name ON products (project_id, LOWER(name));
CREATE INDEX IF NOT EXISTS idx_products_project_id ON products (project_id);

WITH default_project AS (
    SELECT id
    FROM projects
    WHERE LOWER(name) = LOWER('Default Project')
    LIMIT 1
)
INSERT INTO project_memberships (project_id, user_id, created_by)
SELECT dp.id, u.id, NULL
FROM users u
CROSS JOIN default_project dp
ON CONFLICT (project_id, user_id) DO NOTHING;

WITH default_project AS (
    SELECT id
    FROM projects
    WHERE LOWER(name) = LOWER('Default Project')
    LIMIT 1
)
INSERT INTO user_settings (user_id, selected_project_id, updated_at)
SELECT u.id, dp.id, NOW()
FROM users u
CROSS JOIN default_project dp
ON CONFLICT (user_id) DO UPDATE
SET selected_project_id = EXCLUDED.selected_project_id,
    updated_at = NOW();

-- END 009_projects_workspace_selector.up.sql

-- ---------------------------------------------------------------------
-- BEGIN 010_connector_configs_global.up.sql
-- ---------------------------------------------------------------------
-- Connector configuration storage for Settings > Connectors (MVP).
-- This table is future-ready for scoped configs (PRODUCT/SCOPE/TEST),
-- while the current implementation uses only GLOBAL scope.

CREATE TABLE IF NOT EXISTS connector_configs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    connector_type TEXT NOT NULL CHECK (connector_type IN ('JIRA', 'SLACK', 'SMTP')),
    scope_type TEXT NOT NULL DEFAULT 'GLOBAL' CHECK (scope_type IN ('GLOBAL', 'PRODUCT', 'SCOPE', 'TEST')),
    scope_id UUID NULL,
    config_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    is_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    last_test_status TEXT NOT NULL DEFAULT 'NOT_CONFIGURED' CHECK (last_test_status IN ('NOT_CONFIGURED', 'PASSED', 'FAILED')),
    last_test_at TIMESTAMPTZ NULL,
    last_test_message TEXT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_connector_scope_ref
        CHECK (
            (scope_type = 'GLOBAL' AND scope_id IS NULL)
            OR
            (scope_type <> 'GLOBAL' AND scope_id IS NOT NULL)
        )
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_connector_configs_global
    ON connector_configs (connector_type)
    WHERE scope_type = 'GLOBAL' AND scope_id IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS uq_connector_configs_scoped
    ON connector_configs (connector_type, scope_type, scope_id)
    WHERE scope_type <> 'GLOBAL' AND scope_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_connector_configs_scope
    ON connector_configs (scope_type, scope_id);

-- Optional data carry-over from legacy "integrations" rows configured globally.
INSERT INTO connector_configs (
    connector_type,
    scope_type,
    scope_id,
    config_json,
    is_enabled,
    created_at,
    updated_at
)
SELECT
    CASE i.provider
        WHEN 'EMAIL' THEN 'SMTP'
        ELSE i.provider
    END AS connector_type,
    'GLOBAL' AS scope_type,
    NULL::UUID AS scope_id,
    COALESCE(i.config, '{}'::jsonb) AS config_json,
    COALESCE(i.is_active, TRUE) AS is_enabled,
    COALESCE(i.updated_at, NOW()) AS created_at,
    COALESCE(i.updated_at, NOW()) AS updated_at
FROM integrations i
WHERE i.product_id IS NULL
  AND i.scope_id IS NULL
  AND i.test_id IS NULL
  AND i.provider IN ('JIRA', 'SLACK', 'EMAIL')
ON CONFLICT DO NOTHING;

-- END 010_connector_configs_global.up.sql

-- ---------------------------------------------------------------------
-- BEGIN 011_component_malware_findings_triage_and_priorities.up.sql
-- ---------------------------------------------------------------------
-- Malware finding triage (per test) + default priority hierarchy (product/scope/test).
-- Priority levels:
-- - P1: Critical
-- - P2: High (default fallback)
-- - P3: Medium
-- - P4: Low

ALTER TABLE products
    ADD COLUMN IF NOT EXISTS malware_default_priority TEXT;

ALTER TABLE scopes
    ADD COLUMN IF NOT EXISTS malware_default_priority TEXT;

ALTER TABLE tests
    ADD COLUMN IF NOT EXISTS malware_default_priority TEXT;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'chk_products_malware_default_priority'
    ) THEN
        ALTER TABLE products
            ADD CONSTRAINT chk_products_malware_default_priority
            CHECK (malware_default_priority IS NULL OR malware_default_priority IN ('P1', 'P2', 'P3', 'P4'));
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'chk_scopes_malware_default_priority'
    ) THEN
        ALTER TABLE scopes
            ADD CONSTRAINT chk_scopes_malware_default_priority
            CHECK (malware_default_priority IS NULL OR malware_default_priority IN ('P1', 'P2', 'P3', 'P4'));
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'chk_tests_malware_default_priority'
    ) THEN
        ALTER TABLE tests
            ADD CONSTRAINT chk_tests_malware_default_priority
            CHECK (malware_default_priority IS NULL OR malware_default_priority IN ('P1', 'P2', 'P3', 'P4'));
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS component_malware_findings_triage (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    test_id UUID NOT NULL REFERENCES tests(id) ON DELETE CASCADE,
    component_purl TEXT NOT NULL,
    malware_purl TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('OPEN', 'RISK_ACCEPTED', 'FALSE_POSITIVE', 'CLOSED')),
    priority TEXT CHECK (priority IN ('P1', 'P2', 'P3', 'P4')),
    reason TEXT,
    expires_at TIMESTAMPTZ,
    author_id UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_component_malware_findings_triage UNIQUE (test_id, component_purl, malware_purl)
);

CREATE INDEX IF NOT EXISTS idx_component_malware_findings_triage_project
    ON component_malware_findings_triage(project_id, updated_at DESC);

CREATE INDEX IF NOT EXISTS idx_component_malware_findings_triage_test
    ON component_malware_findings_triage(test_id, updated_at DESC);

CREATE INDEX IF NOT EXISTS idx_component_malware_findings_triage_lookup
    ON component_malware_findings_triage(test_id, component_purl, malware_purl);


-- END 011_component_malware_findings_triage_and_priorities.up.sql

-- ---------------------------------------------------------------------
-- BEGIN 012_alerts_mvp.up.sql
-- ---------------------------------------------------------------------
-- Alerts (MVP): batched groups + append-only occurrences + per-project connector routing.
-- NOTE: Connection profiles (SMTP/Slack secrets etc.) live in connector_configs (GLOBAL scope).
-- This migration adds only alert state and routing preferences.

CREATE TABLE IF NOT EXISTS alert_groups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    severity TEXT NOT NULL CHECK (severity IN ('INFO', 'WARN', 'ERROR')),
    category TEXT NOT NULL,
    type TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('OPEN', 'ACKNOWLEDGED', 'CLOSED')),
    group_key TEXT NOT NULL,
    title TEXT NOT NULL,
    entity_ref TEXT NULL,
    occurrences INT NOT NULL DEFAULT 1,
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_notified_at TIMESTAMPTZ NULL,
    acknowledged_at TIMESTAMPTZ NULL,
    acknowledged_by UUID NULL REFERENCES users(id),
    closed_at TIMESTAMPTZ NULL,
    closed_by UUID NULL REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (project_id, group_key)
);

CREATE INDEX IF NOT EXISTS idx_alert_groups_project_status_severity_last_seen
    ON alert_groups (project_id, status, severity, last_seen_at DESC);

CREATE INDEX IF NOT EXISTS idx_alert_groups_project_last_seen
    ON alert_groups (project_id, last_seen_at DESC);

CREATE TABLE IF NOT EXISTS alert_occurrences (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    group_id UUID NOT NULL REFERENCES alert_groups(id) ON DELETE CASCADE,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    product_id UUID NULL REFERENCES products(id) ON DELETE SET NULL,
    scope_id UUID NULL REFERENCES scopes(id) ON DELETE SET NULL,
    test_id UUID NULL REFERENCES tests(id) ON DELETE SET NULL,
    entity_ref TEXT NULL,
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_alert_occurrences_project_occurred_at
    ON alert_occurrences (project_id, occurred_at DESC);

CREATE INDEX IF NOT EXISTS idx_alert_occurrences_project_group_occurred_at
    ON alert_occurrences (project_id, group_id, occurred_at DESC);

CREATE TABLE IF NOT EXISTS alert_connector_settings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    connector_type TEXT NOT NULL CHECK (connector_type IN ('SMTP', 'SLACK')),
    is_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (project_id, connector_type)
);

CREATE TABLE IF NOT EXISTS alert_routes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    connector_type TEXT NOT NULL CHECK (connector_type IN ('SMTP', 'SLACK')),
    target_type TEXT NOT NULL CHECK (target_type IN ('PRODUCT', 'SCOPE', 'TEST')),
    target_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (project_id, connector_type, target_type, target_id)
);

CREATE INDEX IF NOT EXISTS idx_alert_routes_project_connector
    ON alert_routes (project_id, connector_type);


-- END 012_alerts_mvp.up.sql

-- ---------------------------------------------------------------------
-- BEGIN 013_projects_created_by.up.sql
-- ---------------------------------------------------------------------
ALTER TABLE projects
    ADD COLUMN IF NOT EXISTS created_by UUID REFERENCES users(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_projects_created_by ON projects (created_by);


-- END 013_projects_created_by.up.sql

-- ---------------------------------------------------------------------
-- BEGIN 014_product_groups_and_project_roles.up.sql
-- ---------------------------------------------------------------------
ALTER TABLE project_memberships
    ADD COLUMN IF NOT EXISTS project_role TEXT;

UPDATE project_memberships pm
SET project_role = CASE
    WHEN UPPER(u.role) = 'ADMIN' THEN 'ADMIN'
    WHEN UPPER(u.role) = 'WRITER' THEN 'WRITER'
    ELSE 'READER'
END
FROM users u
WHERE u.id = pm.user_id
  AND (pm.project_role IS NULL OR BTRIM(pm.project_role) = '');

ALTER TABLE project_memberships
    ALTER COLUMN project_role SET DEFAULT 'READER';

UPDATE project_memberships
SET project_role = 'READER'
WHERE project_role IS NULL OR BTRIM(project_role) = '';

ALTER TABLE project_memberships
    ALTER COLUMN project_role SET NOT NULL;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'chk_project_memberships_project_role'
    ) THEN
        ALTER TABLE project_memberships
            ADD CONSTRAINT chk_project_memberships_project_role
            CHECK (project_role IN ('ADMIN', 'WRITER', 'READER'));
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_project_memberships_user_project_role
    ON project_memberships (user_id, project_id, project_role);

CREATE TABLE IF NOT EXISTS user_groups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by UUID REFERENCES users(id) ON DELETE RESTRICT
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_user_groups_project_name
    ON user_groups (project_id, LOWER(name));
CREATE INDEX IF NOT EXISTS idx_user_groups_project_id
    ON user_groups (project_id);

CREATE TABLE IF NOT EXISTS user_group_members (
    group_id UUID NOT NULL REFERENCES user_groups(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role TEXT NOT NULL CHECK (role IN ('OWNER', 'EDITOR', 'VIEWER')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    PRIMARY KEY (group_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_user_group_members_user_group
    ON user_group_members (user_id, group_id);

ALTER TABLE products
    ADD COLUMN IF NOT EXISTS owner_group_id UUID REFERENCES user_groups(id) ON DELETE RESTRICT;

ALTER TABLE products
    ADD COLUMN IF NOT EXISTS created_by UUID REFERENCES users(id) ON DELETE RESTRICT;

CREATE INDEX IF NOT EXISTS idx_products_owner_group_id
    ON products (owner_group_id);
CREATE INDEX IF NOT EXISTS idx_products_created_by
    ON products (created_by);

CREATE TABLE IF NOT EXISTS product_group_grants (
    product_id UUID NOT NULL REFERENCES products(id) ON DELETE CASCADE,
    group_id UUID NOT NULL REFERENCES user_groups(id) ON DELETE CASCADE,
    role TEXT NOT NULL CHECK (role IN ('EDITOR', 'VIEWER')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    PRIMARY KEY (product_id, group_id)
);

CREATE INDEX IF NOT EXISTS idx_product_group_grants_group_product
    ON product_group_grants (group_id, product_id);

CREATE OR REPLACE FUNCTION ctwall_products_validate_owner_group()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    owner_project_id UUID;
BEGIN
    IF NEW.owner_group_id IS NULL THEN
        RETURN NEW;
    END IF;

    SELECT ug.project_id
    INTO owner_project_id
    FROM user_groups ug
    WHERE ug.id = NEW.owner_group_id;

    IF owner_project_id IS NULL THEN
        RAISE EXCEPTION 'Owner group not found'
            USING ERRCODE = '23503';
    END IF;
    IF owner_project_id <> NEW.project_id THEN
        RAISE EXCEPTION 'Owner group must belong to the same project as product'
            USING ERRCODE = '23514';
    END IF;

    IF NEW.created_by IS NOT NULL
       AND NOT EXISTS (
           SELECT 1
           FROM user_group_members gm
           WHERE gm.group_id = NEW.owner_group_id
             AND gm.user_id = NEW.created_by
             AND gm.role = 'OWNER'
       ) THEN
        RAISE EXCEPTION 'Product creator must be OWNER in owner group'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_products_validate_owner_group ON products;
CREATE TRIGGER trg_products_validate_owner_group
BEFORE INSERT OR UPDATE OF owner_group_id, project_id, created_by
ON products
FOR EACH ROW
EXECUTE FUNCTION ctwall_products_validate_owner_group();

CREATE OR REPLACE FUNCTION ctwall_product_group_grants_validate()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    product_project_id UUID;
    owner_group_id UUID;
    group_project_id UUID;
BEGIN
    SELECT p.project_id, p.owner_group_id
    INTO product_project_id, owner_group_id
    FROM products p
    WHERE p.id = NEW.product_id;

    IF product_project_id IS NULL THEN
        RAISE EXCEPTION 'Product not found'
            USING ERRCODE = '23503';
    END IF;

    SELECT ug.project_id
    INTO group_project_id
    FROM user_groups ug
    WHERE ug.id = NEW.group_id;

    IF group_project_id IS NULL THEN
        RAISE EXCEPTION 'Group not found'
            USING ERRCODE = '23503';
    END IF;
    IF group_project_id <> product_project_id THEN
        RAISE EXCEPTION 'Grant group must belong to the same project as product'
            USING ERRCODE = '23514';
    END IF;
    IF owner_group_id IS NOT NULL AND NEW.group_id = owner_group_id THEN
        RAISE EXCEPTION 'Owner group is implicit and cannot be inserted into product_group_grants'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_product_group_grants_validate ON product_group_grants;
CREATE TRIGGER trg_product_group_grants_validate
BEFORE INSERT OR UPDATE OF product_id, group_id
ON product_group_grants
FOR EACH ROW
EXECUTE FUNCTION ctwall_product_group_grants_validate();

-- END 014_product_groups_and_project_roles.up.sql

-- ---------------------------------------------------------------------
-- BEGIN 015_users_role_none.up.sql
-- ---------------------------------------------------------------------
ALTER TABLE users
    ALTER COLUMN role SET DEFAULT 'NONE';

ALTER TABLE users
    DROP CONSTRAINT IF EXISTS users_role_check;

ALTER TABLE users
    DROP CONSTRAINT IF EXISTS chk_users_role;

ALTER TABLE users
    ADD CONSTRAINT chk_users_role
    CHECK (role IN ('ADMIN', 'WRITER', 'READER', 'NONE'));

-- END 015_users_role_none.up.sql

-- ---------------------------------------------------------------------
-- BEGIN 016_alert_dispatch_queue.up.sql
-- ---------------------------------------------------------------------
-- Durable queue for Alertmanager integration.
-- Used by dedicated alerting control/dispatcher processes.

CREATE TABLE IF NOT EXISTS alert_dispatch_queue (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    message_type TEXT NOT NULL CHECK (message_type IN ('CONFIG_APPLY', 'ALERT_EVENT')),
    event_state TEXT NULL CHECK (event_state IN ('FIRING', 'RESOLVED')),
    project_id UUID NULL REFERENCES projects(id) ON DELETE CASCADE,
    group_id UUID NULL REFERENCES alert_groups(id) ON DELETE CASCADE,
    payload_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    state TEXT NOT NULL CHECK (state IN ('PENDING', 'IN_FLIGHT', 'RETRY', 'DONE', 'DEAD')),
    attempt_count INT NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NULL,
    locked_at TIMESTAMPTZ NULL,
    locked_by TEXT NULL,
    last_error_code TEXT NULL,
    last_error_message TEXT NULL,
    done_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_alert_dispatch_event_fields
        CHECK (
            (message_type = 'ALERT_EVENT' AND event_state IS NOT NULL AND project_id IS NOT NULL AND group_id IS NOT NULL)
            OR
            (message_type = 'CONFIG_APPLY' AND event_state IS NULL)
        )
);

CREATE INDEX IF NOT EXISTS idx_alert_dispatch_queue_claim
    ON alert_dispatch_queue (message_type, state, next_attempt_at, created_at);

CREATE INDEX IF NOT EXISTS idx_alert_dispatch_queue_group
    ON alert_dispatch_queue (project_id, group_id, message_type, created_at DESC)
    WHERE group_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_alert_dispatch_queue_state_done
    ON alert_dispatch_queue (state, done_at);

-- END 016_alert_dispatch_queue.up.sql

-- ---------------------------------------------------------------------
-- BEGIN 017_alert_dedup_rules.up.sql
-- ---------------------------------------------------------------------
-- Alert deduplication rules per project.
-- Default behavior remains project-global if no explicit rule matches.

CREATE TABLE IF NOT EXISTS alert_dedup_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    alert_type TEXT NOT NULL,
    dedup_scope TEXT NOT NULL CHECK (dedup_scope IN ('GLOBAL', 'PRODUCT', 'SCOPE', 'TEST')),
    product_id UUID NULL REFERENCES products(id) ON DELETE CASCADE,
    scope_id UUID NULL REFERENCES scopes(id) ON DELETE CASCADE,
    test_id UUID NULL REFERENCES tests(id) ON DELETE CASCADE,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_alert_dedup_rules_scope_target
        CHECK (
            (dedup_scope = 'GLOBAL' AND product_id IS NULL AND scope_id IS NULL AND test_id IS NULL)
            OR
            (dedup_scope = 'PRODUCT' AND product_id IS NOT NULL AND scope_id IS NULL AND test_id IS NULL)
            OR
            (dedup_scope = 'SCOPE' AND product_id IS NULL AND scope_id IS NOT NULL AND test_id IS NULL)
            OR
            (dedup_scope = 'TEST' AND product_id IS NULL AND scope_id IS NULL AND test_id IS NOT NULL)
        )
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_alert_dedup_rules_identity
    ON alert_dedup_rules (
        project_id,
        alert_type,
        dedup_scope,
        COALESCE(product_id, '00000000-0000-0000-0000-000000000000'::uuid),
        COALESCE(scope_id, '00000000-0000-0000-0000-000000000000'::uuid),
        COALESCE(test_id, '00000000-0000-0000-0000-000000000000'::uuid)
    );

CREATE INDEX IF NOT EXISTS idx_alert_dedup_rules_lookup
    ON alert_dedup_rules (project_id, alert_type, dedup_scope, enabled);

-- END 017_alert_dedup_rules.up.sql

-- ---------------------------------------------------------------------
-- BEGIN 018_test_revision_finding_diffs.up.sql
-- ---------------------------------------------------------------------
-- SBOM reimport: async revision delta queue + persisted diff rows + revision change summary.

CREATE TABLE IF NOT EXISTS test_revision_finding_diff_queue (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    test_id UUID NOT NULL REFERENCES tests(id) ON DELETE CASCADE,
    from_revision_id UUID REFERENCES test_revisions(id) ON DELETE SET NULL,
    to_revision_id UUID NOT NULL UNIQUE REFERENCES test_revisions(id) ON DELETE CASCADE,
    status TEXT NOT NULL CHECK (status IN ('PENDING', 'PROCESSING', 'COMPLETED', 'FAILED')),
    reason TEXT NOT NULL CHECK (reason IN ('INGEST', 'BACKFILL', 'MANUAL')),
    attempts INT NOT NULL DEFAULT 0,
    last_error TEXT,
    locked_at TIMESTAMPTZ,
    locked_by TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_test_revision_finding_diff_queue_status
    ON test_revision_finding_diff_queue(status, updated_at ASC);

CREATE INDEX IF NOT EXISTS idx_test_revision_finding_diff_queue_test
    ON test_revision_finding_diff_queue(test_id, created_at DESC);

CREATE TABLE IF NOT EXISTS test_revision_change_summary (
    to_revision_id UUID PRIMARY KEY REFERENCES test_revisions(id) ON DELETE CASCADE,
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    test_id UUID NOT NULL REFERENCES tests(id) ON DELETE CASCADE,
    from_revision_id UUID REFERENCES test_revisions(id) ON DELETE SET NULL,
    added_count INT NOT NULL DEFAULT 0,
    removed_count INT NOT NULL DEFAULT 0,
    unchanged_count INT NOT NULL DEFAULT 0,
    reappeared_count INT NOT NULL DEFAULT 0,
    status TEXT NOT NULL CHECK (status IN ('PENDING', 'PROCESSING', 'COMPLETED', 'FAILED')),
    computed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_test_revision_change_summary_test
    ON test_revision_change_summary(test_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_test_revision_change_summary_project
    ON test_revision_change_summary(project_id, created_at DESC);

CREATE TABLE IF NOT EXISTS test_revision_finding_diffs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    test_id UUID NOT NULL REFERENCES tests(id) ON DELETE CASCADE,
    from_revision_id UUID REFERENCES test_revisions(id) ON DELETE SET NULL,
    to_revision_id UUID NOT NULL REFERENCES test_revisions(id) ON DELETE CASCADE,
    finding_type TEXT NOT NULL CHECK (finding_type IN ('MALWARE')),
    diff_type TEXT NOT NULL CHECK (diff_type IN ('ADDED', 'REMOVED', 'UNCHANGED', 'REAPPEARED')),
    component_purl TEXT NOT NULL,
    malware_purl TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_test_revision_finding_diffs_identity
    ON test_revision_finding_diffs(to_revision_id, finding_type, component_purl, malware_purl);

CREATE INDEX IF NOT EXISTS idx_test_revision_finding_diffs_test_revision_type
    ON test_revision_finding_diffs(test_id, to_revision_id, diff_type, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_test_revision_finding_diffs_project_revision
    ON test_revision_finding_diffs(project_id, to_revision_id, created_at DESC);

-- END 018_test_revision_finding_diffs.up.sql

-- ---------------------------------------------------------------------
-- BEGIN 019_reimport_system_actor_password_hash_hardening.up.sql
-- ---------------------------------------------------------------------
-- Ensure legacy system actor rows never keep a plaintext-like value in password_hash.
-- Runtime store bootstrap will replace empty/invalid hashes with fresh argon2id hash.
UPDATE users
SET password_hash = '',
    updated_at = NOW()
WHERE LOWER(email) = LOWER('system@ctwall.local')
  AND (password_hash IS NULL OR password_hash NOT LIKE '$argon2id$%');

-- END 019_reimport_system_actor_password_hash_hardening.up.sql

-- ---------------------------------------------------------------------
-- BEGIN 020_component_malware_findings_triage_fixed_status.up.sql
-- ---------------------------------------------------------------------
-- Replace legacy CLOSED triage status with FIXED for malware findings.
-- Alert group lifecycle still uses OPEN/ACKNOWLEDGED/CLOSED independently.

ALTER TABLE component_malware_findings_triage
    DROP CONSTRAINT IF EXISTS component_malware_findings_triage_status_check;

ALTER TABLE component_malware_findings_triage
    DROP CONSTRAINT IF EXISTS chk_component_malware_findings_triage_status;

UPDATE component_malware_findings_triage
SET status = 'FIXED'
WHERE status = 'CLOSED';

ALTER TABLE component_malware_findings_triage
    ADD CONSTRAINT chk_component_malware_findings_triage_status
    CHECK (status IN ('OPEN', 'RISK_ACCEPTED', 'FALSE_POSITIVE', 'FIXED'));

-- END 020_component_malware_findings_triage_fixed_status.up.sql

-- ---------------------------------------------------------------------
-- BEGIN 021_alertmanager_all_receivers_project_scope.up.sql
-- ---------------------------------------------------------------------
-- Extend connector support to all Alertmanager v0.28.1 receiver types used by CTWall.
-- Switch connector config model to include explicit PROJECT scope.
-- Forward-compatibility note:
-- keep ALERTMANAGER_EXTERNAL allowed here as well, because some environments can
-- already contain this connector type before migration 031 is applied.

ALTER TABLE connector_configs
    ADD COLUMN IF NOT EXISTS config_schema_version INTEGER NOT NULL DEFAULT 1;

ALTER TABLE connector_configs
    DROP CONSTRAINT IF EXISTS connector_configs_connector_type_check;
ALTER TABLE connector_configs
    ADD CONSTRAINT connector_configs_connector_type_check
        CHECK (connector_type IN (
            'DISCORD',
            'SMTP',
            'MSTEAMSV2',
            'JIRA',
            'OPSGENIE',
            'PAGERDUTY',
            'PUSHOVER',
            'ROCKETCHAT',
            'SLACK',
            'SNS',
            'TELEGRAM',
            'VICTOROPS',
            'WEBEX',
            'WEBHOOK',
            'WECHAT',
            'ALERTMANAGER_EXTERNAL'
        ));

ALTER TABLE connector_configs
    DROP CONSTRAINT IF EXISTS connector_configs_scope_type_check;
ALTER TABLE connector_configs
    ADD CONSTRAINT connector_configs_scope_type_check
        CHECK (scope_type IN ('GLOBAL', 'PROJECT', 'PRODUCT', 'SCOPE', 'TEST'));

ALTER TABLE alert_connector_settings
    DROP CONSTRAINT IF EXISTS alert_connector_settings_connector_type_check;
ALTER TABLE alert_connector_settings
    ADD CONSTRAINT alert_connector_settings_connector_type_check
        CHECK (connector_type IN (
            'DISCORD',
            'SMTP',
            'MSTEAMSV2',
            'JIRA',
            'OPSGENIE',
            'PAGERDUTY',
            'PUSHOVER',
            'ROCKETCHAT',
            'SLACK',
            'SNS',
            'TELEGRAM',
            'VICTOROPS',
            'WEBEX',
            'WEBHOOK',
            'WECHAT',
            'ALERTMANAGER_EXTERNAL'
        ));

ALTER TABLE alert_routes
    DROP CONSTRAINT IF EXISTS alert_routes_connector_type_check;
ALTER TABLE alert_routes
    ADD CONSTRAINT alert_routes_connector_type_check
        CHECK (connector_type IN (
            'DISCORD',
            'SMTP',
            'MSTEAMSV2',
            'JIRA',
            'OPSGENIE',
            'PAGERDUTY',
            'PUSHOVER',
            'ROCKETCHAT',
            'SLACK',
            'SNS',
            'TELEGRAM',
            'VICTOROPS',
            'WEBEX',
            'WEBHOOK',
            'WECHAT',
            'ALERTMANAGER_EXTERNAL'
        ));

-- END 021_alertmanager_all_receivers_project_scope.up.sql

-- ---------------------------------------------------------------------
-- BEGIN 022_jira_native_dispatch_foundation.up.sql
-- ---------------------------------------------------------------------
-- Native Jira dispatch foundation:
-- - per-entity Jira settings (product/scope/test)
-- - Jira issue correlation mapping (idempotency + ownership)
-- - Jira delivery attempts history (observability)

CREATE TABLE IF NOT EXISTS jira_entity_settings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    config_level TEXT NOT NULL CHECK (config_level IN ('PRODUCT', 'SCOPE', 'TEST')),
    config_target_id UUID NOT NULL,
    is_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    jira_project_key TEXT NOT NULL DEFAULT '',
    issue_type TEXT NOT NULL DEFAULT '',
    resolve_transition_name TEXT NULL,
    labels JSONB NOT NULL DEFAULT '[]'::jsonb,
    components JSONB NOT NULL DEFAULT '[]'::jsonb,
    severity_to_priority_mapping JSONB NOT NULL DEFAULT '{}'::jsonb,
    ticket_summary_template TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_jira_entity_settings_labels_array CHECK (jsonb_typeof(labels) = 'array'),
    CONSTRAINT chk_jira_entity_settings_components_array CHECK (jsonb_typeof(components) = 'array'),
    CONSTRAINT chk_jira_entity_settings_priority_object CHECK (jsonb_typeof(severity_to_priority_mapping) = 'object'),
    UNIQUE (project_id, config_level, config_target_id)
);

CREATE INDEX IF NOT EXISTS idx_jira_entity_settings_project_level
    ON jira_entity_settings (project_id, config_level, config_target_id);

CREATE TABLE IF NOT EXISTS jira_issue_mappings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    config_level TEXT NOT NULL CHECK (config_level IN ('PRODUCT', 'SCOPE', 'TEST')),
    config_target_id UUID NOT NULL,
    alert_group_id UUID NOT NULL REFERENCES alert_groups(id) ON DELETE CASCADE,
    dedup_rule_id UUID NULL REFERENCES alert_dedup_rules(id) ON DELETE SET NULL,
    jira_issue_key TEXT NULL,
    jira_issue_id TEXT NULL,
    status TEXT NOT NULL CHECK (status IN ('OPEN', 'CLOSED', 'DEAD', 'SUPERSEDED')),
    last_synced_at TIMESTAMPTZ NULL,
    last_error TEXT NULL,
    closed_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Backward/partial-upgrade compatibility:
-- if legacy runs already inserted duplicated identity rows, keep the newest row
-- and remove older duplicates before adding unique identity index.
WITH ranked AS (
    SELECT
        id,
        ROW_NUMBER() OVER (
            PARTITION BY
                project_id,
                config_level,
                config_target_id,
                alert_group_id,
                COALESCE(dedup_rule_id, '00000000-0000-0000-0000-000000000000'::uuid)
            ORDER BY updated_at DESC, created_at DESC, id DESC
        ) AS rn
    FROM jira_issue_mappings
)
DELETE FROM jira_issue_mappings m
USING ranked r
WHERE m.id = r.id
  AND r.rn > 1;

CREATE UNIQUE INDEX IF NOT EXISTS ux_jira_issue_mappings_identity
    ON jira_issue_mappings (
        project_id,
        config_level,
        config_target_id,
        alert_group_id,
        COALESCE(dedup_rule_id, '00000000-0000-0000-0000-000000000000'::uuid)
    );

CREATE INDEX IF NOT EXISTS idx_jira_issue_mappings_group_lookup
    ON jira_issue_mappings (project_id, alert_group_id, status, updated_at DESC);

CREATE INDEX IF NOT EXISTS idx_jira_issue_mappings_owner_lookup
    ON jira_issue_mappings (project_id, config_level, config_target_id, status, updated_at DESC);

CREATE TABLE IF NOT EXISTS jira_delivery_attempts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    queue_job_id UUID NULL REFERENCES alert_dispatch_queue(id) ON DELETE SET NULL,
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    config_level TEXT NULL CHECK (config_level IN ('PRODUCT', 'SCOPE', 'TEST')),
    config_target_id UUID NULL,
    alert_group_id UUID NULL REFERENCES alert_groups(id) ON DELETE SET NULL,
    dedup_rule_id UUID NULL REFERENCES alert_dedup_rules(id) ON DELETE SET NULL,
    jira_issue_mapping_id UUID NULL REFERENCES jira_issue_mappings(id) ON DELETE SET NULL,
    attempt_no INT NOT NULL DEFAULT 1,
    action TEXT NOT NULL CHECK (action IN ('CREATE', 'UPDATE', 'RESOLVE', 'SUPERSEDE_CLOSE', 'NOOP')),
    outcome TEXT NOT NULL CHECK (outcome IN ('SUCCESS', 'RETRY', 'DEAD', 'SKIPPED', 'FAILED')),
    http_status INT NULL,
    error_code TEXT NULL,
    error_message TEXT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_jira_delivery_attempts_project_created
    ON jira_delivery_attempts (project_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_jira_delivery_attempts_mapping
    ON jira_delivery_attempts (jira_issue_mapping_id, created_at DESC)
    WHERE jira_issue_mapping_id IS NOT NULL;

-- END 022_jira_native_dispatch_foundation.up.sql

-- ---------------------------------------------------------------------
-- BEGIN 023_jira_dedup_threshold_and_metadata_cache.up.sql
-- ---------------------------------------------------------------------
-- Jira native phase 3:
-- - connector Jira dedup-rule binding
-- - dedup min severity threshold
-- - Jira metadata cache (DB-backed)

ALTER TABLE alert_dedup_rules
    ADD COLUMN IF NOT EXISTS min_severity TEXT NOT NULL DEFAULT 'INFO';

UPDATE alert_dedup_rules
SET min_severity = 'WARNING'
WHERE min_severity = 'WARN';

ALTER TABLE alert_dedup_rules
    DROP CONSTRAINT IF EXISTS alert_dedup_rules_min_severity_check;
ALTER TABLE alert_dedup_rules
    ADD CONSTRAINT alert_dedup_rules_min_severity_check
        CHECK (min_severity IN ('INFO', 'WARNING', 'ERROR'));

ALTER TABLE alert_connector_settings
    ADD COLUMN IF NOT EXISTS jira_dedup_rule_id UUID NULL
        REFERENCES alert_dedup_rules(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_alert_connector_settings_jira_dedup_rule
    ON alert_connector_settings (project_id, connector_type, jira_dedup_rule_id)
    WHERE connector_type = 'JIRA';

CREATE TABLE IF NOT EXISTS jira_metadata_cache (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    base_url_hash TEXT NOT NULL,
    metadata_type TEXT NOT NULL CHECK (metadata_type IN ('PROJECTS', 'ISSUE_TYPES', 'COMPONENTS', 'PRIORITIES', 'TRANSITIONS')),
    metadata_scope_key TEXT NOT NULL DEFAULT '',
    payload_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    fetched_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (project_id, base_url_hash, metadata_type, metadata_scope_key)
);

CREATE INDEX IF NOT EXISTS idx_jira_metadata_cache_lookup
    ON jira_metadata_cache (project_id, base_url_hash, metadata_type, metadata_scope_key);

-- END 023_jira_dedup_threshold_and_metadata_cache.up.sql

-- ---------------------------------------------------------------------
-- BEGIN 024_users_nickname_required.up.sql
-- ---------------------------------------------------------------------
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS nickname TEXT;

UPDATE users
SET nickname = CASE
    WHEN NULLIF(BTRIM(full_name), '') IS NOT NULL THEN BTRIM(full_name)
    WHEN NULLIF(BTRIM(split_part(email, '@', 1)), '') IS NOT NULL THEN BTRIM(split_part(email, '@', 1))
    ELSE 'user-' || substring(id::text, 1, 8)
END
WHERE nickname IS NULL OR NULLIF(BTRIM(nickname), '') IS NULL;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'chk_users_nickname'
    ) THEN
        ALTER TABLE users
            ADD CONSTRAINT chk_users_nickname
            CHECK (char_length(BTRIM(nickname)) BETWEEN 1 AND 64);
    END IF;
END $$;

ALTER TABLE users
    ALTER COLUMN nickname SET NOT NULL;

ALTER TABLE users
    ALTER COLUMN nickname SET DEFAULT 'user';

-- END 024_users_nickname_required.up.sql

-- ---------------------------------------------------------------------
-- BEGIN 025_component_analysis_schedule_default_6h.up.sql
-- ---------------------------------------------------------------------
-- Normalize component analysis scheduler default interval to 6h.
-- Keep explicit custom intervals untouched; only move legacy 24h default rows.

ALTER TABLE component_analysis_malware_schedule
    ALTER COLUMN interval_seconds SET DEFAULT 21600;

UPDATE component_analysis_malware_schedule
SET interval_seconds = 21600,
    updated_at = NOW()
WHERE id = 1
  AND interval_seconds = 86400;

-- END 025_component_analysis_schedule_default_6h.up.sql

-- ---------------------------------------------------------------------
-- BEGIN 026_jira_issue_fields_and_open_transition.up.sql
-- ---------------------------------------------------------------------
-- Jira settings enhancements:
-- - optional open transition name per entity settings
-- - dynamic Jira required issue fields payload (JSON object)
-- - metadata cache type for ISSUE_FIELDS

ALTER TABLE jira_entity_settings
    ADD COLUMN IF NOT EXISTS open_transition_name TEXT NULL;

ALTER TABLE jira_entity_settings
    ADD COLUMN IF NOT EXISTS issue_fields_json JSONB NOT NULL DEFAULT '{}'::jsonb;

ALTER TABLE jira_entity_settings
    DROP CONSTRAINT IF EXISTS chk_jira_entity_settings_issue_fields_object;
ALTER TABLE jira_entity_settings
    ADD CONSTRAINT chk_jira_entity_settings_issue_fields_object
        CHECK (jsonb_typeof(issue_fields_json) = 'object');

ALTER TABLE jira_metadata_cache
    DROP CONSTRAINT IF EXISTS jira_metadata_cache_metadata_type_check;
ALTER TABLE jira_metadata_cache
    ADD CONSTRAINT jira_metadata_cache_metadata_type_check
        CHECK (metadata_type IN ('PROJECTS', 'ISSUE_TYPES', 'COMPONENTS', 'PRIORITIES', 'ISSUES', 'TRANSITIONS', 'ISSUE_FIELDS'));

-- END 026_jira_issue_fields_and_open_transition.up.sql

-- ---------------------------------------------------------------------
-- BEGIN 027_remove_seed_results_path.up.sql
-- ---------------------------------------------------------------------
-- Remove legacy seed-only results path from OSV API test source scanners.
-- This path is not part of production OSV integration and should not appear in runtime config/UI.

UPDATE source_scanners AS s
SET results_path = NULL
FROM scan_malware_source AS src
WHERE s.source_id = src.id
  AND src.source_type = 'OSV_API'
  AND src.name = 'Seed OSV Source'
  AND s.results_path = '/seed/results';

-- END 027_remove_seed_results_path.up.sql

-- ---------------------------------------------------------------------
-- BEGIN 028_remove_seed_osv_source.up.sql
-- ---------------------------------------------------------------------
-- Remove legacy seed-only OSV API source from runtime data model.
-- Seed source was test scaffolding and should not be exposed in GUI/backend sources list.

DELETE FROM source_malware_input_component_results
WHERE source_id IN (
    SELECT id
    FROM scan_malware_source
    WHERE source_type = 'OSV_API'
      AND name = 'Seed OSV Source'
);

DELETE FROM source_malware_input_queue
WHERE scanner_id IN (
    SELECT sc.id
    FROM source_scanners sc
    JOIN scan_malware_source src ON src.id = sc.source_id
    WHERE src.source_type = 'OSV_API'
      AND src.name = 'Seed OSV Source'
);

DELETE FROM source_scanners
WHERE source_id IN (
    SELECT id
    FROM scan_malware_source
    WHERE source_type = 'OSV_API'
      AND name = 'Seed OSV Source'
);

DELETE FROM scan_malware_source
WHERE source_type = 'OSV_API'
  AND name = 'Seed OSV Source';

-- END 028_remove_seed_osv_source.up.sql

-- ---------------------------------------------------------------------
-- BEGIN 029_jira_metadata_cache_add_issues_type.up.sql
-- ---------------------------------------------------------------------
ALTER TABLE jira_metadata_cache
    DROP CONSTRAINT IF EXISTS jira_metadata_cache_metadata_type_check;

ALTER TABLE jira_metadata_cache
    ADD CONSTRAINT jira_metadata_cache_metadata_type_check
        CHECK (metadata_type IN ('PROJECTS', 'ISSUE_TYPES', 'COMPONENTS', 'PRIORITIES', 'ISSUES', 'TRANSITIONS', 'ISSUE_FIELDS'));

-- END 029_jira_metadata_cache_add_issues_type.up.sql

-- ---------------------------------------------------------------------
-- BEGIN 030_jira_component_lifecycle_and_reopen_action.up.sql
-- ---------------------------------------------------------------------
-- Jira auto lifecycle per component:
-- - correlate mappings by (project_id, test_id, component_purl)
-- - keep effective owner metadata for observability
-- - allow REOPEN delivery action

ALTER TABLE jira_issue_mappings
    ADD COLUMN IF NOT EXISTS test_id UUID NULL REFERENCES tests(id) ON DELETE CASCADE;

ALTER TABLE jira_issue_mappings
    ADD COLUMN IF NOT EXISTS component_purl TEXT NULL;

ALTER TABLE jira_issue_mappings
    ADD COLUMN IF NOT EXISTS effective_config_level TEXT NULL;

ALTER TABLE jira_issue_mappings
    ADD COLUMN IF NOT EXISTS effective_config_target_id UUID NULL;

ALTER TABLE jira_issue_mappings
    DROP CONSTRAINT IF EXISTS jira_issue_mappings_effective_config_level_check;
ALTER TABLE jira_issue_mappings
    ADD CONSTRAINT jira_issue_mappings_effective_config_level_check
        CHECK (
            effective_config_level IS NULL
            OR effective_config_level IN ('PRODUCT', 'SCOPE', 'TEST')
        );

CREATE INDEX IF NOT EXISTS idx_jira_issue_mappings_component_lookup
    ON jira_issue_mappings (project_id, test_id, component_purl, updated_at DESC)
    WHERE test_id IS NOT NULL AND component_purl IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS ux_jira_issue_mappings_open_component
    ON jira_issue_mappings (project_id, test_id, component_purl)
    WHERE status = 'OPEN' AND test_id IS NOT NULL AND component_purl IS NOT NULL;

ALTER TABLE jira_delivery_attempts
    DROP CONSTRAINT IF EXISTS jira_delivery_attempts_action_check;
ALTER TABLE jira_delivery_attempts
    ADD CONSTRAINT jira_delivery_attempts_action_check
        CHECK (action IN ('CREATE', 'UPDATE', 'REOPEN', 'RESOLVE', 'SUPERSEDE_CLOSE', 'NOOP'));

-- END 030_jira_component_lifecycle_and_reopen_action.up.sql

-- ---------------------------------------------------------------------
-- BEGIN 031_alertmanager_external_connector_type.up.sql
-- ---------------------------------------------------------------------
-- Add external Alertmanager connector type as project-level connector.

ALTER TABLE connector_configs
    DROP CONSTRAINT IF EXISTS connector_configs_connector_type_check;
ALTER TABLE connector_configs
    ADD CONSTRAINT connector_configs_connector_type_check
        CHECK (connector_type IN (
            'DISCORD',
            'SMTP',
            'MSTEAMSV2',
            'JIRA',
            'ALERTMANAGER_EXTERNAL',
            'OPSGENIE',
            'PAGERDUTY',
            'PUSHOVER',
            'ROCKETCHAT',
            'SLACK',
            'SNS',
            'TELEGRAM',
            'VICTOROPS',
            'WEBEX',
            'WEBHOOK',
            'WECHAT'
        ));

ALTER TABLE alert_connector_settings
    DROP CONSTRAINT IF EXISTS alert_connector_settings_connector_type_check;
ALTER TABLE alert_connector_settings
    ADD CONSTRAINT alert_connector_settings_connector_type_check
        CHECK (connector_type IN (
            'DISCORD',
            'SMTP',
            'MSTEAMSV2',
            'JIRA',
            'ALERTMANAGER_EXTERNAL',
            'OPSGENIE',
            'PAGERDUTY',
            'PUSHOVER',
            'ROCKETCHAT',
            'SLACK',
            'SNS',
            'TELEGRAM',
            'VICTOROPS',
            'WEBEX',
            'WEBHOOK',
            'WECHAT'
        ));

ALTER TABLE alert_routes
    DROP CONSTRAINT IF EXISTS alert_routes_connector_type_check;
ALTER TABLE alert_routes
    ADD CONSTRAINT alert_routes_connector_type_check
        CHECK (connector_type IN (
            'DISCORD',
            'SMTP',
            'MSTEAMSV2',
            'JIRA',
            'ALERTMANAGER_EXTERNAL',
            'OPSGENIE',
            'PAGERDUTY',
            'PUSHOVER',
            'ROCKETCHAT',
            'SLACK',
            'SNS',
            'TELEGRAM',
            'VICTOROPS',
            'WEBEX',
            'WEBHOOK',
            'WECHAT'
        ));

-- END 031_alertmanager_external_connector_type.up.sql

-- ---------------------------------------------------------------------
-- BEGIN 032_normalize_malware_alert_category_type.up.sql
-- ---------------------------------------------------------------------
-- Normalize legacy malware alert typing used by old seed data.
-- Target canonical values:
--   category = 'malware'
--   type     = 'malware.detected'

-- 1) Normalize alert dedup rules from legacy 'MALWARE' -> 'malware.detected'.
--    Resolve potential uniqueness collisions by removing legacy duplicates first.
DELETE FROM alert_dedup_rules legacy
USING alert_dedup_rules canonical
WHERE legacy.alert_type = 'MALWARE'
  AND canonical.alert_type = 'malware.detected'
  AND legacy.project_id = canonical.project_id
  AND legacy.dedup_scope = canonical.dedup_scope
  AND COALESCE(legacy.product_id, '00000000-0000-0000-0000-000000000000'::uuid)
      = COALESCE(canonical.product_id, '00000000-0000-0000-0000-000000000000'::uuid)
  AND COALESCE(legacy.scope_id, '00000000-0000-0000-0000-000000000000'::uuid)
      = COALESCE(canonical.scope_id, '00000000-0000-0000-0000-000000000000'::uuid)
  AND COALESCE(legacy.test_id, '00000000-0000-0000-0000-000000000000'::uuid)
      = COALESCE(canonical.test_id, '00000000-0000-0000-0000-000000000000'::uuid);

UPDATE alert_dedup_rules
SET alert_type = 'malware.detected',
    updated_at = NOW()
WHERE alert_type = 'MALWARE';

-- 2) Normalize alert groups from legacy type/category.
UPDATE alert_groups
SET category = 'malware',
    type = 'malware.detected',
    updated_at = NOW()
WHERE type = 'MALWARE'
   OR (category = 'security' AND title = 'Seed malware alert group');

-- END 032_normalize_malware_alert_category_type.up.sql

-- ---------------------------------------------------------------------
-- BEGIN 033_jira_mappings_legacy_identity_partial_unique.up.sql
-- ---------------------------------------------------------------------
-- Jira component lifecycle allows multiple mappings per alert group/config identity.
-- Keep legacy uniqueness only for rows without component context.

DROP INDEX IF EXISTS ux_jira_issue_mappings_identity;

CREATE UNIQUE INDEX IF NOT EXISTS ux_jira_issue_mappings_legacy_identity
    ON jira_issue_mappings (
        project_id,
        config_level,
        config_target_id,
        alert_group_id,
        COALESCE(dedup_rule_id, '00000000-0000-0000-0000-000000000000'::uuid)
    )
    WHERE test_id IS NULL
      AND (component_purl IS NULL OR BTRIM(component_purl) = '');

-- END 033_jira_mappings_legacy_identity_partial_unique.up.sql

-- ---------------------------------------------------------------------
-- BEGIN 034_drop_legacy_integrations_table.up.sql
-- ---------------------------------------------------------------------
-- Legacy integrations table is no longer used.
-- Connector configuration is stored in connector_configs.
DROP TABLE IF EXISTS integrations;

-- END 034_drop_legacy_integrations_table.up.sql

-- ---------------------------------------------------------------------
-- BEGIN 035_jira_entity_settings_retry_policy.up.sql
-- ---------------------------------------------------------------------
-- Jira per-entity retry policy for native dispatch retries.
ALTER TABLE jira_entity_settings
    ADD COLUMN IF NOT EXISTS delivery_retry_attempts INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS delivery_retry_backoff_seconds INTEGER NOT NULL DEFAULT 10;

ALTER TABLE jira_entity_settings
    DROP CONSTRAINT IF EXISTS chk_jira_entity_settings_delivery_retry_attempts_range;
ALTER TABLE jira_entity_settings
    ADD CONSTRAINT chk_jira_entity_settings_delivery_retry_attempts_range
        CHECK (delivery_retry_attempts >= 0 AND delivery_retry_attempts <= 20);

ALTER TABLE jira_entity_settings
    DROP CONSTRAINT IF EXISTS chk_jira_entity_settings_delivery_retry_backoff_range;
ALTER TABLE jira_entity_settings
    ADD CONSTRAINT chk_jira_entity_settings_delivery_retry_backoff_range
        CHECK (delivery_retry_backoff_seconds >= 1 AND delivery_retry_backoff_seconds <= 3600);

-- END 035_jira_entity_settings_retry_policy.up.sql

-- ---------------------------------------------------------------------
-- BEGIN 036_components_json_defaults_and_backfill.up.sql
-- ---------------------------------------------------------------------
-- Ensure components JSON fields are never NULL for API scans and downstream processing.
-- Backfill legacy NULL rows.
UPDATE components
SET licenses = '[]'::jsonb
WHERE licenses IS NULL;

UPDATE components
SET properties = '{}'::jsonb
WHERE properties IS NULL;

-- Set defaults for future inserts.
ALTER TABLE components
    ALTER COLUMN licenses SET DEFAULT '[]'::jsonb,
    ALTER COLUMN properties SET DEFAULT '{}'::jsonb;

-- END 036_components_json_defaults_and_backfill.up.sql
