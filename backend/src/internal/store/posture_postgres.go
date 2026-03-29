package store

import (
	"context"
	"database/sql"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/google/uuid"
)

func normalizeSecurityPostureOverviewQuery(q *SecurityPostureOverviewQuery) error {
	if q == nil {
		return ErrInvalidPayload
	}
	if q.ProjectID == uuid.Nil {
		return ErrInvalidPayload
	}
	if q.Since.IsZero() {
		return ErrInvalidPayload
	}
	if q.TopN < 0 {
		q.TopN = DefaultPostureTopN
	}
	q.Bucket = normalizePostureBucket(q.Bucket)
	if q.Bucket == "" {
		return ErrInvalidPayload
	}
	return nil
}

func normalizePostureBucket(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", DefaultPostureBucket:
		return DefaultPostureBucket
	case "week":
		return "week"
	default:
		return ""
	}
}

func postureBucketTruncExpr(bucket string) string {
	if bucket == "week" {
		return "week"
	}
	return "day"
}

// GetSecurityPostureOverview returns project-scoped technical posture aggregates.
func (s *PostgresStore) GetSecurityPostureOverview(q SecurityPostureOverviewQuery) (*SecurityPostureOverview, error) {
	if err := normalizeSecurityPostureOverviewQuery(&q); err != nil {
		return nil, err
	}

	ctx, cancel := s.ctx()
	defer cancel()

	now := time.Now().UTC()
	overview := &SecurityPostureOverview{
		GeneratedAt: now,
		RangeStart:  q.Since.UTC(),
		RangeEnd:    now,
		ProjectID:   q.ProjectID,
		TopN:        q.TopN,
		Bucket:      q.Bucket,
		Score: SecurityPostureScore{
			Value: 100,
			Label: "",
		},
		KPIs: SecurityPostureKPIs{
			OsvSyncStatus: "UNKNOWN",
		},
	}

	if err := s.loadSecurityPostureKpis(ctx, q, overview); err != nil {
		return nil, err
	}
	if err := s.loadSecurityPostureIngestTrend(ctx, q, overview); err != nil {
		return nil, err
	}
	if err := s.loadSecurityPostureIngestFailureTop(ctx, q, overview); err != nil {
		return nil, err
	}
	if err := s.loadSecurityPostureOsvTrend(ctx, q, overview); err != nil {
		return nil, err
	}
	if err := s.loadSecurityPostureOsvTopErrorStages(ctx, q, overview); err != nil {
		return nil, err
	}
	if err := s.loadSecurityPostureInventory(ctx, q, overview); err != nil {
		return nil, err
	}
	if err := s.loadSecurityPostureRecentUploads(ctx, q, overview); err != nil {
		return nil, err
	}
	if err := s.loadSecurityPostureRecentFailures(ctx, q, overview); err != nil {
		return nil, err
	}

	return overview, nil
}

func (s *PostgresStore) loadSecurityPostureKpis(ctx context.Context, q SecurityPostureOverviewQuery, overview *SecurityPostureOverview) error {
	const query = `
WITH active_revisions AS (
  SELECT
    tr.id AS revision_id,
    t.id AS test_id,
    p.id AS product_id
  FROM test_revisions tr
  JOIN tests t ON t.id = tr.test_id
  JOIN scopes sc ON sc.id = t.scope_id
  JOIN products p ON p.id = sc.product_id
  WHERE tr.is_active = TRUE
    AND p.project_id = $1
),
project_products AS (
  SELECT p.id AS product_id
  FROM products p
  WHERE p.project_id = $1
),
active_components AS (
  SELECT
    ar.product_id,
    ar.test_id,
    c.purl,
    LOWER(COALESCE(NULLIF(TRIM(c.pkg_type), ''), 'unknown')) AS pkg_type
  FROM active_revisions ar
  JOIN components c ON c.revision_id = ar.revision_id
),
active_purls AS (
  SELECT DISTINCT purl FROM active_components
),
active_malware_components AS (
  SELECT DISTINCT
    ac.product_id,
    ac.test_id,
    f.component_purl
  FROM component_analysis_malware_findings f
  JOIN active_components ac ON ac.purl = f.component_purl
  JOIN source_malware_input_results r ON r.id = f.source_malware_input_result_id
  LEFT JOIN component_malware_findings_triage tri
    ON tri.project_id = $1
   AND tri.test_id = ac.test_id
   AND tri.component_purl = f.component_purl
   AND tri.malware_purl = f.malware_purl
  WHERE COALESCE(NULLIF(TRIM(r.verdict), ''), 'UNKNOWN') = 'MALWARE'
    AND tri.status = 'OPEN'
),
malware_products AS (
  SELECT DISTINCT amc.product_id
  FROM active_malware_components amc
),
verdict_components AS (
  SELECT
    CASE
      WHEN amc.component_purl IS NOT NULL THEN 'MALWARE'
      WHEN cs.component_purl IS NOT NULL THEN 'CLEAN'
      ELSE 'UNKNOWN'
    END AS verdict
  FROM active_components ac
  LEFT JOIN active_malware_components amc
    ON amc.test_id = ac.test_id
   AND amc.component_purl = ac.purl
  LEFT JOIN component_analysis_malware_component_state cs ON cs.component_purl = ac.purl
),
ingest_scoped AS (
  SELECT
    iq.status,
    iq.completed_at,
    COALESCE(iq.completed_at, iq.updated_at, iq.created_at) AS activity_at
  FROM ingest_queue iq
  LEFT JOIN tests t ON t.id = iq.test_id
  LEFT JOIN scopes sc ON sc.id = COALESCE(iq.scope_id, t.scope_id)
  JOIN products p ON p.id = COALESCE(iq.product_id, sc.product_id)
  WHERE p.project_id = $1
),
inventory_top AS (
  SELECT pkg_type
  FROM active_components
  GROUP BY pkg_type
  ORDER BY COUNT(*) DESC, pkg_type ASC
  LIMIT 1
),
osv_last AS (
  SELECT action, created_at
  FROM audit_logs
  WHERE entity_type = 'malware_source'
    AND action IN (
      'MALWARE_OSV_SYNC_START',
      'MALWARE_OSV_SYNC_PROGRESS',
      'MALWARE_OSV_SYNC_COMPLETE',
      'MALWARE_OSV_SYNC_FAILED'
    )
  ORDER BY created_at DESC
  LIMIT 1
)
SELECT
  COALESCE((SELECT COUNT(*)::int FROM project_products), 0) AS total_products_count,
  COALESCE((SELECT COUNT(*)::int FROM malware_products), 0) AS malware_products_count,
  COALESCE((SELECT COUNT(*)::int FROM verdict_components WHERE verdict NOT IN ('MALWARE', 'CLEAN')), 0) AS unknown_pending,
  COALESCE((SELECT COUNT(*)::int FROM verdict_components), 0) AS active_components_count,
  COALESCE((SELECT COUNT(*)::int FROM ingest_scoped WHERE status = 'FAILED' AND activity_at >= $2), 0) AS ingest_failures,
  COALESCE((SELECT COUNT(*)::int FROM ingest_scoped WHERE status = 'COMPLETED' AND activity_at >= $2), 0) AS ingest_completed,
  COALESCE((
    SELECT COUNT(*)::int
    FROM component_analysis_malware_queue q1
    JOIN active_purls ap ON ap.purl = q1.component_purl
    WHERE q1.status IN ('PENDING', 'PROCESSING')
  ), 0) AS queue_backlog,
  (SELECT pkg_type FROM inventory_top) AS inventory_top_type,
  (SELECT MAX(completed_at) FROM ingest_scoped WHERE status = 'COMPLETED' AND completed_at IS NOT NULL) AS last_analysis_at,
  (SELECT action FROM osv_last) AS osv_last_action,
  (SELECT created_at FROM osv_last) AS osv_last_sync_at,
  COALESCE((
    SELECT COUNT(*)::int
    FROM audit_logs
    WHERE entity_type = 'malware_source'
      AND action = 'MALWARE_OSV_SYNC_ERROR'
      AND created_at >= $2
  ), 0) AS osv_errors
`

	var (
		lastAnalysisAt  sql.NullTime
		lastOsvAt       sql.NullTime
		lastOsvAction   sql.NullString
		topType         sql.NullString
		totalProducts   int
		malwareProducts int
		unknownPending  int
		activeCount     int
		ingestFailures  int
		ingestDone      int
		queueBacklog    int
		osvErrors       int
	)
	if err := s.db.QueryRowContext(ctx, query, q.ProjectID, q.Since.UTC()).Scan(
		&totalProducts,
		&malwareProducts,
		&unknownPending,
		&activeCount,
		&ingestFailures,
		&ingestDone,
		&queueBacklog,
		&topType,
		&lastAnalysisAt,
		&lastOsvAction,
		&lastOsvAt,
		&osvErrors,
	); err != nil {
		return err
	}

	overview.KPIs.TotalProducts = totalProducts
	overview.KPIs.MalwareProducts = malwareProducts
	overview.KPIs.UnknownPending = unknownPending
	overview.KPIs.ActiveComponents = activeCount
	overview.KPIs.IngestFailures = ingestFailures
	overview.KPIs.IngestCompleted = ingestDone
	overview.KPIs.QueueBacklog = queueBacklog
	overview.KPIs.OsvErrors = osvErrors
	if topType.Valid {
		overview.KPIs.InventoryTopType = topType.String
	}
	if lastAnalysisAt.Valid {
		value := lastAnalysisAt.Time.UTC()
		overview.KPIs.LastAnalysisAt = &value
	}
	if lastOsvAt.Valid {
		value := lastOsvAt.Time.UTC()
		overview.KPIs.OsvLastSyncAt = &value
	}
	overview.KPIs.OsvSyncStatus = mapOsvSyncStatus(lastOsvAction.String)

	ingestTotal := ingestFailures + ingestDone
	if ingestTotal > 0 {
		overview.KPIs.IngestFailurePercent = (float64(ingestFailures) / float64(ingestTotal)) * 100
	}
	return nil
}

func mapOsvSyncStatus(lastAction string) string {
	switch strings.TrimSpace(lastAction) {
	case "MALWARE_OSV_SYNC_COMPLETE":
		return "OK"
	case "MALWARE_OSV_SYNC_FAILED":
		return "ERROR"
	case "MALWARE_OSV_SYNC_START", "MALWARE_OSV_SYNC_PROGRESS":
		return "RUNNING"
	default:
		return "UNKNOWN"
	}
}

func (s *PostgresStore) loadSecurityPostureIngestTrend(ctx context.Context, q SecurityPostureOverviewQuery, overview *SecurityPostureOverview) error {
	truncExpr := postureBucketTruncExpr(q.Bucket)
	query := fmt.Sprintf(`
SELECT
  date_trunc('%s', COALESCE(iq.completed_at, iq.updated_at, iq.created_at)) AS bucket_start,
  COUNT(*) FILTER (WHERE iq.status = 'COMPLETED')::int AS imports_count,
  COUNT(*) FILTER (WHERE iq.status = 'FAILED')::int AS failures_count
FROM ingest_queue iq
LEFT JOIN tests t ON t.id = iq.test_id
LEFT JOIN scopes sc ON sc.id = COALESCE(iq.scope_id, t.scope_id)
JOIN products p ON p.id = COALESCE(iq.product_id, sc.product_id)
WHERE p.project_id = $1
  AND COALESCE(iq.completed_at, iq.updated_at, iq.created_at) >= $2
GROUP BY 1
ORDER BY 1 ASC
`, truncExpr)

	rows, err := s.db.QueryContext(ctx, query, q.ProjectID, q.Since.UTC())
	if err != nil {
		return err
	}
	defer rows.Close()

	items := make([]SecurityPostureIngestBucket, 0)
	for rows.Next() {
		var item SecurityPostureIngestBucket
		if err := rows.Scan(&item.BucketStart, &item.Imports, &item.Failures); err != nil {
			return err
		}
		item.BucketStart = item.BucketStart.UTC()
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	overview.IngestTrend = items
	return nil
}

func (s *PostgresStore) loadSecurityPostureIngestFailureTop(ctx context.Context, q SecurityPostureOverviewQuery, overview *SecurityPostureOverview) error {
	limitClause := ""
	args := []any{q.ProjectID, q.Since.UTC()}
	if q.TopN > 0 {
		limitClause = "\nLIMIT $3"
		args = append(args, q.TopN)
	}
	query := fmt.Sprintf(`
SELECT
  LOWER(COALESCE(NULLIF(TRIM(iq.processing_stage), ''), 'unknown')) AS stage,
  COUNT(*)::int AS failures_count
FROM ingest_queue iq
LEFT JOIN tests t ON t.id = iq.test_id
LEFT JOIN scopes sc ON sc.id = COALESCE(iq.scope_id, t.scope_id)
JOIN products p ON p.id = COALESCE(iq.product_id, sc.product_id)
WHERE p.project_id = $1
  AND iq.status = 'FAILED'
  AND COALESCE(iq.completed_at, iq.updated_at, iq.created_at) >= $2
GROUP BY stage
ORDER BY failures_count DESC, stage ASC
%s
`, limitClause)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return err
	}
	defer rows.Close()

	items := make([]SecurityPostureTopItem, 0)
	for rows.Next() {
		var item SecurityPostureTopItem
		if err := rows.Scan(&item.Name, &item.Value); err != nil {
			return err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	overview.IngestFailureTop = items
	return nil
}

func (s *PostgresStore) loadSecurityPostureOsvTrend(ctx context.Context, q SecurityPostureOverviewQuery, overview *SecurityPostureOverview) error {
	truncExpr := postureBucketTruncExpr(q.Bucket)
	query := fmt.Sprintf(`
SELECT
  date_trunc('%s', created_at) AS bucket_start,
  COUNT(*)::int AS runs_count,
  COUNT(*) FILTER (WHERE action = 'MALWARE_OSV_SYNC_FAILED')::int AS failed_runs
FROM audit_logs
WHERE entity_type = 'malware_source'
  AND action IN ('MALWARE_OSV_SYNC_COMPLETE', 'MALWARE_OSV_SYNC_FAILED')
  AND created_at >= $1
GROUP BY 1
ORDER BY 1 ASC
`, truncExpr)

	rows, err := s.db.QueryContext(ctx, query, q.Since.UTC())
	if err != nil {
		return err
	}
	defer rows.Close()

	items := make([]SecurityPostureSyncBucket, 0)
	for rows.Next() {
		var item SecurityPostureSyncBucket
		if err := rows.Scan(&item.BucketStart, &item.Runs, &item.Failures); err != nil {
			return err
		}
		item.BucketStart = item.BucketStart.UTC()
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	overview.OsvSyncTrend = items
	return nil
}

func (s *PostgresStore) loadSecurityPostureOsvTopErrorStages(ctx context.Context, q SecurityPostureOverviewQuery, overview *SecurityPostureOverview) error {
	limitClause := ""
	args := []any{q.Since.UTC()}
	if q.TopN > 0 {
		limitClause = "\nLIMIT $2"
		args = append(args, q.TopN)
	}
	query := fmt.Sprintf(`
SELECT
  LOWER(COALESCE(NULLIF(TRIM(details->>'stage'), ''), 'unknown')) AS stage,
  COUNT(*)::int AS error_count
FROM audit_logs
WHERE entity_type = 'malware_source'
  AND action = 'MALWARE_OSV_SYNC_ERROR'
  AND created_at >= $1
GROUP BY stage
ORDER BY error_count DESC, stage ASC
%s
`, limitClause)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return err
	}
	defer rows.Close()

	items := make([]SecurityPostureTopItem, 0)
	for rows.Next() {
		var item SecurityPostureTopItem
		if err := rows.Scan(&item.Name, &item.Value); err != nil {
			return err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	overview.OsvTopErrorStages = items
	return nil
}

func (s *PostgresStore) loadSecurityPostureInventory(ctx context.Context, q SecurityPostureOverviewQuery, overview *SecurityPostureOverview) error {
	limitClause := ""
	args := []any{q.ProjectID}
	if q.TopN > 0 {
		limitClause = "\n  LIMIT $2"
		args = append(args, q.TopN)
	}
	query := fmt.Sprintf(`
WITH active_revisions AS (
  SELECT tr.id AS revision_id
  FROM test_revisions tr
  JOIN tests t ON t.id = tr.test_id
  JOIN scopes sc ON sc.id = t.scope_id
  JOIN products p ON p.id = sc.product_id
  WHERE tr.is_active = TRUE
    AND p.project_id = $1
),
active_components AS (
  SELECT
    LOWER(COALESCE(NULLIF(TRIM(c.pkg_type), ''), 'unknown')) AS pkg_type
  FROM active_revisions ar
  JOIN components c ON c.revision_id = ar.revision_id
),
counts AS (
  SELECT
    pkg_type,
    COUNT(*)::int AS item_count
  FROM active_components
  GROUP BY pkg_type
),
totals AS (
  SELECT COALESCE(SUM(item_count), 0)::int AS total_count
  FROM counts
),
items_total AS (
  SELECT COUNT(*)::int AS total_items
  FROM counts
),
ranked AS (
  SELECT
    c.pkg_type,
    c.item_count,
    t.total_count,
    i.total_items
  FROM counts c
  CROSS JOIN totals t
  CROSS JOIN items_total i
  ORDER BY c.item_count DESC, c.pkg_type ASC
%s
)
SELECT
  pkg_type,
  item_count,
  total_count,
  total_items
FROM ranked
`, limitClause)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return err
	}
	defer rows.Close()

	items := make([]SecurityPosturePackageType, 0)
	totalItems := 0
	for rows.Next() {
		var (
			item       SecurityPosturePackageType
			totalCount int
			rowTotal   int
		)
		if err := rows.Scan(&item.PackageType, &item.Count, &totalCount, &rowTotal); err != nil {
			return err
		}
		totalItems = rowTotal
		if totalCount > 0 {
			item.Percentage = (float64(item.Count) / float64(totalCount)) * 100
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	overview.InventoryTopTypesTotal = totalItems
	overview.InventoryTopTypes = items
	return nil
}

func (s *PostgresStore) loadSecurityPostureRecentUploads(ctx context.Context, q SecurityPostureOverviewQuery, overview *SecurityPostureOverview) error {
	limitClause := ""
	args := []any{q.ProjectID, q.Since.UTC()}
	if q.TopN > 0 {
		limitClause = "\nLIMIT $3"
		args = append(args, q.TopN)
	}
	query := fmt.Sprintf(`
SELECT
  iq.id,
  COALESCE(iq.completed_at, iq.updated_at, iq.created_at) AS activity_at,
  iq.status,
  COALESCE(iq.processing_stage, ''),
  COALESCE(iq.components_count, 0)::int,
  COALESCE(iq.product_id, sc.product_id)::text AS product_id,
  COALESCE(iq.scope_id, sc.id)::text AS scope_id,
  COALESCE(iq.test_id, t.id)::text AS test_id,
  COALESCE(p.name, ''),
  COALESCE(sc.name, ''),
  COALESCE(t.name, ''),
  COALESCE(iq.error_message, '')
FROM ingest_queue iq
LEFT JOIN tests t ON t.id = iq.test_id
LEFT JOIN scopes sc ON sc.id = COALESCE(iq.scope_id, t.scope_id)
JOIN products p ON p.id = COALESCE(iq.product_id, sc.product_id)
WHERE p.project_id = $1
  AND COALESCE(iq.completed_at, iq.updated_at, iq.created_at) >= $2
ORDER BY activity_at DESC
%s
`, limitClause)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return err
	}
	defer rows.Close()

	items := make([]SecurityPostureUpload, 0)
	for rows.Next() {
		var (
			item      SecurityPostureUpload
			productID sql.NullString
			scopeID   sql.NullString
			testID    sql.NullString
		)
		if err := rows.Scan(
			&item.ID,
			&item.Timestamp,
			&item.Status,
			&item.Stage,
			&item.ComponentsImported,
			&productID,
			&scopeID,
			&testID,
			&item.ProductName,
			&item.ScopeName,
			&item.TestName,
			&item.ErrorMessage,
		); err != nil {
			return err
		}
		if productID.Valid {
			item.ProductID = productID.String
		}
		if scopeID.Valid {
			item.ScopeID = scopeID.String
		}
		if testID.Valid {
			item.TestID = testID.String
		}
		item.Timestamp = item.Timestamp.UTC()
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	overview.RecentUploads = items
	return nil
}

func (s *PostgresStore) loadSecurityPostureRecentFailures(ctx context.Context, q SecurityPostureOverviewQuery, overview *SecurityPostureOverview) error {
	limitClause := ""
	args := []any{q.ProjectID, q.Since.UTC()}
	if q.TopN > 0 {
		limitClause = "\nLIMIT $3"
		args = append(args, q.TopN)
	}
	query := fmt.Sprintf(`
WITH ingest_failures AS (
  SELECT
    COALESCE(iq.completed_at, iq.updated_at, iq.created_at) AS occurred_at,
    ('ingest_queue.' || LOWER(COALESCE(NULLIF(TRIM(iq.processing_stage), ''), 'unknown'))) AS component,
    COALESCE(NULLIF(TRIM(iq.error_message), ''), 'Ingest job failed.') AS summary,
    'FAILED' AS status
  FROM ingest_queue iq
  LEFT JOIN tests t ON t.id = iq.test_id
  LEFT JOIN scopes sc ON sc.id = COALESCE(iq.scope_id, t.scope_id)
  JOIN products p ON p.id = COALESCE(iq.product_id, sc.product_id)
  WHERE p.project_id = $1
    AND iq.status = 'FAILED'
    AND COALESCE(iq.completed_at, iq.updated_at, iq.created_at) >= $2
),
osv_failures AS (
  SELECT
    created_at AS occurred_at,
    'source_sync.osv' AS component,
    CONCAT(
      COALESCE(NULLIF(TRIM(details->>'stage'), ''), 'sync'),
      ': ',
      COALESCE(NULLIF(TRIM(details->>'message'), ''), 'OSV sync error.')
    ) AS summary,
    'ERROR' AS status
  FROM audit_logs
  WHERE entity_type = 'malware_source'
    AND action = 'MALWARE_OSV_SYNC_ERROR'
    AND created_at >= $2
)
SELECT
  occurred_at,
  component,
  summary,
  status
FROM (
  SELECT * FROM ingest_failures
  UNION ALL
  SELECT * FROM osv_failures
) combined
ORDER BY occurred_at DESC
%s
`, limitClause)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return err
	}
	defer rows.Close()

	items := make([]SecurityPostureFailure, 0)
	for rows.Next() {
		var item SecurityPostureFailure
		if err := rows.Scan(&item.Timestamp, &item.Component, &item.Summary, &item.Status); err != nil {
			return err
		}
		item.Timestamp = item.Timestamp.UTC()
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	overview.RecentFailures = items
	return nil
}

// ApplySecurityPostureScore computes 0-100 score from malware-product ratio.
func ApplySecurityPostureScore(overview *SecurityPostureOverview) {
	if overview == nil {
		return
	}

	k := overview.KPIs
	score := 100
	if k.TotalProducts > 0 {
		malwareRatio := float64(k.MalwareProducts) / float64(k.TotalProducts)
		if malwareRatio < 0 {
			malwareRatio = 0
		}
		if malwareRatio > 1 {
			malwareRatio = 1
		}
		score = int(math.Round((1 - malwareRatio) * 100))
	}

	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	overview.Score = SecurityPostureScore{
		Value: score,
		Label: "",
	}
}
