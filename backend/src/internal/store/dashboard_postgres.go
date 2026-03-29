package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

func normalizeDashboardOverviewQuery(q *DashboardOverviewQuery) error {
	if q == nil {
		return ErrInvalidPayload
	}
	if len(q.ProjectIDs) == 0 {
		return ErrInvalidPayload
	}
	if q.Since.IsZero() {
		return ErrInvalidPayload
	}
	if q.TopN < 0 {
		q.TopN = DefaultDashboardTopN
	}
	return nil
}

// GetDashboardOverview returns platform overview aggregates for the provided project scope.
func (s *PostgresStore) GetDashboardOverview(q DashboardOverviewQuery) (*DashboardOverview, error) {
	if err := normalizeDashboardOverviewQuery(&q); err != nil {
		return nil, err
	}

	ctx, cancel := s.ctx()
	defer cancel()

	now := time.Now().UTC()
	overview := &DashboardOverview{
		GeneratedAt:  now,
		RangeStart:   q.Since.UTC(),
		RangeEnd:     now,
		ProjectCount: len(q.ProjectIDs),
		TopN:         q.TopN,
	}

	if err := s.loadDashboardKpis(ctx, q, overview); err != nil {
		return nil, err
	}
	if err := s.loadDashboardTopProducts(ctx, q, overview); err != nil {
		return nil, err
	}
	if err := s.loadDashboardTopScopes(ctx, q, overview); err != nil {
		return nil, err
	}
	if err := s.loadDashboardTopPackageTypes(ctx, q, overview); err != nil {
		return nil, err
	}
	if err := s.loadDashboardTopLicenses(ctx, q, overview); err != nil {
		return nil, err
	}
	if err := s.loadDashboardTopMalwarePackages(ctx, q, overview); err != nil {
		return nil, err
	}
	if err := s.loadDashboardRecentIngest(ctx, q, overview); err != nil {
		return nil, err
	}
	if err := s.loadDashboardIngestTrend(ctx, q, overview); err != nil {
		return nil, err
	}

	return overview, nil
}

func (s *PostgresStore) loadDashboardKpis(ctx context.Context, q DashboardOverviewQuery, overview *DashboardOverview) error {
	const query = `
WITH active_revisions AS (
  SELECT
    tr.id AS revision_id,
    tr.test_id,
    tr.last_modified_at
  FROM test_revisions tr
  JOIN tests t ON t.id = tr.test_id
  JOIN scopes sc ON sc.id = t.scope_id
  JOIN products p ON p.id = sc.product_id
  WHERE tr.is_active = TRUE
    AND p.project_id = ANY($1::uuid[])
),
active_components AS (
  SELECT
    c.purl,
    ar.test_id
  FROM active_revisions ar
  JOIN components c ON c.revision_id = ar.revision_id
),
active_purls AS (
  SELECT DISTINCT purl
  FROM active_components
),
malware_components AS (
  SELECT DISTINCT f.component_purl
  FROM component_analysis_malware_findings f
  JOIN source_malware_input_results r ON r.id = f.source_malware_input_result_id
  JOIN active_purls ap ON ap.purl = f.component_purl
  WHERE COALESCE(NULLIF(TRIM(r.verdict), ''), 'UNKNOWN') = 'MALWARE'
),
purl_verdicts AS (
  SELECT
    ap.purl AS component_purl,
    CASE
      WHEN mc.component_purl IS NOT NULL THEN 'MALWARE'
      WHEN cs.component_purl IS NOT NULL THEN 'CLEAN'
      ELSE 'UNKNOWN'
    END AS verdict,
    cs.scanned_at
  FROM active_purls ap
  LEFT JOIN malware_components mc ON mc.component_purl = ap.purl
  LEFT JOIN component_analysis_malware_component_state cs ON cs.component_purl = ap.purl
),
ingest_scoped AS (
  SELECT
    iq.id,
    iq.status,
    iq.components_count,
    iq.completed_at
  FROM ingest_queue iq
  LEFT JOIN tests t ON t.id = iq.test_id
  LEFT JOIN scopes sc ON sc.id = COALESCE(iq.scope_id, t.scope_id)
  JOIN products p ON p.id = COALESCE(iq.product_id, sc.product_id)
  WHERE p.project_id = ANY($1::uuid[])
)
SELECT
  COALESCE((SELECT COUNT(*)::int FROM purl_verdicts WHERE verdict = 'MALWARE'), 0) AS malware_active,
  COALESCE((SELECT COUNT(*)::int FROM purl_verdicts WHERE verdict = 'CLEAN'), 0) AS clean_count,
  COALESCE((SELECT COUNT(*)::int FROM purl_verdicts WHERE verdict NOT IN ('MALWARE', 'CLEAN')), 0) AS unknown_count,
  COALESCE((
    SELECT COUNT(DISTINCT ac.test_id)::int
    FROM active_components ac
    JOIN malware_components mc ON mc.component_purl = ac.purl
  ), 0) AS affected_tests,
  (
    SELECT MIN(pv.scanned_at)
    FROM purl_verdicts pv
    WHERE pv.scanned_at IS NOT NULL
  ) AS oldest_package_scan_at,
  (SELECT MAX(completed_at) FROM ingest_scoped WHERE status = 'COMPLETED' AND completed_at IS NOT NULL) AS last_analysis_at,
  COALESCE((
    SELECT COUNT(*)::int
    FROM ingest_scoped
    WHERE status = 'COMPLETED'
      AND completed_at IS NOT NULL
      AND completed_at >= $2
  ), 0) AS ingest_imports,
  COALESCE((
    SELECT SUM(COALESCE(components_count, 0))::int
    FROM ingest_scoped
    WHERE status = 'COMPLETED'
      AND completed_at IS NOT NULL
      AND completed_at >= $2
  ), 0) AS ingest_components
`

	var (
		lastAnalysisAt   sql.NullTime
		oldestScanAt     sql.NullTime
		malwareCount     int
		cleanCount       int
		unknownCount     int
		affectedTests    int
		ingestImports    int
		ingestComponents int
	)
	if err := s.db.QueryRowContext(ctx, query, q.ProjectIDs, q.Since.UTC()).Scan(
		&malwareCount,
		&cleanCount,
		&unknownCount,
		&affectedTests,
		&oldestScanAt,
		&lastAnalysisAt,
		&ingestImports,
		&ingestComponents,
	); err != nil {
		return err
	}

	lastSummaryAt, err := s.loadDashboardLastSummaryAt(ctx, q)
	if err != nil {
		return err
	}
	overridesActive, err := s.loadDashboardOverridesActive(ctx, q)
	if err != nil {
		return err
	}

	overview.VerdictDistribution = DashboardVerdictDistribution{
		Malware: malwareCount,
		Clean:   cleanCount,
		Unknown: unknownCount,
	}
	overview.KPIs = DashboardKPIs{
		MalwareActive:    malwareCount,
		AffectedTests:    affectedTests,
		IngestImports:    ingestImports,
		IngestComponents: ingestComponents,
		OverridesActive:  overridesActive,
	}
	if oldestScanAt.Valid {
		value := oldestScanAt.Time.UTC()
		overview.KPIs.OldestPackageScanAt = &value
	}
	if lastAnalysisAt.Valid {
		value := lastAnalysisAt.Time.UTC()
		overview.KPIs.LastAnalysisAt = &value
	}
	if lastSummaryAt != nil {
		overview.KPIs.LastMalwareSummaryComputedAt = lastSummaryAt
	}
	return nil
}

func (s *PostgresStore) loadDashboardLastSummaryAt(ctx context.Context, q DashboardOverviewQuery) (*time.Time, error) {
	const query = `
WITH active_revisions AS (
  SELECT tr.id AS revision_id
  FROM test_revisions tr
  JOIN tests t ON t.id = tr.test_id
  JOIN scopes sc ON sc.id = t.scope_id
  JOIN products p ON p.id = sc.product_id
  WHERE tr.is_active = TRUE
    AND p.project_id = ANY($1::uuid[])
)
SELECT MAX(s.computed_at)
FROM active_revisions ar
JOIN test_revision_malware_summary s ON s.revision_id = ar.revision_id
`

	var value sql.NullTime
	if err := s.db.QueryRowContext(ctx, query, q.ProjectIDs).Scan(&value); err != nil {
		if isDashboardOptionalMetricSchemaError(err) {
			return nil, nil
		}
		return nil, err
	}
	if !value.Valid {
		return nil, nil
	}
	utc := value.Time.UTC()
	return &utc, nil
}

func (s *PostgresStore) loadDashboardOverridesActive(ctx context.Context, q DashboardOverviewQuery) (int, error) {
	const query = `
SELECT COALESCE(COUNT(*)::int, 0) AS overrides_active
FROM component_malware_findings_triage tri
WHERE tri.project_id = ANY($1::uuid[])
  AND tri.status = 'RISK_ACCEPTED'
  AND (tri.expires_at IS NULL OR tri.expires_at > NOW())
`

	var count int
	if err := s.db.QueryRowContext(ctx, query, q.ProjectIDs).Scan(&count); err != nil {
		if isDashboardOptionalMetricSchemaError(err) {
			return 0, nil
		}
		return 0, err
	}
	return count, nil
}

func isDashboardOptionalMetricSchemaError(err error) bool {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return false
	}
	switch pgErr.Code {
	case "42P01", "42703":
		return true
	default:
		return false
	}
}

func (s *PostgresStore) loadDashboardTopProducts(ctx context.Context, q DashboardOverviewQuery, overview *DashboardOverview) error {
	limitClause := ""
	args := []any{q.ProjectIDs}
	if q.TopN > 0 {
		limitClause = "\n  LIMIT $2"
		args = append(args, q.TopN)
	}
	query := fmt.Sprintf(`
WITH active_revisions AS (
  SELECT
    tr.id AS revision_id,
    p.name AS product_name
  FROM test_revisions tr
  JOIN tests t ON t.id = tr.test_id
  JOIN scopes sc ON sc.id = t.scope_id
  JOIN products p ON p.id = sc.product_id
  WHERE tr.is_active = TRUE
    AND p.project_id = ANY($1::uuid[])
),
active_components AS (
  SELECT
    c.purl,
    ar.product_name
  FROM active_revisions ar
  JOIN components c ON c.revision_id = ar.revision_id
),
malware_components AS (
  SELECT DISTINCT f.component_purl
  FROM component_analysis_malware_findings f
  JOIN source_malware_input_results r ON r.id = f.source_malware_input_result_id
  WHERE COALESCE(NULLIF(TRIM(r.verdict), ''), 'UNKNOWN') = 'MALWARE'
),
grouped AS (
  SELECT
    ac.product_name,
    COUNT(DISTINCT ac.purl)::int AS malware_purls
  FROM active_components ac
  JOIN malware_components mc ON mc.component_purl = ac.purl
  GROUP BY ac.product_name
),
totals AS (
  SELECT COUNT(*)::int AS total_items
  FROM grouped
),
ranked AS (
  SELECT
    g.product_name,
    g.malware_purls,
    t.total_items
  FROM grouped g
  CROSS JOIN totals t
  ORDER BY g.malware_purls DESC, g.product_name ASC
%s
)
SELECT
  product_name,
  malware_purls,
  total_items
FROM ranked
`, limitClause)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return err
	}
	defer rows.Close()

	items := make([]DashboardTopItem, 0)
	totalItems := 0
	for rows.Next() {
		var item DashboardTopItem
		if err := rows.Scan(&item.Name, &item.Value, &totalItems); err != nil {
			return err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	overview.TopProductsTotal = totalItems
	overview.TopProducts = items
	return nil
}

func (s *PostgresStore) loadDashboardTopScopes(ctx context.Context, q DashboardOverviewQuery, overview *DashboardOverview) error {
	limitClause := ""
	args := []any{q.ProjectIDs}
	if q.TopN > 0 {
		limitClause = "\n  LIMIT $2"
		args = append(args, q.TopN)
	}
	query := fmt.Sprintf(`
WITH active_revisions AS (
  SELECT
    tr.id AS revision_id,
    sc.name AS scope_name
  FROM test_revisions tr
  JOIN tests t ON t.id = tr.test_id
  JOIN scopes sc ON sc.id = t.scope_id
  JOIN products p ON p.id = sc.product_id
  WHERE tr.is_active = TRUE
    AND p.project_id = ANY($1::uuid[])
),
active_components AS (
  SELECT
    c.purl,
    ar.scope_name
  FROM active_revisions ar
  JOIN components c ON c.revision_id = ar.revision_id
),
malware_components AS (
  SELECT DISTINCT f.component_purl
  FROM component_analysis_malware_findings f
  JOIN source_malware_input_results r ON r.id = f.source_malware_input_result_id
  WHERE COALESCE(NULLIF(TRIM(r.verdict), ''), 'UNKNOWN') = 'MALWARE'
),
grouped AS (
  SELECT
    ac.scope_name,
    COUNT(DISTINCT ac.purl)::int AS malware_purls
  FROM active_components ac
  JOIN malware_components mc ON mc.component_purl = ac.purl
  GROUP BY ac.scope_name
),
totals AS (
  SELECT COUNT(*)::int AS total_items
  FROM grouped
),
ranked AS (
  SELECT
    g.scope_name,
    g.malware_purls,
    t.total_items
  FROM grouped g
  CROSS JOIN totals t
  ORDER BY g.malware_purls DESC, g.scope_name ASC
%s
)
SELECT
  scope_name,
  malware_purls,
  total_items
FROM ranked
`, limitClause)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return err
	}
	defer rows.Close()

	items := make([]DashboardTopItem, 0)
	totalItems := 0
	for rows.Next() {
		var item DashboardTopItem
		if err := rows.Scan(&item.Name, &item.Value, &totalItems); err != nil {
			return err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	overview.TopScopesTotal = totalItems
	overview.TopScopes = items
	return nil
}

func (s *PostgresStore) loadDashboardTopPackageTypes(ctx context.Context, q DashboardOverviewQuery, overview *DashboardOverview) error {
	limitClause := ""
	args := []any{q.ProjectIDs}
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
    AND p.project_id = ANY($1::uuid[])
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

	items := make([]DashboardPackageType, 0)
	totalItems := 0
	for rows.Next() {
		var (
			item       DashboardPackageType
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
	overview.TopPackageTypesTotal = totalItems
	overview.TopPackageTypes = items
	return nil
}

func (s *PostgresStore) loadDashboardTopLicenses(ctx context.Context, q DashboardOverviewQuery, overview *DashboardOverview) error {
	limitClause := ""
	args := []any{q.ProjectIDs}
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
    AND p.project_id = ANY($1::uuid[])
),
license_items AS (
  SELECT
    CASE
      WHEN jsonb_typeof(lic) = 'string' THEN LOWER(NULLIF(BTRIM(lic::text, '" '), ''))
      ELSE LOWER(NULLIF(TRIM(COALESCE(
        lic->>'id',
        lic->>'name',
        lic->>'expression',
        lic->>'spdxId'
      )), ''))
    END AS license_name
  FROM active_revisions ar
  JOIN components c ON c.revision_id = ar.revision_id
  CROSS JOIN LATERAL jsonb_array_elements(COALESCE(c.licenses, '[]'::jsonb)) AS lic
),
counts AS (
  SELECT
    license_name,
    COUNT(*)::int AS item_count
  FROM license_items
  WHERE license_name IS NOT NULL AND license_name <> ''
  GROUP BY license_name
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
    c.license_name,
    c.item_count,
    t.total_count,
    i.total_items
  FROM counts c
  CROSS JOIN totals t
  CROSS JOIN items_total i
  ORDER BY c.item_count DESC, c.license_name ASC
%s
)
SELECT
  license_name,
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

	items := make([]DashboardLicense, 0)
	totalItems := 0
	for rows.Next() {
		var (
			item       DashboardLicense
			totalCount int
			rowTotal   int
		)
		if err := rows.Scan(&item.License, &item.Count, &totalCount, &rowTotal); err != nil {
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
	overview.TopLicensesTotal = totalItems
	overview.TopLicenses = items
	return nil
}

func (s *PostgresStore) loadDashboardTopMalwarePackages(ctx context.Context, q DashboardOverviewQuery, overview *DashboardOverview) error {
	limitClause := ""
	args := []any{q.ProjectIDs}
	if q.TopN > 0 {
		limitClause = "\nLIMIT $2"
		args = append(args, q.TopN)
	}
	query := fmt.Sprintf(`
WITH active_revisions AS (
  SELECT
    tr.id AS revision_id,
    tr.last_modified_at
  FROM test_revisions tr
  JOIN tests t ON t.id = tr.test_id
  JOIN scopes sc ON sc.id = t.scope_id
  JOIN products p ON p.id = sc.product_id
  WHERE tr.is_active = TRUE
    AND p.project_id = ANY($1::uuid[])
),
active_components AS (
  SELECT
    c.purl,
    ar.last_modified_at
  FROM active_revisions ar
  JOIN components c ON c.revision_id = ar.revision_id
),
malware_components AS (
  SELECT DISTINCT f.component_purl
  FROM component_analysis_malware_findings f
  JOIN source_malware_input_results r ON r.id = f.source_malware_input_result_id
  WHERE COALESCE(NULLIF(TRIM(r.verdict), ''), 'UNKNOWN') = 'MALWARE'
)
SELECT
  ac.purl,
  COUNT(*)::int AS occurrences,
  MAX(ac.last_modified_at) AS last_seen_at
FROM active_components ac
JOIN malware_components mc ON mc.component_purl = ac.purl
GROUP BY ac.purl
ORDER BY occurrences DESC, ac.purl ASC
%s
`, limitClause)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return err
	}
	defer rows.Close()

	items := make([]DashboardMalwarePackage, 0)
	for rows.Next() {
		var (
			item       DashboardMalwarePackage
			lastSeenAt sql.NullTime
		)
		if err := rows.Scan(&item.PURL, &item.Occurrences, &lastSeenAt); err != nil {
			return err
		}
		if lastSeenAt.Valid {
			value := lastSeenAt.Time.UTC()
			item.LastSeenAt = &value
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	overview.TopMalwarePackages = items
	return nil
}

func (s *PostgresStore) loadDashboardRecentIngest(ctx context.Context, q DashboardOverviewQuery, overview *DashboardOverview) error {
	limitClause := ""
	args := []any{q.ProjectIDs}
	if q.TopN > 0 {
		limitClause = "\nLIMIT $2"
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
WHERE p.project_id = ANY($1::uuid[])
ORDER BY activity_at DESC
%s
`, limitClause)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return err
	}
	defer rows.Close()

	items := make([]DashboardIngestActivity, 0)
	for rows.Next() {
		var (
			item      DashboardIngestActivity
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
	overview.RecentIngest = items
	return nil
}

func (s *PostgresStore) loadDashboardIngestTrend(ctx context.Context, q DashboardOverviewQuery, overview *DashboardOverview) error {
	const query = `
SELECT
  date_trunc('day', iq.completed_at) AS bucket_start,
  COUNT(*)::int AS imports_count,
  COALESCE(SUM(COALESCE(iq.components_count, 0)), 0)::int AS components_imported
FROM ingest_queue iq
LEFT JOIN tests t ON t.id = iq.test_id
LEFT JOIN scopes sc ON sc.id = COALESCE(iq.scope_id, t.scope_id)
JOIN products p ON p.id = COALESCE(iq.product_id, sc.product_id)
WHERE p.project_id = ANY($1::uuid[])
  AND iq.status = 'COMPLETED'
  AND iq.completed_at IS NOT NULL
  AND iq.completed_at >= $2
GROUP BY 1
ORDER BY 1 ASC
`

	rows, err := s.db.QueryContext(ctx, query, q.ProjectIDs, q.Since.UTC())
	if err != nil {
		return err
	}
	defer rows.Close()

	items := make([]DashboardIngestBucket, 0)
	for rows.Next() {
		var item DashboardIngestBucket
		if err := rows.Scan(&item.BucketStart, &item.Imports, &item.ComponentsImported); err != nil {
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
