package store

import (
	"database/sql"
	"errors"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// ListDataGraphRevisionMalwareCounts returns malware mapping counts per component PURL for a single revision.
func (s *PostgresStore) ListDataGraphRevisionMalwareCounts(
	projectID, testID, revisionID uuid.UUID,
	componentPURLs []string,
) (map[string]int, error) {
	if projectID == uuid.Nil || testID == uuid.Nil || revisionID == uuid.Nil {
		return nil, ErrInvalidPayload
	}
	if len(componentPURLs) == 0 {
		return map[string]int{}, nil
	}

	normalized := make([]string, 0, len(componentPURLs))
	seen := make(map[string]struct{}, len(componentPURLs))
	for _, raw := range componentPURLs {
		purl := strings.TrimSpace(raw)
		if purl == "" {
			continue
		}
		if _, ok := seen[purl]; ok {
			continue
		}
		seen[purl] = struct{}{}
		normalized = append(normalized, purl)
	}
	if len(normalized) == 0 {
		return map[string]int{}, nil
	}

	ctx, cancel := s.ctx()
	defer cancel()

	rows, err := s.db.QueryContext(ctx,
		`WITH revision_guard AS (
		     SELECT 1
		     FROM test_revisions tr
		     JOIN tests t ON t.id = tr.test_id
		     JOIN scopes s ON s.id = t.scope_id
		     JOIN products p ON p.id = s.product_id
		     WHERE tr.id = $1
		       AND tr.test_id = $2
		       AND p.project_id = $3
		   ),
		   input AS (
		     SELECT DISTINCT UNNEST($4::text[]) AS component_purl
		   ),
		   revision_components AS (
		     SELECT DISTINCT c.purl AS component_purl
		     FROM components c
		     JOIN test_revisions tr ON tr.id = c.revision_id
		     WHERE tr.id = $1
		       AND c.purl = ANY($4::text[])
		   ),
		   malware AS (
		     SELECT f.component_purl, COUNT(r.id)::int AS malware_count
		     FROM component_analysis_malware_findings f
		     JOIN source_malware_input_results r
		       ON r.id = f.source_malware_input_result_id
		     JOIN revision_components rc
		       ON rc.component_purl = f.component_purl
		     WHERE r.verdict = 'MALWARE'
		     GROUP BY f.component_purl
		   )
		   SELECT i.component_purl,
		          COALESCE(m.malware_count, 0) AS malware_count
		   FROM input i
		   JOIN revision_guard rg ON TRUE
		   JOIN revision_components rc
		     ON rc.component_purl = i.component_purl
		   LEFT JOIN malware m
		     ON m.component_purl = i.component_purl`,
		revisionID,
		testID,
		projectID,
		pgtype.FlatArray[string](normalized),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make(map[string]int, len(normalized))
	for rows.Next() {
		var purl string
		var count int
		if err := rows.Scan(&purl, &count); err != nil {
			return nil, err
		}
		out[purl] = count
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// GetDataGraphComponentByPURL returns one component from a revision with full hierarchy context.
func (s *PostgresStore) GetDataGraphComponentByPURL(
	projectID, testID, revisionID uuid.UUID,
	componentPURL string,
) (*DataGraphComponentRecord, error) {
	if projectID == uuid.Nil || testID == uuid.Nil || revisionID == uuid.Nil {
		return nil, ErrInvalidPayload
	}
	componentPURL = strings.TrimSpace(componentPURL)
	if componentPURL == "" {
		return nil, ErrInvalidPayload
	}

	ctx, cancel := s.ctx()
	defer cancel()

	row := s.db.QueryRowContext(ctx,
		`SELECT c.id, c.revision_id, c.purl, c.pkg_name, c.version, c.pkg_type, COALESCE(c.pkg_namespace, ''),
		        c.sbom_type, COALESCE(c.publisher, ''), COALESCE(c.supplier, ''), COALESCE(c.licenses, '[]'::jsonb), COALESCE(c.properties, '{}'::jsonb), c.created_at,
		        p.id, p.name, s.id, s.name, t.id, t.name,
		        t.sbom_standard, t.sbom_spec_version, tr.sbom_producer, tr.is_active, tr.created_at
		 FROM components c
		 JOIN test_revisions tr ON tr.id = c.revision_id
		 JOIN tests t ON t.id = tr.test_id
		 JOIN scopes s ON s.id = t.scope_id
		 JOIN products p ON p.id = s.product_id
		 WHERE p.project_id = $1
		   AND t.id = $2
		   AND tr.id = $3
		   AND c.purl = $4
		 ORDER BY c.created_at DESC
		 LIMIT 1`,
		projectID,
		testID,
		revisionID,
		componentPURL,
	)

	var record DataGraphComponentRecord
	record.ProjectID = projectID
	record.Licenses = nil
	record.Properties = nil
	if err := row.Scan(
		&record.ID,
		&record.RevisionID,
		&record.PURL,
		&record.PkgName,
		&record.Version,
		&record.PkgType,
		&record.PkgNamespace,
		&record.SbomType,
		&record.Publisher,
		&record.Supplier,
		&record.Licenses,
		&record.Properties,
		&record.CreatedAt,
		&record.ProductID,
		&record.ProductName,
		&record.ScopeID,
		&record.ScopeName,
		&record.TestID,
		&record.TestName,
		&record.SbomStandard,
		&record.SbomSpecVersion,
		&record.SbomProducer,
		&record.RevisionIsActive,
		&record.RevisionCreatedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &record, nil
}

// ListDataGraphProjectOccurrencesByPURL returns project-scoped occurrences of a component PURL.
func (s *PostgresStore) ListDataGraphProjectOccurrencesByPURL(
	projectID uuid.UUID,
	componentPURL string,
	limit int,
) ([]DataGraphComponentOccurrence, error) {
	if projectID == uuid.Nil {
		return nil, ErrInvalidPayload
	}
	componentPURL = strings.TrimSpace(componentPURL)
	if componentPURL == "" {
		return nil, ErrInvalidPayload
	}
	if limit <= 0 {
		return nil, ErrInvalidPayload
	}
	if limit > MaxDataGraphRowsLimit {
		limit = MaxDataGraphRowsLimit
	}

	ctx, cancel := s.ctx()
	defer cancel()

	rows, err := s.db.QueryContext(ctx,
		`SELECT DISTINCT p.id, p.name, s.id, s.name, t.id, t.name, tr.id, tr.is_active, tr.created_at, tr.sbom_producer
		 FROM components c
		 JOIN test_revisions tr ON tr.id = c.revision_id
		 JOIN tests t ON t.id = tr.test_id
		 JOIN scopes s ON s.id = t.scope_id
		 JOIN products p ON p.id = s.product_id
		 WHERE p.project_id = $1
		   AND c.purl = $2
		 ORDER BY tr.created_at DESC, p.name ASC, s.name ASC, t.name ASC
		 LIMIT $3`,
		projectID,
		componentPURL,
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]DataGraphComponentOccurrence, 0)
	for rows.Next() {
		var item DataGraphComponentOccurrence
		if err := rows.Scan(
			&item.ProductID,
			&item.ProductName,
			&item.ScopeID,
			&item.ScopeName,
			&item.TestID,
			&item.TestName,
			&item.RevisionID,
			&item.RevisionIsActive,
			&item.RevisionCreatedAt,
			&item.SbomProducer,
		); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// ListDataGraphRevisionComponentFindings returns malware mappings with triage for a component in revision/test context.
func (s *PostgresStore) ListDataGraphRevisionComponentFindings(
	projectID, testID, revisionID uuid.UUID,
	componentPURL string,
	limit int,
) ([]DataGraphComponentFinding, error) {
	if projectID == uuid.Nil || testID == uuid.Nil || revisionID == uuid.Nil {
		return nil, ErrInvalidPayload
	}
	componentPURL = strings.TrimSpace(componentPURL)
	if componentPURL == "" {
		return nil, ErrInvalidPayload
	}
	if limit <= 0 {
		return nil, ErrInvalidPayload
	}
	if limit > MaxDataGraphRowsLimit {
		limit = MaxDataGraphRowsLimit
	}

	ctx, cancel := s.ctx()
	defer cancel()

	rows, err := s.db.QueryContext(ctx,
		`WITH revision_components AS (
		     SELECT DISTINCT c.purl AS component_purl
		     FROM components c
		     JOIN test_revisions tr ON tr.id = c.revision_id
		     JOIN tests t ON t.id = tr.test_id
		     JOIN scopes s ON s.id = t.scope_id
		     JOIN products p ON p.id = s.product_id
		     WHERE tr.id = $1
		       AND tr.test_id = $2
		       AND p.project_id = $3
		       AND c.purl = $4
		   )
		   SELECT f.id, f.component_purl, f.malware_purl, f.source_malware_input_result_id, f.match_type, f.created_at, f.updated_at,
		          COALESCE(tg.status, 'OPEN') AS triage_status,
		          tg.priority AS triage_priority,
		          COALESCE(
		            tg.priority,
		            t.malware_default_priority,
		            s.malware_default_priority,
		            p.malware_default_priority,
		            'P2'
		          ) AS effective_priority,
		          tg.reason AS triage_reason,
		          tg.expires_at AS triage_expires_at,
		          tg.updated_at AS triage_updated_at
		   FROM component_analysis_malware_findings f
		   JOIN revision_components rc ON rc.component_purl = f.component_purl
		   JOIN source_malware_input_results r ON r.id = f.source_malware_input_result_id
		   JOIN tests t ON t.id = $2
		   JOIN scopes s ON s.id = t.scope_id
		   JOIN products p ON p.id = s.product_id
		   LEFT JOIN component_malware_findings_triage tg
		     ON tg.project_id = $3
		    AND tg.test_id = t.id
		    AND tg.component_purl = f.component_purl
		    AND tg.malware_purl = f.malware_purl
		   WHERE r.verdict = 'MALWARE'
		   ORDER BY f.updated_at DESC, f.id ASC
		   LIMIT $5`,
		revisionID,
		testID,
		projectID,
		componentPURL,
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]DataGraphComponentFinding, 0)
	for rows.Next() {
		var item DataGraphComponentFinding
		var triagePriority sql.NullString
		var triageReason sql.NullString
		var triageExpiresAt sql.NullTime
		var triageUpdatedAt sql.NullTime
		if err := rows.Scan(
			&item.ID,
			&item.ComponentPURL,
			&item.MalwarePURL,
			&item.SourceMalwareInputResultID,
			&item.MatchType,
			&item.CreatedAt,
			&item.UpdatedAt,
			&item.TriageStatus,
			&triagePriority,
			&item.EffectivePriority,
			&triageReason,
			&triageExpiresAt,
			&triageUpdatedAt,
		); err != nil {
			return nil, err
		}
		if triagePriority.Valid {
			value := triagePriority.String
			item.TriagePriority = &value
		}
		if triageReason.Valid {
			value := triageReason.String
			item.TriageReason = &value
		}
		if triageExpiresAt.Valid {
			value := triageExpiresAt.Time.UTC()
			item.TriageExpiresAt = &value
		}
		if triageUpdatedAt.Valid {
			value := triageUpdatedAt.Time.UTC()
			item.TriageUpdatedAt = &value
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
