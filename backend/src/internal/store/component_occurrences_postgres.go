package store

import (
	"database/sql"
	"fmt"
	"strings"

	"github.com/google/uuid"
)

type malwareVerdictRow struct {
	ComponentPURL string
	Verdict       string
	FindingsCount int
	ScannedAt     sql.NullTime
	ValidUntil    sql.NullTime
}

// SearchComponentOccurrencesPage returns a paginated list of component occurrences across all active test revisions.
// The search is substring-based (contains) on component PURL.
func (s *PostgresStore) SearchComponentOccurrencesPage(query string, limit, offset int) ([]ComponentOccurrence, int, error) {
	return s.searchComponentOccurrencesPage(query, limit, offset, nil)
}

// SearchComponentOccurrencesPageByProject returns component occurrences for a single project.
func (s *PostgresStore) SearchComponentOccurrencesPageByProject(projectID uuid.UUID, query string, limit, offset int) ([]ComponentOccurrence, int, error) {
	return s.searchComponentOccurrencesPage(query, limit, offset, &projectID)
}

func (s *PostgresStore) searchComponentOccurrencesPage(query string, limit, offset int, projectID *uuid.UUID) ([]ComponentOccurrence, int, error) {
	ctx, cancel := s.ctx()
	defer cancel()

	if limit <= 0 {
		return []ComponentOccurrence{}, 0, nil
	}
	if offset < 0 {
		offset = 0
	}
	q := strings.TrimSpace(query)
	if q == "" {
		return nil, 0, ErrInvalidPayload
	}

	var total int
	countQuery := `
SELECT COUNT(*)
FROM components c
JOIN test_revisions tr ON tr.id = c.revision_id
JOIN tests t ON t.id = tr.test_id
JOIN scopes s ON s.id = t.scope_id
JOIN products p ON p.id = s.product_id
WHERE tr.is_active = TRUE
  AND c.purl ILIKE '%' || $1 || '%'`
	countArgs := []any{q}
	if projectID != nil {
		countQuery += " AND p.project_id = $2"
		countArgs = append(countArgs, *projectID)
	}
	row := s.db.QueryRowContext(ctx, countQuery, countArgs...)
	if err := row.Scan(&total); err != nil {
		return nil, 0, err
	}
	if total == 0 {
		return []ComponentOccurrence{}, 0, nil
	}

	baseListQuery := `
SELECT c.id,
       c.revision_id,
       c.purl,
       c.pkg_name,
       c.version,
       c.pkg_type,
       COALESCE(c.pkg_namespace, ''),
       c.created_at,
       t.id,
       t.name,
       s.id,
       s.name,
       p.id,
       p.name
FROM components c
JOIN test_revisions tr ON tr.id = c.revision_id
JOIN tests t ON t.id = tr.test_id
JOIN scopes s ON s.id = t.scope_id
JOIN products p ON p.id = s.product_id
WHERE tr.is_active = TRUE
  AND c.purl ILIKE '%' || $1 || '%'`
	listArgs := []any{q}
	limitArg := 2
	offsetArg := 3
	if projectID != nil {
		baseListQuery += " AND p.project_id = $2"
		listArgs = append(listArgs, *projectID)
		limitArg = 3
		offsetArg = 4
	}
	listQuery := fmt.Sprintf(
		`%s
ORDER BY c.purl ASC, p.name ASC, s.name ASC, t.name ASC, c.id ASC
LIMIT $%d OFFSET $%d`,
		baseListQuery,
		limitArg,
		offsetArg,
	)
	listArgs = append(listArgs, limit, offset)
	rows, err := s.db.QueryContext(ctx, listQuery, listArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	items := make([]ComponentOccurrence, 0, min(limit, total))
	purls := make([]string, 0, min(limit, total))
	seenPURLs := make(map[string]struct{}, limit)

	for rows.Next() {
		var occ ComponentOccurrence
		if err := rows.Scan(
			&occ.ComponentID,
			&occ.RevisionID,
			&occ.PURL,
			&occ.PkgName,
			&occ.Version,
			&occ.PkgType,
			&occ.PkgNamespace,
			&occ.CreatedAt,
			&occ.TestID,
			&occ.TestName,
			&occ.ScopeID,
			&occ.ScopeName,
			&occ.ProductID,
			&occ.ProductName,
		); err != nil {
			return nil, 0, err
		}
		items = append(items, occ)
		if _, ok := seenPURLs[occ.PURL]; !ok && occ.PURL != "" {
			seenPURLs[occ.PURL] = struct{}{}
			purls = append(purls, occ.PURL)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}

	verdicts, err := s.componentMalwareVerdictsByPURLs(purls)
	if err != nil {
		return nil, 0, err
	}
	for i := range items {
		if v, ok := verdicts[items[i].PURL]; ok {
			items[i].MalwareVerdict = v.Verdict
			items[i].MalwareFindingsCount = v.FindingsCount
			if v.ScannedAt.Valid {
				t := v.ScannedAt.Time.UTC()
				items[i].MalwareScannedAt = &t
			}
			if v.ValidUntil.Valid {
				t := v.ValidUntil.Time.UTC()
				items[i].MalwareValidUntil = &t
			}
		} else {
			items[i].MalwareVerdict = "UNKNOWN"
		}
	}

	return items, total, nil
}

func (s *PostgresStore) componentMalwareVerdictsByPURLs(purls []string) (map[string]malwareVerdictRow, error) {
	if len(purls) == 0 {
		return map[string]malwareVerdictRow{}, nil
	}

	ctx, cancel := s.ctx()
	defer cancel()

	// Verdict model:
	// - MALWARE: component purl has at least one mapping to a malware purl with verdict MALWARE in source_malware_input_results
	// - CLEAN: no MALWARE mapping, but component has component_state entry (mapping run was executed)
	// - UNKNOWN: no state found
	rows, err := s.db.QueryContext(ctx,
		`WITH input AS (
		     SELECT UNNEST($1::text[]) AS component_purl
		   ),
		   malware AS (
		     SELECT f.component_purl, COUNT(*)::int AS malware_count
		       FROM component_analysis_malware_findings f
		       JOIN source_malware_input_results r
		         ON r.id = f.source_malware_input_result_id
		      WHERE r.verdict = 'MALWARE'
		        AND f.component_purl = ANY($1::text[])
		      GROUP BY f.component_purl
		   )
		   SELECT i.component_purl,
		          CASE
		            WHEN COALESCE(m.malware_count, 0) > 0 THEN 'MALWARE'
		            WHEN cs.component_purl IS NOT NULL THEN 'CLEAN'
		            ELSE 'UNKNOWN'
		          END AS verdict,
		          COALESCE(m.malware_count, 0) AS findings_count,
		          cs.scanned_at,
		          cs.valid_until
		     FROM input i
		     LEFT JOIN malware m ON m.component_purl = i.component_purl
		     LEFT JOIN component_analysis_malware_component_state cs ON cs.component_purl = i.component_purl`,
		purls,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make(map[string]malwareVerdictRow, len(purls))
	for rows.Next() {
		var row malwareVerdictRow
		if err := rows.Scan(&row.ComponentPURL, &row.Verdict, &row.FindingsCount, &row.ScannedAt, &row.ValidUntil); err != nil {
			return nil, err
		}
		out[row.ComponentPURL] = row
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
