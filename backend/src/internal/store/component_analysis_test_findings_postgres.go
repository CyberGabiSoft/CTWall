package store

import (
	"fmt"

	"backend/internal/models"

	"github.com/google/uuid"
)

// ListActiveTestComponentAnalysisMalwareFindings returns malware mappings for the active test revision,
// filtered to verdict MALWARE (source of truth: source_malware_input_results).
func (s *PostgresStore) ListActiveTestComponentAnalysisMalwareFindings(
	testID uuid.UUID,
	limit, offset int,
) ([]models.ComponentAnalysisFinding, error) {
	ctx, cancel := s.ctx()
	defer cancel()

	if err := s.ensureTestExists(ctx, testID); err != nil {
		return nil, err
	}
	if limit <= 0 {
		return []models.ComponentAnalysisFinding{}, nil
	}
	if offset < 0 {
		offset = 0
	}

	rows, err := s.db.QueryContext(ctx,
		`WITH active_components AS (
			 SELECT DISTINCT c.purl AS component_purl
			 FROM components c
			 JOIN test_revisions tr ON tr.id = c.revision_id
			 WHERE tr.test_id = $1 AND tr.is_active = TRUE
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
		        ) AS effective_priority
		 FROM component_analysis_malware_findings f
		 JOIN active_components ac ON ac.component_purl = f.component_purl
		 JOIN source_malware_input_results r ON r.id = f.source_malware_input_result_id
		 JOIN tests t ON t.id = $1
		 JOIN scopes s ON s.id = t.scope_id
		 JOIN products p ON p.id = s.product_id
		 LEFT JOIN component_malware_findings_triage tg
		   ON tg.test_id = t.id
		  AND tg.component_purl = f.component_purl
		  AND tg.malware_purl = f.malware_purl
		 WHERE r.verdict = 'MALWARE'
		 ORDER BY f.updated_at DESC, f.id ASC
		 LIMIT $2 OFFSET $3`,
		testID,
		limit,
		offset,
	)
	if err != nil {
		return nil, fmt.Errorf("list test malware findings: %w", err)
	}
	defer rows.Close()

	items := make([]models.ComponentAnalysisFinding, 0)
	for rows.Next() {
		finding, err := scanComponentAnalysisFindingRow(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, *finding)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}
