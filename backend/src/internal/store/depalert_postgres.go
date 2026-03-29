package store

import (
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
)

// GetDepAlertRevisionVerdict returns revision-level malware verdict counters for DepAlert sync flow.
func (s *PostgresStore) GetDepAlertRevisionVerdict(projectID, testID, revisionID uuid.UUID) (*DepAlertRevisionVerdict, error) {
	if projectID == uuid.Nil || testID == uuid.Nil || revisionID == uuid.Nil {
		return nil, ErrInvalidPayload
	}

	ctx, cancel := s.ctx()
	defer cancel()

	const query = `
WITH revision_context AS (
  SELECT tr.id AS revision_id,
         tr.test_id AS test_id,
         p.project_id
  FROM test_revisions tr
  JOIN tests t ON t.id = tr.test_id
  JOIN scopes sc ON sc.id = t.scope_id
  JOIN products p ON p.id = sc.product_id
  WHERE p.project_id = $1
    AND tr.test_id = $2
    AND tr.id = $3
),
revision_components AS (
  SELECT DISTINCT c.purl AS component_purl
  FROM components c
  JOIN revision_context rc ON rc.revision_id = c.revision_id
),
malware_components AS (
  SELECT DISTINCT f.component_purl
  FROM component_analysis_malware_findings f
  JOIN source_malware_input_results r ON r.id = f.source_malware_input_result_id
  JOIN revision_components c ON c.component_purl = f.component_purl
  WHERE COALESCE(NULLIF(TRIM(r.verdict), ''), 'UNKNOWN') = 'MALWARE'
),
component_verdicts AS (
  SELECT
    c.component_purl,
    CASE
      WHEN mc.component_purl IS NOT NULL THEN 'MALWARE'
      WHEN st.component_purl IS NOT NULL THEN 'CLEAN'
      ELSE 'UNKNOWN'
    END AS verdict
  FROM revision_components c
  LEFT JOIN malware_components mc ON mc.component_purl = c.component_purl
  LEFT JOIN component_analysis_malware_component_state st ON st.component_purl = c.component_purl
)
SELECT
  rc.project_id,
  rc.test_id,
  rc.revision_id,
  COALESCE(COUNT(cv.component_purl), 0)::int AS total_components,
  COALESCE(COUNT(*) FILTER (WHERE cv.verdict = 'MALWARE'), 0)::int AS malware_components,
  COALESCE(COUNT(*) FILTER (WHERE cv.verdict = 'CLEAN'), 0)::int AS clean_components,
  COALESCE(COUNT(*) FILTER (WHERE cv.verdict = 'UNKNOWN'), 0)::int AS unknown_components
FROM revision_context rc
LEFT JOIN component_verdicts cv ON TRUE
GROUP BY rc.project_id, rc.test_id, rc.revision_id
`

	row := s.db.QueryRowContext(ctx, query, projectID, testID, revisionID)
	result := &DepAlertRevisionVerdict{}
	if err := row.Scan(
		&result.ProjectID,
		&result.TestID,
		&result.RevisionID,
		&result.TotalComponents,
		&result.MalwareComponents,
		&result.CleanComponents,
		&result.UnknownComponents,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	result.ComputedAt = time.Now().UTC()
	switch {
	case result.MalwareComponents > 0:
		result.Verdict = DepAlertVerdictMalware
	case result.TotalComponents == 0:
		result.Verdict = DepAlertVerdictClean
	case result.UnknownComponents > 0:
		result.Verdict = DepAlertVerdictUnknown
	default:
		result.Verdict = DepAlertVerdictClean
	}
	result.Verdict = strings.ToUpper(strings.TrimSpace(result.Verdict))
	return result, nil
}
