package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

const analysisResultsRecomputeTimeout = 5 * time.Minute

// RecomputeAnalysisResultsForSource recomputes aggregated rows in source_malware_input_results
// for component PURLs that appear in raw findings for the given source.
//
// This is intended as an admin-only repair operation to make the summary table converge
// with source_malware_input_component_results, and to backfill/repair analysis_result_id links.
func (s *PostgresStore) RecomputeAnalysisResultsForSource(sourceID uuid.UUID) (int, error) {
	if sourceID == uuid.Nil {
		return 0, ErrInvalidPayload
	}

	ctx, cancel := context.WithTimeout(context.Background(), analysisResultsRecomputeTimeout)
	defer cancel()

	// Even though source_id is not an FK, we treat it as a logical FK for safety.
	if err := ensureSourceExists(ctx, s.db, sourceID); err != nil {
		return 0, err
	}

	scannedAt := time.Now().UTC()

	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return 0, fmt.Errorf("begin tx: %w", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()

	// Protect against concurrent recompute runs per source within a single backend process.
	// This also helps to avoid large, simultaneous writes.
	var locked bool
	if err := tx.QueryRowContext(ctx,
		`SELECT pg_try_advisory_xact_lock(hashtext('ctwall_source_results_recompute'), hashtext($1::text))`,
		sourceID,
	).Scan(&locked); err != nil {
		return 0, fmt.Errorf("advisory lock: %w", err)
	}
	if !locked {
		return 0, ErrBusy
	}

	var affected int
	if err := tx.QueryRowContext(ctx,
		`WITH targets AS (
			 SELECT DISTINCT component_purl
			 FROM source_malware_input_component_results
			 WHERE source_id = $1
		 ),
		 stats AS (
			 SELECT r.component_purl,
			        COUNT(*) AS findings_count,
			        COALESCE(bool_or(r.is_malware), FALSE) AS has_malware,
			        NULLIF(MAX(BTRIM(r.component_hash)), '') AS component_hash
			 FROM source_malware_input_component_results r
			 JOIN targets t ON t.component_purl = r.component_purl
			 GROUP BY r.component_purl
		 ),
		 upserted AS (
			 INSERT INTO source_malware_input_results (
				 component_purl, component_hash, verdict, findings_count, summary, scanned_at, valid_until
			 )
			 SELECT s.component_purl,
			        s.component_hash,
			        CASE WHEN s.has_malware THEN 'MALWARE' ELSE 'CLEAN' END,
			        s.findings_count,
			        NULL,
			        $2,
			        NULL
			 FROM stats s
			 ON CONFLICT (component_purl) DO UPDATE SET
				 component_hash = COALESCE(EXCLUDED.component_hash, source_malware_input_results.component_hash),
				 verdict = EXCLUDED.verdict,
				 findings_count = EXCLUDED.findings_count,
				 scanned_at = EXCLUDED.scanned_at
			 RETURNING id, component_purl
		 ),
		 linked AS (
			 UPDATE source_malware_input_component_results r
			 SET analysis_result_id = u.id
			 FROM upserted u
			 WHERE r.component_purl = u.component_purl
			 RETURNING 1
		 )
		 SELECT COALESCE((SELECT COUNT(*) FROM upserted), 0)`,
		sourceID,
		scannedAt,
	).Scan(&affected); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// No targets -> no upserts.
			affected = 0
		} else {
			return 0, fmt.Errorf("recompute analysis results: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit: %w", err)
	}

	return affected, nil
}
