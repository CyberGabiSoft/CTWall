import { describe, expect, it } from 'vitest';
import { MalwareSource, RecomputeHistoryEntry, ScanComponentResult, SyncHistoryEntry } from '../../data-access/security.types';
import {
  buildFindingsAdvancedFields,
  buildRecomputeHistoryDetailMap,
  buildRecomputeHistoryRows,
  buildSyncHistoryDetailMap,
  buildSyncHistoryRows,
  findingDisplayValue,
  findingValue,
  findingsDetailsJson,
  findingsEvidence,
  findingsDetailRows,
  recomputeHistoryActionLabel,
  sourceConfigValue,
  syncHistoryActionLabel,
} from './security-sources.mapper';

function createSource(): MalwareSource {
  return {
    id: 'source-1',
    name: 'OSV',
    sourceType: 'OSV_MIRROR',
    baseUrl: 'https://storage.googleapis.com/osv-vulnerabilities',
    configJson: { all_zip_url: 'https://example.com/all.zip' },
    isActive: true,
    createdAt: '2026-03-18T10:00:00Z',
  };
}

function createFinding(overrides: Partial<ScanComponentResult> = {}): ScanComponentResult {
  return {
    id: 'finding-1',
    componentPurl: 'pkg:npm/leftpad@1.0.0',
    scanId: 'scan-1',
    sourceId: 'source-1',
    detailsJson: { malwarePurl: 'pkg:npm/bad@1.2.3' },
    isMalware: true,
    createdAt: '2026-03-18T10:00:00Z',
    ...overrides,
  };
}

function createRecomputeEntry(overrides: Partial<RecomputeHistoryEntry> = {}): RecomputeHistoryEntry {
  return {
    id: 'recompute-log-1',
    action: 'MALWARE_SOURCE_RESULTS_RECOMPUTE_START',
    entityType: 'AUDIT_LOG',
    details: { recompute_id: 'recompute-1', started_at: '2026-03-18T10:00:00Z', affected: '12' },
    createdAt: '2026-03-18T10:00:00Z',
    ...overrides,
  };
}

function createSyncEntry(overrides: Partial<SyncHistoryEntry> = {}): SyncHistoryEntry {
  return {
    id: 'sync-log-1',
    action: 'MALWARE_OSV_SYNC_START',
    entityType: 'AUDIT_LOG',
    details: { sync_id: 'sync-1', mode: 'full', started_at: '2026-03-18T10:00:00Z', processed: '0' },
    createdAt: '2026-03-18T10:00:00Z',
    ...overrides,
  };
}

describe('security-sources.mapper', () => {
  it('maps action labels and source config values', () => {
    expect(syncHistoryActionLabel('MALWARE_OSV_SYNC_COMPLETE')).toBe('Sync completed');
    expect(recomputeHistoryActionLabel('MALWARE_SUMMARY_RECOMPUTE_FAILED')).toBe('Summaries recompute failed');
    expect(sourceConfigValue(createSource(), 'all_zip_url')).toBe('https://example.com/all.zip');
    expect(sourceConfigValue(createSource(), 'missing')).toBe('-');
  });

  it('maps finding values and details', () => {
    const finding = createFinding({ resultFilename: 'results.json', evidence: 'osv:malware' });
    expect(findingValue(finding, 'componentPurl')).toContain('pkg:npm');
    expect(findingDisplayValue(finding, 'resultFilename')).toBe('results.json');
    expect(findingsDetailRows(finding).some((detail) => detail.label === 'Component PURL')).toBe(true);
    expect(findingsEvidence(finding)).toBe('osv:malware');
    expect(findingsDetailsJson(finding)).toContain('malwarePurl');
  });

  it('builds recompute history rows and detail map', () => {
    const start = createRecomputeEntry();
    const complete = createRecomputeEntry({
      id: 'recompute-log-2',
      action: 'MALWARE_SOURCE_RESULTS_RECOMPUTE_COMPLETE',
      details: { recompute_id: 'recompute-1', finished_at: '2026-03-18T10:05:00Z', enqueued: '11' },
      createdAt: '2026-03-18T10:05:00Z',
    });
    const rows = buildRecomputeHistoryRows([start, complete]);
    expect(rows).toHaveLength(1);
    expect(rows[0]?.status).toBe('Completed');
    expect(rows[0]?.enqueued).toBe('11');

    const details = buildRecomputeHistoryDetailMap([start, complete]);
    expect(details.get('recompute-1')?.length).toBe(2);
  });

  it('builds sync history rows and detail map', () => {
    const start = createSyncEntry();
    const progress = createSyncEntry({
      id: 'sync-log-2',
      action: 'MALWARE_OSV_SYNC_PROGRESS',
      details: { sync_id: 'sync-1', processed: '25', errors: '1' },
      createdAt: '2026-03-18T10:02:00Z',
    });
    const complete = createSyncEntry({
      id: 'sync-log-3',
      action: 'MALWARE_OSV_SYNC_COMPLETE',
      details: { sync_id: 'sync-1', finished_at: '2026-03-18T10:04:00Z', processed: '50', errors: '1' },
      createdAt: '2026-03-18T10:04:00Z',
    });
    const rows = buildSyncHistoryRows([start, progress, complete]);
    expect(rows).toHaveLength(1);
    expect(rows[0]?.status).toBe('Completed');
    expect(rows[0]?.errorsCount).toBe(1);

    const details = buildSyncHistoryDetailMap([start, progress, complete]);
    const entries = details.get('sync-1') ?? [];
    expect(entries.length).toBeLessThanOrEqual(3);
  });

  it('builds advanced finding filter fields', () => {
    const fields = buildFindingsAdvancedFields(
      {
        componentPurl: 'contains',
        resultFilename: 'contains',
        detectVersion: 'select',
        fixedVersion: 'contains',
        isMalware: 'select',
      },
      {
        componentPurl: 'pkg:npm',
        resultFilename: '',
        detectVersion: '',
        fixedVersion: '',
        isMalware: '',
      },
      {
        componentPurl: [],
        resultFilename: [],
        detectVersion: ['1.2.3'],
        fixedVersion: [],
        isMalware: ['Yes'],
      },
      {
        detectVersion: ['1.2.3'],
        fixedVersion: ['2.0.0'],
        isMalware: ['Yes', 'No'],
      }
    );
    expect(fields).toHaveLength(5);
    expect(fields[0]?.key).toBe('componentPurl');
    expect(fields[4]?.options).toContain('Yes');
  });
});
