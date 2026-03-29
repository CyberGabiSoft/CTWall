// NOTE: Using Vitest here because this module is pure and DI-free.
import { describe, expect, it } from 'vitest';
import { buildOsvConfigDraft, buildOsvUpdatePayload } from './security.utils';
import { MalwareSource } from './security.types';

describe('security.utils', () => {
  it('builds an OSV config draft from snake_case config', () => {
    const source: MalwareSource = {
      id: 'src-1',
      name: 'OSV',
      sourceType: 'OSV_MIRROR',
      baseUrl: 'https://example.com/osv',
      configJson: {
        all_zip_url: 'https://example.com/osv/all.zip',
        modified_csv_url: 'https://example.com/osv/modified_id.csv',
        results_data_path: 'osv',
        timeout: '30s'
      },
      isActive: true,
      createdAt: '2026-02-01T00:00:00Z'
    };

    const draft = buildOsvConfigDraft(source);
    expect(draft.baseUrl).toBe('https://example.com/osv');
    expect(draft.allZipUrl).toBe('https://example.com/osv/all.zip');
    expect(draft.modifiedCsvUrl).toBe('https://example.com/osv/modified_id.csv');
    expect(draft.dataPath).toBe('osv');
    expect(draft.timeout).toBe('30s');
  });

  it('builds update payload with snake_case keys', () => {
    const payload = buildOsvUpdatePayload({
      baseUrl: 'https://mirror.local',
      allZipUrl: 'https://mirror.local/all.zip',
      modifiedCsvUrl: 'https://mirror.local/modified_id.csv',
      dataPath: 'osv',
      timeout: '2m'
    });

    expect(payload.baseUrl).toBe('https://mirror.local');
    expect(payload.config?.['all_zip_url']).toBe('https://mirror.local/all.zip');
    expect(payload.config?.['modified_csv_url']).toBe('https://mirror.local/modified_id.csv');
    expect(payload.config?.['results_data_path']).toBe('osv');
    expect(payload.config?.['timeout']).toBe('2m');
  });
});
