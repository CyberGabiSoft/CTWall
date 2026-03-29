import { MalwareSource, MalwareSourceUpdatePayload } from './security.types';
import { getOwnValue, isSafeObjectKey } from '../../../shared/utils/safe-object';

export interface OsvConfigDraft {
  baseUrl: string;
  allZipUrl: string;
  modifiedCsvUrl: string;
  dataPath: string;
  timeout: string;
}

const readString = (value: unknown): string => (typeof value === 'string' ? value : '');

const readConfigValue = (config: Record<string, unknown>, keys: string[]): string => {
  for (const key of keys) {
    const safeKey = key.trim();
    const value = isSafeObjectKey(safeKey) ? readString(getOwnValue(config, safeKey)) : '';
    if (value) {
      return value;
    }
  }
  return '';
};

export const buildOsvConfigDraft = (source: MalwareSource): OsvConfigDraft => {
  const config = source.configJson ?? {};
  return {
    baseUrl: source.baseUrl ?? '',
    allZipUrl: readConfigValue(config, ['all_zip_url', 'allZipUrl']),
    modifiedCsvUrl: readConfigValue(config, ['modified_csv_url', 'modifiedCsvUrl']),
    dataPath: readConfigValue(config, ['results_data_path', 'resultsDataPath', 'data_path', 'dataPath']),
    timeout: readConfigValue(config, ['timeout'])
  };
};

export const buildOsvUpdatePayload = (draft: OsvConfigDraft): MalwareSourceUpdatePayload => ({
  baseUrl: draft.baseUrl,
  config: {
    all_zip_url: draft.allZipUrl,
    modified_csv_url: draft.modifiedCsvUrl,
    results_data_path: draft.dataPath,
    timeout: draft.timeout
  }
});
