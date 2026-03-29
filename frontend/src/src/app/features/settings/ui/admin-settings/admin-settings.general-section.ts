import { computed } from '@angular/core';
import { SettingsGeneralResponse } from '../../data-access/settings.types';
import { stringifyJson } from './admin-settings.utils';

export class AdminSettingsGeneralSectionController {
  readonly readOnlyLabel = computed(() =>
    this.generalAccessor()?.readOnly ? 'Yes' : 'No',
  );

  readonly configPath = computed(() => this.generalAccessor()?.configPath || '-');

  readonly generatedAt = computed(() => this.generalAccessor()?.generatedAt ?? null);

  readonly configJson = computed(() =>
    stringifyJson(this.generalAccessor()?.config ?? {}),
  );

  constructor(
    private readonly generalAccessor: () => SettingsGeneralResponse | null,
  ) {}
}
