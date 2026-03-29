import { HttpErrorResponse } from '@angular/common/http';
import {
  ChangeDetectionStrategy,
  Component,
  ErrorHandler,
  computed,
  inject,
  signal,
} from '@angular/core';
import { NonNullableFormBuilder, ReactiveFormsModule } from '@angular/forms';
import { MAT_DIALOG_DATA, MatDialogModule, MatDialogRef } from '@angular/material/dialog';
import { MatButtonModule } from '@angular/material/button';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatSelectModule } from '@angular/material/select';
import { MatSlideToggleModule } from '@angular/material/slide-toggle';
import { MatSnackBar } from '@angular/material/snack-bar';
import { LoadingIndicatorComponent } from '../../../../shared/ui/loading-indicator/loading-indicator.component';
import { DataApi } from '../../data-access/data.api';
import {
  JiraConfigLevel,
  JiraDeliveryAttempt,
  JiraEffectiveSettings,
  JiraEntitySettings,
  JiraEntitySettingsUpsertPayload,
  JiraIssueMapping,
  JiraMetadataComponent,
  JiraMetadataIssue,
  JiraMetadataIssueField,
  JiraMetadataIssueFieldOption,
  JiraMetadataIssueType,
  JiraMetadataPriority,
  JiraMetadataProject,
  JiraMetadataTransition,
} from '../../data-access/data.types';
import { LoadState } from '../../../../shared/types/load-state';

const JIRA_EPIC_ISSUE_KEY_FIELD = '__ctwall_epic_issue_key';
const JIRA_EPIC_FIELD_KEY_FIELD = '__ctwall_epic_field_key';
const JIRA_EPIC_MODE_FIELD = '__ctwall_epic_mode';

type JiraEpicMode = 'none' | 'existing';

export interface JiraEntitySettingsDialogData {
  level: JiraConfigLevel;
  targetId: string;
  targetName: string;
}

@Component({
  selector: 'app-jira-entity-settings-dialog',
  imports: [
    ReactiveFormsModule,
    MatDialogModule,
    MatButtonModule,
    MatFormFieldModule,
    MatInputModule,
    MatSelectModule,
    MatSlideToggleModule,
    LoadingIndicatorComponent,
  ],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './jira-entity-settings-dialog.component.html',
  styleUrl: './jira-entity-settings-dialog.component.scss',
})
export class JiraEntitySettingsDialogComponent {
  readonly deliveryRetryAttemptsDefault = 0;
  readonly deliveryRetryAttemptsMin = 0;
  readonly deliveryRetryAttemptsMax = 20;
  readonly deliveryRetryBackoffSecondsDefault = 10;
  readonly deliveryRetryBackoffSecondsMin = 1;
  readonly deliveryRetryBackoffSecondsMax = 3600;

  readonly data = inject<JiraEntitySettingsDialogData>(MAT_DIALOG_DATA);
  private readonly ref = inject(MatDialogRef<JiraEntitySettingsDialogComponent, boolean>);
  private readonly api = inject(DataApi);
  private readonly fb = inject(NonNullableFormBuilder);
  private readonly snackBar = inject(MatSnackBar);
  private readonly errorHandler = inject(ErrorHandler);

  readonly loadState = signal<LoadState>('idle');
  readonly errorMessage = signal<string | null>(null);
  readonly metadataState = signal<LoadState>('idle');
  readonly metadataError = signal<string | null>(null);
  readonly saving = signal(false);

  readonly projects = signal<JiraMetadataProject[]>([]);
  readonly jiraBrowseBaseUrl = signal('');
  readonly issueTypes = signal<JiraMetadataIssueType[]>([]);
  readonly componentsOptions = signal<JiraMetadataComponent[]>([]);
  readonly priorities = signal<JiraMetadataPriority[]>([]);
  readonly transitionSourceIssues = signal<JiraMetadataIssue[]>([]);
  readonly epicIssues = signal<JiraMetadataIssue[]>([]);
  readonly epicIssueSearch = signal('');
  readonly filteredEpicIssues = computed(() => {
    const query = this.epicIssueSearch().trim().toLowerCase();
    const issues = this.epicIssues();
    if (!query) {
      return issues;
    }
    return issues.filter((issue) => {
      const key = (issue.key ?? '').toLowerCase();
      const summary = (issue.summary ?? '').toLowerCase();
      const status = (issue.status ?? '').toLowerCase();
      return key.includes(query) || summary.includes(query) || status.includes(query);
    });
  });
  readonly transitions = signal<JiraMetadataTransition[]>(this.defaultTransitions());
  readonly requiredIssueFields = signal<JiraMetadataIssueField[]>([]);
  readonly requiredIssueFieldValues = signal<Record<string, unknown>>({});
  private readonly persistedIssueFields = signal<Record<string, unknown>>({});

  readonly issueMappings = signal<JiraIssueMapping[]>([]);
  readonly deliveries = signal<JiraDeliveryAttempt[]>([]);
  readonly retryingAlertGroupIDs = signal<Set<string>>(new Set<string>());
  readonly syncAllLinkedIssuesInProgress = signal(false);
  readonly issuesLoading = signal(false);
  readonly issuesStatusFilter = signal<'open' | 'closed' | 'all'>('all');
  readonly issuesComponentFilter = signal('');
  readonly issuesJiraKeyFilter = signal('');
  readonly issuesPage = signal(1);
  readonly issuesPageSize = signal(25);
  readonly issuesTotal = signal(0);
  readonly issuesTotalPages = computed(() => {
    const size = this.issuesPageSize();
    if (size <= 0) {
      return 0;
    }
    return Math.ceil(this.issuesTotal() / size);
  });
  readonly effectiveSettings = signal<JiraEffectiveSettings | null>(null);
  readonly effectiveSettingsMissing = signal(false);

  readonly canShowEffective = computed(() => this.data.level === 'TEST');
  readonly hasProjectOptions = computed(() => this.projects().length > 0);
  readonly hasEpicIssueOptions = computed(() => this.epicIssues().length > 0);
  readonly metadataHint = signal('Metadata can be refreshed on demand when Jira changes.');
  readonly summaryTemplateVariables = [
    { token: '{{project}}', description: 'Project name (or project ID fallback)' },
    { token: '{{product}}', description: 'Product name' },
    { token: '{{scope}}', description: 'Scope name' },
    { token: '{{test}}', description: 'Test name' },
    { token: '{{component_purl}}', description: 'Component PURL from malware occurrence context' },
    { token: '{{severity}}', description: 'Alert severity (INFO/WARNING/ERROR)' },
    { token: '{{finding_count}}', description: 'Number of grouped occurrences' },
    { token: '{{dedup_key}}', description: 'Alert group deduplication key' },
    { token: '{{alert_type}}', description: 'Alert type, e.g. malware.detected' },
  ] as const;
  readonly knownTransitionIssues = computed(() =>
    this.extractKnownTransitionIssues(this.issueMappings()),
  );
  readonly transitionSourceIssue = computed(() => {
    const fromProject = this.transitionSourceIssues()[0]?.key?.trim() ?? '';
    if (fromProject) {
      return fromProject;
    }
    return this.knownTransitionIssues()[0] ?? '';
  });
  readonly availableTransitionNamesLabel = computed(() => {
    const names = Array.from(
      new Set(
        this.transitions()
          .map((item) => (item.name ?? '').trim())
          .filter((item) => item.length > 0),
      ),
    );
    if (names.length === 0) {
      return 'No transition states available.';
    }
    return names.join(', ');
  });
  private issuesFiltersReloadTimer: ReturnType<typeof window.setTimeout> | null = null;

  readonly form = this.fb.group({
    isEnabled: this.fb.control(false),
    jiraProjectKey: this.fb.control(''),
    issueType: this.fb.control(''),
    issueTypeCustom: this.fb.control(''),
    deliveryRetryAttempts: this.fb.control(this.deliveryRetryAttemptsDefault),
    deliveryRetryBackoffSeconds: this.fb.control(this.deliveryRetryBackoffSecondsDefault),
    transitionIssueIdOrKey: this.fb.control(''),
    openTransitionName: this.fb.control(''),
    resolveTransitionName: this.fb.control(''),
    epicMode: this.fb.control<JiraEpicMode>('none'),
    epicIssueKey: this.fb.control(''),
    epicFieldKey: this.fb.control(''),
    labelsText: this.fb.control(''),
    components: this.fb.control<string[]>([]),
    priorityInfo: this.fb.control(''),
    priorityWarning: this.fb.control(''),
    priorityError: this.fb.control(''),
    ticketSummaryTemplate: this.fb.control(''),
  });

  constructor() {
    void this.loadAll(false);
  }

  close(saved = false): void {
    this.ref.close(saved);
  }

  async refreshAll(): Promise<void> {
    await this.loadAll(true);
  }

  async refreshMetadata(): Promise<void> {
    await this.loadMetadata(true);
    await this.loadTransitionsMetadata(true);
  }

  hasSelectedProject(): boolean {
    return this.form.controls.jiraProjectKey.value.trim().length > 0;
  }

  hasSelectedOrCustomIssueType(): boolean {
    return this.currentIssueTypeValue().length > 0;
  }

  epicMode(): JiraEpicMode {
    return this.normalizeEpicMode(this.form.controls.epicMode.value);
  }

  isEpicModeExisting(): boolean {
    return this.epicMode() === 'existing';
  }

  async onProjectKeyChange(nextValue: string): Promise<void> {
    this.form.controls.jiraProjectKey.setValue((nextValue ?? '').trim());
    await this.loadProjectMetadata(this.form.controls.jiraProjectKey.value, false);
  }

  async onIssueTypeChange(nextValue: string): Promise<void> {
    this.form.controls.issueType.setValue((nextValue ?? '').trim());
    this.form.controls.issueTypeCustom.setValue('');
    await this.loadRequiredIssueFields(
      this.form.controls.jiraProjectKey.value,
      this.currentIssueTypeValue(),
      false,
    );
  }

  async onIssueTypeCustomChange(nextValue: string): Promise<void> {
    const custom = (nextValue ?? '').trim();
    this.form.controls.issueTypeCustom.setValue(custom);
    if (custom) {
      this.form.controls.issueType.setValue('');
    }
    await this.loadRequiredIssueFields(
      this.form.controls.jiraProjectKey.value,
      this.currentIssueTypeValue(),
      false,
    );
  }

  onEpicModeChange(nextValue: JiraEpicMode): void {
    const normalized = this.normalizeEpicMode(nextValue);
    this.form.controls.epicMode.setValue(normalized);
    if (normalized !== 'existing') {
      this.epicIssueSearch.set('');
    }
  }

  onEpicIssueSelect(nextValue: string): void {
    this.form.controls.epicIssueKey.setValue((nextValue ?? '').trim());
  }

  onEpicIssueSearchChange(nextValue: string): void {
    this.epicIssueSearch.set((nextValue ?? '').trim());
  }

  async setIssuesStatusFilter(status: 'open' | 'closed' | 'all'): Promise<void> {
    this.issuesStatusFilter.set(status);
    this.issuesPage.set(1);
    await this.loadIssues();
  }

  setIssuesComponentFilter(value: string): void {
    this.issuesComponentFilter.set((value ?? '').trim());
    this.scheduleIssuesFiltersReload();
  }

  setIssuesJiraKeyFilter(value: string): void {
    this.issuesJiraKeyFilter.set((value ?? '').trim());
    this.scheduleIssuesFiltersReload();
  }

  async prevIssuesPage(): Promise<void> {
    const current = this.issuesPage();
    if (current <= 1) {
      return;
    }
    this.issuesPage.set(current - 1);
    await this.loadIssues();
  }

  async nextIssuesPage(): Promise<void> {
    const current = this.issuesPage();
    const totalPages = this.issuesTotalPages();
    if (totalPages > 0 && current >= totalPages) {
      return;
    }
    this.issuesPage.set(current + 1);
    await this.loadIssues();
  }

  canRetryDelivery(attempt: JiraDeliveryAttempt): boolean {
    const groupID = (attempt.alertGroupId ?? '').trim();
    return groupID.length > 0;
  }

  isRetryingDelivery(attempt: JiraDeliveryAttempt): boolean {
    const groupID = (attempt.alertGroupId ?? '').trim();
    if (!groupID) {
      return false;
    }
    return this.retryingAlertGroupIDs().has(groupID);
  }

  isRetryingAlertGroupID(groupIDRaw: string | null | undefined): boolean {
    const groupID = (groupIDRaw ?? '').trim();
    if (!groupID) {
      return false;
    }
    return this.retryingAlertGroupIDs().has(groupID);
  }

  canRetryIssueMapping(issue: JiraIssueMapping): boolean {
    return (issue.alertGroupId ?? '').trim().length > 0;
  }

  async retryDeliveryAttempt(attempt: JiraDeliveryAttempt): Promise<void> {
    const groupID = (attempt.alertGroupId ?? '').trim();
    if (!groupID) {
      this.snackBar.open(
        'Cannot retry: missing alert group ID for this delivery attempt.',
        'Dismiss',
        { duration: 3200 },
      );
      return;
    }
    if (this.retryingAlertGroupIDs().has(groupID)) {
      return;
    }

    this.retryingAlertGroupIDs.update((current) => {
      const next = new Set(current);
      next.add(groupID);
      return next;
    });
    try {
      await this.queueRetryByAlertGroup(groupID);
      this.snackBar.open('✓ Jira retry job queued.', 'Dismiss', { duration: 2400 });
      await Promise.all([this.loadDeliveries(), this.loadIssues()]);
    } finally {
      this.retryingAlertGroupIDs.update((current) => {
        const next = new Set(current);
        next.delete(groupID);
        return next;
      });
    }
  }

  async retryIssueMapping(issue: JiraIssueMapping): Promise<void> {
    const groupID = (issue.alertGroupId ?? '').trim();
    if (!groupID) {
      this.snackBar.open('Cannot retry: missing alert group ID for this Jira issue.', 'Dismiss', {
        duration: 3200,
      });
      return;
    }
    if (this.retryingAlertGroupIDs().has(groupID)) {
      return;
    }

    this.retryingAlertGroupIDs.update((current) => {
      const next = new Set(current);
      next.add(groupID);
      return next;
    });
    try {
      await this.queueRetryByAlertGroup(groupID);
      this.snackBar.open('✓ Jira sync job queued for selected issue.', 'Dismiss', {
        duration: 2400,
      });
      await Promise.all([this.loadDeliveries(), this.loadIssues()]);
    } finally {
      this.retryingAlertGroupIDs.update((current) => {
        const next = new Set(current);
        next.delete(groupID);
        return next;
      });
    }
  }

  async syncAllLinkedIssues(): Promise<void> {
    if (this.syncAllLinkedIssuesInProgress()) {
      return;
    }
    this.syncAllLinkedIssuesInProgress.set(true);
    this.errorMessage.set(null);
    try {
      const mappings = await this.fetchAllIssueMappingsForSync();
      const alertGroupIDs = Array.from(
        new Set(
          mappings
            .filter((item) => {
              const issueKey = (item.jiraIssueKey ?? '').trim();
              const issueID = (item.jiraIssueId ?? '').trim();
              return issueKey.length > 0 || issueID.length > 0;
            })
            .map((item) => (item.alertGroupId ?? '').trim())
            .filter((value) => value.length > 0),
        ),
      );

      if (alertGroupIDs.length === 0) {
        this.snackBar.open('No linked Jira issues to synchronize.', 'Dismiss', { duration: 2600 });
        return;
      }

      let queued = 0;
      let failed = 0;
      for (const alertGroupID of alertGroupIDs) {
        try {
          await this.queueRetryByAlertGroup(alertGroupID);
          queued++;
        } catch {
          failed++;
        }
      }

      if (failed === 0) {
        this.snackBar.open(
          `✓ Jira sync queued for ${queued} linked issue${queued === 1 ? '' : 's'}.`,
          'Dismiss',
          { duration: 3400 },
        );
      } else {
        this.snackBar.open(
          `Queued ${queued} Jira sync job${queued === 1 ? '' : 's'}, failed ${failed}.`,
          'Dismiss',
          { duration: 4200 },
        );
      }
      await Promise.all([this.loadDeliveries(), this.loadIssues()]);
    } catch (error) {
      this.errorHandler.handleError(error);
      this.errorMessage.set(
        this.resolveErrorMessage(error, 'Failed to queue Jira sync for linked issues.'),
      );
    } finally {
      this.syncAllLinkedIssuesInProgress.set(false);
    }
  }

  async save(): Promise<void> {
    if (this.saving()) {
      return;
    }

    const retryAttemptsValue = Number(this.form.controls.deliveryRetryAttempts.value);
    const retryBackoffValue = Number(this.form.controls.deliveryRetryBackoffSeconds.value);
    const retryAttempts = Number.isFinite(retryAttemptsValue)
      ? Math.trunc(retryAttemptsValue)
      : NaN;
    const retryBackoff = Number.isFinite(retryBackoffValue) ? Math.trunc(retryBackoffValue) : NaN;
    if (
      !Number.isFinite(retryAttempts) ||
      retryAttempts < this.deliveryRetryAttemptsMin ||
      retryAttempts > this.deliveryRetryAttemptsMax
    ) {
      this.errorMessage.set(
        `Retry attempts must be between ${this.deliveryRetryAttemptsMin} and ${this.deliveryRetryAttemptsMax}.`,
      );
      return;
    }
    if (
      !Number.isFinite(retryBackoff) ||
      retryBackoff < this.deliveryRetryBackoffSecondsMin ||
      retryBackoff > this.deliveryRetryBackoffSecondsMax
    ) {
      this.errorMessage.set(
        `Retry backoff must be between ${this.deliveryRetryBackoffSecondsMin} and ${this.deliveryRetryBackoffSecondsMax} seconds.`,
      );
      return;
    }

    const payload = this.toUpsertPayload();
    if (payload.isEnabled) {
      if (!payload.jiraProjectKey || !payload.issueType || !payload.ticketSummaryTemplate) {
        this.errorMessage.set(
          'Enabled Jira settings require Jira project key, issue type and ticket summary template.',
        );
        return;
      }
      const epicMode = this.normalizeEpicMode(this.form.controls.epicMode.value);
      if (epicMode === 'existing' && !this.form.controls.epicIssueKey.value.trim()) {
        this.errorMessage.set('Existing Epic mode requires selecting or entering Epic issue key.');
        return;
      }
    }

    this.saving.set(true);
    this.errorMessage.set(null);
    try {
      await this.putSettings(payload);
      this.snackBar.open('✓ Jira settings saved.', 'Dismiss', { duration: 2800 });
      await this.loadAll(false);
    } catch (error) {
      this.errorHandler.handleError(error);
      this.errorMessage.set(this.resolveErrorMessage(error, 'Failed to save Jira settings.'));
    } finally {
      this.saving.set(false);
    }
  }

  trackIssueField(_index: number, field: JiraMetadataIssueField): string {
    return field.key;
  }

  issueFieldOptionToken(option: JiraMetadataIssueFieldOption): string {
    return (option.id ?? option.value ?? option.name ?? '').trim();
  }

  issueFieldOptionLabel(option: JiraMetadataIssueFieldOption): string {
    return (option.name ?? option.value ?? option.id ?? '').trim();
  }

  issueFieldTextValue(fieldKey: string): string {
    const value = this.readRecordValue(this.requiredIssueFieldValues(), fieldKey);
    if (typeof value === 'string') {
      return value;
    }
    if (typeof value === 'number') {
      return String(value);
    }
    return '';
  }

  issueFieldSingleSelectValue(fieldKey: string): string {
    const value = this.readRecordValue(this.requiredIssueFieldValues(), fieldKey);
    return typeof value === 'string' ? value : '';
  }

  issueFieldMultiSelectValue(fieldKey: string): string[] {
    const value = this.readRecordValue(this.requiredIssueFieldValues(), fieldKey);
    if (!Array.isArray(value)) {
      return [];
    }
    return value.map((item) => String(item ?? '').trim()).filter((item) => item.length > 0);
  }

  issueFieldBooleanValue(fieldKey: string): boolean | '' {
    const value = this.readRecordValue(this.requiredIssueFieldValues(), fieldKey);
    if (typeof value === 'boolean') {
      return value;
    }
    return '';
  }

  setIssueFieldTextValue(fieldKey: string, value: string): void {
    this.setIssueFieldValue(fieldKey, value);
  }

  setIssueFieldSingleSelectValue(fieldKey: string, value: string): void {
    this.setIssueFieldValue(fieldKey, (value ?? '').trim());
  }

  setIssueFieldMultiSelectValue(fieldKey: string, value: string[]): void {
    this.setIssueFieldValue(
      fieldKey,
      (value ?? []).map((item) => (item ?? '').trim()).filter((item) => item.length > 0),
    );
  }

  setIssueFieldBooleanValue(fieldKey: string, value: boolean | ''): void {
    this.setIssueFieldValue(fieldKey, value);
  }

  private setIssueFieldValue(fieldKey: string, value: unknown): void {
    this.requiredIssueFieldValues.update((current) => ({
      ...current,
      ...this.recordWithValue(fieldKey, value),
    }));
  }

  private async loadAll(forceMetadataRefresh: boolean): Promise<void> {
    this.loadState.set('loading');
    this.errorMessage.set(null);
    try {
      const [settings] = await Promise.all([
        this.getSettings(),
        this.loadIssues(),
        this.loadDeliveries(),
        this.loadEffectiveSettings(),
      ]);
      this.patchForm(settings);
      await this.loadMetadata(forceMetadataRefresh);
      await this.loadTransitionsMetadata(forceMetadataRefresh);
      this.loadState.set('loaded');
    } catch (error) {
      this.errorHandler.handleError(error);
      this.errorMessage.set(this.resolveErrorMessage(error, 'Failed to load Jira settings.'));
      this.transitions.set(this.defaultTransitions());
      this.loadState.set('error');
    }
  }

  private async loadMetadata(forceRefresh: boolean): Promise<void> {
    this.metadataState.set('loading');
    this.metadataError.set(null);
    try {
      const [projectsResponseResult, prioritiesResponseResult] = await Promise.allSettled([
        this.api.getJiraMetadataProjects(forceRefresh),
        this.api.getJiraMetadataPriorities(forceRefresh),
      ]);

      if (projectsResponseResult.status !== 'fulfilled') {
        throw projectsResponseResult.reason;
      }

      const projectsResponse = projectsResponseResult.value;
      this.jiraBrowseBaseUrl.set((projectsResponse.baseUrl ?? '').trim());
      const prioritiesResponse =
        prioritiesResponseResult.status === 'fulfilled' ? prioritiesResponseResult.value : null;

      const projects = projectsResponse.items ?? [];
      const priorities = prioritiesResponse?.items?.length
        ? prioritiesResponse.items
        : this.defaultPriorities();
      const currentProjectKey = this.form.controls.jiraProjectKey.value.trim();
      const normalizedProjects = this.ensureCurrentProjectInOptions(projects, currentProjectKey);
      this.projects.set(normalizedProjects);
      this.priorities.set(priorities);

      if (!currentProjectKey && normalizedProjects.length > 0) {
        this.form.controls.jiraProjectKey.setValue(normalizedProjects[0]?.key ?? '');
      }
      await this.loadProjectMetadata(this.form.controls.jiraProjectKey.value, forceRefresh);

      const fromCache =
        projectsResponse.fromCache && (prioritiesResponse ? prioritiesResponse.fromCache : false);
      if (prioritiesResponseResult.status !== 'fulfilled') {
        this.metadataHint.set('Projects loaded from Jira. Priorities fallback was applied.');
      } else {
        this.metadataHint.set(
          fromCache ? 'Metadata loaded from cache.' : 'Metadata refreshed from Jira.',
        );
      }
      this.metadataState.set('loaded');
    } catch (error) {
      this.errorHandler.handleError(error);
      this.metadataError.set(this.resolveErrorMessage(error, 'Failed to load Jira metadata.'));
      this.metadataState.set('error');
    }
  }

  jiraIssueBrowseUrl(issue: JiraIssueMapping): string | null {
    const issueKey = (issue.jiraIssueKey ?? '').trim();
    if (!issueKey) {
      return null;
    }
    const base = this.jiraBrowseBaseUrl();
    if (!base) {
      return null;
    }
    return `${base.replace(/\/+$/, '')}/browse/${encodeURIComponent(issueKey)}`;
  }

  private async loadProjectMetadata(projectKeyRaw: string, forceRefresh: boolean): Promise<void> {
    const projectKey = (projectKeyRaw ?? '').trim();
    if (!projectKey) {
      this.issueTypes.set([]);
      this.componentsOptions.set([]);
      this.transitionSourceIssues.set([]);
      this.epicIssues.set([]);
      this.epicIssueSearch.set('');
      this.requiredIssueFields.set([]);
      this.requiredIssueFieldValues.set({});
      this.form.controls.issueType.setValue('');
      this.form.controls.issueTypeCustom.setValue('');
      this.form.controls.components.setValue([]);
      this.form.controls.transitionIssueIdOrKey.setValue('');
      this.transitions.set([]);
      return;
    }

    const [issueTypesResult, componentsResult] = await Promise.allSettled([
      this.api.getJiraMetadataIssueTypes(projectKey, forceRefresh),
      this.api.getJiraMetadataComponents(projectKey, forceRefresh),
    ]);

    let issueTypesLoaded = false;
    if (issueTypesResult.status === 'fulfilled') {
      this.issueTypes.set(issueTypesResult.value.items ?? []);
      issueTypesLoaded = true;
    } else {
      this.errorHandler.handleError(issueTypesResult.reason);
      this.issueTypes.set([]);
      this.form.controls.issueType.setValue('');
      this.requiredIssueFields.set([]);
      this.requiredIssueFieldValues.set({});
      this.metadataError.set(
        this.resolveErrorMessage(
          issueTypesResult.reason,
          'Failed to load Jira issue types for selected project.',
        ),
      );
    }

    if (componentsResult.status === 'fulfilled') {
      this.componentsOptions.set(componentsResult.value.items ?? []);
    } else {
      this.errorHandler.handleError(componentsResult.reason);
      this.componentsOptions.set([]);
      if (!this.metadataError()) {
        this.metadataError.set(
          this.resolveErrorMessage(
            componentsResult.reason,
            'Failed to load Jira components for selected project.',
          ),
        );
      }
    }

    const selectedIssueType = this.form.controls.issueType.value.trim();
    const customIssueType = this.form.controls.issueTypeCustom.value.trim();
    if (
      selectedIssueType &&
      !this.issueTypes().some((item) => item.name === selectedIssueType)
    ) {
      if (!customIssueType) {
        this.form.controls.issueTypeCustom.setValue(selectedIssueType);
      }
      this.form.controls.issueType.setValue('');
    }

    const selectedComponents = this.form.controls.components.value ?? [];
    const allowed = new Set(this.componentsOptions().map((item) => item.name));
    this.form.controls.components.setValue(
      selectedComponents.filter((item) => allowed.has(item)),
    );

    await this.loadTransitionSourceIssues(projectKey, forceRefresh);
    await this.loadEpicIssues(projectKey, forceRefresh);
    if (issueTypesLoaded) {
      await this.loadRequiredIssueFields(
        projectKey,
        this.currentIssueTypeValue(),
        forceRefresh,
      );
    }
    await this.loadTransitionsMetadata(forceRefresh);
  }

  private async loadTransitionSourceIssues(
    projectKeyRaw: string,
    forceRefresh: boolean,
  ): Promise<void> {
    const projectKey = (projectKeyRaw ?? '').trim();
    if (!projectKey) {
      this.transitionSourceIssues.set([]);
      this.form.controls.transitionIssueIdOrKey.setValue('');
      this.transitions.set([]);
      return;
    }

    try {
      const response = await this.api.getJiraMetadataIssues(projectKey, forceRefresh);
      const issues = response.items ?? [];
      this.transitionSourceIssues.set(issues);
      this.form.controls.transitionIssueIdOrKey.setValue(this.transitionSourceIssue());
    } catch (error) {
      this.errorHandler.handleError(error);
      this.metadataError.set(
        this.resolveErrorMessage(error, 'Failed to load Jira issues for selected project.'),
      );
      this.transitionSourceIssues.set([]);
      this.form.controls.transitionIssueIdOrKey.setValue(this.transitionSourceIssue());
    }
  }

  private async loadEpicIssues(projectKeyRaw: string, forceRefresh: boolean): Promise<void> {
    const projectKey = (projectKeyRaw ?? '').trim();
    if (!projectKey) {
      this.epicIssues.set([]);
      this.epicIssueSearch.set('');
      return;
    }

    try {
      const response = await this.api.getJiraMetadataIssues(projectKey, forceRefresh);
      this.epicIssues.set(response.items ?? []);
    } catch {
      this.epicIssues.set([]);
    }
  }

  private async loadRequiredIssueFields(
    projectKeyRaw: string,
    issueTypeNameRaw: string,
    forceRefresh: boolean,
  ): Promise<void> {
    const projectKey = (projectKeyRaw ?? '').trim();
    const issueTypeName = (issueTypeNameRaw ?? '').trim();
    if (!projectKey || !issueTypeName) {
      this.requiredIssueFields.set([]);
      this.requiredIssueFieldValues.set({});
      return;
    }

    const issueTypeId = this.resolveIssueTypeId(issueTypeName);
    if (!issueTypeId) {
      this.requiredIssueFields.set([]);
      this.requiredIssueFieldValues.set({});
      return;
    }

    try {
      const response = await this.api.getJiraMetadataIssueFields(
        projectKey,
        issueTypeId,
        forceRefresh,
      );
      const fields = response.items ?? [];
      this.requiredIssueFields.set(fields);

      const currentValues = this.requiredIssueFieldValues();
      const persistedValues = this.persistedIssueFields();
      const nextValues: Record<string, unknown> = {};
      for (const field of fields) {
        const key = field.key;
        if (this.hasRecordValue(currentValues, key)) {
          this.assignRecordValue(nextValues, key, this.readRecordValue(currentValues, key));
          continue;
        }
        if (this.hasRecordValue(persistedValues, key)) {
          this.assignRecordValue(
            nextValues,
            key,
            this.convertStoredIssueFieldValueToControl(
              field,
              this.readRecordValue(persistedValues, key),
            ),
          );
          continue;
        }
        this.assignRecordValue(nextValues, key, this.defaultIssueFieldControlValue(field));
      }
      this.requiredIssueFieldValues.set(nextValues);
    } catch {
      this.requiredIssueFields.set([]);
      this.requiredIssueFieldValues.set({});
    }
  }

  private async loadTransitionsMetadata(forceRefresh: boolean): Promise<void> {
    const issueIDOrKey = this.transitionSourceIssue();
    this.form.controls.transitionIssueIdOrKey.setValue(issueIDOrKey);
    if (!issueIDOrKey) {
      this.transitions.set(this.defaultTransitions());
      return;
    }
    try {
      const response = await this.api.getJiraMetadataTransitions(issueIDOrKey, forceRefresh);
      const items = response.items ?? [];
      this.transitions.set(items.length > 0 ? items : this.defaultTransitions());
    } catch {
      this.transitions.set(this.defaultTransitions());
    }
  }

  private resolveIssueTypeId(issueTypeName: string): string {
    const normalized = issueTypeName.trim().toLowerCase();
    const issueType = this.issueTypes().find(
      (item) => item.name.trim().toLowerCase() === normalized,
    );
    return (issueType?.id ?? '').trim();
  }

  private currentIssueTypeValue(): string {
    const custom = this.form.controls.issueTypeCustom.value.trim();
    if (custom) {
      return custom;
    }
    return this.form.controls.issueType.value.trim();
  }

  private normalizeEpicMode(value: string | JiraEpicMode): JiraEpicMode {
    const normalized = String(value ?? '').trim().toLowerCase();
    if (normalized === 'existing') {
      return 'existing';
    }
    return 'none';
  }

  private defaultPriorities(): JiraMetadataPriority[] {
    return [
      { id: 'highest', name: 'Highest' },
      { id: 'high', name: 'High' },
      { id: 'medium', name: 'Medium' },
      { id: 'low', name: 'Low' },
      { id: 'lowest', name: 'Lowest' },
    ];
  }

  private defaultTransitions(): JiraMetadataTransition[] {
    return [
      { id: 'todo', name: 'To Do' },
      { id: 'in_progress', name: 'In Progress' },
      { id: 'done', name: 'Done' },
      { id: 'closed', name: 'Closed' },
      { id: 'resolve_issue', name: 'Resolve Issue' },
      { id: 'reopen', name: 'Reopen' },
    ];
  }

  private ensureCurrentProjectInOptions(
    projects: JiraMetadataProject[],
    currentProjectKey: string,
  ): JiraMetadataProject[] {
    const normalizedCurrent = (currentProjectKey ?? '').trim();
    if (!normalizedCurrent) {
      return projects ?? [];
    }
    const existing = (projects ?? []).some(
      (item) => (item?.key ?? '').trim() === normalizedCurrent,
    );
    if (existing) {
      return projects ?? [];
    }
    return [
      {
        id: '',
        key: normalizedCurrent,
        name: 'Configured value',
      },
      ...(projects ?? []),
    ];
  }

  private async loadEffectiveSettings(): Promise<void> {
    if (this.data.level !== 'TEST') {
      this.effectiveSettings.set(null);
      this.effectiveSettingsMissing.set(false);
      return;
    }

    try {
      const response = await this.api.getTestEffectiveJiraSettings(this.data.targetId);
      this.effectiveSettings.set(response);
      this.effectiveSettingsMissing.set(false);
    } catch (error) {
      if (error instanceof HttpErrorResponse && error.status === 404) {
        this.effectiveSettings.set(null);
        this.effectiveSettingsMissing.set(true);
        return;
      }
      throw error;
    }
  }

  private async loadIssues(): Promise<void> {
    this.issuesLoading.set(true);
    try {
      const issuesResponse = await this.api.listJiraIssuesByOwnerWithFilters(
        this.data.level,
        this.data.targetId,
        {
          page: this.issuesPage(),
          pageSize: this.issuesPageSize(),
          status: this.issuesStatusFilter(),
          component: this.issuesComponentFilter(),
          jiraKey: this.issuesJiraKeyFilter(),
        },
      );
      this.issueMappings.set(issuesResponse.items ?? []);
      this.issuesTotal.set(issuesResponse.total ?? 0);
      const totalPages = issuesResponse.totalPages ?? 0;
      if (totalPages > 0 && this.issuesPage() > totalPages) {
        this.issuesPage.set(totalPages);
      }
    } catch {
      this.issueMappings.set([]);
      this.issuesTotal.set(0);
    } finally {
      this.issuesLoading.set(false);
    }
  }

  private scheduleIssuesFiltersReload(): void {
    if (this.issuesFiltersReloadTimer) {
      window.clearTimeout(this.issuesFiltersReloadTimer);
    }
    this.issuesFiltersReloadTimer = window.setTimeout(() => {
      this.issuesPage.set(1);
      void this.loadIssues();
      this.issuesFiltersReloadTimer = null;
    }, 300);
  }

  private async loadDeliveries(): Promise<void> {
    try {
      const deliveriesResponse = await this.api.listJiraDeliveriesByOwner(
        this.data.level,
        this.data.targetId,
        1,
        25,
      );
      this.deliveries.set(deliveriesResponse.items ?? []);
    } catch {
      this.deliveries.set([]);
    }
  }

  private async queueRetryByAlertGroup(alertGroupID: string): Promise<void> {
    this.errorMessage.set(null);
    try {
      await this.api.retryJiraDeliveryByOwner(this.data.level, this.data.targetId, alertGroupID);
    } catch (error) {
      this.errorHandler.handleError(error);
      this.errorMessage.set(this.resolveErrorMessage(error, 'Failed to queue Jira retry.'));
      throw error;
    }
  }

  private async fetchAllIssueMappingsForSync(): Promise<JiraIssueMapping[]> {
    const out: JiraIssueMapping[] = [];
    const pageSize = 200;
    const maxPages = 200;
    let page = 1;

    while (page <= maxPages) {
      const response = await this.api.listJiraIssuesByOwnerWithFilters(
        this.data.level,
        this.data.targetId,
        {
          page,
          pageSize,
          status: 'all',
        },
      );
      const batch = response.items ?? [];
      out.push(...batch);

      const totalPages = response.totalPages ?? 0;
      if (totalPages > 0 && page >= totalPages) {
        break;
      }
      if (totalPages <= 0 && batch.length < pageSize) {
        break;
      }
      page++;
    }

    return out;
  }

  private extractKnownTransitionIssues(items: JiraIssueMapping[]): string[] {
    const out: string[] = [];
    const seen = new Set<string>();
    for (const item of items ?? []) {
      const value = ((item.jiraIssueKey ?? item.jiraIssueId ?? '') as string).trim();
      if (!value || seen.has(value)) {
        continue;
      }
      seen.add(value);
      out.push(value);
    }
    return out;
  }

  private patchForm(settings: JiraEntitySettings): void {
    const mapping = settings.severityToPriorityMapping ?? {};
    const savedIssueFields = this.normalizeIssueFields(settings.issueFields);
    const { issueFields, epicMode, epicIssueKey, epicFieldKey } =
      this.extractEpicMappingFromIssueFields(savedIssueFields);
    this.persistedIssueFields.set(issueFields);

    const knownIssues = this.extractKnownTransitionIssues(this.issueMappings());
    const transitionIssue = knownIssues[0] ?? '';

    this.form.patchValue({
      isEnabled: !!settings.isEnabled,
      jiraProjectKey: (settings.jiraProjectKey ?? '').trim(),
      issueType: (settings.issueType ?? '').trim(),
      issueTypeCustom: '',
      deliveryRetryAttempts: this.clampRetryAttempts(settings.deliveryRetryAttempts),
      deliveryRetryBackoffSeconds: this.clampRetryBackoffSeconds(
        settings.deliveryRetryBackoffSeconds,
      ),
      transitionIssueIdOrKey: transitionIssue,
      openTransitionName: (settings.openTransitionName ?? '').trim(),
      resolveTransitionName: (settings.resolveTransitionName ?? '').trim(),
      epicMode,
      epicIssueKey,
      epicFieldKey,
      labelsText: (settings.labels ?? []).join(', '),
      components: Array.isArray(settings.components) ? settings.components : [],
      priorityInfo: (mapping['INFO'] ?? '').trim(),
      priorityWarning: (mapping['WARNING'] ?? '').trim(),
      priorityError: (mapping['ERROR'] ?? '').trim(),
      ticketSummaryTemplate: (settings.ticketSummaryTemplate ?? '').trim(),
    });
  }

  private normalizeIssueFields(input: unknown): Record<string, unknown> {
    if (!input || typeof input !== 'object' || Array.isArray(input)) {
      return {};
    }
    return input as Record<string, unknown>;
  }

  private defaultIssueFieldControlValue(field: JiraMetadataIssueField): unknown {
    const inputType = (field.inputType ?? '').trim();
    if (inputType === 'multi_select') {
      return [] as string[];
    }
    if (inputType === 'boolean') {
      return '' as const;
    }
    return '';
  }

  private extractOptionTokenFromStoredValue(value: unknown): string {
    if (typeof value === 'string') {
      return value.trim();
    }
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      return '';
    }
    const objectValue = value as { id?: unknown; value?: unknown; name?: unknown };
    const fromId = String(objectValue.id ?? '').trim();
    if (fromId) {
      return fromId;
    }
    const fromValue = String(objectValue.value ?? '').trim();
    if (fromValue) {
      return fromValue;
    }
    return String(objectValue.name ?? '').trim();
  }

  private convertStoredIssueFieldValueToControl(
    field: JiraMetadataIssueField,
    value: unknown,
  ): unknown {
    const inputType = (field.inputType ?? '').trim();
    if (inputType === 'single_select') {
      return this.extractOptionTokenFromStoredValue(value);
    }
    if (inputType === 'multi_select') {
      if (!Array.isArray(value)) {
        return [] as string[];
      }
      return value
        .map((item) => this.extractOptionTokenFromStoredValue(item))
        .filter((item) => item.length > 0);
    }
    if (inputType === 'boolean') {
      return typeof value === 'boolean' ? value : '';
    }
    if (inputType === 'number') {
      if (typeof value === 'number') {
        return String(value);
      }
      return typeof value === 'string' ? value.trim() : '';
    }
    if (typeof value === 'string') {
      return value;
    }
    return '';
  }

  private optionByToken(
    field: JiraMetadataIssueField,
    token: string,
  ): JiraMetadataIssueFieldOption | null {
    const normalized = (token ?? '').trim();
    if (!normalized) {
      return null;
    }
    const options = field.allowedValues ?? [];
    for (const option of options) {
      if (this.issueFieldOptionToken(option) === normalized) {
        return option;
      }
    }
    return null;
  }

  private toJiraIssueFieldOptionValue(
    option: JiraMetadataIssueFieldOption | null,
    fallbackToken: string,
  ): unknown {
    if (!option) {
      const fallback = (fallbackToken ?? '').trim();
      return fallback || null;
    }
    const id = (option.id ?? '').trim();
    if (id) {
      return { id };
    }
    const value = (option.value ?? '').trim();
    if (value) {
      return { value };
    }
    const name = (option.name ?? '').trim();
    if (name) {
      return { name };
    }
    const fallback = (fallbackToken ?? '').trim();
    return fallback || null;
  }

  private buildIssueFieldsPayload(): Record<string, unknown> {
    const fields = this.requiredIssueFields();
    const values = this.requiredIssueFieldValues();
    const entries: Array<[string, unknown]> = [];

    for (const field of fields) {
      const key = field.key;
      const inputType = (field.inputType ?? '').trim();
      const rawValue = this.readRecordValue(values, key);

      if (inputType === 'multi_select') {
        const rawItems = Array.isArray(rawValue)
          ? rawValue.map((item) => String(item ?? '').trim()).filter((item) => item.length > 0)
          : [];
        const jiraItems = rawItems
          .map((token) => this.toJiraIssueFieldOptionValue(this.optionByToken(field, token), token))
          .filter((item) => item !== null);
        if (jiraItems.length > 0) {
          entries.push([key, jiraItems]);
        }
        continue;
      }

      if (inputType === 'single_select') {
        const token = String(rawValue ?? '').trim();
        if (!token) {
          continue;
        }
        const jiraValue = this.toJiraIssueFieldOptionValue(this.optionByToken(field, token), token);
        if (jiraValue !== null) {
          entries.push([key, jiraValue]);
        }
        continue;
      }

      if (inputType === 'boolean') {
        if (typeof rawValue === 'boolean') {
          entries.push([key, rawValue]);
        }
        continue;
      }

      if (inputType === 'number') {
        const parsed = Number(String(rawValue ?? '').trim());
        if (Number.isFinite(parsed)) {
          entries.push([key, parsed]);
        }
        continue;
      }

      const text = String(rawValue ?? '').trim();
      if (text) {
        entries.push([key, text]);
      }
    }

    const payload = Object.fromEntries(entries);
    return this.appendEpicMappingToIssueFieldsPayload(payload);
  }

  private extractEpicMappingFromIssueFields(input: Record<string, unknown>): {
    issueFields: Record<string, unknown>;
    epicMode: JiraEpicMode;
    epicIssueKey: string;
    epicFieldKey: string;
  } {
    const out: Record<string, unknown> = {};
    let epicMode: JiraEpicMode = 'none';
    let epicIssueKey = '';
    let epicFieldKey = '';
    for (const [rawKey, rawValue] of Object.entries(input ?? {})) {
      const key = (rawKey ?? '').trim();
      if (!key) {
        continue;
      }
      if (key === JIRA_EPIC_MODE_FIELD) {
        epicMode = this.normalizeEpicMode(String(rawValue ?? ''));
        continue;
      }
      if (key === JIRA_EPIC_ISSUE_KEY_FIELD) {
        epicIssueKey = String(rawValue ?? '').trim();
        continue;
      }
      if (key === JIRA_EPIC_FIELD_KEY_FIELD) {
        epicFieldKey = String(rawValue ?? '').trim();
        continue;
      }
      if (key === '__ctwall_epic_create_summary' || key === '__ctwall_epic_create_issue_type') {
        continue;
      }
      out[key] = rawValue;
    }
    if (epicMode === 'none' && epicIssueKey) {
      epicMode = 'existing';
    }
    return {
      issueFields: out,
      epicMode,
      epicIssueKey,
      epicFieldKey,
    };
  }

  private appendEpicMappingToIssueFieldsPayload(
    input: Record<string, unknown>,
  ): Record<string, unknown> {
    const epicMode = this.normalizeEpicMode(this.form.controls.epicMode.value);
    const epicIssueKey = this.form.controls.epicIssueKey.value.trim();
    const epicFieldKey = this.form.controls.epicFieldKey.value.trim();
    if (epicMode === 'none') {
      return input;
    }
    const out: Record<string, unknown> = {
      ...input,
      [JIRA_EPIC_MODE_FIELD]: epicMode,
    };
    if (epicFieldKey) {
      out[JIRA_EPIC_FIELD_KEY_FIELD] = epicFieldKey;
    }
    if (epicIssueKey) {
      out[JIRA_EPIC_ISSUE_KEY_FIELD] = epicIssueKey;
    }
    return out;
  }

  private isSafeRecordKey(key: string): boolean {
    const normalized = (key ?? '').trim();
    return normalized.length > 0 && /^[a-zA-Z0-9_.:-]+$/.test(normalized);
  }

  private readRecordValue(record: Readonly<Record<string, unknown>>, key: string): unknown {
    if (!this.isSafeRecordKey(key)) {
      return undefined;
    }
    return Reflect.get(record, key);
  }

  private hasRecordValue(record: Readonly<Record<string, unknown>>, key: string): boolean {
    if (!this.isSafeRecordKey(key)) {
      return false;
    }
    return Object.prototype.hasOwnProperty.call(record, key);
  }

  private assignRecordValue(record: Record<string, unknown>, key: string, value: unknown): void {
    if (!this.isSafeRecordKey(key)) {
      return;
    }
    Reflect.set(record, key, value);
  }

  private recordWithValue(key: string, value: unknown): Record<string, unknown> {
    const out: Record<string, unknown> = {};
    this.assignRecordValue(out, key, value);
    return out;
  }

  private toUpsertPayload(): JiraEntitySettingsUpsertPayload {
    const labels = (this.form.controls.labelsText.value ?? '')
      .split(/[\n,]/g)
      .map((item) => item.trim())
      .filter((item, idx, arr) => item.length > 0 && arr.indexOf(item) === idx);

    const components = (this.form.controls.components.value ?? [])
      .map((item) => item.trim())
      .filter((item, idx, arr) => item.length > 0 && arr.indexOf(item) === idx);

    const severityToPriorityMapping: Record<string, string> = {};
    const info = this.form.controls.priorityInfo.value.trim();
    const warning = this.form.controls.priorityWarning.value.trim();
    const error = this.form.controls.priorityError.value.trim();
    if (info) {
      severityToPriorityMapping['INFO'] = info;
    }
    if (warning) {
      severityToPriorityMapping['WARNING'] = warning;
    }
    if (error) {
      severityToPriorityMapping['ERROR'] = error;
    }

    const deliveryRetryAttempts = this.clampRetryAttempts(
      Number(this.form.controls.deliveryRetryAttempts.value),
    );
    const deliveryRetryBackoffSeconds = this.clampRetryBackoffSeconds(
      Number(this.form.controls.deliveryRetryBackoffSeconds.value),
    );

    return {
      isEnabled: this.form.controls.isEnabled.value,
      jiraProjectKey: this.form.controls.jiraProjectKey.value.trim(),
      issueType: this.currentIssueTypeValue(),
      deliveryRetryAttempts,
      deliveryRetryBackoffSeconds,
      openTransitionName: this.form.controls.openTransitionName.value.trim() || null,
      resolveTransitionName: this.form.controls.resolveTransitionName.value.trim() || null,
      issueFields: this.buildIssueFieldsPayload(),
      labels,
      components,
      severityToPriorityMapping,
      ticketSummaryTemplate: this.form.controls.ticketSummaryTemplate.value.trim(),
    };
  }

  private clampRetryAttempts(input: number): number {
    if (!Number.isFinite(input)) {
      return this.deliveryRetryAttemptsDefault;
    }
    const normalized = Math.trunc(input);
    if (normalized < this.deliveryRetryAttemptsMin) {
      return this.deliveryRetryAttemptsMin;
    }
    if (normalized > this.deliveryRetryAttemptsMax) {
      return this.deliveryRetryAttemptsMax;
    }
    return normalized;
  }

  private clampRetryBackoffSeconds(input: number): number {
    if (!Number.isFinite(input)) {
      return this.deliveryRetryBackoffSecondsDefault;
    }
    const normalized = Math.trunc(input);
    if (normalized < this.deliveryRetryBackoffSecondsMin) {
      return this.deliveryRetryBackoffSecondsMin;
    }
    if (normalized > this.deliveryRetryBackoffSecondsMax) {
      return this.deliveryRetryBackoffSecondsMax;
    }
    return normalized;
  }

  private async getSettings(): Promise<JiraEntitySettings> {
    switch (this.data.level) {
      case 'PRODUCT':
        return this.api.getProductJiraSettings(this.data.targetId);
      case 'SCOPE':
        return this.api.getScopeJiraSettings(this.data.targetId);
      case 'TEST':
        return this.api.getTestJiraSettings(this.data.targetId);
    }
  }

  private async putSettings(payload: JiraEntitySettingsUpsertPayload): Promise<JiraEntitySettings> {
    switch (this.data.level) {
      case 'PRODUCT':
        return this.api.putProductJiraSettings(this.data.targetId, payload);
      case 'SCOPE':
        return this.api.putScopeJiraSettings(this.data.targetId, payload);
      case 'TEST':
        return this.api.putTestJiraSettings(this.data.targetId, payload);
    }
  }

  private resolveErrorMessage(error: unknown, fallback: string): string {
    if (error instanceof HttpErrorResponse) {
      const detail =
        typeof error.error === 'object' &&
        error.error &&
        typeof (error.error as { detail?: unknown }).detail === 'string'
          ? ((error.error as { detail: string }).detail || '').trim()
          : '';
      if (detail) {
        return detail;
      }
      if (error.status === 403) {
        return 'Missing permissions for this Jira configuration.';
      }
      if (error.status === 404) {
        return 'Jira configuration target was not found.';
      }
      if (error.status === 400) {
        return 'Invalid Jira settings payload.';
      }
    }
    return fallback;
  }
}
