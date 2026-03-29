
import { CdkDragDrop, moveItemInArray } from '@angular/cdk/drag-drop';
import { ChangeDetectionStrategy, Component, ErrorHandler, computed, inject, signal } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MatCardModule } from '@angular/material/card';
import { MatDialog, MatDialogModule } from '@angular/material/dialog';
import { LucideAngularModule, Filter, Plus, Users, Trash2, Pencil } from 'lucide-angular';
import { firstValueFrom } from 'rxjs';
import { DataTableComponent } from '../../../../shared/ui/data-table/data-table.component';
import { ColumnDefinition } from '../../../../shared/ui/data-table/data-table.types';
import {
  AdvancedFilterField,
  AdvancedFilterMode,
  AdvancedFilterPanelComponent
} from '../../../../shared/ui/advanced-filter-panel/advanced-filter-panel.component';
import { LoadingIndicatorComponent } from '../../../../shared/ui/loading-indicator/loading-indicator.component';
import { ConfirmDialogComponent } from '../../../../shared/ui/confirm-dialog/confirm-dialog.component';
import { ProjectContextService } from '../../data-access/project-context.service';
import { ProjectsApi } from '../../data-access/projects.api';
import { ProjectCreateRequest, ProjectSummary, ProjectUpdateRequest, ProjectsListItem } from '../../data-access/projects.types';
import { ProjectMembersDialogComponent } from '../project-members-dialog/project-members-dialog.component';
import { ProjectFormDialogComponent, ProjectFormDialogResult } from '../project-form-dialog/project-form-dialog.component';

const columns: ColumnDefinition[] = [
  { key: 'name', label: 'Name', sortKey: 'name', filterKey: 'name' },
  { key: 'id', label: 'Project UUID', sortKey: 'id', filterKey: 'id' },
  { key: 'description', label: 'Description', sortKey: 'description', filterKey: 'description' },
  { key: 'membersCount', label: 'Members', sortKey: 'membersCount', filterKey: 'membersCount' },
  { key: 'createdAt', label: 'Created at', sortKey: 'createdAt', filterKey: 'createdAt' }
];
type SortDirection = 'asc' | 'desc';
type ProjectColumnKey = 'name' | 'id' | 'description' | 'membersCount' | 'createdAt';

@Component({
  selector: 'app-manage-projects',
  imports: [
    MatCardModule,
    MatButtonModule,
    MatDialogModule,
    LucideAngularModule,
    DataTableComponent,
    AdvancedFilterPanelComponent,
    LoadingIndicatorComponent
],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './manage-projects.component.html',
  styleUrl: './manage-projects.component.scss'
})
export class ManageProjectsComponent {
  protected readonly Filter = Filter;
  protected readonly Plus = Plus;
  protected readonly Users = Users;
  protected readonly Trash2 = Trash2;
  protected readonly Pencil = Pencil;
  protected readonly columns = columns;
  protected readonly lockedColumns: ProjectColumnKey[] = ['name'];

  private readonly api = inject(ProjectsApi);
  private readonly projectContext = inject(ProjectContextService);
  private readonly dialog = inject(MatDialog);
  private readonly errorHandler = inject(ErrorHandler);

  readonly status = signal<'loading' | 'loaded' | 'error'>('loading');
  readonly rows = signal<ProjectsListItem[]>([]);
  readonly errorMessage = signal<string | null>(null);
  readonly columnOrder = signal<ProjectColumnKey[]>(['name', 'id', 'description', 'membersCount', 'createdAt']);
  readonly tablePanelOpen = signal(false);
  readonly filterPanelOpen = signal(false);
  readonly filterVisible = signal<Record<ProjectColumnKey, boolean>>({
    name: false,
    id: false,
    description: false,
    membersCount: false,
    createdAt: false
  });
  readonly columnFilters = signal<Record<ProjectColumnKey, string>>({
    name: '',
    id: '',
    description: '',
    membersCount: '',
    createdAt: ''
  });
  readonly filterMode = signal<Record<ProjectColumnKey, AdvancedFilterMode>>({
    name: 'contains',
    id: 'contains',
    description: 'contains',
    membersCount: 'contains',
    createdAt: 'contains'
  });
  readonly multiFilters = signal<Record<ProjectColumnKey, string[]>>({
    name: [],
    id: [],
    description: [],
    membersCount: [],
    createdAt: []
  });
  readonly filterOptions = computed<Record<ProjectColumnKey, string[]>>(() => {
    const rows = this.rows();
    return {
      name: this.sortedOptions(rows.map((row) => this.rowValue(row, 'name'))),
      id: this.sortedOptions(rows.map((row) => this.rowValue(row, 'id'))),
      description: this.sortedOptions(rows.map((row) => this.rowValue(row, 'description'))),
      membersCount: this.sortedOptions(rows.map((row) => this.rowValue(row, 'membersCount'))),
      createdAt: this.sortedOptions(rows.map((row) => this.rowValue(row, 'createdAt')))
    };
  });
  readonly advancedFields = computed<AdvancedFilterField[]>(() => {
    const mode = this.filterMode();
    const filters = this.columnFilters();
    const multi = this.multiFilters();
    const options = this.filterOptions();
    return [
      {
        key: 'name',
        label: 'Name',
        mode: mode.name,
        value: filters.name,
        options: options.name,
        selected: multi.name
      },
      {
        key: 'id',
        label: 'Project UUID',
        mode: mode.id,
        value: filters.id,
        options: options.id,
        selected: multi.id
      },
      {
        key: 'description',
        label: 'Description',
        mode: mode.description,
        value: filters.description,
        options: options.description,
        selected: multi.description
      },
      {
        key: 'membersCount',
        label: 'Members',
        mode: mode.membersCount,
        value: filters.membersCount,
        options: options.membersCount,
        selected: multi.membersCount
      },
      {
        key: 'createdAt',
        label: 'Created at',
        mode: mode.createdAt,
        value: filters.createdAt,
        options: options.createdAt,
        selected: multi.createdAt
      }
    ];
  });
  readonly filterRowVisible = computed(() => Object.values(this.filterVisible()).some(Boolean));
  readonly sortColumn = signal<ProjectColumnKey | null>('name');
  readonly sortDir = signal<SortDirection>('asc');
  readonly availableColumns = computed(() => {
    const selected = new Set(this.columnOrder());
    return this.columns.filter((column) => !selected.has(column.key as ProjectColumnKey));
  });
  readonly tableRows = computed(() => {
    const filters = this.columnFilters();
    const modes = this.filterMode();
    const selected = this.multiFilters();
    const filtered = this.rows().filter((row) => {
      if (!this.matchesAdvancedFilter(this.rowValue(row, 'name'), modes.name, filters.name, selected.name)) return false;
      if (!this.matchesAdvancedFilter(this.rowValue(row, 'id'), modes.id, filters.id, selected.id)) return false;
      if (!this.matchesAdvancedFilter(this.rowValue(row, 'description'), modes.description, filters.description, selected.description)) return false;
      if (!this.matchesAdvancedFilter(this.rowValue(row, 'membersCount'), modes.membersCount, filters.membersCount, selected.membersCount)) return false;
      if (!this.matchesAdvancedFilter(this.rowValue(row, 'createdAt'), modes.createdAt, filters.createdAt, selected.createdAt)) return false;
      return true;
    });
    const sortColumn = this.sortColumn();
    if (!sortColumn) {
      return filtered;
    }
    const mult = this.sortDir() === 'asc' ? 1 : -1;
    return [...filtered].sort((left, right) => {
      if (sortColumn === 'membersCount') {
        return (left.membersCount - right.membersCount) * mult;
      }
      if (sortColumn === 'createdAt') {
        return (Date.parse(left.createdAt) - Date.parse(right.createdAt)) * mult;
      }
      return this.rowValue(left, sortColumn).localeCompare(this.rowValue(right, sortColumn), undefined, {
        sensitivity: 'base'
      }) * mult;
    });
  });

  constructor() {
    void this.load();
  }

  rowValue(row: ProjectsListItem, key: string): string {
    switch (key) {
      case 'name':
        return row.name;
      case 'id':
        return row.id;
      case 'description':
        return (row.description ?? '').trim() || '-';
      case 'membersCount':
        return String(row.membersCount);
      case 'createdAt':
        return this.formatDate(row.createdAt);
      default:
        return '-';
    }
  }

  async refresh(): Promise<void> {
    await this.load();
  }

  toggleExtendedFilters(): void {
    this.filterPanelOpen.update((value) => !value);
  }

  setFilterMode(key: string, mode: AdvancedFilterMode): void {
    if (!this.isColumnKey(key)) {
      return;
    }
    this.filterMode.update((state) => ({ ...state, [key]: mode }));
    if (mode === 'contains') {
      this.multiFilters.update((state) => ({ ...state, [key]: [] }));
      return;
    }
    this.columnFilters.update((state) => ({ ...state, [key]: '' }));
  }

  setFilterValue(key: string, value: string): void {
    if (!this.isColumnKey(key)) {
      return;
    }
    this.columnFilters.update((state) => ({ ...state, [key]: value }));
  }

  setMultiFilter(key: string, values: string[]): void {
    if (!this.isColumnKey(key)) {
      return;
    }
    this.multiFilters.update((state) => ({ ...state, [key]: values }));
  }

  clearFilters(): void {
    this.columnFilters.set({
      name: '',
      id: '',
      description: '',
      membersCount: '',
      createdAt: ''
    });
    this.filterMode.set({
      name: 'contains',
      id: 'contains',
      description: 'contains',
      membersCount: 'contains',
      createdAt: 'contains'
    });
    this.multiFilters.set({
      name: [],
      id: [],
      description: [],
      membersCount: [],
      createdAt: []
    });
  }

  toggleTablePanel(): void {
    this.tablePanelOpen.update((value) => !value);
  }

  dropColumn(event: CdkDragDrop<string[]>): void {
    const next = [...this.columnOrder()];
    moveItemInArray(next, event.previousIndex, event.currentIndex);
    this.columnOrder.set(next);
  }

  removeColumn(value: string): void {
    if (!this.isColumnKey(value) || this.lockedColumns.includes(value)) {
      return;
    }
    const next = this.columnOrder().filter((key) => key !== value);
    if (next.length < 1) {
      return;
    }
    this.columnOrder.set(next);
  }

  addColumn(value: string): void {
    if (!this.isColumnKey(value) || this.columnOrder().includes(value)) {
      return;
    }
    this.columnOrder.set([...this.columnOrder(), value]);
  }

  toggleFilter(key: string, event: Event): void {
    event.stopPropagation();
    if (!this.isColumnKey(key)) {
      return;
    }
    this.filterVisible.update((state) => {
      switch (key) {
        case 'name':
          return { ...state, name: !state.name };
        case 'id':
          return { ...state, id: !state.id };
        case 'description':
          return { ...state, description: !state.description };
        case 'membersCount':
          return { ...state, membersCount: !state.membersCount };
        case 'createdAt':
          return { ...state, createdAt: !state.createdAt };
      }
    });
  }

  setColumnFilter(key: string, event: Event): void {
    if (!this.isColumnKey(key)) {
      return;
    }
    const target = event.target as HTMLInputElement | null;
    const value = target?.value ?? '';
    this.filterMode.update((state) => ({ ...state, [key]: 'contains' }));
    this.multiFilters.update((state) => ({ ...state, [key]: [] }));
    this.columnFilters.update((state) => {
      switch (key) {
        case 'name':
          return { ...state, name: value };
        case 'id':
          return { ...state, id: value };
        case 'description':
          return { ...state, description: value };
        case 'membersCount':
          return { ...state, membersCount: value };
        case 'createdAt':
          return { ...state, createdAt: value };
      }
    });
  }

  toggleSort(key: string): void {
    if (!this.isColumnKey(key)) {
      return;
    }
    if (this.sortColumn() === key) {
      this.sortDir.set(this.sortDir() === 'asc' ? 'desc' : 'asc');
      return;
    }
    this.sortColumn.set(key);
    this.sortDir.set(key === 'createdAt' ? 'desc' : 'asc');
  }

  async createProject(): Promise<void> {
    const ref = this.dialog.open(ProjectFormDialogComponent, {
      width: '460px',
      maxWidth: '96vw',
      data: {
        title: 'Create project',
        confirmLabel: 'Create'
      }
    });
    const payload = await firstValueFrom(ref.afterClosed());
    const request = this.normalizeProjectPayload(payload);
    if (!request) {
      return;
    }

    this.status.set('loading');
    this.errorMessage.set(null);
    try {
      await this.api.createProject(request);
      await this.projectContext.refresh();
      await this.load();
    } catch (error) {
      this.errorHandler.handleError(error);
      this.status.set('error');
      this.errorMessage.set('Failed to create project.');
    }
  }

  async editProject(row: ProjectsListItem): Promise<void> {
    const ref = this.dialog.open(ProjectFormDialogComponent, {
      width: '460px',
      maxWidth: '96vw',
      data: {
        title: `Edit project: ${row.name}`,
        confirmLabel: 'Save',
        initialName: row.name,
        initialDescription: row.description ?? ''
      }
    });
    const payload = await firstValueFrom(ref.afterClosed());
    const request = this.normalizeProjectPayload(payload);
    if (!request) {
      return;
    }

    this.status.set('loading');
    this.errorMessage.set(null);
    try {
      await this.api.updateProject(row.id, request);
      await this.projectContext.refresh();
      await this.load();
    } catch (error) {
      this.errorHandler.handleError(error);
      this.status.set('error');
      this.errorMessage.set('Failed to update project.');
    }
  }

  async deleteProject(row: ProjectsListItem): Promise<void> {
    const ref = this.dialog.open(ConfirmDialogComponent, {
      width: '520px',
      maxWidth: '96vw',
      data: {
        title: `Delete project: ${row.name}`,
        message:
          'This action removes the project and linked products. Continue only if you acknowledge destructive impact.',
        confirmLabel: 'Acknowledge and delete',
        cancelLabel: 'Cancel'
      }
    });

    const confirmed = await firstValueFrom(ref.afterClosed());
    if (!confirmed) {
      return;
    }

    this.status.set('loading');
    this.errorMessage.set(null);
    try {
      await this.api.deleteProject(row.id, true);
      await this.projectContext.refresh();
      await this.load();
    } catch (error) {
      this.errorHandler.handleError(error);
      this.status.set('error');
      this.errorMessage.set('Failed to delete project.');
    }
  }

  async manageMembers(row: ProjectsListItem): Promise<void> {
    const ref = this.dialog.open(ProjectMembersDialogComponent, {
      width: '640px',
      maxWidth: '96vw',
      data: {
        projectId: row.id,
        projectName: row.name
      }
    });
    const changed = await firstValueFrom(ref.afterClosed());
    if (!changed) {
      return;
    }
    await this.load();
  }

  private async load(): Promise<void> {
    this.status.set('loading');
    this.errorMessage.set(null);
    try {
      const projects = await this.api.listProjects();
      const rows = await this.withMembersCount(projects);
      this.rows.set(rows);
      this.status.set('loaded');
    } catch (error) {
      this.errorHandler.handleError(error);
      this.status.set('error');
      this.errorMessage.set('Failed to load projects.');
    }
  }

  private async withMembersCount(projects: ProjectSummary[]): Promise<ProjectsListItem[]> {
    const counts = await Promise.all(
      projects.map(async (project) => {
        try {
          const members = await this.api.listProjectMembers(project.id);
          return { projectId: project.id, count: members.length };
        } catch {
          return { projectId: project.id, count: 0 };
        }
      })
    );
    const countMap = new Map(counts.map((entry) => [entry.projectId, entry.count]));
    return projects
      .map((project) => ({
        ...project,
        membersCount: countMap.get(project.id) ?? 0
      }))
      .sort((a, b) => a.name.localeCompare(b.name));
  }

  private formatDate(value: string): string {
    const parsed = new Date(value);
    if (Number.isNaN(parsed.getTime())) {
      return value;
    }
    return parsed.toLocaleString();
  }

  private normalizeProjectPayload(result: ProjectFormDialogResult | null | undefined): ProjectCreateRequest | ProjectUpdateRequest | null {
    if (!result) {
      return null;
    }
    const name = result.name.trim();
    if (!name) {
      return null;
    }
    const description = (result.description ?? '').trim();
    return {
      name,
      description: description || undefined
    };
  }

  private matchesFilter(value: string, needle: string): boolean {
    const query = needle.trim().toLowerCase();
    if (!query) {
      return true;
    }
    return value.toLowerCase().includes(query);
  }

  private matchesAdvancedFilter(
    value: string,
    mode: AdvancedFilterMode,
    containsValue: string,
    selectedValues: string[]
  ): boolean {
    if (mode === 'select') {
      if (selectedValues.length === 0) {
        return true;
      }
      return selectedValues.includes(value);
    }
    return this.matchesFilter(value, containsValue);
  }

  private sortedOptions(values: string[]): string[] {
    const unique = new Set<string>();
    values.forEach((value) => {
      const normalized = value.trim();
      if (normalized) {
        unique.add(normalized);
      }
    });
    return Array.from(unique).sort((left, right) => left.localeCompare(right, undefined, { sensitivity: 'base' }));
  }

  private isColumnKey(value: string): value is ProjectColumnKey {
    return value === 'name' || value === 'id' || value === 'description' || value === 'membersCount' || value === 'createdAt';
  }
}
