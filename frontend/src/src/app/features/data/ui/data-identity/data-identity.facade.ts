import { CdkDragDrop, moveItemInArray } from '@angular/cdk/drag-drop';
import { HttpErrorResponse } from '@angular/common/http';
import { ErrorHandler, computed, effect, inject, signal } from '@angular/core';
import { MatDialog } from '@angular/material/dialog';
import { firstValueFrom } from 'rxjs';
import {
  AdvancedFilterField,
  AdvancedFilterMode,
} from '../../../../shared/ui/advanced-filter-panel/advanced-filter-panel.component';
import { ColumnDefinition } from '../../../../shared/ui/data-table/data-table.types';
import { AuthStore } from '../../../auth/auth.store';
import { ProjectContextService } from '../../../projects/data-access/project-context.service';
import { ProjectsApi } from '../../../projects/data-access/projects.api';
import { ProjectMember } from '../../../projects/data-access/projects.types';
import { IdentityApi } from '../../data-access/identity.api';
import {
  GroupMemberAssignment,
  GroupMemberRole,
  UserGroup,
  UserGroupMember,
} from '../../data-access/identity.types';
import { GroupFormDialogComponent } from '../group-form-dialog/group-form-dialog.component';
import { LoadState } from '../../../../shared/types/load-state';

type SortDirection = 'asc' | 'desc';
type AssignableMemberRole = Exclude<GroupMemberRole, 'OWNER'>;

type GroupColumnKey = 'name' | 'description' | 'myRole' | 'membersCount' | 'createdAt';
type MemberColumnKey = 'select' | 'email' | 'fullName' | 'role' | 'userId';

interface GroupInsight {
  membersCount: number;
  myRole: GroupMemberRole | null;
}

interface GroupTableRow {
  id: string;
  name: string;
  description: string;
  myRole: GroupMemberRole | '-';
  membersCount: number;
  createdAt: string;
}

interface EditableMemberRow {
  userId: string;
  email: string;
  fullName: string;
  role: GroupMemberRole;
}

const groupColumns: ColumnDefinition[] = [
  { key: 'name', label: 'Group', sortKey: 'name', filterKey: 'name' },
  { key: 'description', label: 'Description', sortKey: 'description', filterKey: 'description' },
  { key: 'myRole', label: 'My role', sortKey: 'myRole', filterKey: 'myRole' },
  { key: 'membersCount', label: 'Members', sortKey: 'membersCount', filterKey: 'membersCount' },
  { key: 'createdAt', label: 'Created', sortKey: 'createdAt', filterKey: 'createdAt' },
];

const memberColumns: ColumnDefinition[] = [
  { key: 'select', label: '', sortKey: '', filterKey: '' },
  { key: 'email', label: 'Email', sortKey: 'email', filterKey: 'email' },
  { key: 'fullName', label: 'Full name', sortKey: 'fullName', filterKey: 'fullName' },
  { key: 'role', label: 'Group role', sortKey: 'role', filterKey: 'role' },
  { key: 'userId', label: 'User ID', sortKey: 'userId', filterKey: 'userId', className: 'mono' },
];

export class DataIdentityFacade {
  protected readonly groupColumns = groupColumns;
  protected readonly memberColumns = memberColumns;
  protected readonly pageSizeOptions = [10, 25, 50, 100];

  private readonly identityApi = inject(IdentityApi);
  private readonly projectsApi = inject(ProjectsApi);
  private readonly projectContext = inject(ProjectContextService);
  private readonly auth = inject(AuthStore);
  private readonly dialog = inject(MatDialog);
  private readonly errorHandler = inject(ErrorHandler);

  readonly groupsStatus = signal<LoadState>('idle');
  readonly groupsError = signal<string | null>(null);
  readonly groups = signal<UserGroup[]>([]);
  readonly groupInsights = signal<Map<string, GroupInsight>>(new Map());
  readonly selectedGroupId = signal<string | null>(null);

  readonly membersStatus = signal<LoadState>('idle');
  readonly membersError = signal<string | null>(null);
  readonly groupMembersOriginal = signal<EditableMemberRow[]>([]);
  readonly groupMembersDraft = signal<EditableMemberRow[]>([]);
  readonly selectedMemberIds = signal<string[]>([]);
  readonly membersSavePending = signal(false);

  readonly projectMembersStatus = signal<LoadState>('idle');
  readonly projectMembersError = signal<string | null>(null);
  readonly projectMembers = signal<ProjectMember[]>([]);
  readonly addProjectUserId = signal('');
  readonly addProjectUserRole = signal<AssignableMemberRole>('VIEWER');

  readonly isAdmin = computed(() => this.projectContext.canAdmin());
  readonly canWrite = computed(() => this.projectContext.canWrite());
  readonly canCreateGroup = computed(() => this.canWrite());
  readonly currentUserId = computed(() => this.auth.user()?.id ?? '');

  readonly selectedGroup = computed(() => {
    const id = this.selectedGroupId();
    if (!id) {
      return null;
    }
    return this.groups().find((group) => group.id === id) ?? null;
  });

  readonly selectedGroupInsight = computed(() => {
    const id = this.selectedGroupId();
    if (!id) {
      return null;
    }
    return this.groupInsights().get(id) ?? null;
  });

  readonly currentUserRoleInSelectedGroup = computed<GroupMemberRole | null>(() => {
    const currentUserId = this.currentUserId();
    if (!currentUserId) {
      return null;
    }
    const row = this.groupMembersDraft().find((member) => member.userId === currentUserId);
    if (row) {
      return row.role;
    }
    return this.selectedGroupInsight()?.myRole ?? null;
  });

  readonly canManageSelectedGroupMembers = computed(() => {
    if (this.isAdmin()) {
      return true;
    }
    if (!this.canWrite()) {
      return false;
    }
    return this.currentUserRoleInSelectedGroup() === 'OWNER';
  });

  readonly hasSelectedGroup = computed(() => !!this.selectedGroupId());
  readonly hasSelectedMembers = computed(() => this.selectedMemberIds().length > 0);
  readonly hasUnsavedMemberChanges = computed(() => {
    return (
      this.membersFingerprint(this.groupMembersOriginal()) !==
      this.membersFingerprint(this.groupMembersDraft())
    );
  });

  readonly groupColumnOrder = signal<GroupColumnKey[]>([
    'name',
    'description',
    'myRole',
    'membersCount',
    'createdAt',
  ]);
  readonly groupTablePanelOpen = signal(false);
  readonly groupFilterPanelOpen = signal(false);
  readonly groupLockedColumns: GroupColumnKey[] = ['name'];
  readonly groupFilterVisible = signal<Record<GroupColumnKey, boolean>>({
    name: false,
    description: false,
    myRole: false,
    membersCount: false,
    createdAt: false,
  });
  readonly groupColumnFilters = signal<Record<GroupColumnKey, string>>({
    name: '',
    description: '',
    myRole: '',
    membersCount: '',
    createdAt: '',
  });
  readonly groupFilterMode = signal<Record<GroupColumnKey, AdvancedFilterMode>>({
    name: 'contains',
    description: 'contains',
    myRole: 'contains',
    membersCount: 'contains',
    createdAt: 'contains',
  });
  readonly groupMultiFilters = signal<Record<GroupColumnKey, string[]>>({
    name: [],
    description: [],
    myRole: [],
    membersCount: [],
    createdAt: [],
  });
  readonly groupFilterRowVisible = computed(() =>
    Object.values(this.groupFilterVisible()).some(Boolean),
  );
  readonly groupSortColumn = signal<GroupColumnKey | null>('name');
  readonly groupSortDir = signal<SortDirection>('asc');
  readonly groupAvailableColumns = computed(() =>
    this.availableColumns(this.groupColumns, this.groupColumnOrder()),
  );
  readonly groupPageIndex = signal(0);
  readonly groupPageSize = signal(25);

  readonly memberColumnOrder = signal<MemberColumnKey[]>([
    'select',
    'email',
    'fullName',
    'role',
    'userId',
  ]);
  readonly memberTablePanelOpen = signal(false);
  readonly memberFilterPanelOpen = signal(false);
  readonly memberLockedColumns: MemberColumnKey[] = ['select', 'email'];
  readonly memberFilterVisible = signal<Record<MemberColumnKey, boolean>>({
    select: false,
    email: false,
    fullName: false,
    role: false,
    userId: false,
  });
  readonly memberColumnFilters = signal<Record<MemberColumnKey, string>>({
    select: '',
    email: '',
    fullName: '',
    role: '',
    userId: '',
  });
  readonly memberFilterMode = signal<Record<MemberColumnKey, AdvancedFilterMode>>({
    select: 'contains',
    email: 'contains',
    fullName: 'contains',
    role: 'contains',
    userId: 'contains',
  });
  readonly memberMultiFilters = signal<Record<MemberColumnKey, string[]>>({
    select: [],
    email: [],
    fullName: [],
    role: [],
    userId: [],
  });
  readonly memberFilterRowVisible = computed(() =>
    Object.values(this.memberFilterVisible()).some(Boolean),
  );
  readonly memberSortColumn = signal<MemberColumnKey | null>('email');
  readonly memberSortDir = signal<SortDirection>('asc');
  readonly memberAvailableColumns = computed(() =>
    this.availableColumns(this.memberColumns, this.memberColumnOrder()),
  );
  readonly memberPageIndex = signal(0);
  readonly memberPageSize = signal(25);

  readonly groupRows = computed<GroupTableRow[]>(() => {
    const insights = this.groupInsights();
    return this.groups().map((group) => {
      const insight = insights.get(group.id);
      return {
        id: group.id,
        name: group.name,
        description: (group.description ?? '').trim() || '-',
        myRole: insight?.myRole ?? '-',
        membersCount: insight?.membersCount ?? 0,
        createdAt: this.formatDate(group.createdAt),
      };
    });
  });

  readonly groupFilterOptions = computed<Record<GroupColumnKey, string[]>>(() => {
    const rows = this.groupRows();
    return {
      name: this.sortedOptions(rows.map((row) => row.name)),
      description: this.sortedOptions(rows.map((row) => row.description)),
      myRole: this.sortedOptions(rows.map((row) => row.myRole)),
      membersCount: this.sortedOptions(rows.map((row) => String(row.membersCount))),
      createdAt: this.sortedOptions(rows.map((row) => row.createdAt)),
    };
  });

  readonly groupAdvancedFields = computed<AdvancedFilterField[]>(() => {
    const mode = this.groupFilterMode();
    const filters = this.groupColumnFilters();
    const multi = this.groupMultiFilters();
    const options = this.groupFilterOptions();
    return [
      {
        key: 'name',
        label: 'Group',
        mode: mode.name,
        value: filters.name,
        options: options.name,
        selected: multi.name,
      },
      {
        key: 'description',
        label: 'Description',
        mode: mode.description,
        value: filters.description,
        options: options.description,
        selected: multi.description,
      },
      {
        key: 'myRole',
        label: 'My role',
        mode: mode.myRole,
        value: filters.myRole,
        options: options.myRole,
        selected: multi.myRole,
      },
      {
        key: 'membersCount',
        label: 'Members',
        mode: mode.membersCount,
        value: filters.membersCount,
        options: options.membersCount,
        selected: multi.membersCount,
      },
      {
        key: 'createdAt',
        label: 'Created',
        mode: mode.createdAt,
        value: filters.createdAt,
        options: options.createdAt,
        selected: multi.createdAt,
      },
    ];
  });

  readonly filteredGroupRows = computed(() => {
    const filters = this.groupColumnFilters();
    const mode = this.groupFilterMode();
    const selected = this.groupMultiFilters();
    const filtered = this.groupRows().filter((row) => {
      if (!this.matchesAdvancedFilter(row.name, mode.name, filters.name, selected.name))
        return false;
      if (
        !this.matchesAdvancedFilter(
          row.description,
          mode.description,
          filters.description,
          selected.description,
        )
      )
        return false;
      if (!this.matchesAdvancedFilter(row.myRole, mode.myRole, filters.myRole, selected.myRole))
        return false;
      if (
        !this.matchesAdvancedFilter(
          String(row.membersCount),
          mode.membersCount,
          filters.membersCount,
          selected.membersCount,
        )
      )
        return false;
      if (
        !this.matchesAdvancedFilter(
          row.createdAt,
          mode.createdAt,
          filters.createdAt,
          selected.createdAt,
        )
      )
        return false;
      return true;
    });

    const sortColumn = this.groupSortColumn();
    if (!sortColumn) {
      return filtered;
    }
    const mult = this.groupSortDir() === 'asc' ? 1 : -1;
    return [...filtered].sort((left, right) => {
      switch (sortColumn) {
        case 'membersCount':
          return (left.membersCount - right.membersCount) * mult;
        case 'createdAt':
          return (
            left.createdAt.localeCompare(right.createdAt, undefined, { sensitivity: 'base' }) * mult
          );
        case 'myRole':
          return left.myRole.localeCompare(right.myRole, undefined, { sensitivity: 'base' }) * mult;
        case 'description':
          return (
            left.description.localeCompare(right.description, undefined, { sensitivity: 'base' }) *
            mult
          );
        case 'name':
        default:
          return left.name.localeCompare(right.name, undefined, { sensitivity: 'base' }) * mult;
      }
    });
  });

  readonly groupTotalPages = computed(() =>
    this.totalPages(this.filteredGroupRows().length, this.groupPageSize()),
  );

  readonly groupsTableRows = computed(() =>
    this.paginate(this.filteredGroupRows(), this.groupPageIndex(), this.groupPageSize()),
  );

  readonly memberRows = computed(() => this.groupMembersDraft());

  readonly memberFilterOptions = computed<Record<MemberColumnKey, string[]>>(() => {
    const rows = this.memberRows();
    return {
      select: [],
      email: this.sortedOptions(rows.map((row) => row.email)),
      fullName: this.sortedOptions(rows.map((row) => row.fullName || '-')),
      role: this.sortedOptions(rows.map((row) => row.role)),
      userId: this.sortedOptions(rows.map((row) => row.userId)),
    };
  });

  readonly memberAdvancedFields = computed<AdvancedFilterField[]>(() => {
    const mode = this.memberFilterMode();
    const filters = this.memberColumnFilters();
    const multi = this.memberMultiFilters();
    const options = this.memberFilterOptions();
    return [
      {
        key: 'email',
        label: 'Email',
        mode: mode.email,
        value: filters.email,
        options: options.email,
        selected: multi.email,
      },
      {
        key: 'fullName',
        label: 'Full name',
        mode: mode.fullName,
        value: filters.fullName,
        options: options.fullName,
        selected: multi.fullName,
      },
      {
        key: 'role',
        label: 'Group role',
        mode: mode.role,
        value: filters.role,
        options: options.role,
        selected: multi.role,
      },
      {
        key: 'userId',
        label: 'User ID',
        mode: mode.userId,
        value: filters.userId,
        options: options.userId,
        selected: multi.userId,
      },
    ];
  });

  readonly filteredMemberRows = computed(() => {
    const filters = this.memberColumnFilters();
    const mode = this.memberFilterMode();
    const selected = this.memberMultiFilters();
    const filtered = this.memberRows().filter((row) => {
      if (!this.matchesAdvancedFilter(row.email, mode.email, filters.email, selected.email))
        return false;
      if (
        !this.matchesAdvancedFilter(
          row.fullName,
          mode.fullName,
          filters.fullName,
          selected.fullName,
        )
      )
        return false;
      if (!this.matchesAdvancedFilter(row.role, mode.role, filters.role, selected.role))
        return false;
      if (!this.matchesAdvancedFilter(row.userId, mode.userId, filters.userId, selected.userId))
        return false;
      return true;
    });

    const sortColumn = this.memberSortColumn();
    if (!sortColumn || sortColumn === 'select') {
      return filtered;
    }
    const mult = this.memberSortDir() === 'asc' ? 1 : -1;
    return [...filtered].sort((left, right) => {
      if (sortColumn === 'role') {
        return left.role.localeCompare(right.role, undefined, { sensitivity: 'base' }) * mult;
      }
      if (sortColumn === 'fullName') {
        return (
          left.fullName.localeCompare(right.fullName, undefined, { sensitivity: 'base' }) * mult
        );
      }
      if (sortColumn === 'userId') {
        return left.userId.localeCompare(right.userId, undefined, { sensitivity: 'base' }) * mult;
      }
      return left.email.localeCompare(right.email, undefined, { sensitivity: 'base' }) * mult;
    });
  });

  readonly memberTotalPages = computed(() =>
    this.totalPages(this.filteredMemberRows().length, this.memberPageSize()),
  );

  readonly membersTableRows = computed(() =>
    this.paginate(this.filteredMemberRows(), this.memberPageIndex(), this.memberPageSize()),
  );

  readonly availableProjectMembersToAdd = computed(() => {
    const selectedIds = new Set(this.groupMembersDraft().map((member) => member.userId));
    return this.projectMembers()
      .filter((member) => !selectedIds.has(member.id))
      .sort((left, right) =>
        left.email.localeCompare(right.email, undefined, { sensitivity: 'base' }),
      );
  });

  constructor() {
    effect(() => {
      const totalPages = this.groupTotalPages();
      if (this.groupPageIndex() >= totalPages) {
        this.groupPageIndex.set(Math.max(totalPages - 1, 0));
      }
    });
    effect(() => {
      const totalPages = this.memberTotalPages();
      if (this.memberPageIndex() >= totalPages) {
        this.memberPageIndex.set(Math.max(totalPages - 1, 0));
      }
    });
    void this.initialize();
  }

  async refresh(): Promise<void> {
    await this.loadGroups();
    await this.loadProjectMembersDirectory();
  }

  async createGroup(): Promise<void> {
    if (!this.canCreateGroup()) {
      return;
    }
    const ref = this.dialog.open(GroupFormDialogComponent, {
      width: '520px',
      data: {
        title: 'Create group',
        confirmLabel: 'Create group',
      },
    });
    const result = await firstValueFrom(ref.afterClosed());
    if (!result) {
      return;
    }
    try {
      const created = await this.identityApi.createGroup({
        name: result.name,
        description: result.description,
      });
      this.groups.update((items) =>
        [...items, created].sort((left, right) =>
          left.name.localeCompare(right.name, undefined, { sensitivity: 'base' }),
        ),
      );
      const currentUserId = this.currentUserId();
      this.groupInsights.update((state) => {
        const next = new Map(state);
        next.set(created.id, {
          membersCount: 1,
          myRole: currentUserId ? 'OWNER' : null,
        });
        return next;
      });
      this.selectedGroupId.set(created.id);
      await this.loadSelectedGroupMembers(created.id);
    } catch (error) {
      this.errorHandler.handleError(error);
      this.groupsError.set('Failed to create group.');
    }
  }

  selectGroup(groupId: string): void {
    if (this.selectedGroupId() === groupId) {
      return;
    }
    this.selectedGroupId.set(groupId);
    this.memberPageIndex.set(0);
    this.selectedMemberIds.set([]);
    void this.loadSelectedGroupMembers(groupId);
  }

  groupValue(row: GroupTableRow, key: string): string {
    switch (key) {
      case 'name':
        return row.name;
      case 'description':
        return row.description;
      case 'myRole':
        return row.myRole;
      case 'membersCount':
        return String(row.membersCount);
      case 'createdAt':
        return row.createdAt;
      default:
        return '-';
    }
  }

  memberValue(row: EditableMemberRow, key: string): string {
    switch (key) {
      case 'email':
        return row.email || '-';
      case 'fullName':
        return row.fullName || '-';
      case 'role':
        return row.role;
      case 'userId':
        return row.userId;
      default:
        return '-';
    }
  }

  memberRoleClass(role: GroupMemberRole): string {
    switch (role) {
      case 'OWNER':
        return 'role-pill role-pill--owner';
      case 'EDITOR':
        return 'role-pill role-pill--editor';
      case 'VIEWER':
      default:
        return 'role-pill role-pill--viewer';
    }
  }

  toggleGroupTablePanel(): void {
    this.groupTablePanelOpen.update((value) => !value);
  }

  dropGroupColumn(event: CdkDragDrop<string[]>): void {
    const next = [...this.groupColumnOrder()];
    moveItemInArray(next, event.previousIndex, event.currentIndex);
    this.groupColumnOrder.set(next);
  }

  removeGroupColumn(value: string): void {
    if (!this.isGroupColumnKey(value) || this.groupLockedColumns.includes(value)) {
      return;
    }
    const next = this.groupColumnOrder().filter((key) => key !== value);
    if (next.length < 1) {
      return;
    }
    this.groupColumnOrder.set(next);
  }

  addGroupColumn(value: string): void {
    if (!this.isGroupColumnKey(value) || this.groupColumnOrder().includes(value)) {
      return;
    }
    this.groupColumnOrder.set([...this.groupColumnOrder(), value]);
  }

  toggleGroupExtendedFilters(): void {
    this.groupFilterPanelOpen.update((value) => !value);
  }

  setGroupFilterMode(key: string, mode: AdvancedFilterMode): void {
    if (!this.isGroupColumnKey(key)) {
      return;
    }
    this.groupPageIndex.set(0);
    this.groupFilterMode.update((state) => ({ ...state, [key]: mode }));
    if (mode === 'contains') {
      this.groupMultiFilters.update((state) => ({ ...state, [key]: [] }));
      return;
    }
    this.groupColumnFilters.update((state) => ({ ...state, [key]: '' }));
  }

  setGroupFilterValue(key: string, value: string): void {
    if (!this.isGroupColumnKey(key)) {
      return;
    }
    this.groupPageIndex.set(0);
    this.groupColumnFilters.update((state) => ({ ...state, [key]: value }));
  }

  setGroupMultiFilter(key: string, values: string[]): void {
    if (!this.isGroupColumnKey(key)) {
      return;
    }
    this.groupPageIndex.set(0);
    this.groupMultiFilters.update((state) => ({ ...state, [key]: values }));
  }

  clearGroupFilters(): void {
    this.groupPageIndex.set(0);
    this.groupColumnFilters.set({
      name: '',
      description: '',
      myRole: '',
      membersCount: '',
      createdAt: '',
    });
    this.groupFilterMode.set({
      name: 'contains',
      description: 'contains',
      myRole: 'contains',
      membersCount: 'contains',
      createdAt: 'contains',
    });
    this.groupMultiFilters.set({
      name: [],
      description: [],
      myRole: [],
      membersCount: [],
      createdAt: [],
    });
  }

  toggleGroupFilter(key: string, event: Event): void {
    event.stopPropagation();
    if (!this.isGroupColumnKey(key)) {
      return;
    }
    this.groupFilterVisible.update((state) => ({
      ...state,
      [key]: !this.groupFilterVisibility(state, key),
    }));
  }

  setGroupColumnFilter(key: string, event: Event): void {
    if (!this.isGroupColumnKey(key)) {
      return;
    }
    this.groupPageIndex.set(0);
    const target = event.target as HTMLInputElement | null;
    const value = target?.value ?? '';
    this.groupFilterMode.update((state) => ({ ...state, [key]: 'contains' }));
    this.groupMultiFilters.update((state) => ({ ...state, [key]: [] }));
    this.groupColumnFilters.update((state) => ({ ...state, [key]: value }));
  }

  toggleGroupSort(key: string): void {
    if (!this.isGroupColumnKey(key)) {
      return;
    }
    this.groupPageIndex.set(0);
    if (this.groupSortColumn() !== key) {
      this.groupSortColumn.set(key);
      this.groupSortDir.set('asc');
      return;
    }
    this.groupSortDir.set(this.groupSortDir() === 'asc' ? 'desc' : 'asc');
  }

  setGroupPageSize(size: number): void {
    if (!Number.isFinite(size) || size <= 0) {
      return;
    }
    this.groupPageSize.set(size);
    this.groupPageIndex.set(0);
  }

  prevGroupPage(): void {
    this.groupPageIndex.set(Math.max(0, this.groupPageIndex() - 1));
  }

  nextGroupPage(): void {
    this.groupPageIndex.set(Math.min(this.groupTotalPages() - 1, this.groupPageIndex() + 1));
  }

  toggleMemberTablePanel(): void {
    this.memberTablePanelOpen.update((value) => !value);
  }

  dropMemberColumn(event: CdkDragDrop<string[]>): void {
    const next = [...this.memberColumnOrder()];
    moveItemInArray(next, event.previousIndex, event.currentIndex);
    this.memberColumnOrder.set(next);
  }

  removeMemberColumn(value: string): void {
    if (!this.isMemberColumnKey(value) || this.memberLockedColumns.includes(value)) {
      return;
    }
    const next = this.memberColumnOrder().filter((key) => key !== value);
    if (next.length < 1) {
      return;
    }
    this.memberColumnOrder.set(next);
  }

  addMemberColumn(value: string): void {
    if (!this.isMemberColumnKey(value) || this.memberColumnOrder().includes(value)) {
      return;
    }
    this.memberColumnOrder.set([...this.memberColumnOrder(), value]);
  }

  toggleMemberExtendedFilters(): void {
    this.memberFilterPanelOpen.update((value) => !value);
  }

  setMemberFilterMode(key: string, mode: AdvancedFilterMode): void {
    if (!this.isMemberColumnKey(key) || key === 'select') {
      return;
    }
    this.memberPageIndex.set(0);
    this.memberFilterMode.update((state) => ({ ...state, [key]: mode }));
    if (mode === 'contains') {
      this.memberMultiFilters.update((state) => ({ ...state, [key]: [] }));
      return;
    }
    this.memberColumnFilters.update((state) => ({ ...state, [key]: '' }));
  }

  setMemberFilterValue(key: string, value: string): void {
    if (!this.isMemberColumnKey(key) || key === 'select') {
      return;
    }
    this.memberPageIndex.set(0);
    this.memberColumnFilters.update((state) => ({ ...state, [key]: value }));
  }

  setMemberMultiFilter(key: string, values: string[]): void {
    if (!this.isMemberColumnKey(key) || key === 'select') {
      return;
    }
    this.memberPageIndex.set(0);
    this.memberMultiFilters.update((state) => ({ ...state, [key]: values }));
  }

  clearMemberFilters(): void {
    this.memberPageIndex.set(0);
    this.memberColumnFilters.set({
      select: '',
      email: '',
      fullName: '',
      role: '',
      userId: '',
    });
    this.memberFilterMode.set({
      select: 'contains',
      email: 'contains',
      fullName: 'contains',
      role: 'contains',
      userId: 'contains',
    });
    this.memberMultiFilters.set({
      select: [],
      email: [],
      fullName: [],
      role: [],
      userId: [],
    });
  }

  toggleMemberFilter(key: string, event: Event): void {
    event.stopPropagation();
    if (!this.isMemberColumnKey(key) || key === 'select') {
      return;
    }
    this.memberFilterVisible.update((state) => ({
      ...state,
      [key]: !this.memberFilterVisibility(state, key),
    }));
  }

  setMemberColumnFilter(key: string, event: Event): void {
    if (!this.isMemberColumnKey(key) || key === 'select') {
      return;
    }
    this.memberPageIndex.set(0);
    const target = event.target as HTMLInputElement | null;
    const value = target?.value ?? '';
    this.memberFilterMode.update((state) => ({ ...state, [key]: 'contains' }));
    this.memberMultiFilters.update((state) => ({ ...state, [key]: [] }));
    this.memberColumnFilters.update((state) => ({ ...state, [key]: value }));
  }

  toggleMemberSort(key: string): void {
    if (!this.isMemberColumnKey(key) || key === 'select') {
      return;
    }
    this.memberPageIndex.set(0);
    if (this.memberSortColumn() !== key) {
      this.memberSortColumn.set(key);
      this.memberSortDir.set('asc');
      return;
    }
    this.memberSortDir.set(this.memberSortDir() === 'asc' ? 'desc' : 'asc');
  }

  setMemberPageSize(size: number): void {
    if (!Number.isFinite(size) || size <= 0) {
      return;
    }
    this.memberPageSize.set(size);
    this.memberPageIndex.set(0);
  }

  prevMemberPage(): void {
    this.memberPageIndex.set(Math.max(0, this.memberPageIndex() - 1));
  }

  nextMemberPage(): void {
    this.memberPageIndex.set(Math.min(this.memberTotalPages() - 1, this.memberPageIndex() + 1));
  }

  isMemberSelected(userId: string): boolean {
    return this.selectedMemberIds().includes(userId);
  }

  toggleMemberSelection(userId: string, checked: boolean): void {
    this.selectedMemberIds.update((state) => {
      const next = new Set(state);
      if (checked) {
        next.add(userId);
      } else {
        next.delete(userId);
      }
      return Array.from(next);
    });
  }

  setMemberRole(userId: string, role: GroupMemberRole): void {
    if (!this.canManageSelectedGroupMembers() || role === 'OWNER' || this.isOwnerMember(userId)) {
      return;
    }
    this.groupMembersDraft.update((rows) =>
      rows.map((row) => (row.userId === userId ? { ...row, role } : row)),
    );
  }

  removeMember(userId: string): void {
    if (!this.canManageSelectedGroupMembers() || this.isOwnerMember(userId)) {
      return;
    }
    this.groupMembersDraft.update((rows) => rows.filter((row) => row.userId !== userId));
    this.selectedMemberIds.update((ids) => ids.filter((id) => id !== userId));
  }

  removeSelectedMembers(): void {
    if (!this.canManageSelectedGroupMembers()) {
      return;
    }
    const selected = new Set(this.selectedMemberIds());
    if (selected.size === 0) {
      return;
    }
    const removable = new Set(
      this.groupMembersDraft()
        .filter((row) => selected.has(row.userId) && row.role !== 'OWNER')
        .map((row) => row.userId),
    );
    if (removable.size === 0) {
      return;
    }
    this.groupMembersDraft.update((rows) => rows.filter((row) => !removable.has(row.userId)));
    this.selectedMemberIds.update((ids) => ids.filter((id) => !removable.has(id)));
  }

  addSelectedProjectMember(): void {
    if (!this.canManageSelectedGroupMembers()) {
      return;
    }
    const userId = this.addProjectUserId().trim();
    if (!userId) {
      return;
    }
    const projectMember = this.projectMembers().find((member) => member.id === userId);
    if (!projectMember) {
      return;
    }
    const role = this.addProjectUserRole();
    this.addMemberToDraft({
      userId: projectMember.id,
      email: projectMember.email,
      fullName: projectMember.fullName ?? '',
      role,
    });
    this.addProjectUserId.set('');
  }

  resetMemberDraft(): void {
    this.groupMembersDraft.set(this.cloneMembers(this.groupMembersOriginal()));
    this.selectedMemberIds.set([]);
  }

  isOwnerRole(role: GroupMemberRole): boolean {
    return role === 'OWNER';
  }

  canRemoveMember(userId: string): boolean {
    if (!this.canManageSelectedGroupMembers()) {
      return false;
    }
    return !this.isOwnerMember(userId);
  }

  async saveMembers(): Promise<void> {
    if (
      !this.selectedGroupId() ||
      !this.canManageSelectedGroupMembers() ||
      this.membersSavePending()
    ) {
      return;
    }
    this.membersSavePending.set(true);
    this.membersError.set(null);
    const groupId = this.selectedGroupId()!;
    const payload: GroupMemberAssignment[] = this.groupMembersDraft().map((row) => ({
      userId: row.userId,
      role: row.role,
    }));
    try {
      await this.identityApi.replaceGroupMembers(groupId, payload);
      await this.loadSelectedGroupMembers(groupId);
    } catch (error) {
      this.errorHandler.handleError(error);
      this.membersError.set('Failed to save group members.');
    } finally {
      this.membersSavePending.set(false);
    }
  }

  private async initialize(): Promise<void> {
    await this.projectContext.initialize();
    await this.loadGroups();
    await this.loadProjectMembersDirectory();
  }

  private async loadGroups(): Promise<void> {
    this.groupsStatus.set('loading');
    this.groupsError.set(null);
    try {
      const items = await this.identityApi.listGroups();
      this.groups.set(items);
      this.groupsStatus.set('loaded');
      await this.loadGroupInsights(items);

      const currentlySelected = this.selectedGroupId();
      if (currentlySelected && items.some((group) => group.id === currentlySelected)) {
        await this.loadSelectedGroupMembers(currentlySelected);
        return;
      }
      const first = items[0];
      this.selectedGroupId.set(first?.id ?? null);
      if (first) {
        await this.loadSelectedGroupMembers(first.id);
      } else {
        this.groupMembersOriginal.set([]);
        this.groupMembersDraft.set([]);
        this.selectedMemberIds.set([]);
        this.membersStatus.set('idle');
      }
    } catch (error) {
      this.errorHandler.handleError(error);
      this.groupsStatus.set('error');
      this.groupsError.set('Failed to load groups.');
    }
  }

  private async loadGroupInsights(groups: UserGroup[]): Promise<void> {
    const currentUserId = this.currentUserId();
    const entries = await Promise.all(
      groups.map(async (group) => {
        try {
          const members = await this.identityApi.listGroupMembers(group.id);
          const myMembership = currentUserId
            ? members.find((member) => member.userId === currentUserId)
            : undefined;
          return [
            group.id,
            {
              membersCount: members.length,
              myRole: (myMembership?.role ?? null) as GroupMemberRole | null,
            },
          ] as const;
        } catch {
          return [
            group.id,
            {
              membersCount: 0,
              myRole: null,
            },
          ] as const;
        }
      }),
    );
    this.groupInsights.set(new Map(entries));
  }

  private async loadSelectedGroupMembers(groupId: string): Promise<void> {
    this.membersStatus.set('loading');
    this.membersError.set(null);
    this.selectedMemberIds.set([]);
    try {
      const members = await this.identityApi.listGroupMembers(groupId);
      const rows = this.mapMembers(members);
      this.groupMembersOriginal.set(rows);
      this.groupMembersDraft.set(this.cloneMembers(rows));
      this.membersStatus.set('loaded');
      this.groupInsights.update((state) => {
        const next = new Map(state);
        next.set(groupId, {
          membersCount: rows.length,
          myRole:
            rows.find((row) => row.userId === this.currentUserId())?.role ??
            state.get(groupId)?.myRole ??
            null,
        });
        return next;
      });
    } catch (error) {
      this.errorHandler.handleError(error);
      this.membersStatus.set('error');
      this.membersError.set('Failed to load group members.');
      this.groupMembersOriginal.set([]);
      this.groupMembersDraft.set([]);
    }
  }

  private async loadProjectMembersDirectory(): Promise<void> {
    const projectId = this.projectContext.selectedProjectId();
    if (!projectId) {
      this.projectMembersStatus.set('error');
      this.projectMembersError.set('Project members directory is unavailable.');
      this.projectMembers.set([]);
      return;
    }
    this.projectMembersStatus.set('loading');
    this.projectMembersError.set(null);
    try {
      const members = await this.projectsApi.listProjectMembers(projectId);
      this.projectMembers.set(
        [...members].sort((left, right) =>
          left.email.localeCompare(right.email, undefined, { sensitivity: 'base' }),
        ),
      );
      this.projectMembersStatus.set('loaded');
    } catch (error) {
      if (error instanceof HttpErrorResponse && error.status === 403) {
        this.projectMembersStatus.set('error');
        this.projectMembersError.set(
          'Project member directory is visible only for project administrators.',
        );
        this.projectMembers.set([]);
        return;
      }
      this.errorHandler.handleError(error);
      this.projectMembersStatus.set('error');
      this.projectMembersError.set('Failed to load project member directory.');
      this.projectMembers.set([]);
    }
  }

  private addMemberToDraft(nextMember: EditableMemberRow): void {
    this.groupMembersDraft.update((rows) => {
      if (rows.some((row) => row.userId === nextMember.userId)) {
        return rows;
      }
      return this.sortMembers([...rows, nextMember]);
    });
  }

  private mapMembers(items: UserGroupMember[]): EditableMemberRow[] {
    const mapped = items.map((member) => ({
      userId: member.userId,
      email: (member.email ?? '').trim(),
      fullName: (member.fullName ?? '').trim(),
      role: member.role,
    }));
    return this.sortMembers(mapped);
  }

  private sortMembers(items: EditableMemberRow[]): EditableMemberRow[] {
    return [...items].sort((left, right) => {
      const leftEmail = (left.email || left.userId).toLowerCase();
      const rightEmail = (right.email || right.userId).toLowerCase();
      if (leftEmail === rightEmail) {
        return left.userId.localeCompare(right.userId, undefined, { sensitivity: 'base' });
      }
      return leftEmail.localeCompare(rightEmail, undefined, { sensitivity: 'base' });
    });
  }

  private cloneMembers(items: EditableMemberRow[]): EditableMemberRow[] {
    return items.map((item) => ({ ...item }));
  }

  private membersFingerprint(items: EditableMemberRow[]): string {
    return this.sortMembers(items)
      .map((item) => `${item.userId}:${item.role}`)
      .join('|');
  }

  private availableColumns(columns: ColumnDefinition[], order: string[]): ColumnDefinition[] {
    const selected = new Set(order);
    return columns.filter((column) => !selected.has(column.key));
  }

  private sortedOptions(values: (string | undefined | null)[]): string[] {
    const set = new Set<string>();
    for (const value of values) {
      const normalized = (value ?? '').trim();
      if (normalized) {
        set.add(normalized);
      }
    }
    return [...set].sort((left, right) =>
      left.localeCompare(right, undefined, { sensitivity: 'base' }),
    );
  }

  private matchesAdvancedFilter(
    value: string,
    mode: AdvancedFilterMode,
    containsFilter: string,
    selectedValues: string[],
  ): boolean {
    const normalizedValue = (value ?? '').trim().toLowerCase();
    if (mode === 'select') {
      if (!selectedValues || selectedValues.length === 0) {
        return true;
      }
      const options = new Set(selectedValues.map((item) => item.trim().toLowerCase()));
      return options.has(normalizedValue);
    }
    const normalizedFilter = (containsFilter ?? '').trim().toLowerCase();
    if (!normalizedFilter) {
      return true;
    }
    return normalizedValue.includes(normalizedFilter);
  }

  private isGroupColumnKey(value: string): value is GroupColumnKey {
    return (
      value === 'name' ||
      value === 'description' ||
      value === 'myRole' ||
      value === 'membersCount' ||
      value === 'createdAt'
    );
  }

  private isMemberColumnKey(value: string): value is MemberColumnKey {
    return (
      value === 'select' ||
      value === 'email' ||
      value === 'fullName' ||
      value === 'role' ||
      value === 'userId'
    );
  }

  private groupFilterVisibility(
    state: Record<GroupColumnKey, boolean>,
    key: GroupColumnKey,
  ): boolean {
    switch (key) {
      case 'name':
        return state.name;
      case 'description':
        return state.description;
      case 'myRole':
        return state.myRole;
      case 'membersCount':
        return state.membersCount;
      case 'createdAt':
        return state.createdAt;
    }
  }

  private memberFilterVisibility(
    state: Record<MemberColumnKey, boolean>,
    key: Exclude<MemberColumnKey, 'select'>,
  ): boolean {
    switch (key) {
      case 'email':
        return state.email;
      case 'fullName':
        return state.fullName;
      case 'role':
        return state.role;
      case 'userId':
        return state.userId;
    }
  }

  private isOwnerMember(userId: string): boolean {
    const row = this.groupMembersDraft().find((item) => item.userId === userId);
    return row?.role === 'OWNER';
  }

  private formatDate(value: string | undefined | null): string {
    if (!value) {
      return '-';
    }
    const parsed = Date.parse(value);
    if (Number.isNaN(parsed)) {
      return '-';
    }
    return new Date(parsed).toLocaleString();
  }

  private paginate<T>(rows: T[], pageIndex: number, pageSize: number): T[] {
    if (pageSize <= 0) {
      return rows;
    }
    const start = pageIndex * pageSize;
    return rows.slice(start, start + pageSize);
  }

  private totalPages(total: number, pageSize: number): number {
    if (pageSize <= 0) {
      return 1;
    }
    return Math.max(1, Math.ceil(total / pageSize));
  }
}
