import { Injectable, computed, inject, signal } from '@angular/core';
import { ProjectsApi } from './projects.api';
import { ProjectSummary, SelectedProjectRole } from './projects.types';

const projectRoleRank = (role: SelectedProjectRole | null): number => {
  switch (role) {
    case 'READER':
      return 1;
    case 'WRITER':
      return 2;
    case 'ADMIN':
      return 3;
    default:
      return 0;
  }
};

@Injectable({ providedIn: 'root' })
export class ProjectContextService {
  private readonly api = inject(ProjectsApi);

  private readonly projectsState = signal<ProjectSummary[]>([]);
  private readonly selectedProjectIdState = signal<string | null>(null);
  private readonly selectedProjectNameState = signal<string | null>(null);
  private readonly selectedProjectRoleState = signal<SelectedProjectRole | null>(null);
  private readonly initializedState = signal(false);
  private readonly loadingState = signal(false);

  readonly projects = computed(() => this.projectsState());
  readonly selectedProjectId = computed(() => this.selectedProjectIdState());
  readonly selectedProjectName = computed(() => this.selectedProjectNameState());
  readonly selectedProjectRole = computed(() => this.selectedProjectRoleState());
  readonly initialized = computed(() => this.initializedState());
  readonly loading = computed(() => this.loadingState());
  readonly canRead = computed(() => projectRoleRank(this.selectedProjectRoleState()) >= 1);
  readonly canWrite = computed(() => projectRoleRank(this.selectedProjectRoleState()) >= 2);
  readonly canAdmin = computed(() => projectRoleRank(this.selectedProjectRoleState()) >= 3);

  async initialize(): Promise<void> {
    if (this.initializedState()) {
      return;
    }
    this.loadingState.set(true);
    try {
      await this.refresh();
      this.initializedState.set(true);
    } finally {
      this.loadingState.set(false);
    }
  }

  async refresh(): Promise<void> {
    const projects = await this.api.listProjects();
    this.projectsState.set(projects);

    if (projects.length === 0) {
      this.selectedProjectIdState.set(null);
      this.selectedProjectNameState.set(null);
      this.selectedProjectRoleState.set(null);
      return;
    }

    try {
      const selected = await this.api.getSelectedProject();
      this.selectedProjectIdState.set(selected.projectId);
      this.selectedProjectNameState.set(selected.name);
      this.selectedProjectRoleState.set(selected.projectRole);
      return;
    } catch {
      const fallback = projects[0];
      const selected = await this.api.setSelectedProject(fallback.id);
      this.selectedProjectIdState.set(selected.projectId);
      this.selectedProjectNameState.set(selected.name);
      this.selectedProjectRoleState.set(selected.projectRole);
    }
  }

  async selectProject(projectId: string): Promise<void> {
    if (!projectId || projectId === this.selectedProjectIdState()) {
      return;
    }
    const selected = await this.api.setSelectedProject(projectId);
    this.selectedProjectIdState.set(selected.projectId);
    this.selectedProjectNameState.set(selected.name);
    this.selectedProjectRoleState.set(selected.projectRole);
  }

  clear(): void {
    this.projectsState.set([]);
    this.selectedProjectIdState.set(null);
    this.selectedProjectNameState.set(null);
    this.selectedProjectRoleState.set(null);
    this.initializedState.set(false);
    this.loadingState.set(false);
  }
}
