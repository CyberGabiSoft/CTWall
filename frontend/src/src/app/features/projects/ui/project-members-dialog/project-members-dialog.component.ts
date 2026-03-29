
import { ChangeDetectionStrategy, Component, ErrorHandler, inject, signal } from '@angular/core';
import { MAT_DIALOG_DATA, MatDialogModule, MatDialogRef } from '@angular/material/dialog';
import { MatButtonModule } from '@angular/material/button';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatSelectModule } from '@angular/material/select';
import { MatOptionModule } from '@angular/material/core';
import { ProjectsApi } from '../../data-access/projects.api';
import {
  ProjectMember,
  ProjectMemberAssignment,
  ProjectRole,
} from '../../data-access/projects.types';
import { LoadingIndicatorComponent } from '../../../../shared/ui/loading-indicator/loading-indicator.component';

interface UserSummary {
  id: string;
  email: string;
  role: 'ADMIN' | 'WRITER' | 'READER';
  accountType: 'USER' | 'SERVICE_ACCOUNT';
  fullName?: string;
}

export interface ProjectMembersDialogData {
  projectId: string;
  projectName: string;
}

@Component({
  selector: 'app-project-members-dialog',
  imports: [
    MatDialogModule,
    MatButtonModule,
    MatFormFieldModule,
    MatSelectModule,
    MatOptionModule,
    LoadingIndicatorComponent
],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './project-members-dialog.component.html',
  styleUrl: './project-members-dialog.component.scss',
})
export class ProjectMembersDialogComponent {
  readonly data = inject<ProjectMembersDialogData>(MAT_DIALOG_DATA);
  private readonly ref = inject(MatDialogRef<ProjectMembersDialogComponent, boolean>);
  private readonly api = inject(ProjectsApi);
  private readonly errorHandler = inject(ErrorHandler);

  readonly status = signal<'loading' | 'loaded' | 'saving' | 'error'>('loading');
  readonly users = signal<UserSummary[]>([]);
  readonly selectedUserIds = signal<string[]>([]);
  readonly roleByUserId = signal<Map<string, ProjectRole>>(new Map());
  readonly errorMessage = signal<string | null>(null);

  constructor() {
    void this.load();
  }

  cancel(): void {
    this.ref.close(false);
  }

  async save(): Promise<void> {
    if (this.status() === 'saving') {
      return;
    }
    this.status.set('saving');
    this.errorMessage.set(null);
    try {
      const members = this.buildMemberAssignments();
      await this.api.replaceProjectMembers(this.data.projectId, members);
      this.ref.close(true);
    } catch (error) {
      this.errorHandler.handleError(error);
      this.status.set('error');
      this.errorMessage.set('Failed to update project members.');
    }
  }

  userLabel(user: UserSummary): string {
    const fullName = (user.fullName ?? '').trim();
    if (fullName.length > 0) {
      return `${fullName} (${user.email})`;
    }
    return user.email;
  }

  memberSelectionLabel(userId: string): string {
    const user = this.users().find((item) => item.id === userId);
    if (!user) {
      return userId;
    }
    const fullName = (user.fullName ?? '').trim();
    if (fullName.length > 0) {
      return `${fullName} (${user.email})`;
    }
    return user.email;
  }

  onSelectionChange(nextUserIds: unknown): void {
    const rawIds = Array.isArray(nextUserIds) ? nextUserIds : [];
    const normalized = rawIds
      .map((value) => (typeof value === 'string' ? value.trim() : ''))
      .filter((value) => value.length > 0);
    const uniqueIds = Array.from(new Set(normalized));
    this.selectedUserIds.set(uniqueIds);
    this.roleByUserId.update((state) => {
      const next = new Map<string, ProjectRole>();
      for (const userId of uniqueIds) {
        next.set(userId, state.get(userId) ?? 'READER');
      }
      return next;
    });
  }

  setMemberRole(userId: string, role: unknown): void {
    const normalized = this.normalizeProjectRole(role);
    if (!normalized) {
      return;
    }
    this.roleByUserId.update((state) => {
      const next = new Map(state);
      next.set(userId, normalized);
      return next;
    });
  }

  getMemberRole(userId: string): ProjectRole {
    return this.roleByUserId().get(userId) ?? 'READER';
  }

  private async load(): Promise<void> {
    this.status.set('loading');
    this.errorMessage.set(null);
    try {
      const [users, members] = await Promise.all([
        this.api.listUsers(),
        this.api.listProjectMembers(this.data.projectId),
      ]);
      const sortedUsers = users.slice().sort((a, b) => a.email.localeCompare(b.email));
      this.users.set(sortedUsers);
      this.selectedUserIds.set(this.memberIds(members));
      this.roleByUserId.set(this.memberRoles(members));
      this.status.set('loaded');
    } catch (error) {
      this.errorHandler.handleError(error);
      this.status.set('error');
      this.errorMessage.set('Failed to load project members.');
    }
  }

  private memberIds(members: ProjectMember[]): string[] {
    return members.map((member) => member.id);
  }

  private memberRoles(members: ProjectMember[]): Map<string, ProjectRole> {
    const out = new Map<string, ProjectRole>();
    for (const member of members) {
      out.set(member.id, member.projectRole);
    }
    return out;
  }

  private buildMemberAssignments(): ProjectMemberAssignment[] {
    const roleState = this.roleByUserId();
    return this.selectedUserIds().map((userId) => ({
      userId,
      projectRole: roleState.get(userId) ?? 'READER',
    }));
  }

  private normalizeProjectRole(role: unknown): ProjectRole | null {
    if (role === 'ADMIN' || role === 'WRITER' || role === 'READER') {
      return role;
    }
    return null;
  }
}
