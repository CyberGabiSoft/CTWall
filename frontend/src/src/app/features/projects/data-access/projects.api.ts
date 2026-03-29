import { HttpClient, HttpParams } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { firstValueFrom } from 'rxjs';
import {
  ProjectMemberAssignment,
  ProjectCreateRequest,
  ProjectDeleteRequest,
  ProjectMember,
  ProjectMembersRequest,
  ProjectSummary,
  ProjectUpdateRequest,
  SelectedProjectResponse,
} from './projects.types';
import { extractItems } from '../../../shared/utils/api-payload';

interface UserSummary {
  id: string;
  email: string;
  role: 'ADMIN' | 'WRITER' | 'READER';
  accountType: 'USER' | 'SERVICE_ACCOUNT';
  fullName?: string;
}

@Injectable({ providedIn: 'root' })
export class ProjectsApi {
  private readonly http = inject(HttpClient);

  async listProjects(): Promise<ProjectSummary[]> {
    return this.fetchAll<ProjectSummary>('/projects');
  }

  async createProject(payload: ProjectCreateRequest): Promise<ProjectSummary> {
    return firstValueFrom(this.http.post<ProjectSummary>('/projects', payload));
  }

  async updateProject(projectId: string, payload: ProjectUpdateRequest): Promise<ProjectSummary> {
    return firstValueFrom(
      this.http.put<ProjectSummary>(`/projects/${encodeURIComponent(projectId)}`, payload),
    );
  }

  async deleteProject(projectId: string, acknowledge = true): Promise<void> {
    const body: ProjectDeleteRequest = { acknowledge };
    await firstValueFrom(
      this.http.request<void>('DELETE', `/projects/${encodeURIComponent(projectId)}`, { body }),
    );
  }

  async listProjectMembers(projectId: string): Promise<ProjectMember[]> {
    return firstValueFrom(
      this.http.get<ProjectMember[]>(`/projects/${encodeURIComponent(projectId)}/members`),
    );
  }

  async replaceProjectMembers(
    projectId: string,
    members: ProjectMemberAssignment[],
  ): Promise<void> {
    const payload: ProjectMembersRequest = { members };
    await firstValueFrom(
      this.http.put<void>(`/projects/${encodeURIComponent(projectId)}/members`, payload),
    );
  }

  async getSelectedProject(): Promise<SelectedProjectResponse> {
    return firstValueFrom(this.http.get<SelectedProjectResponse>('/me/project'));
  }

  async setSelectedProject(projectId: string): Promise<SelectedProjectResponse> {
    return firstValueFrom(this.http.put<SelectedProjectResponse>('/me/project', { projectId }));
  }

  async listUsers(): Promise<UserSummary[]> {
    return this.fetchAll<UserSummary>('/users');
  }

  private async fetchAll<T>(url: string): Promise<T[]> {
    const pageSize = 200;
    const items: T[] = [];
    let page = 1;

    while (true) {
      const params = new HttpParams().set('page', String(page)).set('pageSize', String(pageSize));
      const payload = await firstValueFrom(this.http.get<unknown>(url, { params }));
      const batch = extractItems<T>(payload);
      items.push(...batch);
      if (batch.length < pageSize) {
        break;
      }
      page += 1;
    }

    return items;
  }
}
