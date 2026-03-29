import { HttpClient, HttpParams } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { firstValueFrom } from 'rxjs';
import { extractItems } from '../../../shared/utils/api-payload';
import {
  GroupCreateRequest,
  GroupMemberAssignment,
  GroupMembersSetRequest,
  UserGroup,
  UserGroupMember,
} from './identity.types';

@Injectable({ providedIn: 'root' })
export class IdentityApi {
  private readonly http = inject(HttpClient);

  async listGroups(): Promise<UserGroup[]> {
    return this.fetchAll<UserGroup>('/groups');
  }

  async createGroup(payload: GroupCreateRequest): Promise<UserGroup> {
    return firstValueFrom(this.http.post<UserGroup>('/groups', payload));
  }

  async listGroupMembers(groupId: string): Promise<UserGroupMember[]> {
    return firstValueFrom(
      this.http.get<UserGroupMember[]>(`/groups/${encodeURIComponent(groupId)}/members`),
    );
  }

  async replaceGroupMembers(groupId: string, members: GroupMemberAssignment[]): Promise<void> {
    const payload: GroupMembersSetRequest = { members };
    await firstValueFrom(
      this.http.put<void>(`/groups/${encodeURIComponent(groupId)}/members`, payload),
    );
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
