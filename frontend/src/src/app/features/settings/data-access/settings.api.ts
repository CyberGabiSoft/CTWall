import { HttpClient, HttpContext, HttpParams } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { firstValueFrom } from 'rxjs';
import { SKIP_SUCCESS_FEEDBACK } from '../../../core/interceptors/success-feedback.interceptor';
import {
  AdminConnector,
  ConnectorTestRequest,
  CreateUserTokenRequest,
  CreateUserTokenResponse,
  ConnectorTestResponse,
  ConnectorUpsertRequest,
  CreateUserRequest,
  ResetUserPasswordRequest,
  SettingsGeneralResponse,
  SettingsUser,
  UpdateUserRequest
} from './settings.types';
import { extractItems } from '../../../shared/utils/api-payload';

@Injectable({ providedIn: 'root' })
export class SettingsApi {
  private readonly http = inject(HttpClient);

  async getGeneral(): Promise<SettingsGeneralResponse> {
    return firstValueFrom(this.http.get<SettingsGeneralResponse>('/admin/settings/general'));
  }

  async listConnectors(): Promise<AdminConnector[]> {
    return firstValueFrom(this.http.get<AdminConnector[]>('/admin/connectors'));
  }

  async updateConnector(type: string, payload: ConnectorUpsertRequest): Promise<AdminConnector> {
    return firstValueFrom(
      this.http.put<AdminConnector>(`/admin/connectors/${encodeURIComponent(type)}`, payload)
    );
  }

  async testConnector(type: string, payload?: ConnectorTestRequest): Promise<ConnectorTestResponse> {
    return firstValueFrom(
      this.http.post<ConnectorTestResponse>(`/admin/connectors/${encodeURIComponent(type)}/test`, payload ?? {}, {
        context: new HttpContext().set(SKIP_SUCCESS_FEEDBACK, true)
      })
    );
  }

  async listUsers(): Promise<SettingsUser[]> {
    return this.fetchAll<SettingsUser>('/users');
  }

  async createUser(payload: CreateUserRequest): Promise<SettingsUser> {
    return firstValueFrom(this.http.post<SettingsUser>('/users', payload));
  }

  async updateUser(userId: string, payload: UpdateUserRequest): Promise<SettingsUser> {
    return firstValueFrom(this.http.patch<SettingsUser>(`/users/${encodeURIComponent(userId)}`, payload));
  }

  async resetUserPassword(userId: string, payload: ResetUserPasswordRequest): Promise<void> {
    await firstValueFrom(this.http.post<void>(`/users/${encodeURIComponent(userId)}/password`, payload));
  }

  async createUserToken(userId: string, payload?: CreateUserTokenRequest): Promise<CreateUserTokenResponse> {
    return firstValueFrom(
      this.http.post<CreateUserTokenResponse>(`/users/${encodeURIComponent(userId)}/tokens`, payload ?? {})
    );
  }

  async deleteUser(userId: string): Promise<void> {
    await firstValueFrom(this.http.delete<void>(`/users/${encodeURIComponent(userId)}`));
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
