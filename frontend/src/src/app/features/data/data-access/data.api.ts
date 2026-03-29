import { HttpClient, HttpParams } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { firstValueFrom } from 'rxjs';
import {
  ComponentSummary,
  JiraConfigLevel,
  JiraDeliveriesResponse,
  JiraEffectiveSettings,
  JiraEntitySettings,
  JiraEntitySettingsUpsertPayload,
  JiraIssueMappingsResponse,
  JiraManualRetryResponse,
  JiraMetadataComponent,
  JiraMetadataIssue,
  JiraMetadataIssueField,
  JiraMetadataIssueType,
  JiraMetadataPriority,
  JiraMetadataProject,
  JiraMetadataResponse,
  JiraMetadataTransition,
  ProductSummary,
  ScopeSummary,
  TestRevisionChangeSummary,
  TestRevisionFindingDiff,
  TestRevisionSummary,
  TestSummary
} from './data.types';
import { extractItems } from '../../../shared/utils/api-payload';

@Injectable({ providedIn: 'root' })
export class DataApi {
  private readonly http = inject(HttpClient);

  async getProducts(): Promise<ProductSummary[]> {
    return this.fetchAll<ProductSummary>('/products');
  }

  async createProduct(name: string): Promise<ProductSummary> {
    return firstValueFrom(this.http.post<ProductSummary>('/products', { name }));
  }

  async deleteProduct(productId: string): Promise<void> {
    await firstValueFrom(this.http.delete<void>(`/products/${encodeURIComponent(productId)}`));
  }

  async getScopes(productId: string): Promise<ScopeSummary[]> {
    return this.fetchAll<ScopeSummary>(`/products/${encodeURIComponent(productId)}/scopes`);
  }

  async createScope(productId: string, name: string): Promise<ScopeSummary> {
    return firstValueFrom(
      this.http.post<ScopeSummary>(`/products/${encodeURIComponent(productId)}/scopes`, { name })
    );
  }

  async getAllScopes(): Promise<ScopeSummary[]> {
    return this.fetchAll<ScopeSummary>('/scopes');
  }

  async deleteScope(scopeId: string): Promise<void> {
    await firstValueFrom(this.http.delete<void>(`/scopes/${encodeURIComponent(scopeId)}`));
  }

  async getTests(scopeId: string): Promise<TestSummary[]> {
    return this.fetchAll<TestSummary>(`/scopes/${encodeURIComponent(scopeId)}/tests`);
  }

  async getAllTests(): Promise<TestSummary[]> {
    return this.fetchAll<TestSummary>('/tests');
  }

  async deleteTest(testId: string): Promise<void> {
    await firstValueFrom(this.http.delete<void>(`/tests/${encodeURIComponent(testId)}`));
  }

  async getRevisions(testId: string): Promise<TestRevisionSummary[]> {
    return this.fetchAll<TestRevisionSummary>(`/tests/${encodeURIComponent(testId)}/revisions`);
  }

  async getRevisionLastChanges(testId: string): Promise<TestRevisionChangeSummary[]> {
    return this.fetchAll<TestRevisionChangeSummary>(`/tests/${encodeURIComponent(testId)}/revisions/last-changes`);
  }

  async getRevisionChanges(testId: string, revisionId: string, diffTypes: string[] = []): Promise<TestRevisionFindingDiff[]> {
    let params = new HttpParams();
    for (const diffType of diffTypes) {
      const normalized = diffType.trim();
      if (normalized.length > 0) {
        params = params.append('diffType', normalized);
      }
    }
    return this.fetchAllWithParams<TestRevisionFindingDiff>(
      `/tests/${encodeURIComponent(testId)}/revisions/${encodeURIComponent(revisionId)}/changes`,
      params
    );
  }

  async getRevisionChangesSummary(testId: string, revisionId: string): Promise<TestRevisionChangeSummary> {
    return firstValueFrom(
      this.http.get<TestRevisionChangeSummary>(
        `/tests/${encodeURIComponent(testId)}/revisions/${encodeURIComponent(revisionId)}/changes/summary`
      )
    );
  }

  async getComponents(testId: string): Promise<ComponentSummary[]> {
    return this.fetchAll<ComponentSummary>(`/tests/${encodeURIComponent(testId)}/components`);
  }

  async getComponentsPage(testId: string, page: number, pageSize: number, q?: string): Promise<ComponentSummary[]> {
    let params = new HttpParams()
      .set('page', String(page))
      .set('pageSize', String(pageSize));
    const query = (q ?? '').trim();
    if (query.length > 0) {
      params = params.set('q', query);
    }

    const payload = await firstValueFrom(
      this.http.get<unknown>(`/tests/${encodeURIComponent(testId)}/components`, { params })
    );

    return extractItems<ComponentSummary>(payload);
  }

  async getComponentsCount(testId: string): Promise<number> {
    const payload = await firstValueFrom(
      this.http.get<{ count: number }>(`/tests/${encodeURIComponent(testId)}/components/count`)
    );
    return payload?.count ?? 0;
  }

  async getProductJiraSettings(productId: string): Promise<JiraEntitySettings> {
    return firstValueFrom(this.http.get<JiraEntitySettings>(`/data/products/${encodeURIComponent(productId)}/jira/settings`));
  }

  async putProductJiraSettings(productId: string, payload: JiraEntitySettingsUpsertPayload): Promise<JiraEntitySettings> {
    return firstValueFrom(
      this.http.put<JiraEntitySettings>(`/data/products/${encodeURIComponent(productId)}/jira/settings`, payload)
    );
  }

  async getScopeJiraSettings(scopeId: string): Promise<JiraEntitySettings> {
    return firstValueFrom(this.http.get<JiraEntitySettings>(`/data/scopes/${encodeURIComponent(scopeId)}/jira/settings`));
  }

  async putScopeJiraSettings(scopeId: string, payload: JiraEntitySettingsUpsertPayload): Promise<JiraEntitySettings> {
    return firstValueFrom(
      this.http.put<JiraEntitySettings>(`/data/scopes/${encodeURIComponent(scopeId)}/jira/settings`, payload)
    );
  }

  async getTestJiraSettings(testId: string): Promise<JiraEntitySettings> {
    return firstValueFrom(this.http.get<JiraEntitySettings>(`/data/tests/${encodeURIComponent(testId)}/jira/settings`));
  }

  async putTestJiraSettings(testId: string, payload: JiraEntitySettingsUpsertPayload): Promise<JiraEntitySettings> {
    return firstValueFrom(
      this.http.put<JiraEntitySettings>(`/data/tests/${encodeURIComponent(testId)}/jira/settings`, payload)
    );
  }

  async getTestEffectiveJiraSettings(testId: string): Promise<JiraEffectiveSettings> {
    return firstValueFrom(
      this.http.get<JiraEffectiveSettings>(`/data/tests/${encodeURIComponent(testId)}/jira/effective-settings`)
    );
  }

  async listJiraIssuesByOwner(level: JiraConfigLevel, targetId: string, page = 1, pageSize = 25): Promise<JiraIssueMappingsResponse> {
    return this.listJiraIssuesByOwnerWithFilters(level, targetId, {
      page,
      pageSize,
      status: 'open'
    });
  }

  async listJiraIssuesByOwnerWithFilters(
    level: JiraConfigLevel,
    targetId: string,
    options: {
      page?: number;
      pageSize?: number;
      status?: 'open' | 'closed' | 'all';
      component?: string;
      jiraKey?: string;
    } = {}
  ): Promise<JiraIssueMappingsResponse> {
    let params = new HttpParams()
      .set('page', String(options.page ?? 1))
      .set('pageSize', String(options.pageSize ?? 25))
      .set('status', options.status ?? 'open');
    const component = (options.component ?? '').trim();
    if (component.length > 0) {
      params = params.set('component', component);
    }
    const jiraKey = (options.jiraKey ?? '').trim();
    if (jiraKey.length > 0) {
      params = params.set('jiraKey', jiraKey);
    }
    return firstValueFrom(
      this.http.get<JiraIssueMappingsResponse>(`${this.jiraOwnerBasePath(level, targetId)}/jira/issues`, { params })
    );
  }

  async listJiraDeliveriesByOwner(level: JiraConfigLevel, targetId: string, page = 1, pageSize = 25): Promise<JiraDeliveriesResponse> {
    return firstValueFrom(
      this.http.get<JiraDeliveriesResponse>(`${this.jiraOwnerBasePath(level, targetId)}/jira/deliveries`, {
        params: new HttpParams().set('page', String(page)).set('pageSize', String(pageSize))
      })
    );
  }

  async retryJiraDeliveryByOwner(level: JiraConfigLevel, targetId: string, alertGroupId: string): Promise<JiraManualRetryResponse> {
    return firstValueFrom(
      this.http.post<JiraManualRetryResponse>(`${this.jiraOwnerBasePath(level, targetId)}/jira/retry`, {
        alertGroupId: (alertGroupId ?? '').trim()
      })
    );
  }

  async getJiraMetadataProjects(forceRefresh = false): Promise<JiraMetadataResponse<JiraMetadataProject>> {
    let params = new HttpParams();
    if (forceRefresh) {
      params = params.set('forceRefresh', 'true');
    }
    return firstValueFrom(this.http.get<JiraMetadataResponse<JiraMetadataProject>>('/data/jira/metadata/projects', { params }));
  }

  async getJiraMetadataIssueTypes(projectKey: string, forceRefresh = false): Promise<JiraMetadataResponse<JiraMetadataIssueType>> {
    let params = new HttpParams().set('projectKey', projectKey);
    if (forceRefresh) {
      params = params.set('forceRefresh', 'true');
    }
    return firstValueFrom(this.http.get<JiraMetadataResponse<JiraMetadataIssueType>>('/data/jira/metadata/issue-types', { params }));
  }

  async getJiraMetadataComponents(projectKey: string, forceRefresh = false): Promise<JiraMetadataResponse<JiraMetadataComponent>> {
    let params = new HttpParams().set('projectKey', projectKey);
    if (forceRefresh) {
      params = params.set('forceRefresh', 'true');
    }
    return firstValueFrom(this.http.get<JiraMetadataResponse<JiraMetadataComponent>>('/data/jira/metadata/components', { params }));
  }

  async getJiraMetadataPriorities(forceRefresh = false): Promise<JiraMetadataResponse<JiraMetadataPriority>> {
    let params = new HttpParams();
    if (forceRefresh) {
      params = params.set('forceRefresh', 'true');
    }
    return firstValueFrom(this.http.get<JiraMetadataResponse<JiraMetadataPriority>>('/data/jira/metadata/priorities', { params }));
  }

  async getJiraMetadataIssues(
    projectKey: string,
    forceRefresh = false,
    issueTypeName?: string
  ): Promise<JiraMetadataResponse<JiraMetadataIssue>> {
    let params = new HttpParams().set('projectKey', projectKey);
    if (forceRefresh) {
      params = params.set('forceRefresh', 'true');
    }
    const normalizedIssueTypeName = (issueTypeName ?? '').trim();
    if (normalizedIssueTypeName) {
      params = params.set('issueTypeName', normalizedIssueTypeName);
    }
    return firstValueFrom(this.http.get<JiraMetadataResponse<JiraMetadataIssue>>('/data/jira/metadata/issues', { params }));
  }

  async getJiraMetadataTransitions(issueIdOrKey: string, forceRefresh = false): Promise<JiraMetadataResponse<JiraMetadataTransition>> {
    let params = new HttpParams().set('issueIdOrKey', issueIdOrKey);
    if (forceRefresh) {
      params = params.set('forceRefresh', 'true');
    }
    return firstValueFrom(this.http.get<JiraMetadataResponse<JiraMetadataTransition>>('/data/jira/metadata/transitions', { params }));
  }

  async getJiraMetadataIssueFields(
    projectKey: string,
    issueTypeId: string,
    forceRefresh = false
  ): Promise<JiraMetadataResponse<JiraMetadataIssueField>> {
    let params = new HttpParams()
      .set('projectKey', projectKey)
      .set('issueTypeId', issueTypeId);
    if (forceRefresh) {
      params = params.set('forceRefresh', 'true');
    }
    return firstValueFrom(this.http.get<JiraMetadataResponse<JiraMetadataIssueField>>('/data/jira/metadata/issue-fields', { params }));
  }

  private async fetchAll<T>(url: string): Promise<T[]> {
    return this.fetchAllWithParams<T>(url);
  }

  private async fetchAllWithParams<T>(url: string, baseParams?: HttpParams): Promise<T[]> {
    const pageSize = 200;
    const items: T[] = [];
    let page = 1;

    while (true) {
      let params = new HttpParams()
        .set('page', String(page))
        .set('pageSize', String(pageSize));
      if (baseParams) {
        for (const key of baseParams.keys()) {
          const values = baseParams.getAll(key);
          if (!values) {
            continue;
          }
          for (const value of values) {
            params = params.append(key, value);
          }
        }
      }

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

  private jiraOwnerBasePath(level: JiraConfigLevel, targetId: string): string {
    const id = encodeURIComponent(targetId);
    switch (level) {
      case 'PRODUCT':
        return `/data/products/${id}`;
      case 'SCOPE':
        return `/data/scopes/${id}`;
      case 'TEST':
        return `/data/tests/${id}`;
    }
  }
}
