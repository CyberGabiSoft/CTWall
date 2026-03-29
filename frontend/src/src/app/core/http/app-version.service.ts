import { HttpClient } from '@angular/common/http';
import { Injectable, inject, signal } from '@angular/core';
import { firstValueFrom } from 'rxjs';
import { API_PREFIX } from './http.tokens';

interface HealthResponse {
  status?: string;
  version?: string;
}

@Injectable({ providedIn: 'root' })
export class AppVersionService {
  private readonly http = inject(HttpClient);
  private readonly apiPrefix = inject(API_PREFIX);
  private hasLoaded = false;
  private readonly healthUrl = `${this.apiPrefix.replace(/\/$/, '')}/health`;

  readonly version = signal('');

  constructor() {
    void this.load();
  }

  private async load(): Promise<void> {
    if (this.hasLoaded) {
      return;
    }
    this.hasLoaded = true;

    try {
      const response = await firstValueFrom(this.http.get<HealthResponse>(this.healthUrl));
      const version = response.version?.trim() ?? '';
      if (version.length > 0) {
        this.version.set(version);
      }
    } catch {
      this.version.set('');
    }
  }
}
