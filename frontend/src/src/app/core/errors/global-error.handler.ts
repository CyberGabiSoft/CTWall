import { ErrorHandler, Injectable, inject, isDevMode } from '@angular/core';
import { HttpErrorResponse } from '@angular/common/http';
import { ErrorStateService } from './error-state.service';

interface ProblemDetails {
  title?: string;
  status?: number;
  detail?: string;
  instance?: string;
  errorId?: string;
}

@Injectable({ providedIn: 'root' })
export class GlobalErrorHandler extends ErrorHandler {
  private readonly errorState = inject(ErrorStateService);

  override handleError(error: unknown): void {
    const normalized = this.normalizeError(error);

    // Avoid logging sensitive data; keep logs concise.
    if (isDevMode()) {
      // In dev, preserve the original error for debugging.
      console.error('[GlobalErrorHandler]', normalized.original ?? normalized.message);
    } else {
      console.error('[GlobalErrorHandler]', normalized.message);
    }

    if (normalized.showToUser) {
      this.errorState.setError({
        message: normalized.message,
        errorId: normalized.errorId,
        status: normalized.status
      });
    }
  }

  private normalizeError(error: unknown): {
    message: string;
    original?: unknown;
    status?: number;
    errorId?: string;
    showToUser: boolean;
  } {
    if (error instanceof HttpErrorResponse) {
      const problem = this.asProblemDetails(error.error);
      const status = typeof problem.status === 'number' ? problem.status : error.status;
      const title = problem.title ?? error.statusText ?? 'HTTP error';
      const detail = problem.detail ?? 'Request failed.';
      const instance = problem.instance ? ` (${problem.instance})` : '';
      const errorId = (problem.errorId ?? '').trim() || this.extractErrorId(error);
      const isServerError = status >= 500 || status === 0;
      const message = isServerError
        ? 'Server error. Please try again.'
        : `${title} [${status}]: ${detail}${instance}`;
      return {
        message,
        original: error,
        status,
        errorId,
        showToUser: isServerError
      };
    }

    if (error instanceof Error) {
      const message = (error.message ?? '').trim() || 'Unknown error';
      if (this.isIgnoredRuntimeNoise(message)) {
        return { message, original: error, showToUser: false };
      }
      return { message, original: error, showToUser: true };
    }

    return { message: 'Unknown error', original: error, showToUser: true };
  }

  private asProblemDetails(value: unknown): ProblemDetails {
    if (!value || typeof value !== 'object') {
      return {};
    }

    const record = value as Record<string, unknown>;
    return {
      title: typeof record['title'] === 'string' ? record['title'] : undefined,
      status: typeof record['status'] === 'number' ? record['status'] : undefined,
      detail: typeof record['detail'] === 'string' ? record['detail'] : undefined,
      instance: typeof record['instance'] === 'string' ? record['instance'] : undefined,
      errorId: typeof record['errorId'] === 'string' ? record['errorId'] : undefined,
    };
  }

  private extractErrorId(error: HttpErrorResponse): string | undefined {
    const traceparent = error.headers?.get('traceparent');
    if (traceparent) {
      const parts = traceparent.split('-');
      if (parts.length >= 3 && parts[1]) {
        return parts[1];
      }
      return traceparent;
    }

    return error.headers?.get('X-Trace-ID') ?? error.headers?.get('x-trace-id') ?? undefined;
  }

  private isIgnoredRuntimeNoise(message: string): boolean {
    const normalized = message.toLowerCase();
    return normalized.includes('unable to add filesystem') && normalized.includes('illegal path');
  }
}
