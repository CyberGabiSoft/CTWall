import { Injectable, computed, signal } from '@angular/core';

export interface ErrorState {
  message: string;
  errorId?: string;
  status?: number;
}

@Injectable({ providedIn: 'root' })
export class ErrorStateService {
  private readonly errorState = signal<ErrorState | null>(null);

  readonly error = computed(() => this.errorState());

  setError(state: ErrorState): void {
    this.errorState.set(state);
  }

  clear(): void {
    this.errorState.set(null);
  }
}
