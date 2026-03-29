
import { ChangeDetectionStrategy, Component, ErrorHandler, computed, inject, signal } from '@angular/core';
import { MAT_DIALOG_DATA, MatDialogModule, MatDialogRef } from '@angular/material/dialog';
import { MatButtonModule } from '@angular/material/button';
import { SecurityApi } from '../../data-access/security.api';
import { SyncHistoryEntry } from '../../data-access/security.types';
import { LoadingIndicatorComponent } from '../../../../shared/ui/loading-indicator/loading-indicator.component';

export interface SyncErrorsDialogData {
  sourceId: string;
  syncId: string;
}

type LoadState = 'loading' | 'loaded' | 'error';

interface SyncErrorRow {
  id: string;
  time: string;
  stage: string;
  item: string;
  message: string;
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null;

@Component({
  selector: 'app-sync-errors-dialog',
  imports: [MatDialogModule, MatButtonModule, LoadingIndicatorComponent],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './sync-errors-dialog.component.html',
  styleUrl: './sync-errors-dialog.component.scss'
})
export class SyncErrorsDialogComponent {
  readonly data = inject<SyncErrorsDialogData>(MAT_DIALOG_DATA);
  private readonly ref = inject(MatDialogRef<SyncErrorsDialogComponent, void>);
  private readonly api = inject(SecurityApi);
  private readonly errorHandler = inject(ErrorHandler);

  readonly status = signal<LoadState>('loading');
  readonly items = signal<SyncHistoryEntry[]>([]);

  readonly title = computed(() => `Errors for sync ${this.data.syncId}`);

  readonly rows = computed<SyncErrorRow[]>(() =>
    this.items().map((entry) => this.toRow(entry))
  );

  constructor() {
    void this.load();
  }

  close(): void {
    this.ref.close();
  }

  private async load(): Promise<void> {
    this.status.set('loading');
    try {
      const items = await this.api.listSyncErrors(this.data.sourceId, this.data.syncId);
      this.items.set(items);
      this.status.set('loaded');
    } catch (error) {
      this.errorHandler.handleError(error);
      this.status.set('error');
    }
  }

  private toRow(entry: SyncHistoryEntry): SyncErrorRow {
    const details = this.extractDetails(entry);
    const stage = this.stringValue(details['stage']);
    const item = this.stringValue(details['item']);
    const message = this.stringValue(details['message']);
    return {
      id: entry.id,
      time: entry.createdAt,
      stage,
      item,
      message
    };
  }

  private extractDetails(entry: { details?: Record<string, unknown> | undefined }): Record<string, unknown> {
    const details = entry.details;
    if (!details || !isRecord(details)) {
      return {};
    }
    return details;
  }

  private stringValue(value: unknown): string {
    if (value === null || value === undefined) {
      return '';
    }
    if (typeof value === 'string') {
      return value;
    }
    if (typeof value === 'number' || typeof value === 'boolean') {
      return String(value);
    }
    return '';
  }
}
