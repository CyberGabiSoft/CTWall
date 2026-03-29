
import { ChangeDetectionStrategy, Component, ErrorHandler, computed, inject, signal } from '@angular/core';
import { MAT_DIALOG_DATA, MatDialogModule, MatDialogRef } from '@angular/material/dialog';
import { MatButtonModule } from '@angular/material/button';
import { MatCardModule } from '@angular/material/card';
import { EventsApi } from '../data-access/events.api';
import { AuditLogEntry, EventAggregate, EventDetailsResponse } from '../data-access/events.types';
import { LoadingIndicatorComponent } from '../../../shared/ui/loading-indicator/loading-indicator.component';
import { CopyBlockComponent } from '../../../shared/ui/copy-block/copy-block.component';

export interface EventDetailsDialogData {
  eventKey: string;
  canAck: boolean;
}

type LoadState = 'loading' | 'loaded' | 'error';

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null;

@Component({
  selector: 'app-event-details-dialog',
  imports: [
    MatDialogModule,
    MatButtonModule,
    MatCardModule,
    LoadingIndicatorComponent,
    CopyBlockComponent
],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './event-details-dialog.component.html',
  styleUrl: './event-details-dialog.component.scss'
})
export class EventDetailsDialogComponent {
  readonly data = inject<EventDetailsDialogData>(MAT_DIALOG_DATA);
  private readonly ref = inject(MatDialogRef<EventDetailsDialogComponent, { refresh?: boolean } | void>);
  private readonly api = inject(EventsApi);
  private readonly errorHandler = inject(ErrorHandler);

  readonly status = signal<LoadState>('loading');
  readonly payload = signal<EventDetailsResponse | null>(null);

  readonly event = computed<EventAggregate | null>(() => this.payload()?.event ?? null);
  readonly occurrences = computed<AuditLogEntry[]>(() => this.payload()?.occurrences ?? []);

  readonly title = computed(() => {
    const event = this.event();
    if (!event) {
      return 'Event';
    }
    const sev = event.severity ? `[${event.severity}]` : '';
    return `${sev} ${event.title || 'Event'}`.trim();
  });

  readonly canAck = computed(() => Boolean(this.data.canAck) && this.event()?.status === 'open');
  readonly ackInFlight = signal(false);

  constructor() {
    void this.load();
  }

  close(refresh = false): void {
    this.ref.close(refresh ? { refresh: true } : undefined);
  }

  async acknowledge(): Promise<void> {
    if (!this.canAck() || this.ackInFlight()) {
      return;
    }
    const key = (this.data.eventKey ?? '').trim();
    if (!key) {
      return;
    }
    this.ackInFlight.set(true);
    try {
      await this.api.ack(key);
      window.dispatchEvent(new CustomEvent('ctwall:events-updated', { detail: { kind: 'ack' } }));
      this.close(true);
    } catch (error) {
      this.errorHandler.handleError(error);
      this.ackInFlight.set(false);
    }
  }

  occurrenceDetailsJson(entry: AuditLogEntry): string {
    const details = entry.details;
    if (!details || !isRecord(details)) {
      return '{}';
    }
    return JSON.stringify(details, null, 2);
  }

  private async load(): Promise<void> {
    this.status.set('loading');
    try {
      const payload = await this.api.get(this.data.eventKey);
      this.payload.set(payload);
      this.status.set('loaded');
    } catch (error) {
      this.errorHandler.handleError(error);
      this.status.set('error');
    }
  }
}
