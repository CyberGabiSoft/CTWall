
import { ChangeDetectionStrategy, Component, computed, input } from '@angular/core';
import { CopyButtonComponent } from '../copy-button/copy-button.component';

export interface DataTableExpandedDetailItem {
  key?: string;
  label: string;
  value: string;
  copyValue?: string;
  mono?: boolean;
}

export interface DataTableExpandedVisibleColumn {
  key: string;
  label: string;
}

@Component({
  selector: 'app-data-table-expanded-details',
  imports: [CopyButtonComponent],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    @if (columns() === 2) {
      <div class="details-columns">
        <div class="details-grid">
          @for (item of leftColumnItems(); track item.key ?? item.label) {
            <span class="detail-label">{{ item.label }}</span>
            <span class="detail-value" [class.mono]="item.mono === true">
              <span class="detail-text">{{ item.value }}</span>
              <app-copy-button
                [value]="item.copyValue ?? item.value"
                [ariaLabel]="'Copy ' + item.label"
                [disabled]="isEmpty(item.copyValue ?? item.value)"
              ></app-copy-button>
            </span>
          }
        </div>
        <div class="details-grid">
          @for (item of rightColumnItems(); track item.key ?? item.label) {
            <span class="detail-label">{{ item.label }}</span>
            <span class="detail-value" [class.mono]="item.mono === true">
              <span class="detail-text">{{ item.value }}</span>
              <app-copy-button
                [value]="item.copyValue ?? item.value"
                [ariaLabel]="'Copy ' + item.label"
                [disabled]="isEmpty(item.copyValue ?? item.value)"
              ></app-copy-button>
            </span>
          }
        </div>
      </div>
    } @else {
      <div class="details-grid">
        @for (item of mergedItems(); track item.key ?? item.label) {
          <span class="detail-label">{{ item.label }}</span>
          <span class="detail-value" [class.mono]="item.mono === true">
            <span class="detail-text">{{ item.value }}</span>
            <app-copy-button
              [value]="item.copyValue ?? item.value"
              [ariaLabel]="'Copy ' + item.label"
              [disabled]="isEmpty(item.copyValue ?? item.value)"
            ></app-copy-button>
          </span>
        }
      </div>
    }
  `
})
export class DataTableExpandedDetailsComponent {
  readonly items = input.required<ReadonlyArray<DataTableExpandedDetailItem>>();
  readonly columns = input<1 | 2>(1);
  readonly visibleColumns = input<ReadonlyArray<DataTableExpandedVisibleColumn> | null>(null);
  readonly visibleRow = input<unknown | null>(null);
  readonly visibleValue = input<((row: unknown, key: string) => string) | null>(null);

  readonly mergedItems = computed<ReadonlyArray<DataTableExpandedDetailItem>>(() => {
    const base = this.items();
    const columns = this.visibleColumns();
    const row = this.visibleRow();
    const resolver = this.visibleValue();
    if (!columns || !row || !resolver || columns.length === 0) {
      return base;
    }

    const next: DataTableExpandedDetailItem[] = [...base];
    const seenLabels = new Set(base.map((item) => item.label.trim().toLowerCase()).filter((value) => value.length > 0));
    for (const column of columns) {
      const label = (column.label ?? '').trim();
      if (!label || seenLabels.has(label.toLowerCase())) {
        continue;
      }
      const resolved = resolver(row, column.key);
      next.push({
        key: `visible:${column.key}`,
        label,
        value: resolved,
        copyValue: resolved
      });
      seenLabels.add(label.toLowerCase());
    }
    return next;
  });

  readonly leftColumnItems = computed<ReadonlyArray<DataTableExpandedDetailItem>>(() => {
    return this.mergedItems().filter((_, index) => index % 2 === 0);
  });

  readonly rightColumnItems = computed<ReadonlyArray<DataTableExpandedDetailItem>>(() => {
    return this.mergedItems().filter((_, index) => index % 2 === 1);
  });

  isEmpty(value: string | null | undefined): boolean {
    const text = (value ?? '').toString().trim();
    return text.length === 0 || text === '-';
  }
}
