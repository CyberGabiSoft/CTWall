
import { ChangeDetectionStrategy, Component, input, output } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MatButtonToggleModule } from '@angular/material/button-toggle';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatOptionModule } from '@angular/material/core';
import { MatSelectModule } from '@angular/material/select';

export type AdvancedFilterMode = 'contains' | 'select';

export interface AdvancedFilterField {
  key: string;
  label: string;
  mode: AdvancedFilterMode;
  value: string;
  options: string[];
  selected: string[];
  selectPlaceholder?: string;
  containsPlaceholder?: string;
}

@Component({
  selector: 'app-advanced-filter-panel',
  imports: [
    MatButtonModule,
    MatButtonToggleModule,
    MatFormFieldModule,
    MatInputModule,
    MatOptionModule,
    MatSelectModule
],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './advanced-filter-panel.component.html',
  styleUrl: './advanced-filter-panel.component.scss'
})
export class AdvancedFilterPanelComponent {
  readonly fields = input<AdvancedFilterField[]>([]);
  readonly idPrefix = input('filter');
  readonly showClear = input(true);

  readonly modeChange = output<{ key: string; mode: AdvancedFilterMode }>();
  readonly valueChange = output<{ key: string; value: string }>();
  readonly selectionChange = output<{ key: string; values: string[] }>();
  readonly clearFilters = output<void>();

  inputPlaceholder(field: AdvancedFilterField): string {
    if (field.mode === 'select') {
      return field.selectPlaceholder ?? 'Exact';
    }
    return field.containsPlaceholder ?? 'Contains';
  }

  onValueChange(key: string, event: Event): void {
    const target = event.target as HTMLInputElement | null;
    this.valueChange.emit({ key, value: target?.value ?? '' });
  }
}
