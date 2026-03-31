import { CdkDragDrop, DragDropModule } from '@angular/cdk/drag-drop';
import { ChangeDetectionStrategy, Component, computed, inject } from '@angular/core';
import { MatAutocompleteModule } from '@angular/material/autocomplete';
import { MatButtonModule } from '@angular/material/button';
import { MatButtonToggleModule } from '@angular/material/button-toggle';
import { MatCardModule } from '@angular/material/card';
import { MatChipsModule } from '@angular/material/chips';
import { MatOptionModule } from '@angular/material/core';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatSelectModule } from '@angular/material/select';
import { AdvancedFilterPanelComponent } from '../../../../shared/ui/advanced-filter-panel/advanced-filter-panel.component';
import { DataTableComponent } from '../../../../shared/ui/data-table/data-table.component';
import { LoadingIndicatorComponent } from '../../../../shared/ui/loading-indicator/loading-indicator.component';
import { CopyButtonComponent } from '../../../../shared/ui/copy-button/copy-button.component';
import { ComponentMalwarePanelComponent } from '../component-malware-panel/component-malware-panel.component';
import {
  ComponentColumnFilterKey,
  ComponentColumnKey,
  LastChangeColumnKey,
  RevisionChangeColumnKey
} from '../data.columns';
import { DataFacade } from '../data.facade';
import {
  ComponentSummary,
  TestRevisionChangeSummary,
  TestRevisionFindingDiff
} from '../../data-access/data.types';
import { Filter, GripVertical, LucideAngularModule, Table, X } from 'lucide-angular';

@Component({
  selector: 'app-data-detail-tables',
  imports: [
    DragDropModule,
    MatAutocompleteModule,
    MatButtonModule,
    MatButtonToggleModule,
    MatCardModule,
    MatChipsModule,
    MatFormFieldModule,
    MatInputModule,
    MatOptionModule,
    MatSelectModule,
    LucideAngularModule,
    AdvancedFilterPanelComponent,
    DataTableComponent,
    LoadingIndicatorComponent,
    CopyButtonComponent,
    ComponentMalwarePanelComponent
  ],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './data-detail-tables.component.html',
  styleUrl: './data-detail-tables.component.scss'
})
export class DataDetailTablesComponent {
  readonly data = inject(DataFacade);
  protected readonly Filter = Filter;
  protected readonly Table = Table;
  protected readonly GripVertical = GripVertical;
  protected readonly X = X;

  readonly exportValueForComponents = (row: unknown, columnKey: string): string =>
    this.componentColumnValue(row as ComponentSummary, columnKey);
  readonly exportValueForLastChanges = (row: unknown, columnKey: string): string =>
    this.data.lastChangeColumnValue(row as TestRevisionChangeSummary, columnKey as LastChangeColumnKey);
  readonly exportValueForRevisionChanges = (row: unknown, columnKey: string): string =>
    this.data.revisionChangeColumnValue(row as TestRevisionFindingDiff, columnKey as RevisionChangeColumnKey);

  readonly componentAdvancedFields = computed(() => {
    const modes = this.data.componentFilterMode();
    const filters = this.data.componentColumnFilters();
    const options = this.data.componentFilterOptions();
    const multi = this.data.componentMultiFilters();
    return [
      {
        key: 'purl',
        label: 'PURL',
        mode: modes.purl,
        value: filters.purl ?? '',
        options: [],
        selected: [],
        selectPlaceholder: 'Exact'
      },
      {
        key: 'type',
        label: 'Pkg Type',
        mode: modes.type,
        value: filters.type ?? '',
        options: options.type ?? [],
        selected: multi.type ?? []
      },
      {
        key: 'name',
        label: 'Pkg Name',
        mode: modes.name,
        value: filters.name ?? '',
        options: [],
        selected: [],
        selectPlaceholder: 'Exact'
      },
      {
        key: 'version',
        label: 'Version',
        mode: modes.version,
        value: filters.version ?? '',
        options: [],
        selected: [],
        selectPlaceholder: 'Exact'
      },
      {
        key: 'namespace',
        label: 'Pkg Namespace',
        mode: modes.namespace,
        value: filters.namespace ?? '',
        options: options.namespace ?? [],
        selected: multi.namespace ?? []
      },
      {
        key: 'sbomType',
        label: 'SBOM Type',
        mode: modes.sbomType,
        value: filters.sbomType ?? '',
        options: options.sbomType ?? [],
        selected: multi.sbomType ?? []
      },
      {
        key: 'publisher',
        label: 'Publisher',
        mode: modes.publisher,
        value: filters.publisher ?? '',
        options: options.publisher ?? [],
        selected: multi.publisher ?? []
      },
      {
        key: 'supplier',
        label: 'Supplier',
        mode: modes.supplier,
        value: filters.supplier ?? '',
        options: options.supplier ?? [],
        selected: multi.supplier ?? []
      },
      {
        key: 'malwareTriageStatus',
        label: 'Malware triage',
        mode: modes.malwareTriageStatus,
        value: filters.malwareTriageStatus ?? '',
        options: options.malwareTriageStatus ?? [],
        selected: [],
        selectPlaceholder: 'Exact'
      },
      {
        key: 'licenses',
        label: 'Licenses',
        mode: modes.licenses,
        value: filters.licenses ?? '',
        options: options.licenses ?? [],
        selected: multi.licenses ?? []
      }
    ];
  });

  componentColumnValue(component: ComponentSummary, column: string): string {
    return this.data.componentColumnValue(component, column as ComponentColumnKey);
  }

  componentColumnTitle(component: ComponentSummary, column: string): string | null {
    if (column === 'purl') {
      return component.purl ?? '-';
    }
    if (column === 'malwareVerdict' || column === 'malwareScannedAt' || column === 'malwareValidUntil') {
      return this.data.componentMalwareTooltip(component.purl);
    }
    return null;
  }

  onComponentFilterModeChange(payload: { key: string; mode: 'contains' | 'select' }): void {
    this.data.setComponentFilterMode(payload.key as ComponentColumnFilterKey, payload.mode);
  }

  onComponentFilterValueChange(payload: { key: string; value: string }): void {
    this.data.setComponentFilterValue(payload.key as ComponentColumnFilterKey, payload.value);
  }

  onComponentFilterSelectionChange(payload: { key: string; values: string[] }): void {
    if (this.isComponentMultiFilterKey(payload.key)) {
      this.data.setComponentMultiFilter(payload.key, payload.values);
    }
  }

  onToggleComponentFilter(key: string, event: Event): void {
    this.data.toggleComponentFilter(key as ComponentColumnFilterKey, event as MouseEvent);
  }

  onSetComponentColumnFilter(key: string, event: Event): void {
    this.data.setComponentColumnFilter(key as ComponentColumnFilterKey, event);
  }

  onToggleComponentSort(key: string): void {
    this.data.toggleComponentSort(key as ComponentColumnKey);
  }

  onComponentDropColumn(event: CdkDragDrop<string[]>): void {
    this.data.dropComponentColumn(event as CdkDragDrop<ComponentColumnKey[]>);
  }

  onComponentRemoveColumn(value: string): void {
    this.data.removeComponentColumn(value as ComponentColumnKey);
  }

  onComponentAddColumn(value: string): void {
    this.data.addComponentColumn(value as ComponentColumnKey);
  }

  onToggleLastChangeFilter(key: string, event: Event): void {
    this.data.toggleLastChangeFilter(key as LastChangeColumnKey, event as MouseEvent);
  }

  onSetLastChangeColumnFilter(key: string, event: Event): void {
    this.data.setLastChangeColumnFilter(key as LastChangeColumnKey, event);
  }

  onToggleLastChangeSort(key: string): void {
    this.data.toggleLastChangeSort(key as LastChangeColumnKey);
  }

  onLastChangeDropColumn(event: CdkDragDrop<string[]>): void {
    this.data.dropLastChangeColumn(event as CdkDragDrop<LastChangeColumnKey[]>);
  }

  onLastChangeRemoveColumn(value: string): void {
    this.data.removeLastChangeColumn(value as LastChangeColumnKey);
  }

  onLastChangeAddColumn(value: string): void {
    this.data.addLastChangeColumn(value as LastChangeColumnKey);
  }

  onToggleRevisionChangeFilter(key: string, event: Event): void {
    this.data.toggleRevisionChangeFilter(key as RevisionChangeColumnKey, event as MouseEvent);
  }

  onSetRevisionChangeColumnFilter(key: string, event: Event): void {
    this.data.setRevisionChangeColumnFilter(key as RevisionChangeColumnKey, event);
  }

  onToggleRevisionChangeSort(key: string): void {
    this.data.toggleRevisionChangeSort(key as RevisionChangeColumnKey);
  }

  onRevisionChangeDropColumn(event: CdkDragDrop<string[]>): void {
    this.data.dropRevisionChangeColumn(event as CdkDragDrop<RevisionChangeColumnKey[]>);
  }

  onRevisionChangeRemoveColumn(value: string): void {
    this.data.removeRevisionChangeColumn(value as RevisionChangeColumnKey);
  }

  onRevisionChangeAddColumn(value: string): void {
    this.data.addRevisionChangeColumn(value as RevisionChangeColumnKey);
  }

  private isComponentMultiFilterKey(
    key: string
  ): key is 'type' | 'namespace' | 'licenses' | 'sbomType' | 'publisher' | 'supplier' {
    return (
      key === 'type' ||
      key === 'namespace' ||
      key === 'licenses' ||
      key === 'sbomType' ||
      key === 'publisher' ||
      key === 'supplier'
    );
  }
}
