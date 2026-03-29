import { CdkDragDrop, DragDropModule } from '@angular/cdk/drag-drop';
import { ChangeDetectionStrategy, Component, inject } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MatButtonToggleModule } from '@angular/material/button-toggle';
import { MatCardModule } from '@angular/material/card';
import { MatChipsModule } from '@angular/material/chips';
import { MatOptionModule } from '@angular/material/core';
import { MatAutocompleteModule } from '@angular/material/autocomplete';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatSelectModule } from '@angular/material/select';
import { MatMenuModule } from '@angular/material/menu';
import { MatProgressBarModule } from '@angular/material/progress-bar';
import { ArrowRight, Filter, GripVertical, LucideAngularModule, MoreVertical, Table, X } from 'lucide-angular';
import { DataTableComponent } from '../../../../shared/ui/data-table/data-table.component';
import {
  DataTableExpandedDetailItem,
  DataTableExpandedDetailsComponent
} from '../../../../shared/ui/data-table/data-table-expanded-details.component';
import { DataFacade } from '../data.facade';
import { ProductColumnKey, ScopeColumnKey, TestColumnKey } from '../data.columns';
import { ProductSummary, ScopeSummary, TestSummary } from '../../data-access/data.types';

@Component({
  selector: 'app-data-list-tables',
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
    MatMenuModule,
    MatProgressBarModule,
    LucideAngularModule,
    DataTableComponent,
    DataTableExpandedDetailsComponent
  ],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './data-list-tables.component.html',
  styleUrl: './data-list-tables.component.scss'
})
export class DataListTablesComponent {
  protected readonly ArrowRight = ArrowRight;
  protected readonly Filter = Filter;
  protected readonly Table = Table;
  protected readonly GripVertical = GripVertical;
  protected readonly X = X;
  protected readonly MoreVertical = MoreVertical;
  readonly data = inject(DataFacade);

  readonly exportValueForProducts = (row: unknown, columnKey: string): string => {
    return this.data.productColumnValue(
      row as ProductSummary & { scopesCount?: number | null },
      columnKey as ProductColumnKey
    );
  };

  readonly exportValueForScopes = (row: unknown, columnKey: string): string => {
    return this.data.scopeColumnValue(
      row as ScopeSummary & { testsCount?: number | null },
      columnKey as ScopeColumnKey
    );
  };

  readonly exportValueForTests = (row: unknown, columnKey: string): string => {
    return this.data.testColumnValue(
      row as TestSummary & { componentsCount?: number | null },
      columnKey as TestColumnKey
    );
  };

  readonly productExpandedDetailsForTable = (row: unknown): DataTableExpandedDetailItem[] =>
    this.productExpandedItems(row as ProductSummary);

  readonly scopeExpandedDetailsForTable = (row: unknown): DataTableExpandedDetailItem[] =>
    this.scopeExpandedItems(row as ScopeSummary);

  readonly testExpandedDetailsForTable = (row: unknown): DataTableExpandedDetailItem[] =>
    this.testExpandedItems(row as TestSummary);

  productExpandedItems(product: ProductSummary): DataTableExpandedDetailItem[] {
    return [
      { label: 'Product ID', value: product.id ?? '-', mono: true },
      { label: 'Created', value: product.createdAt ?? '-', mono: true },
      { label: 'Updated', value: product.updatedAt ?? '-', mono: true }
    ];
  }

  scopeExpandedItems(scope: ScopeSummary): DataTableExpandedDetailItem[] {
    return [
      { label: 'Scope ID', value: scope.id ?? '-', mono: true },
      { label: 'Product', value: this.data.getProductName(scope.productId ?? this.data.selectedProductId()) },
      { label: 'Created', value: scope.createdAt ?? '-', mono: true },
      { label: 'Updated', value: scope.updatedAt ?? '-', mono: true }
    ];
  }

  testExpandedItems(test: TestSummary): DataTableExpandedDetailItem[] {
    return [
      { label: 'Test ID', value: test.id ?? '-', mono: true },
      { label: 'Scope', value: this.data.getScopeName(test.scopeId ?? this.data.selectedScopeId()) },
      { label: 'Created', value: test.createdAt ?? '-' },
      { label: 'Public', value: test.isPublic ? 'Yes' : 'No' }
    ];
  }

  onToggleExpanded(value: string | number): void {
    this.data.toggleExpanded(String(value));
  }

  onProductDropColumn(event: CdkDragDrop<string[]>): void {
    this.data.dropProductColumn(event as CdkDragDrop<ProductColumnKey[]>);
  }

  onProductRemoveColumn(value: string): void {
    this.data.removeProductColumn(value as ProductColumnKey);
  }

  onProductAddColumn(value: string): void {
    this.data.addProductColumn(value as ProductColumnKey);
  }

  onProductToggleFilter(payload: { key: string; event: Event }): void {
    this.data.toggleProductFilter(payload.key as ProductColumnKey, payload.event as MouseEvent);
  }

  onProductSetColumnFilter(payload: { key: string; event: Event }): void {
    this.data.setProductColumnFilter(payload.key as ProductColumnKey, payload.event);
  }

  onProductToggleSort(value: string): void {
    this.data.toggleProductSort(value as ProductColumnKey);
  }

  onScopeDropColumn(event: CdkDragDrop<string[]>): void {
    this.data.dropScopeColumn(event as CdkDragDrop<ScopeColumnKey[]>);
  }

  onScopeRemoveColumn(value: string): void {
    this.data.removeScopeColumn(value as ScopeColumnKey);
  }

  onScopeAddColumn(value: string): void {
    this.data.addScopeColumn(value as ScopeColumnKey);
  }

  onScopeToggleFilter(payload: { key: string; event: Event }): void {
    this.data.toggleScopeFilter(payload.key as ScopeColumnKey, payload.event as MouseEvent);
  }

  onScopeSetColumnFilter(payload: { key: string; event: Event }): void {
    this.data.setScopeColumnFilter(payload.key as ScopeColumnKey, payload.event);
  }

  onScopeToggleSort(value: string): void {
    this.data.toggleScopeSort(value as ScopeColumnKey);
  }

  onTestDropColumn(event: CdkDragDrop<string[]>): void {
    this.data.dropTestColumn(event as CdkDragDrop<TestColumnKey[]>);
  }

  onTestRemoveColumn(value: string): void {
    this.data.removeTestColumn(value as TestColumnKey);
  }

  onTestAddColumn(value: string): void {
    this.data.addTestColumn(value as TestColumnKey);
  }

  onTestToggleFilter(payload: { key: string; event: Event }): void {
    this.data.toggleTestFilter(payload.key as TestColumnKey, payload.event as MouseEvent);
  }

  onTestSetColumnFilter(payload: { key: string; event: Event }): void {
    this.data.setTestColumnFilter(payload.key as TestColumnKey, payload.event);
  }

  onTestToggleSort(value: string): void {
    this.data.toggleTestSort(value as TestColumnKey);
  }
}
