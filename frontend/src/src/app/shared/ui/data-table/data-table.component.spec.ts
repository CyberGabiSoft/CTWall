import { ComponentFixture, TestBed } from '@angular/core/testing';
import { CdkDragDrop } from '@angular/cdk/drag-drop';
import { DataTableComponent } from './data-table.component';

describe('DataTableComponent', () => {
  it('allows moving detail column between base columns in table panel order', async () => {
    await TestBed.configureTestingModule({
      imports: [DataTableComponent]
    }).compileComponents();

    const fixture: ComponentFixture<DataTableComponent> = TestBed.createComponent(DataTableComponent);
    const baseColumns = [
      { key: 'severity', label: 'Severity', sortKey: 'severity', filterKey: 'severity' },
      { key: 'status', label: 'Status', sortKey: 'status', filterKey: 'status' }
    ];
    const dropSpy = vi.fn();
    fixture.componentInstance.dropColumn.subscribe(dropSpy);

    fixture.componentRef.setInput('columns', baseColumns);
    fixture.componentRef.setInput('columnOrder', ['severity', 'status']);
    fixture.componentRef.setInput('availableColumns', baseColumns);
    fixture.componentRef.setInput('rows', [{ id: 'row-1' }]);
    fixture.componentRef.setInput('expandedDetails', () => [
      {
        key: 'malwarePurl',
        label: 'Malware PURL',
        value: 'pkg:npm/bad@1.2.3'
      }
    ]);
    fixture.detectChanges();

    fixture.componentInstance.onAddColumn('__detail__:malwarepurl');
    fixture.detectChanges();

    fixture.componentInstance.onDropPanelColumn({
      previousIndex: 2,
      currentIndex: 1
    } as CdkDragDrop<string[]>);
    fixture.detectChanges();

    expect(dropSpy).not.toHaveBeenCalled();
    expect(fixture.componentInstance.tableOptionColumnKeys()).toEqual([
      'severity',
      '__detail__:malwarepurl',
      'status'
    ]);
    expect(fixture.componentInstance.orderedColumns().map((column) => column.key)).toEqual([
      'severity',
      '__detail__:malwarepurl',
      'status'
    ]);
  });
});
