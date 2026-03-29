import { TestBed } from '@angular/core/testing';
import { DataDetailTablesComponent } from './data-detail-tables.component';
import { DataFacade } from '../data.facade';

const createFacadeStub = (): DataFacade => {
  const stub = {
    selectedTest: () => null,
    selectedTestId: () => null,
    selectedProductId: () => null,
    selectedScopeId: () => null,
    getProductName: () => '-',
    getScopeName: () => '-',
    formatSbom: () => '-',
    backToTests: () => {},
    revisionTotal: () => 0,
    revisionTablePanelOpen: () => false,
    revisionFilterPanelOpen: () => false,
    toggleRevisionFilterPanel: () => {},
    toggleRevisionTablePanel: () => {},
    revisionsStatus: () => 'loading',
    lastChangeTotal: () => 0,
    lastChangeRows: () => [],
    lastChangePage: () => [],
    lastChangeColumnDefinitions: () => [],
    lastChangeColumnOrder: () => [],
    lastChangeColumnQuery: () => '',
    availableLastChangeColumns: () => [],
    lastChangeTablePanelOpen: () => false,
    lastChangeFilterPanelOpen: () => false,
    lastChangeFilterRowVisible: () => false,
    lastChangeFilterVisible: () => ({}),
    lastChangeColumnFilters: () => ({}),
    lastChangeSortColumn: () => 'createdAt',
    lastChangeSortDir: () => 'desc',
    lastChangesTableStatus: () => 'loading',
    lastChangePageSize: () => 10,
    lastChangePageIndex: () => 0,
    lastChangeTotalPages: () => 1,
    toggleLastChangeFilterPanel: () => {},
    toggleLastChangeTablePanel: () => {},
    setLastChangeColumnQuery: () => {},
    selectedRevisionChangeSummary: () => null,
    selectedRevisionChangeStatusLabel: () => '-',
    revisionChangeTotal: () => 0,
    revisionChangeRows: () => [],
    revisionChangePage: () => [],
    revisionChangeColumnDefinitions: () => [],
    revisionChangeColumnOrder: () => [],
    revisionChangeColumnQuery: () => '',
    availableRevisionChangeColumns: () => [],
    revisionChangeTablePanelOpen: () => false,
    revisionChangeFilterPanelOpen: () => false,
    revisionChangeFilterRowVisible: () => false,
    revisionChangeFilterVisible: () => ({}),
    revisionChangeColumnFilters: () => ({}),
    revisionChangeSortColumn: () => 'createdAt',
    revisionChangeSortDir: () => 'desc',
    revisionChangesTableStatus: () => 'loading',
    revisionChangesLoadingMessage: () => 'Loading revision changes...',
    revisionChangesErrorMessage: () => 'Failed to load revision changes.',
    revisionChangePageSize: () => 25,
    revisionChangePageIndex: () => 0,
    revisionChangeTotalPages: () => 1,
    toggleRevisionChangeFilterPanel: () => {},
    toggleRevisionChangeTablePanel: () => {},
    setRevisionChangeColumnQuery: () => {},
    pageSizeOptions: [10, 25, 50, 100, 0],
    openRevisionChanges: () => {},
    componentTotal: () => 0,
    componentFilterPanelOpen: () => false,
    componentTablePanelOpen: () => false,
    toggleComponentFilterPanel: () => {},
    toggleComponentTablePanel: () => {},
    componentsStatus: () => 'loading'
  };

  return new Proxy(stub as unknown as DataFacade, {
    get(target, prop) {
      if (prop in target) {
        return target[prop as keyof typeof target];
      }
      return () => {};
    }
  });
};

describe('DataDetailTablesComponent (TestBed)', () => {
  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [DataDetailTablesComponent],
      providers: [{ provide: DataFacade, useFactory: createFacadeStub }]
    }).compileComponents();
  });

  it('renders loading states for revisions and components', () => {
    const fixture = TestBed.createComponent(DataDetailTablesComponent);
    fixture.detectChanges();
    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.textContent).toContain('Loading revisions');
    expect(compiled.textContent).toContain('Loading components');
  });
});
