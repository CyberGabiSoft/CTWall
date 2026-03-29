import { TestBed } from '@angular/core/testing';
import { DataFacade } from '../data.facade';
import { DataListTablesComponent } from './data-list-tables.component';

const createFacadeStub = (): DataFacade => {
  const stub = {
    section: () => 'products',
    productsStatus: () => 'loading',
    productColumnDefinitions: () => [],
    productColumnOrder: () => [],
    productColumnQuery: () => '',
    availableProductColumns: () => [],
    productFilterRowVisible: () => false,
    productFilterVisible: () => ({}),
    productColumnFilters: () => ({}),
    productSortColumn: () => null,
    productSortDir: () => 'asc',
    productPage: () => [],
    productExpandedIds: () => new Set(),
    productFilterPanelOpen: () => false,
    productTablePanelOpen: () => false,
    toggleProductFilterPanel: () => {},
    toggleProductTablePanel: () => {},
    toggleProductFilter: () => {},
    setProductColumnFilter: () => {},
    toggleProductSort: () => {},
    dropProductColumn: () => {},
    removeProductColumn: () => {},
    addProductColumn: () => {},
    setProductColumnQuery: () => {},
    toggleExpanded: () => {},
    productPageSize: () => 25,
    productPageIndex: () => 0,
    productTotalPages: () => 1,
    setProductPageSize: () => {},
    prevProductPage: () => {},
    nextProductPage: () => {},
    pageSizeOptions: [10, 25, 50]
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

describe('DataListTablesComponent (TestBed)', () => {
  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [DataListTablesComponent],
      providers: [{ provide: DataFacade, useFactory: createFacadeStub }]
    }).compileComponents();
  });

  it('renders loading state for products', () => {
    const fixture = TestBed.createComponent(DataListTablesComponent);
    fixture.detectChanges();
    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.textContent).toContain('Loading products');
  });
});
