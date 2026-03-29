import { TestBed } from '@angular/core/testing';
import { DataFacade } from '../data.facade';
import { DataHeaderComponent } from './data-header.component';

const createFacadeStub = (): DataFacade => {
  return {
    section: () => 'products',
    productTotal: () => 0,
    scopeTotal: () => 0,
    testTotal: () => 0,
    selectedProductId: () => null,
    selectedScopeId: () => null,
    selectedTestId: () => null,
    isTestDetail: () => false,
    setSection: () => {},
    navigateToProduct: () => {},
    navigateToScope: () => {},
    getProductName: () => '-',
    getScopeName: () => '-',
    getTestName: () => '-'
  } as unknown as DataFacade;
};

describe('DataHeaderComponent (TestBed)', () => {
  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [DataHeaderComponent],
      providers: [{ provide: DataFacade, useFactory: createFacadeStub }]
    }).compileComponents();
  });

  it('renders section toggles', () => {
    const fixture = TestBed.createComponent(DataHeaderComponent);
    fixture.detectChanges();
    const compiled = fixture.nativeElement as HTMLElement;
    const toggles = compiled.querySelectorAll('mat-button-toggle');
    expect(toggles.length).toBe(3);
  });
});
