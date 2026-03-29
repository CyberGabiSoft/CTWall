import { TestBed } from '@angular/core/testing';
import { ErrorBannerComponent } from './error-banner.component';
import { ErrorStateService } from '../../errors/error-state.service';

describe('ErrorBannerComponent (TestBed)', () => {
  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [ErrorBannerComponent]
    }).compileComponents();
  });

  it('renders error id when provided', () => {
    const fixture = TestBed.createComponent(ErrorBannerComponent);
    const errorState = TestBed.inject(ErrorStateService);
    errorState.setError({ message: 'Server error', errorId: 'trace-123' });
    fixture.detectChanges();
    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.textContent).toContain('Server error');
    expect(compiled.textContent).toContain('Error ID: trace-123');
  });
});
