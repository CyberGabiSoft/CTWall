import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { ChangePasswordComponent } from './change-password.component';
import { AuthService } from '../../data-access/auth.service';

class AuthServiceStub {
  async changePassword(): Promise<void> {}
  logout(): void {}
}

describe('ChangePasswordComponent (TestBed)', () => {
  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [ChangePasswordComponent],
      providers: [provideRouter([]), { provide: AuthService, useClass: AuthServiceStub }]
    }).compileComponents();
  });

  it('renders change password form', () => {
    const fixture = TestBed.createComponent(ChangePasswordComponent);
    fixture.detectChanges();
    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.textContent).toContain('Change password');
    expect(compiled.textContent).toContain('Current password');
    expect(compiled.textContent).toContain('New password');
    expect(compiled.textContent).toContain('Confirm new password');
  });
});
