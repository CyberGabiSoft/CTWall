
import {
  ChangeDetectionStrategy,
  Component,
  DestroyRef,
  computed,
  inject,
  signal
} from '@angular/core';
import {
  AbstractControl,
  NonNullableFormBuilder,
  ReactiveFormsModule,
  ValidationErrors,
  ValidatorFn,
  Validators
} from '@angular/forms';
import { HttpErrorResponse } from '@angular/common/http';
import { ActivatedRoute, Router } from '@angular/router';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { MatButtonModule } from '@angular/material/button';
import { MatCardModule } from '@angular/material/card';
import { MatCheckboxModule } from '@angular/material/checkbox';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatProgressBarModule } from '@angular/material/progress-bar';
import { AuthService } from '../../data-access/auth.service';
import { AuthStore } from '../../auth.store';
import { isStrongPassword, passwordRequirements } from './change-password.utils';

const passwordStrengthValidator = (minLength: number): ValidatorFn => {
  return (control: AbstractControl): ValidationErrors | null => {
    const value = typeof control.value === 'string' ? control.value : '';
    if (!value) {
      return null;
    }
    return isStrongPassword(value, minLength) ? null : { passwordStrength: true };
  };
};

const passwordMatchValidator = (passwordKey: string, confirmKey: string): ValidatorFn => {
  return (group: AbstractControl): ValidationErrors | null => {
    const password = group.get(passwordKey)?.value ?? '';
    const confirm = group.get(confirmKey)?.value ?? '';
    if (!password || !confirm) {
      return null;
    }
    return password === confirm ? null : { passwordMismatch: true };
  };
};

@Component({
  selector: 'app-change-password',
  imports: [
    ReactiveFormsModule,
    MatButtonModule,
    MatCardModule,
    MatCheckboxModule,
    MatFormFieldModule,
    MatInputModule,
    MatProgressBarModule
],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './change-password.component.html',
  styleUrl: './change-password.component.scss'
})
export class ChangePasswordComponent {
  private readonly auth = inject(AuthService);
  private readonly authStore = inject(AuthStore);
  private readonly router = inject(Router);
  private readonly route = inject(ActivatedRoute);
  private readonly destroyRef = inject(DestroyRef);
  private readonly fb = inject(NonNullableFormBuilder);

  readonly isSubmitting = signal(false);
  readonly error = signal<string | null>(null);
  readonly user = this.authStore.user;
  readonly isServiceAccount = computed(() => this.user()?.accountType === 'SERVICE_ACCOUNT');
  private readonly returnUrl = signal(
    this.sanitizeReturnUrl(this.route.snapshot.queryParamMap.get('returnUrl'))
  );

  readonly form = this.fb.group(
    {
      currentPassword: ['', [Validators.required]],
      newPassword: [
        '',
        [
          Validators.required,
          Validators.minLength(passwordRequirements.minLength),
          passwordStrengthValidator(passwordRequirements.minLength)
        ]
      ],
      confirmPassword: ['', [Validators.required]],
      accept: [false, [Validators.requiredTrue]]
    },
    {
      validators: [passwordMatchValidator('newPassword', 'confirmPassword')]
    }
  );

  constructor() {
    this.form.valueChanges.pipe(takeUntilDestroyed(this.destroyRef)).subscribe(() => {
      if (this.error()) {
        this.error.set(null);
      }
    });
  }

  async onSubmit(): Promise<void> {
    if (this.isServiceAccount()) {
      this.error.set('Service accounts cannot change passwords.');
      return;
    }
    if (this.form.invalid || this.isSubmitting()) {
      this.form.markAllAsTouched();
      return;
    }

    this.isSubmitting.set(true);
    this.error.set(null);

    try {
      const payload = this.form.getRawValue();
      await this.auth.changePassword({
        currentPassword: payload.currentPassword,
        newPassword: payload.newPassword
      });
      this.auth.logout();
      const redirect = this.returnUrl();
      await this.router.navigate(['/login'], { queryParams: { redirect } });
    } catch (error) {
      this.error.set(this.resolveErrorMessage(error));
    } finally {
      this.isSubmitting.set(false);
    }
  }

  onCancel(): void {
    const target = this.returnUrl();
    void this.router.navigateByUrl(target);
  }

  passwordErrorMessage(): string {
    return `Password must be at least ${passwordRequirements.minLength} characters and include uppercase, lowercase, digit, and special character.`;
  }

  private resolveErrorMessage(error: unknown): string {
    if (error instanceof HttpErrorResponse) {
      if (error.status === 403) {
        return 'Current password is incorrect or this account cannot change passwords.';
      }
      if (error.status === 400) {
        return 'Password does not meet the required complexity rules.';
      }
    }
    return 'Unable to update password. Please try again.';
  }

  private sanitizeReturnUrl(value: string | null): string {
    if (!value) {
      return '/dashboard';
    }
    if (!value.startsWith('/') || value.startsWith('//')) {
      return '/dashboard';
    }
    if (value.startsWith('/login')) {
      return '/dashboard';
    }
    if (value.startsWith('/account/change-password')) {
      return '/dashboard';
    }
    return value;
  }
}
