import { NgOptimizedImage } from '@angular/common';
import { HttpErrorResponse } from '@angular/common/http';
import { ChangeDetectionStrategy, Component, DestroyRef, inject, signal } from '@angular/core';
import { ReactiveFormsModule, Validators, NonNullableFormBuilder } from '@angular/forms';
import { ActivatedRoute, Router } from '@angular/router';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { AuthService } from '../../data-access/auth.service';
import { MatButtonModule } from '@angular/material/button';
import { MatCardModule } from '@angular/material/card';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { Copyright, Eye, EyeOff, LucideAngularModule } from 'lucide-angular';
import { AppVersionService } from '../../../../core/http/app-version.service';

@Component({
  selector: 'app-login',
  imports: [
    NgOptimizedImage,
    ReactiveFormsModule,
    MatButtonModule,
    MatCardModule,
    MatFormFieldModule,
    MatInputModule,
    LucideAngularModule
],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './login.component.html',
  styleUrl: './login.component.scss'
})
export class LoginComponent {
  private readonly auth = inject(AuthService);
  private readonly router = inject(Router);
  private readonly route = inject(ActivatedRoute);
  private readonly destroyRef = inject(DestroyRef);
  private readonly fb = inject(NonNullableFormBuilder);
  private readonly appVersionService = inject(AppVersionService);

  readonly isSubmitting = signal(false);
  readonly error = signal<string | null>(null);
  readonly showPassword = signal(false);
  readonly isPasswordFocused = signal(false);
  readonly appVersion = this.appVersionService.version;
  readonly Copyright = Copyright;
  readonly Eye = Eye;
  readonly EyeOff = EyeOff;

  readonly form = this.fb.group({
    email: ['', [Validators.required, Validators.email]],
    password: ['', [Validators.required, Validators.minLength(12)]]
  });

  constructor() {
    this.form.valueChanges.pipe(takeUntilDestroyed(this.destroyRef)).subscribe(() => {
      if (this.error()) {
        this.error.set(null);
      }
    });
  }

  async onSubmit(): Promise<void> {
    if (this.form.invalid || this.isSubmitting()) {
      this.form.markAllAsTouched();
      return;
    }

    this.isSubmitting.set(true);
    this.error.set(null);

    try {
      await this.auth.login(this.form.getRawValue());
      const redirect = this.sanitizeRedirect(this.route.snapshot.queryParamMap.get('redirect'));
      await this.router.navigateByUrl(redirect);
    } catch (error) {
      const message = this.resolveErrorMessage(error);
      this.error.set(message);
    } finally {
      this.isSubmitting.set(false);
    }
  }

  togglePasswordVisibility(): void {
    this.showPassword.update((value) => !value);
  }

  private resolveErrorMessage(error: unknown): string {
    if (error instanceof HttpErrorResponse) {
      if (error.status === 401) {
        return 'Invalid email or password.';
      }
      if (error.status === 429) {
        return 'Too many login attempts. Please wait and try again.';
      }
    }
    return 'Login failed. Please try again.';
  }

  private sanitizeRedirect(value: string | null): string {
    if (!value) {
      return '/dashboard';
    }
    if (!value.startsWith('/') || value.startsWith('//')) {
      return '/dashboard';
    }
    if (value.startsWith('/login')) {
      return '/dashboard';
    }
    return value;
  }
}
