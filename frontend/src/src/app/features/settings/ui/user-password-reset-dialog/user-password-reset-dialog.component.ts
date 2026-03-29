
import { ChangeDetectionStrategy, Component, computed, inject } from '@angular/core';
import { AbstractControl, NonNullableFormBuilder, ReactiveFormsModule, ValidationErrors, ValidatorFn, Validators } from '@angular/forms';
import { MAT_DIALOG_DATA, MatDialogModule, MatDialogRef } from '@angular/material/dialog';
import { MatButtonModule } from '@angular/material/button';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { isStrongPassword, passwordRequirements } from '../../../auth/ui/change-password/change-password.utils';

const passwordStrengthValidator = (minLength: number): ValidatorFn => {
  return (control: AbstractControl<string>): ValidationErrors | null => {
    const value = (control.value ?? '').trim();
    if (!value) {
      return null;
    }
    return isStrongPassword(value, minLength) ? null : { passwordStrength: true };
  };
};

const passwordMatchValidator = (passwordKey: string, confirmKey: string): ValidatorFn => {
  return (control: AbstractControl): ValidationErrors | null => {
    const password = (control.get(passwordKey)?.value ?? '').toString();
    const confirm = (control.get(confirmKey)?.value ?? '').toString();
    if (!password || !confirm) {
      return null;
    }
    return password === confirm ? null : { passwordMismatch: true };
  };
};

export interface UserPasswordResetDialogData {
  email: string;
}

export interface UserPasswordResetDialogResult {
  newPassword: string;
}

@Component({
  selector: 'app-user-password-reset-dialog',
  imports: [ReactiveFormsModule, MatDialogModule, MatButtonModule, MatFormFieldModule, MatInputModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './user-password-reset-dialog.component.html',
  styleUrl: './user-password-reset-dialog.component.scss'
})
export class UserPasswordResetDialogComponent {
  readonly data = inject<UserPasswordResetDialogData>(MAT_DIALOG_DATA);
  private readonly ref = inject(MatDialogRef<UserPasswordResetDialogComponent, UserPasswordResetDialogResult | null>);
  private readonly fb = inject(NonNullableFormBuilder);

  readonly form = this.fb.group(
    {
      newPassword: [
        '',
        [
          Validators.required,
          Validators.minLength(passwordRequirements.minLength),
          Validators.maxLength(120),
          passwordStrengthValidator(passwordRequirements.minLength)
        ]
      ],
      confirmPassword: ['', [Validators.required]]
    },
    {
      validators: [passwordMatchValidator('newPassword', 'confirmPassword')]
    }
  );

  readonly passwordHint = computed(() => {
    return `Password must be at least ${passwordRequirements.minLength} characters and include uppercase, lowercase, digit, and special character.`;
  });

  cancel(): void {
    this.ref.close(null);
  }

  submit(): void {
    if (this.form.invalid) {
      this.form.markAllAsTouched();
      return;
    }
    const newPassword = this.form.controls.newPassword.value.trim();
    if (!newPassword) {
      return;
    }
    this.ref.close({ newPassword });
  }
}
