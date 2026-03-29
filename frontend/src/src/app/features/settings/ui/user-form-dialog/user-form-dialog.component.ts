
import { ChangeDetectionStrategy, Component, inject } from '@angular/core';
import { NonNullableFormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';
import { MAT_DIALOG_DATA, MatDialogModule, MatDialogRef } from '@angular/material/dialog';
import { MatButtonModule } from '@angular/material/button';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatSelectModule } from '@angular/material/select';
import { AccountType, UserRole } from '../../../auth/auth.types';
import { CreateUserRequest, SettingsUser, UpdateUserRequest } from '../../data-access/settings.types';

export interface UserFormDialogData {
  mode: 'create' | 'edit';
  title: string;
  confirmLabel: string;
  user?: SettingsUser;
}

export type EditUserFormResult = UpdateUserRequest;

export type UserFormDialogResult = CreateUserRequest | EditUserFormResult;

@Component({
  selector: 'app-user-form-dialog',
  imports: [
    ReactiveFormsModule,
    MatDialogModule,
    MatButtonModule,
    MatFormFieldModule,
    MatInputModule,
    MatSelectModule
],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './user-form-dialog.component.html',
  styleUrl: './user-form-dialog.component.scss'
})
export class UserFormDialogComponent {
  readonly data = inject<UserFormDialogData>(MAT_DIALOG_DATA);
  private readonly ref = inject(MatDialogRef<UserFormDialogComponent, UserFormDialogResult | null>);
  private readonly fb = inject(NonNullableFormBuilder);
  readonly isCreateMode = this.data.mode === 'create';

  readonly roleOptions: ReadonlyArray<{ value: UserRole; label: string }> = [
    { value: 'NONE', label: 'NONE (no project access)' },
    { value: 'READER', label: 'READER' },
    { value: 'WRITER', label: 'WRITER' },
    { value: 'ADMIN', label: 'ADMIN' }
  ];
  readonly accountTypes: AccountType[] = ['USER', 'SERVICE_ACCOUNT'];

  readonly form = this.fb.group({
    email: ['', [Validators.required, Validators.email, Validators.maxLength(120)]],
    nickname: ['', [Validators.required, Validators.maxLength(64)]],
    password: [
      '',
      [
        Validators.minLength(12),
        Validators.maxLength(120),
        Validators.pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).+$/)
      ]
    ],
    role: ['NONE' as UserRole, [Validators.required]],
    accountType: ['USER' as AccountType, [Validators.required]],
    fullName: ['', [Validators.maxLength(120)]]
  });

  constructor() {
    const user = this.data.user;
    if (user) {
      this.form.patchValue({
        email: user.email,
        nickname: user.nickname,
        role: user.role,
        accountType: user.accountType,
        fullName: user.fullName ?? ''
      });
    }
    if (this.isCreateMode) {
      this.form.controls.password.addValidators(Validators.required);
    } else {
      this.form.controls.email.disable({ emitEvent: false });
      this.form.controls.password.clearValidators();
      this.form.controls.password.setValue('');
    }
    this.form.controls.password.updateValueAndValidity();
  }

  cancel(): void {
    this.ref.close(null);
  }

  submit(): void {
    if (this.form.invalid) {
      this.form.markAllAsTouched();
      return;
    }

    const fullName = this.form.controls.fullName.value.trim();
    const nickname = this.form.controls.nickname.value.trim();
    if (!nickname) {
      return;
    }
    if (this.isCreateMode) {
      const email = this.form.controls.email.value.trim();
      if (!email) {
        return;
      }
      const password = this.form.controls.password.value.trim();
      if (!password) {
        return;
      }
      this.ref.close({
        email,
        password,
        role: this.form.controls.role.value,
        accountType: this.form.controls.accountType.value,
        nickname,
        fullName: fullName || undefined
      });
      return;
    }

    const result: EditUserFormResult = {
      role: this.form.controls.role.value,
      accountType: this.form.controls.accountType.value,
      nickname,
      fullName: fullName || undefined
    };
    this.ref.close(result);
  }
}
