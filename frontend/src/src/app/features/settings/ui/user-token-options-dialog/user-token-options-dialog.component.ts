
import { ChangeDetectionStrategy, Component, signal, inject } from '@angular/core';
import { NonNullableFormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';
import { MatButtonModule } from '@angular/material/button';
import { MatDialogModule, MatDialogRef } from '@angular/material/dialog';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { CreateUserTokenRequest } from '../../data-access/settings.types';

@Component({
  selector: 'app-user-token-options-dialog',
  imports: [
    ReactiveFormsModule,
    MatDialogModule,
    MatButtonModule,
    MatFormFieldModule,
    MatInputModule
],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './user-token-options-dialog.component.html',
  styleUrl: './user-token-options-dialog.component.scss'
})
export class UserTokenOptionsDialogComponent {
  private readonly ref = inject(MatDialogRef<UserTokenOptionsDialogComponent, CreateUserTokenRequest | null>);
  private readonly fb = inject(NonNullableFormBuilder);
  readonly expiresAtInvalid = signal(false);
  readonly expiresAtPast = signal(false);

  readonly form = this.fb.group({
    name: ['', [Validators.maxLength(120)]],
    expiresAt: ['']
  });

  cancel(): void {
    this.ref.close(null);
  }

  submit(): void {
    this.expiresAtInvalid.set(false);
    this.expiresAtPast.set(false);
    if (this.form.invalid) {
      this.form.markAllAsTouched();
      return;
    }

    const name = this.form.controls.name.value.trim();
    const expiresAtInput = this.form.controls.expiresAt.value.trim();
    const payload: CreateUserTokenRequest = {};
    if (name) {
      payload.name = name;
    }
    if (expiresAtInput) {
      const parsed = new Date(expiresAtInput);
      if (Number.isNaN(parsed.getTime())) {
        this.expiresAtInvalid.set(true);
        this.form.controls.expiresAt.markAsTouched();
        return;
      }
      if (parsed.getTime() <= Date.now()) {
        this.expiresAtPast.set(true);
        this.form.controls.expiresAt.markAsTouched();
        return;
      }
      payload.expiresAt = parsed.toISOString();
    }

    this.ref.close(payload);
  }
}
