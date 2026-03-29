
import { ChangeDetectionStrategy, Component, inject } from '@angular/core';
import { NonNullableFormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';
import { MAT_DIALOG_DATA, MatDialogModule, MatDialogRef } from '@angular/material/dialog';
import { MatButtonModule } from '@angular/material/button';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';

export interface SmtpTestDialogData {
  defaultToEmail?: string;
}

export interface SmtpTestDialogResult {
  toEmail: string;
}

@Component({
  selector: 'app-smtp-test-dialog',
  imports: [
    ReactiveFormsModule,
    MatDialogModule,
    MatButtonModule,
    MatFormFieldModule,
    MatInputModule
],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './smtp-test-dialog.component.html',
  styleUrl: './smtp-test-dialog.component.scss'
})
export class SmtpTestDialogComponent {
  readonly data = inject<SmtpTestDialogData | null>(MAT_DIALOG_DATA, { optional: true });
  private readonly ref = inject(MatDialogRef<SmtpTestDialogComponent, SmtpTestDialogResult | null>);
  private readonly fb = inject(NonNullableFormBuilder);

  readonly form = this.fb.group({
    toEmail: [this.data?.defaultToEmail?.trim() ?? '', [Validators.required, Validators.email, Validators.maxLength(254)]]
  });

  cancel(): void {
    this.ref.close(null);
  }

  submit(): void {
    if (this.form.invalid) {
      this.form.markAllAsTouched();
      return;
    }
    this.ref.close({
      toEmail: this.form.controls.toEmail.value.trim()
    });
  }
}
