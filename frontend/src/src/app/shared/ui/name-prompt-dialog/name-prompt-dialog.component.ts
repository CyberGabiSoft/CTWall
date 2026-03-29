
import { ChangeDetectionStrategy, Component, inject } from '@angular/core';
import { NonNullableFormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';
import { MAT_DIALOG_DATA, MatDialogModule, MatDialogRef } from '@angular/material/dialog';
import { MatButtonModule } from '@angular/material/button';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';

export interface NamePromptDialogData {
  title: string;
  label: string;
  confirmLabel?: string;
}

@Component({
  selector: 'app-name-prompt-dialog',
  imports: [
    ReactiveFormsModule,
    MatDialogModule,
    MatButtonModule,
    MatFormFieldModule,
    MatInputModule
],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './name-prompt-dialog.component.html',
  styleUrl: './name-prompt-dialog.component.scss'
})
export class NamePromptDialogComponent {
  readonly data = inject<NamePromptDialogData>(MAT_DIALOG_DATA);
  private readonly ref = inject(MatDialogRef<NamePromptDialogComponent, string | null>);
  private readonly fb = inject(NonNullableFormBuilder);

  readonly form = this.fb.group({
    name: ['', [Validators.required, Validators.maxLength(120)]]
  });

  cancel(): void {
    this.ref.close(null);
  }

  submit(): void {
    if (this.form.invalid) {
      this.form.markAllAsTouched();
      return;
    }
    const name = this.form.controls.name.value.trim();
    if (!name) {
      this.form.controls.name.setValue('');
      this.form.controls.name.markAsTouched();
      return;
    }
    this.ref.close(name);
  }
}
