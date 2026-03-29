
import { ChangeDetectionStrategy, Component, inject } from '@angular/core';
import { NonNullableFormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';
import { MAT_DIALOG_DATA, MatDialogModule, MatDialogRef } from '@angular/material/dialog';
import { MatButtonModule } from '@angular/material/button';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';

export interface ProjectFormDialogData {
  title: string;
  confirmLabel: string;
  initialName?: string;
  initialDescription?: string;
}

export interface ProjectFormDialogResult {
  name: string;
  description?: string;
}

@Component({
  selector: 'app-project-form-dialog',
  imports: [
    ReactiveFormsModule,
    MatDialogModule,
    MatButtonModule,
    MatFormFieldModule,
    MatInputModule
],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './project-form-dialog.component.html',
  styleUrl: './project-form-dialog.component.scss'
})
export class ProjectFormDialogComponent {
  readonly data = inject<ProjectFormDialogData>(MAT_DIALOG_DATA);
  private readonly ref = inject(MatDialogRef<ProjectFormDialogComponent, ProjectFormDialogResult | null>);
  private readonly fb = inject(NonNullableFormBuilder);

  readonly form = this.fb.group({
    name: [this.data.initialName ?? '', [Validators.required, Validators.maxLength(120)]],
    description: [this.data.initialDescription ?? '', [Validators.maxLength(2000)]]
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

    const description = this.form.controls.description.value.trim();
    this.ref.close({
      name,
      description: description || undefined
    });
  }
}
