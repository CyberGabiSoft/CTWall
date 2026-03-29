
import { ChangeDetectionStrategy, Component, inject } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MAT_DIALOG_DATA, MatDialogModule, MatDialogRef } from '@angular/material/dialog';
import { CopyBlockComponent } from '../../../../shared/ui/copy-block/copy-block.component';

export interface UserTokenDialogData {
  userEmail: string;
  token: string;
  tokenId: string;
  name: string;
  createdAt: string;
  expiresAt?: string;
}

@Component({
  selector: 'app-user-token-dialog',
  imports: [MatDialogModule, MatButtonModule, CopyBlockComponent],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './user-token-dialog.component.html',
  styleUrl: './user-token-dialog.component.scss'
})
export class UserTokenDialogComponent {
  readonly data = inject<UserTokenDialogData>(MAT_DIALOG_DATA);
  private readonly ref = inject(MatDialogRef<UserTokenDialogComponent, void>);

  close(): void {
    this.ref.close();
  }
}
