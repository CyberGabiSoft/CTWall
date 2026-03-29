
import { ChangeDetectionStrategy, Component, input, inject } from '@angular/core';
import { ClipboardService } from '../../../core/clipboard/clipboard.service';
import { Copy, LucideAngularModule } from 'lucide-angular';

@Component({
  selector: 'app-copy-button',
  imports: [LucideAngularModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <button
      type="button"
      class="copy-btn"
      [disabled]="disabled()"
      [attr.aria-label]="ariaLabel()"
      (click)="copy()"
    >
      <lucide-icon [img]="Copy" aria-hidden="true"></lucide-icon>
    </button>
  `
})
export class CopyButtonComponent {
  protected readonly Copy = Copy;
  private readonly clipboard = inject(ClipboardService);

  readonly value = input<string | null | undefined>(null);
  readonly ariaLabel = input('Copy value');
  readonly disabled = input(false);

  async copy(): Promise<void> {
    if (this.disabled()) {
      return;
    }
    await this.clipboard.copyText(this.value());
  }
}
