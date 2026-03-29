
import { ChangeDetectionStrategy, Component, input } from '@angular/core';
import { CopyButtonComponent } from '../copy-button/copy-button.component';

@Component({
  selector: 'app-copy-block',
  imports: [CopyButtonComponent],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    @if (value(); as text) {
      <div class="detail-block">
        <div class="detail-block-header">
          <div class="detail-label">{{ label() }}</div>
          <app-copy-button [value]="text" [ariaLabel]="'Copy ' + label()"></app-copy-button>
        </div>
        <pre class="detail-pre">{{ text }}</pre>
      </div>
    }
  `
})
export class CopyBlockComponent {
  readonly label = input.required<string>();
  readonly value = input<string | null | undefined>(null);
}

