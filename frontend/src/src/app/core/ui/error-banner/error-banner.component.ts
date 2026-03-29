import { ChangeDetectionStrategy, Component, inject } from '@angular/core';
import { ErrorStateService } from '../../errors/error-state.service';

@Component({
  selector: 'app-error-banner',
  imports: [],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './error-banner.component.html',
  styleUrl: './error-banner.component.scss'
})
export class ErrorBannerComponent {
  private readonly errorState = inject(ErrorStateService);

  readonly error = this.errorState.error;

  dismiss(): void {
    this.errorState.clear();
  }
}
