import { ChangeDetectionStrategy, Component, inject } from '@angular/core';
import { MatButtonToggleModule } from '@angular/material/button-toggle';
import { MatCardModule } from '@angular/material/card';
import { DataFacade } from '../data.facade';

@Component({
  selector: 'app-data-header',
  imports: [MatButtonToggleModule, MatCardModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './data-header.component.html',
  styleUrl: './data-header.component.scss'
})
export class DataHeaderComponent {
  readonly data = inject(DataFacade);
}
