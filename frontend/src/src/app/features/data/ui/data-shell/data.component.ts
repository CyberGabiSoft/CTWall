import { ChangeDetectionStrategy, Component } from '@angular/core';
import { DataFacade } from '../data.facade';
import { DataDetailTablesComponent } from '../data-detail-tables/data-detail-tables.component';
import { DataHeaderComponent } from '../data-header/data-header.component';
import { DataListTablesComponent } from '../data-list-tables/data-list-tables.component';

@Component({
  selector: 'app-data',
  imports: [DataDetailTablesComponent, DataHeaderComponent, DataListTablesComponent],
  providers: [
    {
      provide: DataFacade,
      useExisting: DataComponent
    }
  ],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './data.component.html',
  styleUrl: './data.component.scss'
})
export class DataComponent extends DataFacade {}
