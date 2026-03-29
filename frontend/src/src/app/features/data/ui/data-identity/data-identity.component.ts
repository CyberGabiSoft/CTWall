
import { ChangeDetectionStrategy, Component } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MatCardModule } from '@angular/material/card';
import { MatCheckboxModule } from '@angular/material/checkbox';
import { MatDialogModule } from '@angular/material/dialog';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatOptionModule } from '@angular/material/core';
import { MatSelectModule } from '@angular/material/select';
import { MatTooltipModule } from '@angular/material/tooltip';
import {
  Check,
  CirclePlus,
  Filter,
  LucideAngularModule,
  RefreshCw,
  Save,
  Trash2,
  Undo2,
  UserPlus,
  Users,
} from 'lucide-angular';
import { AdvancedFilterPanelComponent } from '../../../../shared/ui/advanced-filter-panel/advanced-filter-panel.component';
import { DataTableComponent } from '../../../../shared/ui/data-table/data-table.component';
import { LoadingIndicatorComponent } from '../../../../shared/ui/loading-indicator/loading-indicator.component';
import { DataIdentityFacade } from './data-identity.facade';

@Component({
  selector: 'app-data-identity',
  imports: [
    MatButtonModule,
    MatCardModule,
    MatCheckboxModule,
    MatDialogModule,
    MatFormFieldModule,
    MatOptionModule,
    MatSelectModule,
    MatTooltipModule,
    LucideAngularModule,
    DataTableComponent,
    LoadingIndicatorComponent,
    AdvancedFilterPanelComponent
],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './data-identity.component.html',
  styleUrl: './data-identity.component.scss',
})
export class DataIdentityComponent extends DataIdentityFacade {
  protected readonly RefreshCw = RefreshCw;
  protected readonly CirclePlus = CirclePlus;
  protected readonly Users = Users;
  protected readonly Filter = Filter;
  protected readonly Save = Save;
  protected readonly Undo2 = Undo2;
  protected readonly UserPlus = UserPlus;
  protected readonly Trash2 = Trash2;
  protected readonly Check = Check;
}
