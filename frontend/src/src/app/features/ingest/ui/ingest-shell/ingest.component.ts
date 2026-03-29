
import { ChangeDetectionStrategy, Component } from '@angular/core';
import { ReactiveFormsModule } from '@angular/forms';
import { MatButtonModule } from '@angular/material/button';
import { MatCardModule } from '@angular/material/card';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatSelectModule } from '@angular/material/select';
import { Check, LucideAngularModule, Upload } from 'lucide-angular';
import { LoadingIndicatorComponent } from '../../../../shared/ui/loading-indicator/loading-indicator.component';
import { IngestFacade } from '../ingest.facade';

@Component({
  selector: 'app-ingest',
  imports: [
    ReactiveFormsModule,
    MatButtonModule,
    MatCardModule,
    MatFormFieldModule,
    MatInputModule,
    MatSelectModule,
    LucideAngularModule,
    LoadingIndicatorComponent
],
  providers: [
    {
      provide: IngestFacade,
      useExisting: IngestComponent
    }
  ],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './ingest.component.html',
  styleUrl: './ingest.component.scss'
})
export class IngestComponent extends IngestFacade {
  protected readonly Upload = Upload;
  protected readonly Check = Check;
}
