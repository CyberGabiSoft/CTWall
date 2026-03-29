import { Component } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { NoopAnimationsModule } from '@angular/platform-browser/animations';
import {
  AdvancedFilterField,
  AdvancedFilterPanelComponent
} from './advanced-filter-panel.component';

@Component({
  imports: [AdvancedFilterPanelComponent],
  template: `
    <app-advanced-filter-panel
      [fields]="fields"
      [idPrefix]="'test'"
      (valueChange)="onValueChange($event)"
    ></app-advanced-filter-panel>
  `
})
class AdvancedFilterPanelHostComponent {
  fields: AdvancedFilterField[] = [
    {
      key: 'purl',
      label: 'PURL',
      mode: 'contains',
      value: '',
      options: [],
      selected: []
    }
  ];

  lastValueChange: { key: string; value: string } | null = null;

  onValueChange(event: { key: string; value: string }): void {
    this.lastValueChange = event;
  }
}

describe('AdvancedFilterPanelComponent (TestBed)', () => {
  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [AdvancedFilterPanelHostComponent, NoopAnimationsModule]
    }).compileComponents();
  });

  it('emits value changes for input fields', () => {
    const fixture = TestBed.createComponent(AdvancedFilterPanelHostComponent);
    fixture.detectChanges();

    const input = fixture.nativeElement.querySelector('input') as HTMLInputElement;
    expect(input).toBeTruthy();
    input.value = 'pkg:maven/test@1.0.0';
    input.dispatchEvent(new Event('input'));
    fixture.detectChanges();

    expect(fixture.componentInstance.lastValueChange).toEqual({
      key: 'purl',
      value: 'pkg:maven/test@1.0.0'
    });
  });
});
