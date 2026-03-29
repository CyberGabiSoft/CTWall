import { Injectable, NgZone, inject } from '@angular/core';
import { OverlayContainer } from '@angular/cdk/overlay';

@Injectable({
  providedIn: 'root'
})
export class MatSelectLiveFilterService {
  private readonly zone = inject(NgZone);
  private readonly overlay = inject(OverlayContainer);

  private activePanel: HTMLElement | null = null;
  private query = '';
  private clearTimer: number | null = null;
  private initialized = false;

  init(): void {
    if (this.initialized || typeof document === 'undefined') {
      return;
    }
    this.initialized = true;
    this.zone.runOutsideAngular(() => {
      document.addEventListener('keydown', this.onKeydown, true);
      document.addEventListener('click', this.onDocumentClick, true);
    });
  }

  private readonly onKeydown = (event: KeyboardEvent): void => {
    const panel = this.getOpenSelectPanel();
    if (!panel) {
      this.reset();
      return;
    }

    if (this.isTypingIntoTextField(event.target)) {
      return;
    }

    if (event.key === 'Escape') {
      this.reset();
      this.applyFilter(panel);
      return;
    }

    if (event.key === 'Backspace') {
      if (!this.query) {
        return;
      }
      this.query = this.query.slice(0, -1);
      this.applyFilter(panel);
      this.scheduleQueryReset(panel);
      event.preventDefault();
      event.stopPropagation();
      return;
    }

    if (!this.isSearchCharacter(event)) {
      return;
    }

    this.query += event.key.toLowerCase();
    this.applyFilter(panel);
    this.scheduleQueryReset(panel);
    event.preventDefault();
    event.stopPropagation();
  };

  private readonly onDocumentClick = (event: MouseEvent): void => {
    if (!this.activePanel) {
      return;
    }
    const target = event.target as Node | null;
    if (!target || !this.activePanel.contains(target)) {
      this.reset();
      this.applyFilter(this.activePanel);
    }
  };

  private getOpenSelectPanel(): HTMLElement | null {
    const root = this.overlay.getContainerElement();
    const openPanel = Array.from(root.querySelectorAll<HTMLElement>('.mat-mdc-select-panel'))
      .find((panel) => this.isVisible(panel)) ?? null;

    if (openPanel !== this.activePanel) {
      this.reset();
      if (this.activePanel) {
        this.applyFilter(this.activePanel);
      }
      this.activePanel = openPanel;
    }

    return openPanel;
  }

  private applyFilter(panel: HTMLElement): void {
    const options = Array.from(panel.querySelectorAll<HTMLElement>('.mat-mdc-option'));
    const normalizedQuery = this.normalize(this.query);
    let firstVisible: HTMLElement | null = null;

    for (const option of options) {
      const text = this.normalize(option.textContent ?? '');
      const shouldShow = normalizedQuery.length === 0 || text.includes(normalizedQuery);
      option.classList.toggle('ctw-option-filter-hidden', !shouldShow);
      option.setAttribute('aria-hidden', shouldShow ? 'false' : 'true');
      if (shouldShow && !firstVisible) {
        firstVisible = option;
      }
    }

    if (firstVisible && normalizedQuery.length > 0) {
      firstVisible.scrollIntoView({ block: 'nearest' });
    }
  }

  private scheduleQueryReset(panel: HTMLElement): void {
    if (this.clearTimer !== null) {
      window.clearTimeout(this.clearTimer);
    }
    this.clearTimer = window.setTimeout(() => {
      this.query = '';
      this.applyFilter(panel);
      this.clearTimer = null;
    }, 900);
  }

  private reset(): void {
    this.query = '';
    if (this.clearTimer !== null) {
      window.clearTimeout(this.clearTimer);
      this.clearTimer = null;
    }
  }

  private isSearchCharacter(event: KeyboardEvent): boolean {
    return (
      event.key.length === 1
      && !event.altKey
      && !event.ctrlKey
      && !event.metaKey
    );
  }

  private isTypingIntoTextField(target: EventTarget | null): boolean {
    if (!(target instanceof HTMLElement)) {
      return false;
    }
    const tag = target.tagName.toLowerCase();
    return tag === 'input' || tag === 'textarea' || target.isContentEditable;
  }

  private isVisible(element: HTMLElement): boolean {
    return element.offsetParent !== null || element.getClientRects().length > 0;
  }

  private normalize(value: string): string {
    return value.toLowerCase().trim();
  }
}
