import { DOCUMENT } from '@angular/common';
import { effect, inject, Injectable, signal } from '@angular/core';

export type ThemeMode = 'light' | 'dark';

const STORAGE_KEY = 'ctw-theme';
const THEME_LIGHT_CLASS = 'ctw-theme-light';
const THEME_DARK_CLASS = 'ctw-theme-dark';

@Injectable({ providedIn: 'root' })
export class ThemeService {
  private readonly documentRef = inject(DOCUMENT);
  private readonly hasWindow = typeof window !== 'undefined';
  readonly theme = signal<ThemeMode>(this.resolveInitialTheme());

  constructor() {
    effect(() => {
      const nextTheme = this.theme();
      this.applyTheme(nextTheme);
      this.persistTheme(nextTheme);
    });
  }

  toggle(): void {
    this.theme.update(current => (current === 'dark' ? 'light' : 'dark'));
  }

  initialize(): void {
    const current = this.theme();
    this.applyTheme(current);
    this.persistTheme(current);
  }

  setTheme(theme: ThemeMode): void {
    this.theme.set(theme);
  }

  private resolveInitialTheme(): ThemeMode {
    const stored = this.readStoredTheme();
    if (stored) {
      return stored;
    }
    if (this.hasWindow && window.matchMedia) {
      return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
    }
    return 'light';
  }

  private readStoredTheme(): ThemeMode | '' {
    if (!this.hasWindow || !window.localStorage) {
      return '';
    }
    const value = window.localStorage.getItem(STORAGE_KEY);
    return value === 'dark' || value === 'light' ? value : '';
  }

  private persistTheme(theme: ThemeMode): void {
    if (!this.hasWindow || !window.localStorage) {
      return;
    }
    window.localStorage.setItem(STORAGE_KEY, theme);
  }

  private applyTheme(theme: ThemeMode): void {
    const root = this.documentRef.documentElement;
    root.setAttribute('data-theme', theme);
    root.classList.remove(THEME_LIGHT_CLASS, THEME_DARK_CLASS);
    root.classList.add(theme === 'dark' ? THEME_DARK_CLASS : THEME_LIGHT_CLASS);
  }
}
