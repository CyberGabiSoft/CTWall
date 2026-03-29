import { getTestBed } from '@angular/core/testing';
import { BrowserTestingModule, platformBrowserTesting } from '@angular/platform-browser/testing';

const g = globalThis as typeof globalThis & {
  __ctwallTestBedInitialized?: boolean;
  ResizeObserver?: typeof ResizeObserver;
};

if (!g.__ctwallTestBedInitialized) {
  try {
    getTestBed().initTestEnvironment(BrowserTestingModule, platformBrowserTesting());
  } catch (error) {
    if (!(error instanceof Error) || !error.message.includes('Cannot set base providers because it has already been called')) {
      throw error;
    }
  }
  g.__ctwallTestBedInitialized = true;
}

if (typeof g.ResizeObserver === 'undefined') {
  class ResizeObserverMock {
    observe(): void {}
    unobserve(): void {}
    disconnect(): void {}
  }
  g.ResizeObserver = ResizeObserverMock as unknown as typeof ResizeObserver;
}
