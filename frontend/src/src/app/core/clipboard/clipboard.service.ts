import { DOCUMENT } from '@angular/common';
import { Injectable, inject } from '@angular/core';

@Injectable({ providedIn: 'root' })
export class ClipboardService {
  private readonly document = inject(DOCUMENT);

  async copyText(value: string | null | undefined): Promise<boolean> {
    const text = (value ?? '').toString();
    if (!text) {
      return false;
    }

    try {
      const clipboard = globalThis.navigator?.clipboard;
      if (clipboard?.writeText) {
        await clipboard.writeText(text);
        return true;
      }
    } catch {
      // Fall through to legacy copy behavior below.
    }

    const doc = this.document;
    const textarea = doc.createElement('textarea');
    textarea.value = text;
    textarea.setAttribute('readonly', 'true');
    textarea.style.position = 'absolute';
    textarea.style.left = '-9999px';

    doc.body.appendChild(textarea);
    textarea.select();
    try {
      return doc.execCommand('copy');
    } finally {
      doc.body.removeChild(textarea);
    }
  }
}

