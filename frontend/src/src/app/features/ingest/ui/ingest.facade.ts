import { HttpErrorResponse } from '@angular/common/http';
import { DestroyRef, computed, effect, inject, signal } from '@angular/core';
import { AbstractControl, NonNullableFormBuilder, ValidationErrors, ValidatorFn, Validators } from '@angular/forms';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { ActivatedRoute } from '@angular/router';
import { IngestApi } from '../data-access/ingest.api';
import { IngestResponse } from '../data-access/ingest.types';
import { IngestStore } from '../state/ingest.store';
import { formatBytes, hasControlCharacters, NAME_MAX_LENGTH, normalizeName } from '../ingest.utils';
import { ProjectContextService } from '../../projects/data-access/project-context.service';

const nameValidator: ValidatorFn = (control: AbstractControl): ValidationErrors | null => {
  const value = typeof control.value === 'string' ? control.value : '';
  const normalized = normalizeName(value);
  if (!normalized) {
    return { required: true };
  }
  if (normalized.length > NAME_MAX_LENGTH) {
    return { maxLength: true };
  }
  if (hasControlCharacters(normalized)) {
    return { controlChars: true };
  }
  return null;
};

type UploadStatus = 'idle' | 'uploading' | 'success' | 'error';

interface FileState {
  file: File;
  name: string;
  size: number;
  sizeLabel: string;
}

type TestMode = 'new' | 'existing';

export abstract class IngestFacade {
  private readonly api = inject(IngestApi);
  private readonly store = inject(IngestStore);
  private readonly projectContext = inject(ProjectContextService);
  private readonly fb = inject(NonNullableFormBuilder);
  private readonly destroyRef = inject(DestroyRef);
  private readonly route = inject(ActivatedRoute);

  private readonly pendingProductId = signal('');
  private readonly pendingScopeId = signal('');

  readonly canWrite = computed(() => this.projectContext.canWrite());

  readonly products = this.store.products;
  readonly productsStatus = this.store.productsStatus;
  readonly productsError = this.store.productsError;
  readonly scopes = this.store.scopes;
  readonly scopesStatus = this.store.scopesStatus;
  readonly scopesError = this.store.scopesError;
  readonly tests = this.store.tests;
  readonly testsStatus = this.store.testsStatus;
  readonly testsError = this.store.testsError;

  readonly isDragging = signal(false);
  readonly isParsing = signal(false);
  readonly parseError = signal<string | null>(null);
  readonly fileState = signal<FileState | null>(null);

  readonly uploadStatus = signal<UploadStatus>('idle');
  readonly uploadError = signal<string | null>(null);
  readonly uploadResult = signal<IngestResponse | null>(null);

  readonly form = this.fb.group({
    productId: ['', [Validators.required]],
    scopeId: ['', [Validators.required]],
    testMode: ['new' as TestMode, [Validators.required]],
    testId: [''],
    testName: ['', [nameValidator]]
  });

  readonly formValid = signal(this.form.valid);
  readonly testNameValue = signal(this.form.controls.testName.value);
  readonly selectedProductId = signal(this.form.controls.productId.value);
  readonly selectedScopeId = signal(this.form.controls.scopeId.value);
  readonly selectedTestMode = signal(this.form.controls.testMode.value);
  readonly selectedTestId = signal(this.form.controls.testId.value);
  readonly testNameCount = computed(() => this.testNameValue().trim().length);

  readonly canSubmit = computed(
    () =>
      this.canWrite() &&
      this.formValid() &&
      !!this.selectedProductId() &&
      !!this.selectedScopeId() &&
      (this.selectedTestMode() === 'new' ? !!normalizeName(this.testNameValue()) : !!this.selectedTestId()) &&
      this.fileState() !== null &&
      this.uploadStatus() !== 'uploading' &&
      !this.isParsing()
  );

  constructor() {
    void this.store.ensureProducts();

    // Allow deep links from Data -> Tests (e.g. /data/import?productId=...&scopeId=...).
    this.route.queryParamMap
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe((params) => {
        const safeId = (raw: string | null): string => {
          const value = (raw ?? '').trim();
          if (!value) {
            return '';
          }
          // Basic abuse guard: avoid huge values and control chars in URL-driven form state.
          if (value.length > 200 || hasControlCharacters(value)) {
            return '';
          }
          return value;
        };

        this.pendingProductId.set(safeId(params.get('productId')));
        this.pendingScopeId.set(safeId(params.get('scopeId')));
      });

    this.form.statusChanges.pipe(takeUntilDestroyed(this.destroyRef)).subscribe(() => {
      this.formValid.set(this.form.valid);
    });

    this.form.controls.testName.valueChanges
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe((value) => {
        this.testNameValue.set(value ?? '');
      });

    this.form.controls.productId.valueChanges
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe((value) => {
        const productId = value ?? '';
        this.selectedProductId.set(productId);
        this.form.controls.scopeId.setValue('', { emitEvent: false });
        this.selectedScopeId.set('');
        this.store.clearScopes();
        this.store.clearTests();
        this.form.controls.testId.setValue('', { emitEvent: false });
        this.selectedTestId.set('');
        this.clearUploadState();
        if (productId) {
          this.store.loadScopes(productId);
        }
      });

    this.form.controls.scopeId.valueChanges
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe((value) => {
        const scopeId = value ?? '';
        this.selectedScopeId.set(scopeId);
        this.form.controls.testId.setValue('', { emitEvent: false });
        this.selectedTestId.set('');
        this.store.clearTests();
        this.clearUploadState();
        if (scopeId) {
          this.store.loadTests(scopeId);
        }
      });

    this.form.controls.testMode.valueChanges
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe((value) => {
        const mode = value === 'existing' ? 'existing' : 'new';
        this.selectedTestMode.set(mode);
        this.form.controls.testId.setValue('', { emitEvent: false });
        this.selectedTestId.set('');
        this.clearUploadState();
      });

    this.form.controls.testId.valueChanges
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe((value) => {
        this.selectedTestId.set(value ?? '');
      });

    effect(() => {
      if (this.productsStatus() === 'loaded' && this.form.controls.productId.value) {
        void this.store.ensureScopes(this.form.controls.productId.value);
      }
    });

    effect(() => {
      if (this.scopesStatus() === 'loaded' && this.form.controls.scopeId.value) {
        void this.store.ensureTests(this.form.controls.scopeId.value);
      }
    });

    effect(() => {
      if (this.productsStatus() !== 'loaded') {
        return;
      }
      if (this.scopesStatus() === 'loading') {
        return;
      }
      const productId = this.pendingProductId();
      if (!productId) {
        return;
      }
      const exists = this.products().some((product) => product.id === productId);
      if (!exists) {
        this.pendingProductId.set('');
        this.pendingScopeId.set('');
        return;
      }
      if (this.form.controls.productId.value !== productId) {
        this.form.controls.productId.setValue(productId);
      }
      this.pendingProductId.set('');
    });

    effect(() => {
      if (this.scopesStatus() !== 'loaded') {
        return;
      }
      const scopeId = this.pendingScopeId();
      if (!scopeId) {
        return;
      }
      const productId = this.selectedProductId();
      if (!productId) {
        return;
      }
      const exists = this.scopes().some((scope) => scope.id === scopeId);
      if (!exists) {
        this.pendingScopeId.set('');
        return;
      }
      if (this.form.controls.scopeId.value !== scopeId) {
        this.form.controls.scopeId.setValue(scopeId);
      }
      this.pendingScopeId.set('');
    });

    effect(() => {
      const productControl = this.form.controls.productId;
      if (this.canWrite() && this.productsStatus() === 'loaded') {
        productControl.enable({ emitEvent: false });
      } else {
        productControl.disable({ emitEvent: false });
      }
    });

    effect(() => {
      const scopeControl = this.form.controls.scopeId;
      if (this.canWrite() && this.selectedProductId() && this.scopesStatus() !== 'loading') {
        scopeControl.enable({ emitEvent: false });
      } else {
        scopeControl.disable({ emitEvent: false });
      }
    });

    effect(() => {
      const modeControl = this.form.controls.testMode;
      if (this.canWrite() && this.selectedScopeId()) {
        modeControl.enable({ emitEvent: false });
      } else {
        modeControl.disable({ emitEvent: false });
      }
    });

    effect(() => {
      const testNameControl = this.form.controls.testName;
      if (this.canWrite() && this.selectedScopeId() && this.selectedTestMode() === 'new') {
        testNameControl.enable({ emitEvent: false });
      } else {
        testNameControl.disable({ emitEvent: false });
      }
    });

    effect(() => {
      const testIdControl = this.form.controls.testId;
      if (this.canWrite() && this.selectedScopeId() && this.selectedTestMode() === 'existing' && this.testsStatus() !== 'loading') {
        testIdControl.enable({ emitEvent: false });
      } else {
        testIdControl.disable({ emitEvent: false });
      }
    });
  }

  async onSubmit(): Promise<void> {
    if (!this.canSubmit()) {
      this.form.markAllAsTouched();
      return;
    }

    const fileState = this.fileState();
    if (!fileState) {
      return;
    }

    const productId = this.form.controls.productId.value;
    const scopeId = this.form.controls.scopeId.value;
    const testMode = this.selectedTestMode();
    const testName = normalizeName(this.form.controls.testName.value);
    const testId = (this.form.controls.testId.value ?? '').trim();

    this.uploadStatus.set('uploading');
    this.uploadError.set(null);
    this.uploadResult.set(null);

    try {
      const response = await this.api.uploadSbom({
        productId,
        scopeId,
        testName: testMode === 'new' ? testName : undefined,
        testId: testMode === 'existing' ? testId : undefined,
        file: fileState.file
      });
      this.uploadResult.set(response);
      this.uploadStatus.set('success');
    } catch (error) {
      this.uploadError.set(this.resolveUploadError(error));
      this.uploadStatus.set('error');
    }
  }

  async onFileSelected(event: Event): Promise<void> {
    const input = event.target as HTMLInputElement | null;
    const file = input?.files?.[0];
    if (!file) {
      return;
    }
    input.value = '';
    await this.validateFile(file);
  }

  async onFileDropped(event: DragEvent): Promise<void> {
    event.preventDefault();
    this.isDragging.set(false);
    if (!this.canWrite()) {
      return;
    }
    const file = event.dataTransfer?.files?.[0];
    if (!file) {
      return;
    }
    await this.validateFile(file);
  }

  onDragOver(event: DragEvent): void {
    event.preventDefault();
    if (!this.canWrite()) {
      return;
    }
    this.isDragging.set(true);
  }

  onDragLeave(): void {
    this.isDragging.set(false);
  }

  clearFile(): void {
    this.fileState.set(null);
    this.parseError.set(null);
    this.uploadStatus.set('idle');
    this.uploadError.set(null);
    this.uploadResult.set(null);
  }

  resetForm(): void {
    this.form.reset({ productId: '', scopeId: '', testMode: 'new', testId: '', testName: '' });
    this.store.clearScopes();
    this.store.clearTests();
    this.clearFile();
  }

  private clearUploadState(): void {
    this.uploadStatus.set('idle');
    this.uploadError.set(null);
    this.uploadResult.set(null);
  }

  private resetFileState(): void {
    this.fileState.set(null);
    this.parseError.set(null);
    this.isParsing.set(false);
  }

  private async validateFile(file: File): Promise<void> {
    this.resetFileState();
    this.clearUploadState();
    this.isParsing.set(true);

    const maxBytes = 50 * 1024 * 1024;
    const fileName = file.name ?? '';

    if (file.size === 0) {
      this.parseError.set('Selected file is empty.');
      this.isParsing.set(false);
      return;
    }
    if (file.size > maxBytes) {
      this.parseError.set('File exceeds 50 MB limit for manual ingestion.');
      this.isParsing.set(false);
      return;
    }

    try {
      const text = await file.text();
      JSON.parse(text);
      const validatedFile = new File([text], fileName, {
        type: file.type || 'application/json'
      });
      this.fileState.set({
        file: validatedFile,
        name: fileName,
        size: validatedFile.size,
        sizeLabel: formatBytes(validatedFile.size)
      });
    } catch {
      this.parseError.set('SBOM file is not valid JSON.');
    } finally {
      this.isParsing.set(false);
    }
  }

  private resolveUploadError(error: unknown): string {
    if (error instanceof HttpErrorResponse) {
      const detail = this.extractProblemDetail(error.error);
      if (detail) {
        return detail;
      }
      if (error.status === 400) {
        return 'Validation failed. Check product, scope, test name, and SBOM format.';
      }
      if (error.status === 401 || error.status === 403) {
        return 'You do not have permission to upload SBOMs.';
      }
      if (error.status === 413) {
        return 'SBOM file is too large for manual upload.';
      }
      if (error.status === 415) {
        return 'Unsupported SBOM file type.';
      }
    }
    return 'Upload failed. Please try again.';
  }

  private extractProblemDetail(payload: unknown): string | null {
    if (payload && typeof payload === 'object' && 'detail' in payload) {
      const detail = (payload as { detail?: unknown }).detail;
      if (typeof detail === 'string' && detail.trim().length > 0) {
        return detail;
      }
    }
    return null;
  }
}
