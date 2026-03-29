
import {
  ChangeDetectionStrategy,
  Component,
  computed,
  ElementRef,
  input,
  output,
  signal,
  viewChild,
} from '@angular/core';

export interface PieChartSlice {
  id?: string;
  label: string;
  value: number;
  color: string;
  tooltipValue?: string;
}

interface PieChartGeometry {
  size: number;
  center: number;
  outerRadius: number;
  innerRadius: number;
}

interface PieChartSegment extends PieChartSlice {
  sourceIndex: number;
  sharePercent: number;
  startDeg: number;
  endDeg: number;
  midDeg: number;
  path: string;
  centroidX: number;
  centroidY: number;
}

interface PieChartTooltip {
  label: string;
  valueText: string;
  shareText: string;
  leftPx: number;
  topPx: number;
}

interface PieChartPointerAnchor {
  sourceIndex: number;
  clientX: number;
  clientY: number;
}

@Component({
  selector: 'app-pie-chart',
  imports: [],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './pie-chart.component.html',
  styleUrl: './pie-chart.component.scss',
})
export class PieChartComponent {
  private readonly integerFormatter = new Intl.NumberFormat();
  private readonly decimalFormatter = new Intl.NumberFormat(undefined, {
    minimumFractionDigits: 0,
    maximumFractionDigits: 2,
  });
  private readonly percentFormatter = new Intl.NumberFormat(undefined, {
    minimumFractionDigits: 0,
    maximumFractionDigits: 1,
  });

  readonly slices = input<ReadonlyArray<PieChartSlice>>([]);
  readonly total = input<number | null>(null);
  readonly size = input(120);
  readonly innerCutout = input(0.64);
  readonly chartLabel = input('Pie chart');
  readonly valueLabel = input('Value');
  readonly showTooltip = input(true);
  readonly showCounter = input(true);
  readonly counterLabel = input('Items');
  readonly totalItems = input<number | null>(null);

  readonly sliceSelected = output<number | null>();
  readonly sliceHovered = output<number | null>();

  private readonly chartRoot = viewChild<ElementRef<HTMLDivElement>>('chartRoot');
  private readonly selectedSourceIndex = signal<number | null>(null);
  private readonly hoveredSourceIndex = signal<number | null>(null);
  private readonly hoveredPointerAnchor = signal<PieChartPointerAnchor | null>(null);

  readonly geometry = computed<PieChartGeometry>(() => {
    const size = Math.max(48, this.size());
    const center = size / 2;
    const outerRadius = Math.max(12, center - 2);
    const normalizedCutout = Math.max(0.2, Math.min(0.9, this.innerCutout()));
    const innerRadius = Math.max(2, outerRadius * normalizedCutout);
    return {
      size,
      center,
      outerRadius,
      innerRadius,
    };
  });

  readonly segments = computed<PieChartSegment[]>(() => {
    const slices = this.slices();
    const normalized = slices
      .map((slice, sourceIndex) => ({ ...slice, sourceIndex, value: Math.max(0, slice.value) }))
      .filter((slice) => slice.value > 0);
    if (!normalized.length) {
      return [];
    }

    const geometry = this.geometry();
    const inputTotal = this.total();
    const total =
      typeof inputTotal === 'number' && Number.isFinite(inputTotal) && inputTotal > 0
        ? inputTotal
        : normalized.reduce((sum, slice) => sum + slice.value, 0);
    if (total <= 0) {
      return [];
    }

    let offset = 0;
    return normalized.map((slice) => {
      const span = (slice.value / total) * 360;
      const startDeg = offset;
      const endDeg = Math.min(360, startDeg + span);
      const midDeg = startDeg + (endDeg - startDeg) / 2;
      offset = endDeg;

      const path = this.donutSlicePath(geometry, startDeg, endDeg);
      const centroid = this.polarToCartesian(
        geometry.center,
        geometry.center,
        (geometry.outerRadius + geometry.innerRadius) / 2,
        midDeg,
      );

      return {
        ...slice,
        sharePercent: (slice.value / total) * 100,
        startDeg,
        endDeg,
        midDeg,
        path,
        centroidX: centroid.x,
        centroidY: centroid.y,
      };
    });
  });

  readonly activeSourceIndex = computed<number | null>(() => {
    const hovered = this.hoveredSourceIndex();
    if (this.findSegmentBySourceIndex(hovered)) {
      return hovered;
    }
    const selected = this.selectedSourceIndex();
    if (this.findSegmentBySourceIndex(selected)) {
      return selected;
    }
    return null;
  });

  readonly tooltip = computed<PieChartTooltip | null>(() => {
    if (!this.showTooltip()) {
      return null;
    }
    const activeSourceIndex = this.activeSourceIndex();
    const segment = this.findSegmentBySourceIndex(activeSourceIndex);
    if (!segment) {
      return null;
    }
    const geometry = this.geometry();
    const chartRect = this.chartRoot()?.nativeElement.getBoundingClientRect();
    if (!chartRect) {
      return null;
    }
    const pointerAnchor = this.hoveredPointerAnchor();
    const hasPointerAnchor =
      pointerAnchor !== null && activeSourceIndex !== null && pointerAnchor.sourceIndex === activeSourceIndex;
    let anchorX = hasPointerAnchor
      ? pointerAnchor.clientX
      : chartRect.left + (segment.centroidX / geometry.size) * chartRect.width;
    let anchorY = hasPointerAnchor
      ? pointerAnchor.clientY
      : chartRect.top + (segment.centroidY / geometry.size) * chartRect.height;
    const viewportHeight = Math.max(240, window.innerHeight || 0);
    anchorY = this.clamp(anchorY, 56, viewportHeight - 20);
    return {
      label: segment.label,
      valueText: segment.tooltipValue ?? this.formatValue(segment.value),
      shareText: `${this.percentFormatter.format(segment.sharePercent)}%`,
      leftPx: anchorX,
      topPx: anchorY,
    };
  });

  readonly displayedItemsCount = computed(() => {
    const count = this.slices().length;
    if (!Number.isFinite(count) || count < 0) {
      return 0;
    }
    return Math.trunc(count);
  });

  readonly totalItemsCount = computed(() => {
    const fallback = this.displayedItemsCount();
    const inputTotal = this.totalItems();
    if (typeof inputTotal !== 'number' || !Number.isFinite(inputTotal) || inputTotal < 0) {
      return fallback;
    }
    return Math.max(fallback, Math.trunc(inputTotal));
  });

  onSliceEnter(sourceIndex: number): void {
    this.hoveredSourceIndex.set(sourceIndex);
    this.sliceHovered.emit(sourceIndex);
  }

  onSliceLeave(): void {
    this.hoveredSourceIndex.set(null);
    this.hoveredPointerAnchor.set(null);
    this.sliceHovered.emit(null);
  }

  onSliceMove(event: MouseEvent, sourceIndex: number): void {
    const target = event.currentTarget;
    if (!(target instanceof SVGPathElement) || !target.ownerSVGElement) {
      return;
    }
    const rect = target.ownerSVGElement.getBoundingClientRect();
    if (rect.width <= 0 || rect.height <= 0) {
      return;
    }
    this.hoveredPointerAnchor.set({
      sourceIndex,
      clientX: event.clientX,
      clientY: event.clientY,
    });
  }

  onSliceClick(sourceIndex: number): void {
    const nextIndex = this.selectedSourceIndex() === sourceIndex ? null : sourceIndex;
    this.selectedSourceIndex.set(nextIndex);
    this.sliceSelected.emit(nextIndex);
  }

  onSliceKeydown(event: KeyboardEvent, sourceIndex: number): void {
    if (event.key !== 'Enter' && event.key !== ' ') {
      return;
    }
    event.preventDefault();
    this.onSliceClick(sourceIndex);
  }

  sliceAriaLabel(segment: PieChartSegment): string {
    return `${segment.label}. ${this.valueLabel()}: ${
      segment.tooltipValue ?? this.formatValue(segment.value)
    }. Share: ${this.percentFormatter.format(segment.sharePercent)}%.`;
  }

  isSliceActive(sourceIndex: number): boolean {
    return this.activeSourceIndex() === sourceIndex;
  }

  private findSegmentBySourceIndex(sourceIndex: number | null): PieChartSegment | null {
    if (sourceIndex === null) {
      return null;
    }
    return this.segments().find((segment) => segment.sourceIndex === sourceIndex) ?? null;
  }

  private formatValue(value: number): string {
    if (Number.isInteger(value)) {
      return this.integerFormatter.format(value);
    }
    return this.decimalFormatter.format(value);
  }

  private donutSlicePath(geometry: PieChartGeometry, startDeg: number, endDeg: number): string {
    const clampedSpan = Math.max(0, Math.min(360, endDeg - startDeg));
    if (clampedSpan >= 359.999) {
      return this.fullDonutPath(geometry);
    }

    const start = this.polarToCartesian(
      geometry.center,
      geometry.center,
      geometry.outerRadius,
      startDeg,
    );
    const end = this.polarToCartesian(geometry.center, geometry.center, geometry.outerRadius, endDeg);
    const innerStart = this.polarToCartesian(
      geometry.center,
      geometry.center,
      geometry.innerRadius,
      startDeg,
    );
    const innerEnd = this.polarToCartesian(
      geometry.center,
      geometry.center,
      geometry.innerRadius,
      endDeg,
    );
    const largeArc = clampedSpan > 180 ? 1 : 0;

    return [
      `M ${start.x} ${start.y}`,
      `A ${geometry.outerRadius} ${geometry.outerRadius} 0 ${largeArc} 1 ${end.x} ${end.y}`,
      `L ${innerEnd.x} ${innerEnd.y}`,
      `A ${geometry.innerRadius} ${geometry.innerRadius} 0 ${largeArc} 0 ${innerStart.x} ${innerStart.y}`,
      'Z',
    ].join(' ');
  }

  private fullDonutPath(geometry: PieChartGeometry): string {
    const cx = geometry.center;
    const cy = geometry.center;
    const outer = geometry.outerRadius;
    const inner = geometry.innerRadius;

    return [
      `M ${cx} ${cy - outer}`,
      `A ${outer} ${outer} 0 1 1 ${cx} ${cy + outer}`,
      `A ${outer} ${outer} 0 1 1 ${cx} ${cy - outer}`,
      `L ${cx} ${cy - inner}`,
      `A ${inner} ${inner} 0 1 0 ${cx} ${cy + inner}`,
      `A ${inner} ${inner} 0 1 0 ${cx} ${cy - inner}`,
      'Z',
    ].join(' ');
  }

  private polarToCartesian(cx: number, cy: number, radius: number, angleDeg: number): { x: number; y: number } {
    const radians = ((angleDeg - 90) * Math.PI) / 180;
    const x = cx + radius * Math.cos(radians);
    const y = cy + radius * Math.sin(radians);
    return { x, y };
  }

  private clamp(value: number, min: number, max: number): number {
    return Math.max(min, Math.min(max, value));
  }
}
