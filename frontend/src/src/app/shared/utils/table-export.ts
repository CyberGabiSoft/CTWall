import { getOwnValue, isSafeObjectKey } from './safe-object';

export type TableExportFormat = 'csv' | 'xlsx' | 'pdf';

export interface TableExportColumn {
  key: string;
  label: string;
}

export type TableExportValueFn<Row> = (row: Row, columnKey: string) => string;

const dangerousCellPrefix = /^[=+\-@]/;

const sanitizeSpreadsheetCell = (raw: string): string => {
  const value = raw ?? '';
  // CSV/Excel injection: if a field starts with an Excel formula prefix (or tab/null),
  // prefix with a single quote to force a literal string.
  // See: DOCS/development/sec_owasp_asvs.md (CSV/Excel injection).
  if (
    value.startsWith('\t') ||
    value.startsWith('\0') ||
    dangerousCellPrefix.test(value)
  ) {
    return `'${value}`;
  }
  return value;
};

const csvEscape = (raw: string): string => {
  const value = sanitizeSpreadsheetCell(raw);
  const needsQuotes = /[",\r\n]/.test(value);
  if (!needsQuotes) {
    return value;
  }
  return `"${value.replaceAll('"', '""')}"`;
};

const toIsoFilename = (date: Date): string => {
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}_${pad(date.getHours())}${pad(date.getMinutes())}${pad(date.getSeconds())}`;
};

const excelColumnRef = (index: number): string => {
  let n = Math.max(1, index);
  let out = '';
  while (n > 0) {
    const mod = (n - 1) % 26;
    out = String.fromCharCode(65 + mod) + out;
    n = Math.floor((n - 1) / 26);
  }
  return out;
};

const downloadBlob = (filename: string, blob: Blob): void => {
  const url = URL.createObjectURL(blob);
  try {
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.rel = 'noopener';
    a.click();
  } finally {
    // Give the browser a moment to start the download.
    window.setTimeout(() => URL.revokeObjectURL(url), 1_000);
  }
};

const defaultValueFor = <Row>(row: Row, key: string): string => {
  if (!row || typeof row !== 'object') {
    return '';
  }
  if (!isSafeObjectKey(key)) {
    return '';
  }
  const value = getOwnValue(row as unknown as Record<string, unknown>, key);
  if (value === null || value === undefined) {
    return '';
  }
  if (typeof value === 'string') {
    return value;
  }
  if (typeof value === 'number' || typeof value === 'boolean') {
    return String(value);
  }
  return '';
};

export const exportTableToCsv = async <Row>(opts: {
  filenameBase: string;
  columns: TableExportColumn[];
  rows: Row[];
  valueForCell?: TableExportValueFn<Row> | null;
}): Promise<void> => {
  const now = new Date();
  const filename = `${opts.filenameBase}_${toIsoFilename(now)}.csv`;
  const headers = opts.columns.map((c) => csvEscape(c.label));
  const valueForCell = opts.valueForCell ?? defaultValueFor<Row>;
  const body = opts.rows.map((row) =>
    opts.columns.map((col) => csvEscape(valueForCell(row, col.key)))
  );
  const csv = [headers.join(','), ...body.map((line) => line.join(','))].join('\r\n');
  downloadBlob(filename, new Blob([csv], { type: 'text/csv;charset=utf-8' }));
};

export const exportTableToXlsx = async <Row>(opts: {
  filenameBase: string;
  sheetName?: string;
  columns: TableExportColumn[];
  rows: Row[];
  valueForCell?: TableExportValueFn<Row> | null;
}): Promise<void> => {
  const now = new Date();
  const filename = `${opts.filenameBase}_${toIsoFilename(now)}.xlsx`;
  const sheetName = (opts.sheetName ?? 'Export').slice(0, 31) || 'Export';
  const valueForCell = opts.valueForCell ?? defaultValueFor<Row>;

  // Lazy-load JSZip to keep initial bundle small.
  const { default: JSZip } = await import('jszip');
  const zip = new JSZip();

  const xmlEscape = (value: string): string =>
    value
      .replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;')
      .replaceAll('>', '&gt;')
      .replaceAll('"', '&quot;')
      .replaceAll("'", '&apos;');

  const allRows = [
    opts.columns.map((c) => c.label),
    ...opts.rows.map((row) => opts.columns.map((c) => sanitizeSpreadsheetCell(valueForCell(row, c.key))))
  ];

  const rowsXml = allRows
    .map((rowValues, rowIndex) => {
      const rowRef = rowIndex + 1;
      const cellsXml = rowValues
        .map((cellValue, colIndex) => {
          const cellRef = `${excelColumnRef(colIndex + 1)}${rowRef}`;
          // Header row gets bold style (style index 1).
          const styleAttr = rowRef === 1 ? ' s="1"' : '';
          return `<c r="${cellRef}" t="inlineStr"${styleAttr}><is><t>${xmlEscape(cellValue)}</t></is></c>`;
        })
        .join('');
      return `<row r="${rowRef}">${cellsXml}</row>`;
    })
    .join('');

  const lastCol = excelColumnRef(Math.max(1, opts.columns.length));
  const lastRow = Math.max(1, allRows.length);
  const dimensionRef = `A1:${lastCol}${lastRow}`;
  const autoFilterXml =
    opts.columns.length > 0 ? `<autoFilter ref="A1:${lastCol}1"/>` : '';

  const worksheetXml =
    `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
    `<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">` +
    `<dimension ref="${dimensionRef}"/>` +
    `<sheetViews><sheetView workbookViewId="0"/></sheetViews>` +
    `<sheetFormatPr defaultRowHeight="15"/>` +
    `${autoFilterXml}` +
    `<sheetData>${rowsXml}</sheetData>` +
    `</worksheet>`;

  const workbookXml =
    `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
    `<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">` +
    `<sheets>` +
    `<sheet name="${xmlEscape(sheetName)}" sheetId="1" r:id="rId1"/>` +
    `</sheets>` +
    `</workbook>`;

  const workbookRelsXml =
    `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
    `<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
    `<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>` +
    `<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>` +
    `</Relationships>`;

  const rootRelsXml =
    `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
    `<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
    `<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>` +
    `</Relationships>`;

  const contentTypesXml =
    `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
    `<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
    `<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>` +
    `<Default Extension="xml" ContentType="application/xml"/>` +
    `<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>` +
    `<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>` +
    `<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>` +
    `</Types>`;

  const stylesXml =
    `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
    `<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">` +
    `<fonts count="2">` +
    `<font><sz val="11"/><name val="Calibri"/></font>` +
    `<font><b/><sz val="11"/><name val="Calibri"/></font>` +
    `</fonts>` +
    `<fills count="2"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill></fills>` +
    `<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>` +
    `<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>` +
    `<cellXfs count="2">` +
    `<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>` +
    `<xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0" applyFont="1"/>` +
    `</cellXfs>` +
    `</styleSheet>`;

  zip.file('[Content_Types].xml', contentTypesXml);
  zip.folder('_rels')?.file('.rels', rootRelsXml);
  const xl = zip.folder('xl');
  xl?.file('workbook.xml', workbookXml);
  xl?.folder('_rels')?.file('workbook.xml.rels', workbookRelsXml);
  xl?.folder('worksheets')?.file('sheet1.xml', worksheetXml);
  xl?.file('styles.xml', stylesXml);

  const buffer = await zip.generateAsync({ type: 'uint8array', compression: 'DEFLATE' });
  const arrayBuffer = new ArrayBuffer(buffer.byteLength);
  new Uint8Array(arrayBuffer).set(buffer);
  downloadBlob(
    filename,
    new Blob([arrayBuffer], {
      type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    })
  );
};

export const exportTableToPdf = async <Row>(opts: {
  filenameBase: string;
  title?: string;
  columns: TableExportColumn[];
  rows: Row[];
  valueForCell?: TableExportValueFn<Row> | null;
}): Promise<void> => {
  // Minimal implementation without a heavy PDF dependency:
  // render a print-friendly HTML view in a hidden iframe and open the print dialog
  // (user can choose "Save as PDF"). This avoids popup blockers.
  const valueForCell = opts.valueForCell ?? defaultValueFor<Row>;
  const title = opts.title ?? opts.filenameBase;
  const now = new Date();

  const escapeHtml = (value: string): string =>
    value
      .replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;')
      .replaceAll('>', '&gt;')
      .replaceAll('"', '&quot;')
      .replaceAll("'", '&#39;');

  const html = `<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${escapeHtml(title)}</title>
  <style>
    body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin: 24px; color: #0f172a; }
    h1 { margin: 0 0 4px; font-size: 18px; }
    .meta { margin: 0 0 16px; color: #475569; font-size: 12px; }
    table { width: 100%; border-collapse: collapse; font-size: 12px; }
    th, td { border: 1px solid #d9e3ef; padding: 6px 8px; text-align: left; vertical-align: top; }
    th { background: #f1f6fd; color: #334155; }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, Liberation Mono, Courier New, monospace; }
    @media print { body { margin: 12mm; } }
  </style>
</head>
<body>
  <h1>${escapeHtml(title)}</h1>
  <p class="meta">Generated: ${escapeHtml(now.toISOString())} | Rows: ${opts.rows.length}</p>
  <table>
    <thead>
      <tr>${opts.columns.map((c) => `<th>${escapeHtml(c.label)}</th>`).join('')}</tr>
    </thead>
    <tbody>
      ${opts.rows
        .map(
          (row) =>
            `<tr>${opts.columns
              .map((c) => `<td>${escapeHtml(valueForCell(row, c.key) ?? '')}</td>`)
              .join('')}</tr>`
        )
        .join('')}
    </tbody>
  </table>
</body>
</html>`;

  if (!document.body) {
    throw new Error('Failed to export PDF (document not ready).');
  }

  const iframe = document.createElement('iframe');
  iframe.setAttribute('aria-hidden', 'true');
  // Keep it off-screen but in the DOM so printing works reliably.
  iframe.style.position = 'fixed';
  iframe.style.right = '-9999px';
  iframe.style.bottom = '0';
  iframe.style.width = '1px';
  iframe.style.height = '1px';
  iframe.style.border = '0';
  iframe.style.opacity = '0';
  iframe.style.pointerEvents = 'none';

  let cleaned = false;
  const cleanup = () => {
    if (cleaned) {
      return;
    }
    cleaned = true;
    iframe.remove();
  };

  iframe.onload = () => {
    const frameWindow = iframe.contentWindow;
    if (!frameWindow) {
      cleanup();
      return;
    }
    const frameCleanup = () => cleanup();
    frameWindow.addEventListener('afterprint', frameCleanup, { once: true });
    window.setTimeout(cleanup, 4_000);
    window.setTimeout(() => {
      try {
        // Some browsers require focus before printing.
        frameWindow.focus();
        frameWindow.print();
      } catch {
        cleanup();
      }
    }, 30);
  };

  document.body.appendChild(iframe);
  try {
    iframe.srcdoc = html;
  } catch {
    // Legacy fallback for old/embedded browsers where srcdoc may fail.
    const frameDoc = iframe.contentDocument;
    if (!frameDoc) {
      cleanup();
      return;
    }
    frameDoc.open();
    frameDoc.write(html);
    frameDoc.close();
    window.setTimeout(() => {
      const frameWindow = iframe.contentWindow;
      if (!frameWindow) {
        cleanup();
        return;
      }
      frameWindow.addEventListener('afterprint', cleanup, { once: true });
      window.setTimeout(cleanup, 4_000);
      try {
        frameWindow.focus();
        frameWindow.print();
      } catch {
        cleanup();
      }
    }, 50);
  }
};
