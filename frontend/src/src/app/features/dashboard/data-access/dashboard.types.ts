export type DashboardRange = '24h' | '7d' | '30d' | '90d';
export type DashboardScope = 'project';

export interface DashboardTopItem {
  name: string;
  value: number;
}

export interface DashboardPackageType {
  packageType: string;
  count: number;
  percentage: number;
}

export interface DashboardLicense {
  license: string;
  count: number;
  percentage: number;
}

export interface DashboardMalwarePackage {
  purl: string;
  occurrences: number;
  lastSeenAt?: string | null;
}

export interface DashboardIngestActivity {
  id: string;
  timestamp: string;
  status: string;
  stage: string;
  componentsImported: number;
  productId?: string | null;
  scopeId?: string | null;
  testId?: string | null;
  productName: string;
  scopeName: string;
  testName: string;
  errorMessage?: string;
}

export interface DashboardIngestBucket {
  bucketStart: string;
  imports: number;
  componentsImported: number;
}

export interface DashboardKpis {
  malwareActive: number;
  affectedTests: number;
  oldestPackageScanAt?: string | null;
  lastAnalysisAt?: string | null;
  lastMalwareSummaryComputedAt?: string | null;
  ingestImports: number;
  ingestComponents: number;
  overridesActive: number;
}

export interface DashboardVerdictDistribution {
  malware: number;
  clean: number;
  unknown: number;
}

export interface DashboardOverviewData {
  generatedAt: string;
  rangeStart: string;
  rangeEnd: string;
  projectCount: number;
  topN: number;
  kpis: DashboardKpis;
  verdictDistribution: DashboardVerdictDistribution;
  topProductsTotal: number;
  topScopesTotal: number;
  topPackageTypesTotal: number;
  topLicensesTotal: number;
  topProducts: DashboardTopItem[];
  topScopes: DashboardTopItem[];
  topPackageTypes: DashboardPackageType[];
  topLicenses: DashboardLicense[];
  topMalwarePackages: DashboardMalwarePackage[];
  recentIngest: DashboardIngestActivity[];
  ingestTrend: DashboardIngestBucket[];
}

export interface DashboardOverviewResponse {
  scope: DashboardScope;
  projectId: string;
  range: DashboardRange;
  data: DashboardOverviewData;
}
