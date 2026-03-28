export interface ScanResult {
  id: string;
  url: string;
  riskScore: number;
  verdict: "safe" | "warning" | "danger";
  checks: SecurityCheck[];
  aiSummary?: string;
  scannedAt: string;
  location?: {
    lat: number;
    lng: number;
  };
}

export interface SecurityCheck {
  name: string;
  label: string;
  value: string;
  status: "pass" | "warn" | "fail";
  icon: string;
}

export interface QRCodeEntry {
  id: string;
  identifier: string;
  targetUrl: string;
  protectedUrl: string;
  scanCount: number;
  createdAt: string;
  status: "active" | "flagged" | "expired";
}

export interface SecurityEvent {
  id: string;
  message: string;
  type: "info" | "threat" | "success";
  timestamp: string;
}

export interface DashboardMetrics {
  totalScans: number;
  scansTrend: number;
  threatsBlocked: number;
  threatsSeverity: string;
  activeManifests: number;
}
