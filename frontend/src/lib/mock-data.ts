import { ScanResult, QRCodeEntry, SecurityEvent, DashboardMetrics } from "./types";

export const mockSafeResult: ScanResult = {
  id: "scan-001",
  url: "https://www.paypal.com/login",
  riskScore: 12,
  verdict: "safe",
  checks: [
    {
      name: "domain_age",
      label: "DOMAIN AGE",
      value: "14 Years",
      status: "pass",
      icon: "clock",
    },
    {
      name: "ssl_cert",
      label: "SSL CERTIFICATE",
      value: "Valid (DigiCert)",
      status: "pass",
      icon: "shield-check",
    },
    {
      name: "typosquatting",
      label: "TYPOSQUATTING",
      value: "Not Detected",
      status: "pass",
      icon: "type",
    },
  ],
  aiSummary:
    "This link is officially associated with PayPal and shows no malicious behavior. Originating from a high-reputation infrastructure with consistent historical uptime.",
  scannedAt: new Date().toISOString(),
};

export const mockDangerResult: ScanResult = {
  id: "scan-002",
  url: "https://paypa1-secure.login-verify.com/auth",
  riskScore: 94,
  verdict: "danger",
  checks: [
    {
      name: "domain_age",
      label: "DOMAIN AGE",
      value: "2 Days",
      status: "fail",
      icon: "clock",
    },
    {
      name: "ssl_cert",
      label: "SSL CERTIFICATE",
      value: "MISMATCHED",
      status: "warn",
      icon: "shield-alert",
    },
    {
      name: "phishing_db",
      label: "KNOWN PHISHING DATABASE",
      value: "MATCH",
      status: "fail",
      icon: "database",
    },
  ],
  aiSummary:
    'This appears to be a fake login page designed to harvest your credentials. DO NOT PROCEED.',
  scannedAt: new Date().toISOString(),
};

export const mockQREntries: QRCodeEntry[] = [
  {
    id: "qr-9921",
    identifier: "#QR-9921",
    targetUrl: "qroulette.io/v/alpha-node",
    protectedUrl: "qroulette.app/go?url=alpha-node",
    scanCount: 142,
    createdAt: "2026-03-27T10:00:00Z",
    status: "active",
  },
  {
    id: "qr-8842",
    identifier: "#QR-8842",
    targetUrl: "external.cdn/track/303",
    protectedUrl: "qroulette.app/go?url=track303",
    scanCount: 89,
    createdAt: "2026-03-26T14:00:00Z",
    status: "flagged",
  },
  {
    id: "qr-7721",
    identifier: "#QR-7721",
    targetUrl: "secure.vault/access/key",
    protectedUrl: "qroulette.app/go?url=vault-key",
    scanCount: 56,
    createdAt: "2026-03-25T09:00:00Z",
    status: "active",
  },
  {
    id: "qr-6610",
    identifier: "#QR-6610",
    targetUrl: "marketing.campaign/2024",
    protectedUrl: "qroulette.app/go?url=campaign24",
    scanCount: 203,
    createdAt: "2026-03-24T16:00:00Z",
    status: "active",
  },
];

export const mockSecurityEvents: SecurityEvent[] = [
  {
    id: "evt-1",
    message: "QR-9921 scanned from IP: 192.168.1.44",
    type: "info",
    timestamp: "JUST NOW",
  },
  {
    id: "evt-2",
    message: "Threat detected: Suspicious redirect intercepted on QR-8842",
    type: "threat",
    timestamp: "12 MINUTES AGO",
  },
  {
    id: "evt-3",
    message: "System manifest updated: New QR Code generated successfully",
    type: "success",
    timestamp: "1 HOUR AGO",
  },
];

export const mockDashboardMetrics: DashboardMetrics = {
  totalScans: 1200,
  scansTrend: 14,
  threatsBlocked: 48,
  threatsSeverity: "CRITICAL",
  activeManifests: 12,
};
