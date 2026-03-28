// QRoulette Backend API client
// Matches contract from backend/models/contracts.py

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

export interface RiskAnalysis {
  risk_score: number;
  risk_level: "safe" | "suspicious" | "danger";
  flagged_safe_browsing: boolean;
  flagged_threat_intel: boolean;
  typosquatting_detected: boolean;
  domain_age_days: number | null;
  redirect_hops: number;
  ssl_valid: boolean;
  ai_summary: string;
}

export interface ScanDecisionResponse {
  allowed: boolean;
  destination: string; // Resolved final URL after redirects.
  reason: string;
  analysis: RiskAnalysis;
}

export interface DashboardSummaryResponse {
  safe: number;
  suspicious: number;
  danger: number;
  total: number;
}

export interface ScanRecord {
  id: string;
  created_at: string;
  scanned_url: string;
  qr_code_id: string | null;
  risk_score: number | null;
  risk_level: "safe" | "suspicious" | "danger" | null;
  flagged_safe_browsing: boolean;
  flagged_threat_intel: boolean;
  typosquatting_detected: boolean;
  domain_age_days: number | null;
  redirect_hops: number | null;
  ssl_valid: boolean | null;
  ai_summary: string | null;
  ip_address: string | null;
  user_agent: string | null;
  country: string | null;
}

export interface HealthResponse {
  status: string;
}

export interface ContractResponse {
  version: string;
  routes: Record<string, string>;
}

/**
 * Calls POST /scan on the FastAPI backend.
 * Returns the full analysis or null if the backend is unreachable.
 */
export async function scanUrl(
  url: string,
  qrCodeId?: string
): Promise<ScanDecisionResponse | null> {
  try {
    const res = await fetch(`${API_BASE}/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url, qr_code_id: qrCodeId ?? null }),
    });
    if (!res.ok) return null;
    return (await res.json()) as ScanDecisionResponse;
  } catch {
    // Backend unreachable — caller falls back to client-side checks
    return null;
  }
}

export async function getDashboardSummary(): Promise<DashboardSummaryResponse | null> {
  try {
    const res = await fetch(`${API_BASE}/dashboard/summary`, {
      method: "GET",
      headers: { "Content-Type": "application/json" },
    });
    if (!res.ok) return null;
    return (await res.json()) as DashboardSummaryResponse;
  } catch {
    return null;
  }
}

export async function getDashboardRecent(limit = 25): Promise<ScanRecord[] | null> {
  try {
    const res = await fetch(`${API_BASE}/dashboard/recent?limit=${limit}`, {
      method: "GET",
      headers: { "Content-Type": "application/json" },
    });
    if (!res.ok) return null;
    return (await res.json()) as ScanRecord[];
  } catch {
    return null;
  }
}

export async function getApiHealth(): Promise<HealthResponse | null> {
  try {
    const res = await fetch(`${API_BASE}/health`, {
      method: "GET",
      headers: { "Content-Type": "application/json" },
    });
    if (!res.ok) return null;
    return (await res.json()) as HealthResponse;
  } catch {
    return null;
  }
}

export async function getApiContract(): Promise<ContractResponse | null> {
  try {
    const res = await fetch(`${API_BASE}/contract`, {
      method: "GET",
      headers: { "Content-Type": "application/json" },
    });
    if (!res.ok) return null;
    return (await res.json()) as ContractResponse;
  } catch {
    return null;
  }
}

export function buildProtectedGoUrl(url: string, qrCodeId?: string): string {
  const params = new URLSearchParams({ url });
  if (qrCodeId) params.set("qr_code_id", qrCodeId);
  return `${API_BASE}/go?${params.toString()}`;
}
