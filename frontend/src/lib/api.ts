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
  destination: string;
  reason: string;
  analysis: RiskAnalysis;
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
