// QRoulette Backend API client
// Matches the FastAPI backend at /api/scan/analyze

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

// --- Backend response types (mirrors Python schemas) ---

export interface ScoreBreakdownItem {
  source_type: string;
  label: string;
  score: number;
  weight: number;
  rationale: string;
}

export interface RiskResult {
  score: number;
  verdict: "safe" | "suspicious" | "dangerous";
  summary: string;
  score_breakdown: ScoreBreakdownItem[];
  override_reasons: string[];
  flagged_safe_browsing: boolean;
  flagged_threat_intel: boolean;
  typosquatting_detected: boolean;
  domain_age_days: number | null;
  redirect_hops: number;
  ssl_valid: boolean;
}

export interface UrlAnalysisResult {
  input_url: string;
  normalized_url: string;
  normalized_scheme: string;
  normalized_hostname: string;
  normalized_path: string;
  registrable_domain: string;
  subdomain: string;
  has_non_ascii_domain: boolean;
  has_punycode_domain: boolean;
  has_homoglyph_lookalike: boolean;
  has_suspicious_char_substitution: boolean;
  has_suspicious_file_extension: boolean;
  suspicious_file_extension: string | null;
  reasons: string[];
  redirect_result: {
    input_url: string;
    final_url: string;
    chain: string[];
    hop_count: number;
    has_cross_domain_redirect: boolean;
  } | null;
}

export interface ScanAnalyzeResponse {
  scan_id: string;
  analysis: UrlAnalysisResult;
  risk: RiskResult;
  explanation: string | null;
  persisted: boolean;
  message: string;
}

interface ApiResponse<T> {
  success: boolean;
  data: T;
  error: null | { code: string; message: string };
}

/**
 * Calls POST /api/scan/analyze on the FastAPI backend.
 * Returns the scan analysis or null if the backend is unreachable.
 */
export async function scanUrl(
  url: string
): Promise<ScanAnalyzeResponse | null> {
  try {
    // Ensure URL has a scheme for the backend's HttpUrl validator
    const normalizedUrl = /^https?:\/\//i.test(url) ? url : `https://${url}`;

    const res = await fetch(`${API_BASE}/api/scan/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: normalizedUrl }),
    });
    if (!res.ok) return null;

    const json = (await res.json()) as ApiResponse<ScanAnalyzeResponse>;
    if (!json.success || !json.data) return null;

    return json.data;
  } catch {
    // Backend unreachable — caller falls back to client-side checks
    return null;
  }
}
