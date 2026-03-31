"use client";

import { useState, useEffect, Suspense } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  ShieldCheck,
  ShieldAlert,
  Clock,
  AlertTriangle,
  Database,
  ChevronDown,
  ArrowRight,
  ArrowLeft,
  X,
  CheckCircle2,
  Type,
  Link2,
  Globe,
} from "lucide-react";
import { useSearchParams, useRouter } from "next/navigation";
import { mockSafeResult, mockDangerResult } from "@/lib/mock-data";
import type { ScanAnalyzeResponse } from "@/lib/api";
import type { ScanResult, SecurityCheck } from "@/lib/types";

/**
 * Convert the real backend API response into the ScanResult shape
 * used by the result UI.
 */
function apiResponseToScanResult(api: ScanAnalyzeResponse): ScanResult {
  const risk = api.risk;
  const verdict: "safe" | "warning" | "danger" =
    risk.verdict === "dangerous" ? "danger" : risk.verdict === "suspicious" ? "warning" : "safe";

  const checks: SecurityCheck[] = [];

  // Domain age check
  if (risk.domain_age_days !== null) {
    const years = Math.floor(risk.domain_age_days / 365);
    const ageLabel = years >= 1 ? `${years} Year${years > 1 ? "s" : ""}` : `${risk.domain_age_days} Days`;
    checks.push({
      name: "domain_age",
      label: "DOMAIN AGE",
      value: ageLabel,
      status: risk.domain_age_days < 90 ? "fail" : risk.domain_age_days < 365 ? "warn" : "pass",
      icon: "clock",
    });
  }

  // SSL certificate check
  checks.push({
    name: "ssl_cert",
    label: "SSL CERTIFICATE",
    value: risk.ssl_valid ? "Valid" : "INVALID",
    status: risk.ssl_valid ? "pass" : "fail",
    icon: risk.ssl_valid ? "shield-check" : "shield-alert",
  });

  // Typosquatting check
  checks.push({
    name: "typosquatting",
    label: "TYPOSQUATTING",
    value: risk.typosquatting_detected ? "DETECTED" : "Not Detected",
    status: risk.typosquatting_detected ? "fail" : "pass",
    icon: "type",
  });

  // Safe Browsing / phishing DB check
  if (risk.flagged_safe_browsing) {
    checks.push({
      name: "phishing_db",
      label: "KNOWN PHISHING DATABASE",
      value: "MATCH",
      status: "fail",
      icon: "database",
    });
  }

  // Threat intel check
  if (risk.flagged_threat_intel) {
    checks.push({
      name: "threat_intel",
      label: "THREAT INTELLIGENCE",
      value: "FLAGGED",
      status: "fail",
      icon: "database",
    });
  }

  // Redirect hops check
  if (risk.redirect_hops > 0) {
    checks.push({
      name: "redirects",
      label: "REDIRECT CHAIN",
      value: `${risk.redirect_hops} Hop${risk.redirect_hops > 1 ? "s" : ""}`,
      status: risk.redirect_hops >= 3 ? "warn" : "pass",
      icon: "link",
    });
  }

  return {
    id: api.scan_id,
    url: api.analysis.normalized_url,
    riskScore: risk.score,
    verdict,
    checks,
    aiSummary: api.explanation || risk.summary,
    scannedAt: new Date().toISOString(),
  };
}

function ResultContent() {
  const searchParams = useSearchParams();
  const router = useRouter();
  const verdictParam = searchParams.get("verdict") || "safe";
  const [showAiSummary, setShowAiSummary] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);

  useEffect(() => {
    const stored = sessionStorage.getItem("qr_scan_result");
    if (stored) {
      try {
        const apiResponse: ScanAnalyzeResponse = JSON.parse(stored);
        setResult(apiResponseToScanResult(apiResponse));
      } catch {
        // Corrupt storage — fall back to mock
        setResult(verdictParam === "safe" ? mockSafeResult : mockDangerResult);
      }
    } else {
      // No real data — use mock
      setResult(verdictParam === "safe" ? mockSafeResult : mockDangerResult);
    }
  }, [verdictParam]);

  if (!result) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="w-8 h-8 border-2 border-accent-green border-t-transparent rounded-full animate-spin" />
      </div>
    );
  }

  const isSafe = result.verdict === "safe";
  const isWarning = result.verdict === "warning";

  const scoreColor = isSafe ? "text-accent-green" : isWarning ? "text-accent-yellow" : "text-accent-red";
  const borderColor = isSafe
    ? "border-accent-green/30"
    : isWarning
      ? "border-accent-yellow/30"
      : "border-accent-red/30";
  const bgGlow = isSafe
    ? "from-accent-green/5"
    : isWarning
      ? "from-accent-yellow/5"
      : "from-accent-red/5";

  const checkIcon = (status: string) => {
    switch (status) {
      case "pass":
        return <CheckCircle2 className="w-5 h-5 text-accent-green" />;
      case "warn":
        return <AlertTriangle className="w-5 h-5 text-accent-yellow" />;
      case "fail":
        return <X className="w-5 h-5 text-accent-red" />;
      default:
        return null;
    }
  };

  const checkNameIcon = (name: string) => {
    switch (name) {
      case "domain_age":
        return <Clock className="w-5 h-5 text-muted" />;
      case "ssl_cert":
        return isSafe ? (
          <ShieldCheck className="w-5 h-5 text-muted" />
        ) : (
          <ShieldAlert className="w-5 h-5 text-muted" />
        );
      case "typosquatting":
        return <Type className="w-5 h-5 text-muted" />;
      case "phishing_db":
      case "threat_intel":
        return <Database className="w-5 h-5 text-muted" />;
      case "redirects":
        return <Link2 className="w-5 h-5 text-muted" />;
      default:
        return <Globe className="w-5 h-5 text-muted" />;
    }
  };

  const verdictLabel = isSafe
    ? "Verified Safe"
    : isWarning
      ? "Suspicious"
      : "Threat Detected";

  return (
    <div className="px-5 py-6 max-w-lg mx-auto space-y-6">
      {/* Verdict Badge */}
      {!isSafe && (
        <motion.div
          initial={{ opacity: 0, scale: 0.9 }}
          animate={{ opacity: 1, scale: 1 }}
          className="flex justify-center"
        >
          <div
            className={`px-4 py-2 ${
              isWarning
                ? "bg-accent-yellow/10 border-accent-yellow/40"
                : "bg-accent-red/10 border-accent-red/40"
            } border rounded-full`}
          >
            <span
              className={`text-xs font-bold tracking-[0.2em] uppercase flex items-center gap-2 ${
                isWarning ? "text-accent-yellow" : "text-accent-red"
              }`}
            >
              <AlertTriangle className="w-3 h-3" />
              {verdictLabel}
            </span>
          </div>
        </motion.div>
      )}

      {/* Risk Score */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className={`text-center py-6 bg-gradient-to-b ${bgGlow} to-transparent rounded-lg`}
      >
        <div className="flex items-baseline justify-center">
          <span className={`text-7xl font-black ${scoreColor}`}>
            {result.riskScore}
          </span>
          <span className="text-2xl text-muted font-light">/100</span>
        </div>
        {isSafe ? (
          <div className="flex items-center justify-center gap-3 mt-3">
            <span className="px-3 py-1 bg-accent-green/10 border border-accent-green/30 rounded-full text-xs font-bold tracking-wider text-accent-green uppercase flex items-center gap-1.5">
              <ShieldCheck className="w-3 h-3" />
              Verified Safe
            </span>
            <span className="text-xs text-muted tracking-wider uppercase">
              Risk Index Analysis
            </span>
          </div>
        ) : (
          <p className={`text-xs tracking-[0.2em] uppercase mt-2 ${isWarning ? "text-accent-yellow" : "text-muted"}`}>
            {isWarning ? "Caution Advised" : "Critical Risk Score"}
          </p>
        )}
      </motion.div>

      {/* Scanned URL */}
      <div className="bg-card border border-card-border rounded-lg px-4 py-2.5">
        <p className="text-[10px] text-muted tracking-widest uppercase mb-1">TARGET URL</p>
        <p className="text-xs font-mono text-foreground truncate">{result.url}</p>
      </div>

      {/* AI Summary - Expandable */}
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.2 }}
        className={`bg-card border ${borderColor} rounded-lg overflow-hidden`}
      >
        <button
          onClick={() => setShowAiSummary(!showAiSummary)}
          className="w-full px-4 py-3 flex items-center justify-between hover:bg-surface/50 transition-colors"
        >
          <div className="flex items-center gap-2">
            {isSafe ? (
              <ShieldCheck className="w-4 h-4 text-accent-green" />
            ) : (
              <ShieldAlert className={`w-4 h-4 ${isWarning ? "text-accent-yellow" : "text-accent-red"}`} />
            )}
            <span className="text-xs tracking-[0.2em] uppercase">
              {isSafe ? "AI Intelligence Summary" : "AI Threat Analysis"}
            </span>
          </div>
          <motion.div
            animate={{ rotate: showAiSummary ? 180 : 0 }}
            transition={{ duration: 0.2 }}
          >
            <ChevronDown className="w-4 h-4 text-muted" />
          </motion.div>
        </button>
        <AnimatePresence>
          {showAiSummary && (
            <motion.div
              initial={{ height: 0, opacity: 0 }}
              animate={{ height: "auto", opacity: 1 }}
              exit={{ height: 0, opacity: 0 }}
              transition={{ duration: 0.3 }}
              className="overflow-hidden"
            >
              <div className="px-4 pb-4 border-t border-card-border pt-3">
                <p className="text-sm leading-relaxed">
                  {result.aiSummary}
                  {!isSafe && !isWarning && (
                    <span className="text-accent-red font-bold">
                      {" "}
                      DO NOT PROCEED.
                    </span>
                  )}
                </p>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </motion.div>

      {/* Security Checks */}
      <div className="space-y-3">
        {!isSafe && (
          <p className="text-xs text-muted tracking-[0.2em] uppercase">
            Vulnerability Breakdown
          </p>
        )}
        {result.checks.map((check, i) => (
          <motion.div
            key={check.name}
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: 0.3 + i * 0.1 }}
            className={`flex items-center justify-between p-4 bg-card border ${
              check.status === "pass"
                ? "border-accent-green/20"
                : check.status === "warn"
                ? "border-accent-yellow/20"
                : "border-accent-red/20"
            } rounded-lg`}
          >
            <div className="flex items-center gap-3">
              {checkNameIcon(check.name)}
              <div>
                <p className="text-[10px] text-muted tracking-widest uppercase">
                  {check.label}
                </p>
                <p className="text-base font-bold">{check.value}</p>
              </div>
            </div>
            {checkIcon(check.status)}
          </motion.div>
        ))}
      </div>

      {/* Network visualization placeholder */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.6 }}
        className="relative h-24 bg-card border border-card-border rounded-lg overflow-hidden"
      >
        <div
          className="absolute inset-0 opacity-20"
          style={{
            backgroundImage:
              "radial-gradient(circle at 30% 50%, rgba(0,255,136,0.3), transparent 50%), radial-gradient(circle at 70% 50%, rgba(59,130,246,0.2), transparent 50%)",
          }}
        />
        <div className="absolute bottom-2 left-3 text-[10px] text-muted tracking-widest">
          NODE CLUSTER TRAFFIC
        </div>
        <div className="absolute bottom-2 right-3 text-[10px] text-accent-green tracking-widest">
          LATENCY: 14ms
        </div>
      </motion.div>

      {/* Action Button */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.7 }}
      >
        {isSafe ? (
          <button
            onClick={() => window.open(result.url, "_blank")}
            className="w-full py-4 bg-accent-green text-background font-bold text-sm tracking-[0.2em] uppercase rounded-lg flex items-center justify-center gap-2 hover:bg-accent-green/90 transition-colors"
          >
            Proceed to Site
            <ArrowRight className="w-4 h-4" />
          </button>
        ) : (
          <div className="space-y-3">
            <div className={`py-3 border ${isWarning ? "border-accent-yellow/30" : "border-accent-red/30"} rounded-lg text-center`}>
              <p className={`text-[10px] tracking-[0.2em] uppercase font-semibold ${isWarning ? "text-accent-yellow" : "text-accent-red"}`}>
                {isWarning
                  ? "Proceed with Caution — Suspicious Signals Detected"
                  : "Navigation Restricted by Security Policy"}
              </p>
            </div>
            <button
              onClick={() => router.push("/")}
              className="w-full py-4 bg-card border border-card-border text-foreground font-bold text-sm tracking-[0.2em] uppercase rounded-lg flex items-center justify-center gap-2 hover:border-foreground/30 transition-colors"
            >
              <ArrowLeft className="w-4 h-4" />
              Return to Safety
            </button>
          </div>
        )}
      </motion.div>
    </div>
  );
}

export default function ResultPage() {
  return (
    <Suspense
      fallback={
        <div className="flex items-center justify-center h-64">
          <div className="w-8 h-8 border-2 border-accent-green border-t-transparent rounded-full animate-spin" />
        </div>
      }
    >
      <ResultContent />
    </Suspense>
  );
}
