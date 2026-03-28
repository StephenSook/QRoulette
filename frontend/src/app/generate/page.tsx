"use client";

import { useState, useRef } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Download,
  Printer,
  Copy,
  ShieldCheck,
  Crosshair,
  AlertTriangle,
  ShieldAlert,
  X,
  CheckCircle,
} from "lucide-react";
import QRCode from "qrcode";
import { buildProtectedGoUrl, scanUrl, type ScanDecisionResponse } from "@/lib/api";

interface UrlCheckResult {
  score: number;
  verdict: "safe" | "warning" | "danger";
  flags: { label: string; severity: "low" | "medium" | "high"; detail: string }[];
  reason: string;
}

export default function GeneratePage() {
  const [url, setUrl] = useState("");
  const [qrDataUrl, setQrDataUrl] = useState<string | null>(null);
  const [protectedSlug, setProtectedSlug] = useState<string | null>(null);
  const [isGenerating, setIsGenerating] = useState(false);
  const [copied, setCopied] = useState(false);
  const [checkResult, setCheckResult] = useState<UrlCheckResult | null>(null);
  const [apiError, setApiError] = useState<string | null>(null);
  const [isChecking, setIsChecking] = useState(false);
  const [overrideWarning, setOverrideWarning] = useState(false);
  const canvasRef = useRef<HTMLCanvasElement>(null);

  const generateSlug = () => {
    const chars = "abcdefghijklmnopqrstuvwxyz0123456789";
    const parts = [4, 4, 4].map(() =>
      Array.from({ length: 4 }, () => chars[Math.floor(Math.random() * chars.length)]).join("")
    );
    return parts.join("-");
  };

  const doGenerate = async () => {
    setIsGenerating(true);
    const slug = generateSlug();
    const protectedUrl = buildProtectedGoUrl(url.trim(), slug);
    setProtectedSlug(protectedUrl);

    try {
      const dataUrl = await QRCode.toDataURL(protectedUrl, {
        width: 300,
        margin: 2,
        color: { dark: "#000000", light: "#ffffff" },
        errorCorrectionLevel: "H",
      });
      setQrDataUrl(dataUrl);
    } catch {
      console.error("QR generation failed");
    } finally {
      setIsGenerating(false);
    }
  };

  const handleGenerate = async () => {
    if (!url.trim()) return;

    // Analyze via backend contract first.
    setIsChecking(true);
    setCheckResult(null);
    setApiError(null);
    setOverrideWarning(false);
    setQrDataUrl(null);
    setProtectedSlug(null);

    const trimmedUrl = url.trim();
    const apiResult = await scanUrl(trimmedUrl);
    if (!apiResult) {
      setApiError("Backend scan API unavailable. Please verify API is running.");
      setIsChecking(false);
      return;
    }

    const merged = mapFromApi(apiResult);
    setCheckResult(merged);
    setIsChecking(false);

    // If safe, generate immediately
    if (merged.verdict === "safe") {
      await doGenerate();
    }
    // If warning/danger, show the result and let user decide
  };

  function mapFromApi(api: ScanDecisionResponse): UrlCheckResult {
    const flags: UrlCheckResult["flags"] = [];
    const a = api.analysis;
    if (a.flagged_safe_browsing) {
      flags.push({
        label: "SAFE BROWSING HIT",
        severity: "high",
        detail: "Google Safe Browsing flagged this URL as a known threat.",
      });
    }
    if (a.flagged_threat_intel || (a.domain_age_days !== null && a.domain_age_days < 30)) {
      flags.push({
        label: "THREAT INTEL SIGNAL",
        severity: "high",
        detail: "Threat intelligence heuristics flagged this domain as risky.",
      });
    }
    if (a.typosquatting_detected) {
      flags.push({
        label: "TYPOSQUATTING",
        severity: "high",
        detail: "Backend analysis detected domain typosquatting patterns.",
      });
    }
    if (a.domain_age_days !== null && a.domain_age_days < 30) {
      flags.push({
        label: "NEW DOMAIN",
        severity: "medium",
        detail: `Domain registered ${a.domain_age_days} day${a.domain_age_days !== 1 ? "s" : ""} ago — newly created domains are high-risk.`,
      });
    }
    if (a.redirect_hops > 2) {
      flags.push({
        label: "REDIRECT CHAIN",
        severity: "medium",
        detail: `URL follows ${a.redirect_hops} redirects — long chains can obscure the final destination.`,
      });
    }
    if (!a.ssl_valid && !flags.some((f) => f.label === "NO ENCRYPTION")) {
      flags.push({
        label: "NO ENCRYPTION",
        severity: "low",
        detail: "Destination does not use HTTPS.",
      });
    }
    if (flags.length === 0) {
      flags.push({
        label: "NO CRITICAL FLAGS",
        severity: "low",
        detail: "No high-risk signals were returned by backend analysis.",
      });
    }

    return {
      score: a.risk_score,
      verdict: a.risk_level === "danger" ? "danger" : a.risk_level === "suspicious" ? "warning" : "safe",
      flags,
      reason: api.reason,
    };
  }

  const handleOverrideAndGenerate = async () => {
    setOverrideWarning(true);
    await doGenerate();
  };

  const handleDismissWarning = () => {
    setCheckResult(null);
    setUrl("");
  };

  const handleDownload = () => {
    if (!qrDataUrl) return;
    const link = document.createElement("a");
    link.download = `qroulette-${protectedSlug?.split("/").pop()}.png`;
    link.href = qrDataUrl;
    link.click();
  };

  const handleCopyLink = async () => {
    if (!protectedSlug) return;
    await navigator.clipboard.writeText(protectedSlug);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handlePrintSvg = async () => {
    if (!protectedSlug) return;
    const svgStr = await QRCode.toString(protectedSlug, { type: "svg", width: 400, margin: 2 });
    const blob = new Blob([svgStr], { type: "image/svg+xml" });
    const svgUrl = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.download = `qroulette-${protectedSlug.split("/").pop()}.svg`;
    link.href = svgUrl;
    link.click();
    URL.revokeObjectURL(svgUrl);
  };

  return (
    <div className="px-5 py-6 max-w-lg mx-auto space-y-6">
      {/* Page Header */}
      <div>
        <p className="text-xs tracking-[0.3em] text-accent-green uppercase mb-1">
          Secure Terminal
        </p>
        <h1 className="text-2xl font-black tracking-tight">GENERATE</h1>
        <p className="mt-2 text-sm text-muted leading-relaxed">
          Input your destination URL to wrap it in our kinetic security
          perimeter.
        </p>
      </div>

      {/* URL Input */}
      <div className="bg-card border border-card-border rounded-lg p-4 space-y-4">
        <label className="text-[10px] text-muted tracking-[0.2em] uppercase block">
          Destination_URL
        </label>
        <input
          type="url"
          value={url}
          onChange={(e) => {
            setUrl(e.target.value);
            // Reset check state when URL changes
            if (checkResult) {
              setCheckResult(null);
              setQrDataUrl(null);
              setProtectedSlug(null);
              setOverrideWarning(false);
              setApiError(null);
            }
          }}
          placeholder="https://your-business-link"
          className="w-full bg-surface border border-card-border rounded-lg px-4 py-3 text-sm text-foreground placeholder:text-muted/50 focus:outline-none focus:border-accent-green/50 transition-colors font-mono"
          onKeyDown={(e) => e.key === "Enter" && handleGenerate()}
        />
        <button
          onClick={handleGenerate}
          disabled={!url.trim() || isGenerating || isChecking}
          className="w-full py-4 bg-accent-blue text-white font-bold text-sm tracking-[0.2em] uppercase rounded-lg flex items-center justify-center gap-2 hover:bg-accent-blue/90 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
        >
          <Crosshair className="w-4 h-4" />
          {isChecking
            ? "ANALYZING URL..."
            : isGenerating
              ? "GENERATING..."
              : "GENERATE PROTECTED QR CODE"}
        </button>
      </div>

      {apiError && (
        <div className="bg-card border border-accent-red/40 rounded-lg p-4">
          <p className="text-xs text-accent-red tracking-wider uppercase">{apiError}</p>
        </div>
      )}

      {/* URL Analysis Progress */}
      <AnimatePresence>
        {isChecking && (
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
            className="bg-card border border-card-border rounded-lg p-4"
          >
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 rounded-full border-2 border-accent-green/30 border-t-accent-green animate-spin" />
              <div>
                <p className="text-sm font-bold tracking-wider">THREAT ANALYSIS</p>
                <p className="text-[10px] text-muted tracking-widest mt-0.5">
                  Running security protocols on target URL...
                </p>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* URL Check Result — Warning/Danger */}
      <AnimatePresence>
        {checkResult && checkResult.verdict !== "safe" && !overrideWarning && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            className="space-y-4"
          >
            {/* Threat Banner */}
            <div
              className={`bg-card border rounded-lg p-4 ${
                checkResult.verdict === "danger"
                  ? "border-accent-red/40"
                  : "border-accent-yellow/40"
              }`}
            >
              <div className="flex items-start gap-3 mb-3">
                <ShieldAlert
                  className={`w-6 h-6 shrink-0 mt-0.5 ${
                    checkResult.verdict === "danger" ? "text-accent-red" : "text-accent-yellow"
                  }`}
                />
                <div className="flex-1">
                  <div className="flex items-center justify-between mb-1">
                    <h3 className="text-sm font-bold tracking-wider uppercase">
                      {checkResult.verdict === "danger" ? "THREAT DETECTED" : "CAUTION ADVISED"}
                    </h3>
                    <span
                      className={`text-lg font-black font-mono ${
                        checkResult.verdict === "danger" ? "text-accent-red" : "text-accent-yellow"
                      }`}
                    >
                      {checkResult.score}/100
                    </span>
                  </div>
                  <p className="text-xs text-muted leading-relaxed">
                    {checkResult.verdict === "danger"
                      ? "This URL exhibits characteristics commonly associated with phishing or malicious activity."
                      : "This URL has some characteristics that may warrant additional review."}
                  </p>
                  <p className="text-[10px] text-muted tracking-widest mt-1">
                    POLICY_DECISION: {checkResult.reason}
                  </p>
                </div>
              </div>

              {/* Individual Flags */}
              <div className="space-y-2 mt-4">
                {checkResult.flags.map((flag, i) => (
                  <motion.div
                    key={flag.label}
                    initial={{ opacity: 0, x: -10 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: i * 0.1 }}
                    className="flex items-start gap-2.5 bg-surface/50 rounded-md px-3 py-2"
                  >
                    <AlertTriangle
                      className={`w-3.5 h-3.5 shrink-0 mt-0.5 ${
                        flag.severity === "high"
                          ? "text-accent-red"
                          : flag.severity === "medium"
                            ? "text-accent-yellow"
                            : "text-muted"
                      }`}
                    />
                    <div>
                      <p className="text-[11px] font-bold tracking-wider">{flag.label}</p>
                      <p className="text-[10px] text-muted leading-relaxed mt-0.5">
                        {flag.detail}
                      </p>
                    </div>
                  </motion.div>
                ))}
              </div>
            </div>

            {/* Action buttons */}
            <div className="grid grid-cols-2 gap-3">
              <button
                onClick={handleDismissWarning}
                className="py-3.5 bg-card border border-card-border rounded-lg text-xs font-bold tracking-widest uppercase flex items-center justify-center gap-2 hover:border-foreground/30 transition-colors"
              >
                <X className="w-3.5 h-3.5" />
                Cancel
              </button>
              <button
                onClick={handleOverrideAndGenerate}
                className={`py-3.5 rounded-lg text-xs font-bold tracking-widest uppercase flex items-center justify-center gap-2 transition-colors ${
                  checkResult.verdict === "danger"
                    ? "bg-accent-red/20 border border-accent-red/40 text-accent-red hover:bg-accent-red/30"
                    : "bg-accent-yellow/20 border border-accent-yellow/40 text-accent-yellow hover:bg-accent-yellow/30"
                }`}
              >
                <AlertTriangle className="w-3.5 h-3.5" />
                Generate Anyway
              </button>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Safe URL confirmation */}
      <AnimatePresence>
        {checkResult && checkResult.verdict === "safe" && !qrDataUrl && !isGenerating && (
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0 }}
            className="bg-card border border-accent-green/30 rounded-lg p-4 flex items-center gap-3"
          >
            <CheckCircle className="w-5 h-5 text-accent-green shrink-0" />
            <div>
              <p className="text-sm font-bold tracking-wider">URL CLEARED</p>
              <p className="text-[10px] text-muted tracking-widest mt-0.5">
                No threats detected — generating protected QR code...
              </p>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Generated QR Code */}
      <AnimatePresence>
        {qrDataUrl && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            className="space-y-4"
          >
            {/* Override warning banner */}
            {overrideWarning && checkResult && checkResult.verdict !== "safe" && (
              <div
                className={`rounded-lg px-4 py-2.5 flex items-center gap-2 text-xs font-bold tracking-wider ${
                  checkResult.verdict === "danger"
                    ? "bg-accent-red/10 border border-accent-red/30 text-accent-red"
                    : "bg-accent-yellow/10 border border-accent-yellow/30 text-accent-yellow"
                }`}
              >
                <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
                Generated despite {checkResult.flags.length} warning{checkResult.flags.length !== 1 ? "s" : ""}
              </div>
            )}

            {/* QR Display */}
            <div className="bg-card border border-card-border rounded-lg p-6 flex flex-col items-center">
              <div className="bg-white rounded-lg p-4 shadow-lg">
                {/* eslint-disable-next-line @next/next/no-img-element */}
                <img
                  src={qrDataUrl}
                  alt="Generated QR Code"
                  className="w-48 h-48"
                />
              </div>
              <div className="mt-4 text-center">
                <p className="text-[10px] text-muted tracking-[0.2em] uppercase">
                  Authenticated String
                </p>
                <p className="text-sm text-accent-green font-mono mt-1">
                  {protectedSlug}
                </p>
              </div>
            </div>

            {/* Security Protocol Info */}
            <div className="bg-card border border-accent-green/20 rounded-lg p-4">
              <div className="flex items-start gap-3">
                <ShieldCheck className="w-5 h-5 text-accent-green mt-0.5 shrink-0" />
                <div>
                  <h3 className="text-sm font-bold mb-1">
                    Security Protocol Active
                  </h3>
                  <p className="text-xs text-muted leading-relaxed">
                    This QR code routes through QRoulette. Every scan is
                    analyzed and logged. Dynamic threat assessment is performed
                    in real-time to protect your business assets.
                  </p>
                </div>
              </div>
            </div>

            {/* Download Button */}
            <button
              onClick={handleDownload}
              className="w-full py-4 bg-accent-green text-background font-bold text-sm tracking-[0.2em] uppercase rounded-lg flex items-center justify-center gap-2 hover:bg-accent-green/90 transition-colors"
            >
              <Download className="w-4 h-4" />
              Download QR Code
            </button>

            {/* Options */}
            <div className="space-y-2">
              <p className="text-[10px] text-muted tracking-[0.2em] uppercase text-center">
                Options
              </p>
              <div className="grid grid-cols-2 gap-3">
                <button
                  onClick={handlePrintSvg}
                  className="py-3 bg-card border border-card-border rounded-lg text-xs font-bold tracking-widest uppercase flex items-center justify-center gap-2 hover:border-foreground/30 transition-colors"
                >
                  <Printer className="w-3.5 h-3.5" />
                  Print SVG
                </button>
                <button
                  onClick={handleCopyLink}
                  className="py-3 bg-card border border-card-border rounded-lg text-xs font-bold tracking-widest uppercase flex items-center justify-center gap-2 hover:border-foreground/30 transition-colors"
                >
                  <Copy className="w-3.5 h-3.5" />
                  {copied ? "COPIED!" : "Copy Link"}
                </button>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      <canvas ref={canvasRef} className="hidden" />
    </div>
  );
}
