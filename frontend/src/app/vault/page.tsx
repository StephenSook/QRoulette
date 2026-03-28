"use client";

import { useEffect, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  RefreshCw,
  Download,
  Scan,
  ShieldAlert,
  QrCode,
  Eye,
} from "lucide-react";
import { getDashboardRecent, getDashboardSummary, type ScanRecord } from "@/lib/api";
import type { DashboardMetrics, QRCodeEntry, SecurityEvent } from "@/lib/types";

const fadeUp = {
  hidden: { opacity: 0, y: 15 },
  visible: (i: number) => ({
    opacity: 1,
    y: 0,
    transition: { delay: i * 0.08, duration: 0.4 },
  }),
};

export default function VaultPage() {
  const [metrics, setMetrics] = useState<DashboardMetrics>({
    totalScans: 0,
    scansTrend: 0,
    threatsBlocked: 0,
    threatsSeverity: "NORMAL",
    activeManifests: 0,
  });
  const [entries, setEntries] = useState<QRCodeEntry[]>([]);
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [toast, setToast] = useState<string | null>(null);
  const [systemClock, setSystemClock] = useState("--:--:--");
  const [topCountries, setTopCountries] = useState<string>("No country data");

  const mapRecentToView = (recent: ScanRecord[]) => {
    const mappedEntries: QRCodeEntry[] = recent.map((row) => ({
      id: row.id,
      identifier: row.qr_code_id || `#SCAN-${row.id.slice(0, 6).toUpperCase()}`,
      targetUrl: row.scanned_url,
      protectedUrl: row.qr_code_id ? `qroulette.app/go?qr=${row.qr_code_id}` : "Direct scan",
      scanCount: 1,
      createdAt: row.created_at,
      status: row.risk_level === "danger" ? "flagged" : "active",
    }));

    const mappedEvents: SecurityEvent[] = recent.slice(0, 8).map((row) => ({
      id: `evt-${row.id}`,
      message:
        row.risk_level === "danger"
          ? `Threat blocked for ${row.scanned_url}`
          : row.risk_level === "suspicious"
            ? `Suspicious scan reviewed for ${row.scanned_url}`
            : `Safe scan passed for ${row.scanned_url}`,
      type: row.risk_level === "danger" ? "threat" : row.risk_level === "safe" ? "success" : "info",
      timestamp: new Date(row.created_at).toLocaleTimeString(),
    }));

    setEntries(mappedEntries);
    setEvents(mappedEvents);
    const countries = recent
      .map((row) => row.country?.trim().toUpperCase())
      .filter((c): c is string => Boolean(c));
    const unique = Array.from(new Set(countries)).slice(0, 3);
    setTopCountries(unique.length > 0 ? unique.join(", ") : "No country data");
  };

  const hydrateSummary = async (showToasts = false) => {
    const [summary, recent] = await Promise.all([
      getDashboardSummary(),
      getDashboardRecent(25),
    ]);

    if (!summary || !recent) {
      if (showToasts) setToast("Dashboard API unavailable — using cached data");
      return;
    }

    setMetrics((prev) => ({
      ...prev,
      totalScans: summary.total,
      threatsBlocked: summary.danger,
      activeManifests: recent.length,
      threatsSeverity:
        summary.danger > 0 ? "CRITICAL" : summary.suspicious > 0 ? "ELEVATED" : "NORMAL",
    }));
    mapRecentToView(recent);
    if (showToasts) setToast("Live dashboard summary synced");
  };

  useEffect(() => {
    hydrateSummary(false);
  }, []);

  useEffect(() => {
    const renderUtcClock = () =>
      new Date().toLocaleTimeString("en-US", { hour12: false, timeZone: "UTC" });

    setSystemClock(renderUtcClock());
    const timer = setInterval(() => {
      setSystemClock(renderUtcClock());
    }, 1000);

    return () => clearInterval(timer);
  }, []);

  const handleExportCsv = () => {
    const header = "ID,Identifier,Target URL,Protected URL,Scans,Created,Status";
    const rows = entries.map((e) =>
      [e.id, e.identifier, e.targetUrl, e.protectedUrl, e.scanCount, e.createdAt, e.status].join(",")
    );
    const csv = [header, ...rows].join("\n");
    const blob = new Blob([csv], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.download = "qroulette-vault-export.csv";
    link.href = url;
    link.click();
    URL.revokeObjectURL(url);
    setToast("CSV exported successfully");
    setTimeout(() => setToast(null), 2000);
  };

  const handleRefresh = () => {
    if (isRefreshing) return;
    setIsRefreshing(true);
    setToast("Refreshing data...");
    setTimeout(async () => {
      await hydrateSummary(true);
      setIsRefreshing(false);
      setTimeout(() => setToast(null), 2000);
    }, 1500);
  };

  return (
    <div className="px-5 py-6 max-w-lg mx-auto space-y-6 relative">
      {/* Page Header */}
      <div>
        <div className="flex items-center gap-2 mb-1">
          <div className="w-1 h-5 bg-accent-green rounded-full" />
          <span className="text-xs tracking-[0.3em] text-accent-green uppercase">
            System Status: Active
          </span>
        </div>
        <h1 className="text-2xl font-black tracking-tight leading-tight">
          OPERATIONAL
          <br />
          INTELLIGENCE
        </h1>
      </div>

      {/* Action Buttons */}
      <div className="flex gap-3">
        <button
          onClick={handleRefresh}
          disabled={isRefreshing}
          className="flex-1 py-2.5 bg-card border border-card-border rounded-lg text-xs font-bold tracking-widest uppercase flex items-center justify-center gap-2 hover:border-foreground/30 transition-colors disabled:opacity-60"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isRefreshing ? "animate-spin" : ""}`} />
          {isRefreshing ? "Refreshing..." : "Refresh_Data"}
        </button>
        <button
          onClick={handleExportCsv}
          className="flex-1 py-2.5 bg-accent-blue/10 border border-accent-blue/30 rounded-lg text-xs font-bold tracking-widest uppercase text-accent-blue flex items-center justify-center gap-2 hover:bg-accent-blue/20 transition-colors active:bg-accent-blue/30"
        >
          <Download className="w-3.5 h-3.5" />
          Export_CSV
        </button>
      </div>

      {/* Toast */}
      <AnimatePresence>
        {toast && (
          <motion.div
            initial={{ opacity: 0, y: -10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
            className="fixed top-20 left-1/2 -translate-x-1/2 z-50 px-4 py-2.5 bg-card/95 backdrop-blur border border-card-border rounded-lg shadow-lg"
          >
            <p className="text-[11px] text-foreground tracking-widest whitespace-nowrap">
              {toast}
            </p>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Metrics */}
      <div className="space-y-3">
        {/* Scans */}
        <motion.div
          custom={0}
          initial="hidden"
          animate="visible"
          variants={fadeUp}
          className="bg-card border border-card-border rounded-lg p-4"
        >
          <div className="flex items-center justify-between mb-2">
            <span className="text-[10px] text-muted tracking-widest uppercase">
              Metric_01 / Scans
            </span>
            <Scan className="w-4 h-4 text-accent-blue" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-4xl font-black">
              {metrics.totalScans.toLocaleString()}
            </span>
            <span className="text-sm text-accent-green font-bold">
              +{metrics.scansTrend}%
            </span>
          </div>
          <p className="text-[10px] text-muted tracking-widest uppercase mt-1">
            Total Network Throughput
          </p>
        </motion.div>

        {/* Threats */}
        <motion.div
          custom={1}
          initial="hidden"
          animate="visible"
          variants={fadeUp}
          className="bg-card border border-card-border rounded-lg p-4"
        >
          <div className="flex items-center justify-between mb-2">
            <span className="text-[10px] text-muted tracking-widest uppercase">
              Metric_02 / Threats
            </span>
            <ShieldAlert className="w-4 h-4 text-accent-red" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-4xl font-black">
              {metrics.threatsBlocked}
            </span>
            <span className="text-sm text-accent-red font-bold uppercase">
              {metrics.threatsSeverity}
            </span>
          </div>
          <p className="text-[10px] text-muted tracking-widest uppercase mt-1">
            Malicious Redirects Blocked
          </p>
        </motion.div>

        {/* Active Manifests */}
        <motion.div
          custom={2}
          initial="hidden"
          animate="visible"
          variants={fadeUp}
          className="bg-card border border-card-border rounded-lg p-4"
        >
          <div className="flex items-center justify-between mb-2">
            <span className="text-[10px] text-muted tracking-widest uppercase">
              Metric_03 / Active
            </span>
            <QrCode className="w-4 h-4 text-accent-green" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-4xl font-black">
              {metrics.activeManifests}
            </span>
            <span className="text-sm text-accent-green font-bold uppercase">
              Live
            </span>
          </div>
          <p className="text-[10px] text-muted tracking-widest uppercase mt-1">
            Propagated QR Manifests
          </p>
        </motion.div>
      </div>

      {/* Endpoint Manifest Table */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.3 }}
        className="bg-card border border-card-border rounded-lg overflow-hidden"
      >
        <div className="px-4 py-3 flex items-center justify-between border-b border-card-border">
          <h2 className="text-sm font-bold tracking-wider uppercase">
            Endpoint Manifest
          </h2>
          <span className="text-[10px] text-muted tracking-widest uppercase">
            Filter: All_Systems
          </span>
        </div>

        {/* Table Header */}
        <div className="grid grid-cols-2 px-4 py-2 border-b border-card-border/50">
          <span className="text-[10px] text-muted tracking-widest uppercase">
            Identifier
          </span>
          <span className="text-[10px] text-muted tracking-widest uppercase">
            Target_URL
          </span>
        </div>

        {/* Table Rows */}
        {entries.map((entry, i) => (
          <motion.div
            key={entry.id}
            custom={i}
            initial="hidden"
            animate="visible"
            variants={fadeUp}
            className="grid grid-cols-2 px-4 py-3 border-b border-card-border/30 last:border-0 hover:bg-surface/50 transition-colors"
          >
            <span className="text-sm font-bold">{entry.identifier}</span>
            <span className="text-xs text-muted font-mono truncate">
              {entry.targetUrl}
            </span>
          </motion.div>
        ))}

        <div className="px-4 py-2 flex items-center justify-between text-[10px] text-muted tracking-widest">
          <span>RECORDS_SHOWN: {entries.length.toString().padStart(2, "0")}</span>
          <span>SYSTEM_CLK: {systemClock}_UTC</span>
        </div>
      </motion.div>

      {/* Global Scan Distribution */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.4 }}
        className="bg-card border border-card-border rounded-lg overflow-hidden"
      >
        <div className="px-4 py-3 flex items-center justify-between">
          <h2 className="text-sm font-bold tracking-wider uppercase">
            Global Scan Distribution
          </h2>
          <Eye className="w-4 h-4 text-muted" />
        </div>
        <div className="relative h-40 bg-surface/50">
          <div
            className="absolute inset-0 opacity-30"
            style={{
              backgroundImage:
                "radial-gradient(circle at 40% 60%, rgba(0,255,136,0.2), transparent 40%), radial-gradient(circle at 60% 40%, rgba(59,130,246,0.15), transparent 40%)",
            }}
          />
          <div className="absolute inset-0 flex items-center justify-center">
            <div className="bg-card/80 border border-card-border rounded px-3 py-2 text-center">
              <p className="text-[10px] text-muted tracking-widest">
                TOP_COUNTRIES
              </p>
              <p className="text-[10px] text-muted tracking-widest">
                {topCountries}
              </p>
            </div>
          </div>
        </div>
      </motion.div>

      {/* Security Event Log */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.5 }}
        className="bg-card border border-card-border rounded-lg p-4 space-y-4"
      >
        <h2 className="text-sm font-bold tracking-wider uppercase">
          Security Event Log
        </h2>
        {events.map((event) => (
          <div key={event.id} className="flex items-start gap-3">
            <div
              className={`w-2 h-2 rounded-full mt-1.5 shrink-0 ${
                event.type === "info"
                  ? "bg-accent-green"
                  : event.type === "threat"
                  ? "bg-accent-red"
                  : "bg-accent-blue"
              }`}
            />
            <div className="flex-1 min-w-0">
              <p className="text-sm leading-relaxed">{event.message}</p>
              <p className="text-[10px] text-muted tracking-widest uppercase mt-0.5">
                {event.timestamp}
              </p>
            </div>
          </div>
        ))}
        <button className="w-full text-center text-[10px] text-muted tracking-[0.2em] uppercase hover:text-foreground transition-colors py-2">
          Log entries loaded: {events.length}
        </button>
      </motion.div>
    </div>
  );
}
