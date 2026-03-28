"use client";

import { useState, useCallback, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Flashlight, History, Camera, CameraOff, ShieldAlert, RotateCcw } from "lucide-react";
import { useRouter } from "next/navigation";
import { Scanner, type IDetectedBarcode } from "@yudiel/react-qr-scanner";
import { scanUrl } from "@/lib/api";

type ScanState = "initializing" | "scanning" | "found" | "analyzing" | "error";

export default function ScannerPage() {
  const router = useRouter();
  const [scanState, setScanState] = useState<ScanState>("initializing");
  const [paused, setPaused] = useState(false);
  const [detectedUrl, setDetectedUrl] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [facingMode, setFacingMode] = useState<"environment" | "user">("environment");
  const [hasMultipleCameras, setHasMultipleCameras] = useState(false);
  const [toast, setToast] = useState<string | null>(null);

  const showToast = (msg: string) => {
    setToast(msg);
    setTimeout(() => setToast(null), 2000);
  };

  // Check for multiple cameras
  useEffect(() => {
    navigator.mediaDevices?.enumerateDevices().then((devices) => {
      const videoInputs = devices.filter((d) => d.kind === "videoinput");
      setHasMultipleCameras(videoInputs.length > 1);
    }).catch(() => {});
  }, []);

  // Mark as scanning once component mounts
  useEffect(() => {
    const timer = setTimeout(() => {
      if (scanState === "initializing") setScanState("scanning");
    }, 1500);
    return () => clearTimeout(timer);
  }, [scanState]);

  const handleScan = useCallback(
    (detectedCodes: IDetectedBarcode[]) => {
      if (paused || scanState === "found" || scanState === "analyzing") return;

      const code = detectedCodes[0];
      if (!code?.rawValue) return;

      const url = code.rawValue;
      setDetectedUrl(url);
      setScanState("found");
      setPaused(true);

      // Brief "found" animation, then call backend
      setTimeout(async () => {
        setScanState("analyzing");

        // Try the real backend first; fall back to mock logic
        const apiResult = await scanUrl(url);

        let verdict: "safe" | "danger";
        if (apiResult) {
          verdict = apiResult.analysis.risk_level === "danger" ? "danger" : "safe";
        } else {
          // Backend unreachable — use simple heuristic
          verdict = url.includes("paypal.com") && !url.includes("paypa1") ? "safe" : "danger";
        }

        router.push(`/result?verdict=${verdict}`);
      }, 800);
    },
    [paused, scanState, router]
  );

  const handleError = useCallback((error: unknown) => {
    console.error("Scanner error:", error);
    const msg = error instanceof Error ? error.message : String(error);

    if (msg.includes("NotAllowedError") || msg.includes("Permission")) {
      setErrorMessage("Camera access denied. Please allow camera permissions in your browser settings.");
    } else if (msg.includes("NotFoundError") || msg.includes("no video")) {
      setErrorMessage("No camera found on this device.");
    } else if (msg.includes("NotReadableError")) {
      setErrorMessage("Camera is in use by another application.");
    } else {
      setErrorMessage("Failed to access camera. Please try again.");
    }
    setScanState("error");
  }, []);

  const toggleCamera = () => {
    setFacingMode((prev) => (prev === "environment" ? "user" : "environment"));
  };

  const resetScanner = () => {
    setScanState("scanning");
    setPaused(false);
    setDetectedUrl(null);
    setErrorMessage(null);
  };

  return (
    <div className="flex flex-col h-[calc(100vh-130px)] max-w-lg mx-auto relative">
      {/* Page Header */}
      <div className="px-5 py-4">
        <p className="text-xs tracking-[0.3em] text-accent-green uppercase mb-1">
          Secure Terminal
        </p>
        <h1 className="text-2xl font-black tracking-tight">SCANNER</h1>
      </div>

      {/* Camera Viewfinder Area */}
      <div className="flex-1 flex items-center justify-center px-5 relative">
        <div className="relative w-full aspect-square max-w-[320px]">
          {/* Background pattern */}
          <div
            className="absolute inset-0 opacity-20 rounded-lg"
            style={{
              backgroundImage:
                "linear-gradient(rgba(0,255,136,0.1) 1px, transparent 1px), linear-gradient(90deg, rgba(0,255,136,0.1) 1px, transparent 1px)",
              backgroundSize: "12px 12px",
            }}
          />

          {/* Camera Feed */}
          <div className="absolute inset-0 rounded-lg overflow-hidden">
            {scanState === "error" ? (
              <div className="w-full h-full bg-surface/80 flex flex-col items-center justify-center gap-4 p-6">
                <CameraOff className="w-12 h-12 text-accent-red" />
                <p className="text-xs text-center text-muted leading-relaxed">
                  {errorMessage}
                </p>
                <button
                  onClick={resetScanner}
                  className="px-4 py-2 bg-card border border-card-border rounded-lg text-xs font-bold tracking-widest uppercase flex items-center gap-2 hover:border-accent-green/50 transition-colors"
                >
                  <RotateCcw className="w-3.5 h-3.5" />
                  Retry
                </button>
              </div>
            ) : (
              <Scanner
                onScan={handleScan}
                onError={handleError}
                paused={paused}
                constraints={{
                  facingMode,
                  aspectRatio: 1,
                }}
                formats={["qr_code"]}
                scanDelay={500}
                components={{
                  finder: false,
                  torch: false,
                  zoom: false,
                  onOff: false,
                }}
                styles={{
                  container: {
                    width: "100%",
                    height: "100%",
                    position: "relative",
                    overflow: "hidden",
                    borderRadius: "0.5rem",
                  },
                  video: {
                    objectFit: "cover",
                    width: "100%",
                    height: "100%",
                  },
                }}
              />
            )}
          </div>

          {/* Viewfinder overlay (on top of camera) */}
          <div className="absolute inset-0 rounded-lg border-2 border-accent-green/40 pointer-events-none z-10">
            {/* Corner brackets */}
            <div className="absolute top-0 left-0 w-8 h-8 border-t-2 border-l-2 border-accent-green" />
            <div className="absolute top-0 right-0 w-8 h-8 border-t-2 border-r-2 border-accent-green" />
            <div className="absolute bottom-0 left-0 w-8 h-8 border-b-2 border-l-2 border-accent-green" />
            <div className="absolute bottom-0 right-0 w-8 h-8 border-b-2 border-r-2 border-accent-green" />
          </div>

          {/* Scanning line animation */}
          {(scanState === "scanning" || scanState === "initializing") && (
            <motion.div
              className="absolute left-2 right-2 h-0.5 bg-gradient-to-r from-transparent via-accent-green to-transparent z-10 pointer-events-none"
              animate={{ top: ["10%", "90%", "10%"] }}
              transition={{ duration: 3, repeat: Infinity, ease: "easeInOut" }}
            />
          )}

          {/* QR Detected flash */}
          <AnimatePresence>
            {scanState === "found" && (
              <motion.div
                className="absolute inset-0 rounded-lg z-10 pointer-events-none"
                initial={{ backgroundColor: "rgba(0, 255, 136, 0)" }}
                animate={{ backgroundColor: ["rgba(0, 255, 136, 0.3)", "rgba(0, 255, 136, 0)"] }}
                transition={{ duration: 0.8 }}
              />
            )}
          </AnimatePresence>
        </div>

        {/* Side Controls */}
        <div className="absolute right-7 flex flex-col gap-3 z-20">
          <button
            onClick={() => showToast("Flashlight — connecting soon")}
            className="w-10 h-10 bg-card border border-card-border rounded-lg flex items-center justify-center hover:border-accent-green/50 transition-colors active:scale-90 active:border-accent-green/40"
            title="Toggle flashlight"
          >
            <Flashlight className="w-4 h-4 text-muted" />
          </button>
          {hasMultipleCameras && (
            <button
              onClick={toggleCamera}
              className="w-10 h-10 bg-card border border-card-border rounded-lg flex items-center justify-center hover:border-accent-green/50 transition-colors active:scale-90"
              title="Switch camera"
            >
              <Camera className="w-4 h-4 text-muted" />
            </button>
          )}
          <button
            onClick={() => showToast("Scan history — connecting soon")}
            className="w-10 h-10 bg-card border border-card-border rounded-lg flex items-center justify-center hover:border-accent-green/50 transition-colors active:scale-90 active:border-accent-green/40"
            title="Scan history"
          >
            <History className="w-4 h-4 text-muted" />
          </button>
        </div>

        {/* Toast notification */}
        <AnimatePresence>
          {toast && (
            <motion.div
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: 10 }}
              className="absolute bottom-2 left-1/2 -translate-x-1/2 z-30 px-4 py-2 bg-card/95 backdrop-blur border border-card-border rounded-lg"
            >
              <p className="text-[10px] text-muted tracking-widest whitespace-nowrap">
                {toast}
              </p>
            </motion.div>
          )}
        </AnimatePresence>
      </div>

      {/* Detected URL display */}
      <AnimatePresence>
        {detectedUrl && (
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0 }}
            className="px-5 py-2"
          >
            <div className="bg-card border border-accent-green/30 rounded-lg px-4 py-2.5 flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-accent-green shrink-0" />
              <p className="text-xs font-mono text-foreground truncate">
                {detectedUrl}
              </p>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Location + Auth Data */}
      <div className="px-5 py-3">
        <div className="flex items-center justify-between text-[10px] text-muted tracking-widest">
          <div className="space-y-0.5">
            <p>LAT: 33.7490° N</p>
            <p>LNG: 84.3880° W</p>
          </div>
          <div className="text-right space-y-0.5">
            <p>
              AUTH_STATUS:{" "}
              <span
                className={
                  scanState === "found" || scanState === "analyzing"
                    ? "text-accent-yellow"
                    : scanState === "error"
                      ? "text-accent-red"
                      : "text-accent-green"
                }
              >
                {scanState === "found"
                  ? "DETECTED"
                  : scanState === "analyzing"
                    ? "ANALYZING"
                    : scanState === "error"
                      ? "OFFLINE"
                      : "STANDBY"}
              </span>
            </p>
            <p>SIGNAL: 100%</p>
          </div>
        </div>
      </div>

      {/* Scanning Status */}
      <div className="px-5 pb-6 text-center space-y-3">
        <div className="inline-flex items-center gap-2 px-6 py-3 bg-card border border-card-border rounded-lg">
          <span className="text-sm font-bold tracking-[0.3em] uppercase">
            {scanState === "found"
              ? "QR DETECTED"
              : scanState === "analyzing"
                ? "DECRYPTING"
                : scanState === "error"
                  ? "OFFLINE"
                  : "SCANNING"}
          </span>
          {scanState !== "error" && (
            <span className="flex gap-1">
              <span className="w-1.5 h-1.5 rounded-full bg-accent-green animate-typing-dot-1" />
              <span className="w-1.5 h-1.5 rounded-full bg-accent-green animate-typing-dot-2" />
              <span className="w-1.5 h-1.5 rounded-full bg-accent-green animate-typing-dot-3" />
            </span>
          )}
        </div>
        <p className="text-[10px] text-muted tracking-[0.2em] uppercase">
          {scanState === "error"
            ? "Camera access required for scanning"
            : scanState === "analyzing"
              ? "Running threat analysis on captured payload"
              : "Align QR code within perimeter for decryption"}
        </p>
      </div>
    </div>
  );
}
