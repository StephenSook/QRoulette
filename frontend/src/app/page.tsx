"use client";

import { motion } from "framer-motion";
import {
  QrCode,
  ShieldPlus,
  AlertTriangle,
  Landmark,
  ShieldCheck,
  Scan,
  FileSearch,
  Hash,
  Lock,
} from "lucide-react";
import Link from "next/link";

const fadeUp = {
  hidden: { opacity: 0, y: 20 },
  visible: (i: number) => ({
    opacity: 1,
    y: 0,
    transition: { delay: i * 0.1, duration: 0.5 },
  }),
};

const stats = [
  {
    icon: AlertTriangle,
    value: "400%",
    label: "SURGE IN QR PHISHING",
    color: "text-accent-yellow",
    borderColor: "border-accent-yellow/30",
  },
  {
    icon: Landmark,
    value: "$16.6B",
    label: "LOST TO FRAUD IN 2024",
    color: "text-accent-red",
    borderColor: "border-accent-red/30",
  },
  {
    icon: ShieldCheck,
    value: "3M+",
    label: "THREATS BLOCKED BY QROULETTE",
    color: "text-accent-green",
    borderColor: "border-accent-green/30",
  },
];

const protocols = [
  {
    num: "01",
    title: "INSTANT SANDBOX",
    desc: "Every scanned link is opened in an isolated, headless browser session to check for redirects and zero-day exploits.",
    icon: Scan,
  },
  {
    num: "02",
    title: "METADATA SCRUBBING",
    desc: "Strip tracking parameters and PII from URLs before they ever touch your device's history or cache.",
    icon: FileSearch,
  },
  {
    num: "03",
    title: "HASH VERIFICATION",
    desc: "Cross-reference QR payloads against a global database of known malicious signatures in real-time.",
    icon: Hash,
  },
  {
    num: "04",
    title: "VAULT STORAGE",
    desc: "Save your trusted codes in an encrypted, offline-first vault protected by biometric authentication.",
    icon: Lock,
  },
];

export default function HomePage() {
  return (
    <div className="px-5 py-6 max-w-lg mx-auto space-y-8">
      {/* System Status */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        className="flex items-center gap-2"
      >
        <div className="w-1 h-6 bg-accent-green rounded-full" />
        <span className="text-xs tracking-[0.3em] text-accent-green uppercase">
          System Status: Active
        </span>
      </motion.div>

      {/* Hero */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6 }}
      >
        <h1 className="text-3xl font-black leading-tight tracking-tight">
          DON&apos;T SCAN BLIND.
          <br />
          SCAN SMART.
        </h1>
        <p className="mt-4 text-sm text-muted leading-relaxed">
          The QRoulette protocol intercepts malicious payloads before they reach
          your browser. Institutional-grade validation for every pixelated link.
        </p>
      </motion.div>

      {/* CTAs */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.2, duration: 0.5 }}
        className="space-y-3"
      >
        <Link
          href="/scanner"
          className="flex items-center justify-between w-full px-5 py-4 bg-card border border-card-border rounded-lg hover:border-accent-green/50 transition-colors group"
        >
          <span className="text-sm font-semibold tracking-widest uppercase">
            Scan a QR Code
          </span>
          <QrCode className="w-5 h-5 text-muted group-hover:text-accent-green transition-colors" />
        </Link>
        <Link
          href="/generate"
          className="flex items-center justify-between w-full px-5 py-4 bg-card border border-accent-green/30 rounded-lg hover:border-accent-green/60 transition-colors group"
        >
          <span className="text-sm font-semibold tracking-widest uppercase">
            Generate Protected QR
          </span>
          <ShieldPlus className="w-5 h-5 text-accent-green" />
        </Link>
      </motion.div>

      {/* Live Threat Feed */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.4 }}
        className="bg-card border border-card-border rounded-lg overflow-hidden"
      >
        <div className="relative h-32 bg-gradient-to-b from-accent-green/5 to-card overflow-hidden">
          <div className="absolute inset-0 opacity-10">
            <div className="w-full h-full" style={{
              backgroundImage: "linear-gradient(rgba(0,255,136,0.1) 1px, transparent 1px), linear-gradient(90deg, rgba(0,255,136,0.1) 1px, transparent 1px)",
              backgroundSize: "20px 20px",
            }} />
          </div>
          <div className="absolute top-3 left-3 flex items-center gap-2">
            <div className="w-2 h-2 rounded-full bg-accent-green animate-pulse" />
            <span className="text-[10px] tracking-[0.2em] text-accent-green uppercase">
              Live Threat Feed - Global Perimeter
            </span>
          </div>
        </div>
        <div className="px-4 py-3 flex items-center justify-between">
          <div className="space-y-1">
            <p className="text-[10px] text-muted tracking-widest">
              TRACE_ID: QRL_8829_VX
            </p>
            <p className="text-[10px] text-muted tracking-widest">
              ORIGIN: CLOUD_NODE_04
            </p>
          </div>
          <span className="text-sm font-bold text-accent-green tracking-wider">
            SECURED
          </span>
        </div>
      </motion.div>

      {/* Stats Cards */}
      <div className="space-y-4">
        {stats.map((stat, i) => (
          <motion.div
            key={stat.label}
            custom={i}
            initial="hidden"
            whileInView="visible"
            viewport={{ once: true }}
            variants={fadeUp}
            className={`bg-card border ${stat.borderColor} rounded-lg p-6`}
          >
            <stat.icon className={`w-6 h-6 ${stat.color} mb-4`} />
            <p className={`text-4xl font-black ${stat.color}`}>{stat.value}</p>
            <p className="text-xs text-muted tracking-widest mt-2 uppercase">
              {stat.label}
            </p>
          </motion.div>
        ))}
      </div>

      {/* System Protocols */}
      <div className="space-y-6">
        <h2 className="text-xs tracking-[0.3em] text-muted uppercase">
          System Protocols
        </h2>
        {protocols.map((proto, i) => (
          <motion.div
            key={proto.num}
            custom={i}
            initial="hidden"
            whileInView="visible"
            viewport={{ once: true }}
            variants={fadeUp}
            className="flex gap-4"
          >
            <span className="text-2xl font-black text-card-border">
              {proto.num}
            </span>
            <div className="flex-1">
              <h3 className="text-sm font-bold tracking-wider mb-1">
                {proto.title}
              </h3>
              <p className="text-xs text-muted leading-relaxed">
                {proto.desc}
              </p>
            </div>
          </motion.div>
        ))}
      </div>
    </div>
  );
}
