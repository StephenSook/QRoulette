import type { Metadata, Viewport } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import { Header } from "@/components/header";
import { BottomNav } from "@/components/bottom-nav";
import { PWARegister } from "@/components/pwa-register";
import { CyberBackground } from "@/components/ui/cyber-background";
import "./globals.css";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "QRoulette — Don't Scan Blind. Scan Smart.",
  description:
    "Consumer financial fraud prevention. Intercept malicious QR code payloads before they reach your browser.",
  manifest: "/manifest.json",
  appleWebApp: {
    capable: true,
    statusBarStyle: "black-translucent",
    title: "QRoulette",
  },
};

export const viewport: Viewport = {
  themeColor: "#0a0e17",
  width: "device-width",
  initialScale: 1,
  maximumScale: 1,
  userScalable: false,
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html
      lang="en"
      className={`${geistSans.variable} ${geistMono.variable} h-full antialiased dark`}
    >
      <body className="min-h-full flex flex-col bg-background text-foreground relative">
        <CyberBackground />
        <PWARegister />
        <Header />
        <main className="relative z-10 flex-1 pb-20 overflow-y-auto">{children}</main>
        <BottomNav />
      </body>
    </html>
  );
}
