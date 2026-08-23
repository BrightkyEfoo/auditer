import "./globals.css";
import type { ReactNode } from "react";
import { AuthBadge } from "@/components/auth-badge";

export const metadata = {
  title: "auditer",
  description: "Multi-pillar code / repo / CVE / DAST / UX audit platform",
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>
        <div className="mx-auto max-w-6xl px-6 py-8">
          <header className="mb-8 flex items-center justify-between">
            <a href="/" className="text-xl font-bold tracking-tight">
              auditer
            </a>
            <div className="flex items-center gap-4">
              <span className="hidden text-xs text-neutral-500 sm:inline">
                code · repo · CVE · DAST · UX
              </span>
              <AuthBadge />
            </div>
          </header>
          {children}
        </div>
      </body>
    </html>
  );
}
