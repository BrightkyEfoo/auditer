import "./globals.css";
import type { ReactNode } from "react";
import type { Metadata } from "next";
import { display, mono } from "@/lib/fonts";
import { SmoothScroll } from "@/components/smooth-scroll";

const SITE = process.env.WEB_URL ?? "https://auditer.brightkyefoo.cm";

export const metadata: Metadata = {
  metadataBase: new URL(SITE),
  title: {
    default: "auditer — le relevé complet de votre code",
    template: "%s · auditer",
  },
  description:
    "Connectez GitHub ou GitLab et obtenez un relevé mesuré de votre code : secrets exposés, CVE, SAST, qualité, hygiène de dépôt, pentest web et UX. Sept piliers, un seul rapport.",
  openGraph: {
    type: "website",
    siteName: "auditer",
    locale: "fr_FR",
    title: "auditer — le relevé complet de votre code",
    description:
      "Sept piliers d'audit, seize moteurs open source, une sandbox gVisor. Le score est calculé, jamais deviné.",
  },
  robots: { index: true, follow: true },
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="fr" className={`${display.variable} ${mono.variable}`}>
      {/* `grain` paints a fixed noise layer over everything; it is the only
          full-page effect in the system. */}
      <body className="grain">
        {/* Le défilement adouci est monté ici, une seule fois pour toute
            l'application : il agit sur le document, et le remonter à chaque
            navigation le réinitialiserait au milieu d'une lecture. Il se
            désactive tout seul sur pointeur tactile et sous
            `prefers-reduced-motion` (voir le composant). */}
        <SmoothScroll />
        {children}
      </body>
    </html>
  );
}
