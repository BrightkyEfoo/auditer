import type { MetadataRoute } from "next";
import { LEGAL_SLUGS } from "@/lib/legal";

const SITE = process.env.WEB_URL ?? "https://auditer.brightkyefoo.cm";

/** Public pages only — everything behind the auth gate is noindex by design. */
export default function sitemap(): MetadataRoute.Sitemap {
  const now = new Date();
  return [
    { url: SITE, lastModified: now, changeFrequency: "weekly", priority: 1 },
    { url: `${SITE}/securite`, lastModified: now, changeFrequency: "monthly", priority: 0.8 },
    { url: `${SITE}/tarifs`, lastModified: now, changeFrequency: "monthly", priority: 0.8 },
    { url: `${SITE}/inscription`, lastModified: now, changeFrequency: "yearly", priority: 0.6 },
    ...LEGAL_SLUGS.map((slug) => ({
      url: `${SITE}/legal/${slug}`,
      lastModified: now,
      changeFrequency: "yearly" as const,
      priority: 0.3,
    })),
  ];
}
