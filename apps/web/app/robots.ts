import type { MetadataRoute } from "next";

const SITE = process.env.WEB_URL ?? "https://auditer.brightkyefoo.cm";

export default function robots(): MetadataRoute.Robots {
  return {
    rules: {
      userAgent: "*",
      allow: "/",
      // The product surface and the api are not content; keeping them out of
      // crawls also keeps signed-in-only routes from being probed at scale.
      disallow: ["/api/", "/tableau-de-bord", "/depots", "/audits", "/reglages", "/connexion"],
    },
    sitemap: `${SITE}/sitemap.xml`,
  };
}
