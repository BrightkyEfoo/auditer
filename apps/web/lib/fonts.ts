import localFont from "next/font/local";

/**
 * Fonts are SELF-HOSTED (files committed under app/fonts) rather than pulled
 * from Google at build time: the Docker build on the deploy host must not
 * depend on fonts.gstatic.com being reachable, and a failed font fetch would
 * otherwise break the whole deploy.
 *
 * Two faces, no more — the art direction is "technical instrument sheet":
 * Space Grotesk carries the voice, JetBrains Mono carries the measurements.
 */
export const display = localFont({
  src: "../app/fonts/SpaceGrotesk.woff2",
  variable: "--font-display",
  display: "swap",
  weight: "300 700",
  fallback: ["ui-sans-serif", "system-ui", "sans-serif"],
});

export const mono = localFont({
  src: "../app/fonts/JetBrainsMono.woff2",
  variable: "--font-mono",
  display: "swap",
  weight: "400 600",
  fallback: ["ui-monospace", "SFMono-Regular", "Menlo", "monospace"],
});
