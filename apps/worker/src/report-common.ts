import type { Severity } from "@auditer/types";

/**
 * Shared typographic register for the deliverables that accompany the technical
 * relevé (report-html.ts): the executive note, the progression report and the
 * attestation.
 *
 * Deliberately a SEPARATE module rather than an extraction out of
 * report-html.ts. That file is finished and owned elsewhere; refactoring it to
 * share four helpers would put a working document at risk to save forty lines.
 * The cost of the duplication is one constant table; the cost of the refactor
 * is a merge conflict in the one artifact a client actually receives.
 *
 * Everything here is pure and self-contained: no assets, no fonts to fetch, no
 * network. A document that needs a CDN to look right is a document that stops
 * looking right the day it is opened from an archive.
 */

export const SEV_COLOR: Record<Severity, string> = {
  critical: "#b3261e",
  high: "#b35a00",
  medium: "#8a6d00",
  low: "#3f6b52",
  info: "#5b6470",
};

export const SEV_ORDER: readonly Severity[] = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
] as const;

export const SEV_FR: Record<Severity, string> = {
  critical: "critique",
  high: "élevé",
  medium: "moyen",
  low: "faible",
  info: "information",
};

/** Plural of the French severity label — "3 risques élevés", "3 risques moyens". */
export const SEV_FR_PLURAL: Record<Severity, string> = {
  critical: "critiques",
  high: "élevés",
  medium: "moyens",
  low: "faibles",
  info: "informations",
};

/**
 * Reader-facing pillar names. The executive note must never print the raw
 * pillar key (`sca`, `sast`) — it is jargon, and jargon is what that document
 * exists to remove.
 */
export const PILLAR_FR: Record<string, string> = {
  secrets: "Secrets exposés",
  sca: "Dépendances tierces",
  sast: "Code applicatif",
  quality: "Qualité et dette technique",
  hygiene: "Configuration et hébergement",
  dast: "Exposition web",
  ux: "Accessibilité et performance",
};

export function pillarLabel(p: string): string {
  return PILLAR_FR[p] ?? p;
}

/**
 * Scan states, in the reader's language. The persisted values are English
 * lifecycle names; printing `success` / `failed` in a document a client
 * forwards to their own auditor reads as an unfinished export. Unknown states
 * pass through verbatim rather than being swallowed — a state we do not know
 * about must remain visible.
 */
const SCAN_STATUS_FR: Record<string, string> = {
  success: "exécuté",
  partial: "partiel",
  failed: "en échec",
  skipped: "non applicable",
  pending: "non lancé",
  running: "non terminé",
};

export function scanStatusLabel(s: string | null | undefined): string {
  if (!s) return "état inconnu";
  return SCAN_STATUS_FR[s] ?? s;
}

/** "13 points fermés" — count, noun and past participle agreed in one place. */
export function countLabel(n: number, singular: string, participle?: string): string {
  const s = n > 1 ? "s" : "";
  return participle ? `${n} ${singular}${s} ${participle}${s}` : `${n} ${singular}${s}`;
}

export function esc(s: string): string {
  return s.replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!,
  );
}

/** Long French date + time. "non déclaré" rather than a fabricated date. */
export function fmtDate(iso: string | null | undefined): string {
  if (!iso) return "non déclaré";
  const d = new Date(iso);
  return Number.isNaN(d.getTime())
    ? "non déclaré"
    : d.toLocaleString("fr-FR", { dateStyle: "long", timeStyle: "short" });
}

/** Day only — an attestation dates a day, not a minute. */
export function fmtDay(iso: string | null | undefined): string {
  if (!iso) return "non déclaré";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "non déclaré" : d.toLocaleDateString("fr-FR", { dateStyle: "long" });
}

/** Numeric day, for filenames and reference codes. */
export function fmtIsoDay(iso: string | null | undefined): string {
  if (!iso) return "0000-00-00";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "0000-00-00" : d.toISOString().slice(0, 10);
}

/**
 * "il y a six semaines". The executive note needs elapsed time in the unit a
 * human uses to talk about it, not in days — "il y a 43 jours" makes a reader
 * do arithmetic in the one paragraph they were meant to absorb instantly.
 */
export function frenchAgo(days: number | null | undefined): string {
  if (days == null || !Number.isFinite(days)) return "à une date non déclarée";
  if (days <= 0) return "aujourd'hui";
  if (days === 1) return "hier";
  if (days < 14) return `il y a ${days} jours`;
  const weeks = Math.round(days / 7);
  if (days < 60) return `il y a ${spellFr(weeks)} semaines`;
  const months = Math.round(days / 30.44);
  if (days < 365) return `il y a ${spellFr(months)} mois`;
  const years = Math.floor(days / 365);
  const rest = Math.round((days % 365) / 30.44);
  return rest >= 2
    ? `il y a ${spellFr(years)} an${years > 1 ? "s" : ""} et ${spellFr(rest)} mois`
    : `il y a ${spellFr(years)} an${years > 1 ? "s" : ""}`;
}

/** Duration in the same unit vocabulary, without the "il y a". */
export function frenchDuration(days: number | null | undefined): string {
  if (days == null || !Number.isFinite(days)) return "durée inconnue";
  if (days < 1) return "moins d'un jour";
  if (days < 14) return `${days} jour${days > 1 ? "s" : ""}`;
  if (days < 60) return `${spellFr(Math.round(days / 7))} semaines`;
  if (days < 365) return `${spellFr(Math.round(days / 30.44))} mois`;
  const years = Math.floor(days / 365);
  return `plus de ${spellFr(years)} an${years > 1 ? "s" : ""}`;
}

/** Small numbers read better spelled out in a document meant to be read aloud. */
const WORDS = [
  "zéro",
  "un",
  "deux",
  "trois",
  "quatre",
  "cinq",
  "six",
  "sept",
  "huit",
  "neuf",
  "dix",
  "onze",
  "douze",
];
export function spellFr(n: number): string {
  return n >= 0 && n < WORDS.length ? WORDS[n]! : String(n);
}

/** French decimal comma, for day estimates ("2,5"). Rounded to the half-day —
 *  a flat-rate scale that printed three decimals would claim a precision it
 *  does not have. */
export function fmtDays(n: number): string {
  const rounded = Math.round(n * 2) / 2;
  return rounded.toFixed(rounded % 1 === 0 ? 0 : 1).replace(".", ",");
}

/** "0,5 jour" · "1,5 jour" · "3,5 jours" — French pluralises only from 2. */
export function fmtDayCount(n: number): string {
  const rounded = Math.round(n * 2) / 2;
  return `${fmtDays(rounded)} jour${rounded >= 2 ? "s" : ""}`;
}

/** Signed integer with an explicit sign — a delta must never read as a total. */
export function signed(n: number): string {
  return n > 0 ? `+${n}` : String(n);
}

export function duration(from?: string | null, to?: string | null): string {
  if (!from || !to) return "non mesurée";
  const ms = new Date(to).getTime() - new Date(from).getTime();
  if (!Number.isFinite(ms) || ms < 0) return "non mesurée";
  const m = Math.floor(ms / 60000);
  const s = Math.round((ms % 60000) / 1000);
  return m > 0 ? `${m} min ${s} s` : `${s} s`;
}

/**
 * The base stylesheet, shared so the four deliverables of one mission read as
 * one set of documents.
 *
 * The three variants exist because two of these documents have a HARD page
 * budget and one does not:
 *
 *   report   — the progression report. Runs as long as the findings require.
 *   note     — the executive note. TWO pages, and the scale is what makes that
 *              achievable without amputating the content that earns them.
 *   compact  — the attestation. ONE page, no second chance, no continuation.
 *
 * Verified by rendering, not by eye: a sample of each is printed to PDF and its
 * page count counted. A budget nobody measures is a budget nobody keeps.
 */
export type CssVariant = "report" | "note" | "compact";

export function baseCss(variant: CssVariant = "report"): string {
  const compact = variant === "compact";
  const body = compact ? "8.5pt/1.3" : variant === "note" ? "10pt/1.4" : "11pt/1.55";
  const margin = compact ? "12mm 13mm" : variant === "note" ? "15mm 15mm" : "18mm 16mm";
  const h1 = compact ? "15pt" : variant === "note" ? "19pt" : "22pt";
  const h2 = compact ? "9.5pt" : variant === "note" ? "11.5pt" : "13pt";
  const h2Top = compact ? "3mm" : variant === "note" ? "3.5mm" : "9mm";
  const small = compact ? "7.8pt" : variant === "note" ? "9pt" : "10pt";
  const cell = compact ? "1mm 1.5mm" : "1.5mm 2mm";
  return `
  @page { size: A4; margin: ${margin}; }
  * { box-sizing: border-box; }
  body { font: ${body} "Iowan Old Style", Georgia, serif; color: #14181f; background: #fff;
         margin: 0 auto; max-width: 190mm; padding: ${variant === "report" ? "12mm 0" : "0"}; }
  .mono { font-family: ui-monospace, "SF Mono", Menlo, monospace; }
  h1 { font-size: ${h1}; line-height: 1.15; margin: 0 0 2mm; font-weight: 400; }
  h2 { font-size: ${h2}; font-weight: 600; margin: ${h2Top} 0 2mm;
       padding-bottom: 1.2mm; border-bottom: 1px solid #14181f; page-break-after: avoid; }
  h3 { font-size: ${compact ? "8.5pt" : variant === "note" ? "10pt" : "11pt"}; font-weight: 600;
       margin: 4mm 0 1.5mm; page-break-after: avoid; }
  p { margin: 0 0 ${compact ? "1.5mm" : variant === "note" ? "1.8mm" : "2mm"}; }
  .lbl { font-family: ui-monospace, Menlo, monospace; font-size: 7.2pt; letter-spacing: .1em;
         text-transform: uppercase; color: #5c6675; }
  .meta { display: grid; grid-template-columns: repeat(2, 1fr); gap: 1.5mm 8mm; margin: 2.5mm 0 0;
          border-top: 1px solid #dde2e9; border-bottom: 1px solid #dde2e9; padding: 2mm 0; }
  .meta div { font-size: ${small}; }
  .meta.four { grid-template-columns: repeat(4, 1fr); }
  table { border-collapse: collapse; width: 100%; font-size: ${compact ? "7.8pt" : variant === "note" ? "8.8pt" : "9.5pt"};
          margin: 2mm 0; }
  th, td { text-align: left; padding: ${cell}; border-bottom: 1px solid #dde2e9; vertical-align: top; }
  th { font-family: ui-monospace, Menlo, monospace; font-size: 7pt; letter-spacing: .07em;
       text-transform: uppercase; color: #5c6675; font-weight: 500; }
  td.num { font-family: ui-monospace, Menlo, monospace; text-align: right; white-space: nowrap; }
  .sev { font-family: ui-monospace, Menlo, monospace; font-size: 7.6pt; text-transform: uppercase;
         letter-spacing: .05em; white-space: nowrap; }
  ul { margin: 0 0 2mm; padding-left: 4.5mm; }
  li { margin-bottom: 1mm; }
  .kv { font-size: ${compact ? "7.6pt" : "8.4pt"}; color: #5c6675; margin: .8mm 0 1.5mm; }
  .warn { background: #f8ebe8; border-left: 2pt solid #b3261e; padding: 2mm 2.5mm; margin: 2.5mm 0;
          font-size: ${small}; page-break-inside: avoid; }
  .note { background: #f4f6f9; border-left: 2pt solid #5c6675; padding: 2mm 2.5mm; margin: 2.5mm 0;
          font-size: ${small}; page-break-inside: avoid; }
  .good { background: #eef4f0; border-left: 2pt solid #3f6b52; padding: 2mm 2.5mm; margin: 2.5mm 0;
          font-size: ${small}; page-break-inside: avoid; }
  .foot { margin-top: ${compact ? "1.5mm" : variant === "note" ? "2.5mm" : "5mm"}; padding-top: 1.5mm;
          border-top: 1px solid #dde2e9; font-size: 7.6pt; color: #5c6675; }
  .brand { display: flex; align-items: baseline; justify-content: space-between; gap: 6mm;
           border-bottom: 2px solid #14181f; padding-bottom: 1.5mm; margin-bottom: 3mm; }
  .brand .name { font-family: ui-monospace, Menlo, monospace; font-size: 12pt; letter-spacing: .16em;
                 text-transform: lowercase; font-weight: 600; }
  .avoid { page-break-inside: avoid; }`;
}

/** The masthead every companion document opens with. */
export function brandHeader(documentName: string, reference: string): string {
  return `<div class="brand">
  <span class="name">auditer</span>
  <span class="lbl">${esc(documentName)} · ${esc(reference)}</span>
</div>`;
}

/**
 * Identifiers and engine names that MUST NOT reach the executive note.
 *
 * Not cosmetic. The note's whole claim is that it can be handed to someone who
 * does not read security reports; one `CVE-2024-3094` in it and the reader
 * concludes the document was not written for them and stops. It also keeps a
 * document meant for wide circulation free of the strings that make a finding
 * searchable — the technical relevé is where exploitable detail belongs.
 *
 * Applied to every caller-supplied free-text string, including model-authored
 * prose, because the model was never told about this constraint.
 */
const ENGINE_NAMES = [
  "gitleaks",
  "trufflehog",
  "osv-scanner",
  "osv",
  "semgrep",
  "trivy",
  "grype",
  "checkov",
  "hadolint",
  "nuclei",
  "lighthouse",
  "jscpd",
  "scc",
  "zap",
  "axe-core",
  "axe",
  "sonarqube",
  "snyk",
];

export function neutralize(text: string): string {
  let out = text
    // CVE / GHSA / OSV / CWE / CAPEC identifiers.
    .replace(/\b(CVE|GHSA|OSV|CWE|CAPEC)[-–][A-Za-z0-9-]+/gi, "un défaut publié")
    // "CVSS 9.8", "score CVSS de 7,5", "EPSS 0.94".
    .replace(/\b(CVSS|EPSS)\b[^.,;)]{0,20}?\d+([.,]\d+)?/gi, "une gravité élevée")
    .replace(/\b(CVSS|EPSS)\b/gi, "gravité");
  for (const name of ENGINE_NAMES) {
    out = out.replace(new RegExp(`\\b${name}\\b`, "gi"), "un moteur d'analyse");
  }
  // Collapse the repetition the substitutions can produce.
  return out.replace(/(un moteur d'analyse[ ,]*){2,}/g, "un moteur d'analyse ").trim();
}
