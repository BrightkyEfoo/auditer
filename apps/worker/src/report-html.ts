import type { ExecutiveSummary, Severity } from "@auditer/types";

/**
 * Builds a self-contained, print-ready HTML audit report.
 *
 * The structure follows what the three reference firms (Cure53, Trail of Bits,
 * NCC Group) and NIST SP 800-115 actually put in a report, because the parts
 * that make a report credible are NOT the findings list — every scanner
 * produces one of those. They are:
 *
 *   - a declared scope, down to the commit, including what was EXCLUDED;
 *   - a methodology stated per pillar, including the checks that found nothing;
 *   - limitations written plainly rather than buried;
 *   - a severity glossary, so the reader can argue with the ranking;
 *   - the scanners that did NOT run, and why.
 *
 * That last one is the difference between an audit and a scan dump: a pillar
 * that was requested but whose scanner failed must appear as a hole in the
 * coverage, never as an implicit "nothing found".
 *
 * Self-contained (inline CSS, no assets) so it renders identically as a stored
 * artifact and when a browser prints it. AI-authored sections are labelled as
 * such — after the 2025 flood of machine-written vulnerability reports, an
 * unlabelled one reads as less trustworthy, not more.
 */

interface FindingRow {
  pillar: string;
  tool: string;
  severity: string;
  title: string;
  description: string;
  vulnIds: string[];
  cvssScore: number | null;
  aiExplanation: string | null;
  aiRemediation: string | null;
  aiNeedsHuman: boolean;
  /** Optional enrichment; absent until the vuln feeds are wired in. */
  epssScore?: number | null;
  kevListed?: boolean | null;
  location?: string | null;
}

/**
 * One scanner's outcome. `status` is a plain string rather than a union: it
 * comes straight from the persisted scan row, and a report that silently
 * dropped an unrecognised state would hide the very gap it exists to show.
 */
export interface ScannerRow {
  tool: string;
  pillar: string;
  version?: string | null;
  imageRef?: string | null;
  status?: string | null;
  findingCount?: number | null;
  /** Raw error blob from the scan row; only its message is rendered. */
  error?: unknown;
}

const FAILED_STATES = new Set(["failed", "partial"]);

/** Pulls a readable reason out of the persisted error blob, if there is one. */
function errorReason(e: unknown): string | null {
  if (!e || typeof e !== "object") return null;
  const m = (e as { message?: unknown }).message;
  return typeof m === "string" && m.length > 0 ? m.slice(0, 200) : null;
}

interface ReportInput {
  runId: string;
  fullName: string | null;
  commitSha: string | null;
  riskScore: number | null;
  scoringVersion: string | null;
  pillars: { pillar: string; score: number; grade: string }[];
  summary: ExecutiveSummary | null;
  findings: FindingRow[];
  scanners: ScannerRow[];
  generatedAt: string;
  /* ── Optional context. Every one of these degrades to an honest
        "non déclaré" rather than to a silent claim. ────────────────── */
  ref?: string | null;
  startedAt?: string | null;
  finishedAt?: string | null;
  requestedPillars?: string[];
  /** Measured lines of code, and whether it was MEASURED or assumed. */
  kloc?: number | null;
  klocMeasured?: boolean;
  /** Snapshot date of the vulnerability databases used by this run. */
  vulnFeedsSnapshot?: string | null;
  /** Provenance of the offline OSV database the SCA verdict rests on. */
  osvDb?: {
    covered: string[];
    missing: string[];
    advisories: number;
    oldest: string | null;
  } | null;
  excludedPaths?: string[];
}

const SEV_COLOR: Record<Severity, string> = {
  critical: "#b3261e",
  high: "#b35a00",
  medium: "#8a6d00",
  low: "#3f6b52",
  info: "#5b6470",
};
const SEV_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

const SEV_FR: Record<string, string> = {
  critical: "critique",
  high: "élevé",
  medium: "moyen",
  low: "faible",
  info: "information",
};

/** What each pillar actually looks for. Printed even when it finds nothing —
 *  a reader cannot judge a clean result without knowing what was attempted. */
const PILLAR_METHOD: Record<string, { name: string; looked: string }> = {
  secrets: {
    name: "Secrets exposés",
    looked:
      "Analyse de l'historique git complet, toutes branches et objets non référencés : clés d'API, jetons d'accès, clés privées, identifiants de base de données, certificats.",
  },
  sca: {
    name: "Dépendances et CVE",
    looked:
      "Lecture des fichiers de verrouillage et résolution des dépendances transitives, puis correspondance avec la base de vulnérabilités OSV. Aucun paquet n'est installé et aucun script d'installation n'est exécuté.",
  },
  sast: {
    name: "Sécurité statique",
    looked:
      "Analyse du code source contre un jeu de règles versionné : injection, désérialisation non sûre, traversée de chemin, cryptographie faible, évaluation dynamique, contrôle d'accès.",
  },
  quality: {
    name: "Qualité et dette",
    looked:
      "Duplication de blocs, volumétrie et complexité par fichier. Ces mesures ne sont pas des défauts de sécurité : elles servent de dénominateur au score et de comparaison d'un relevé au suivant.",
  },
  hygiene: {
    name: "Hygiène du dépôt et infrastructure",
    looked:
      "Dockerfile, manifestes d'infrastructure, configuration de conteneurs et permissions déclarées. La faille se trouve souvent dans la chaîne de construction plutôt que dans le code applicatif.",
  },
  dast: {
    name: "Test dynamique web",
    looked:
      "Sondage de la cible dont la propriété a été vérifiée : en-têtes de sécurité, configuration TLS, expositions connues. Aucune charge destructrice n'est envoyée.",
  },
  ux: {
    name: "Expérience, performance et accessibilité",
    looked:
      "Mesure des Core Web Vitals et détection automatique des violations WCAG. Les tests automatiques couvrent environ 57 % des critères d'accessibilité ; le reste exige une vérification humaine.",
  },
};

function esc(s: string): string {
  return s.replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!,
  );
}

function fmtDate(iso: string | null | undefined): string {
  if (!iso) return "non déclaré";
  const d = new Date(iso);
  return Number.isNaN(d.getTime())
    ? "non déclaré"
    : d.toLocaleString("fr-FR", { dateStyle: "long", timeStyle: "short" });
}

function duration(from?: string | null, to?: string | null): string {
  if (!from || !to) return "non mesurée";
  const ms = new Date(to).getTime() - new Date(from).getTime();
  if (!Number.isFinite(ms) || ms < 0) return "non mesurée";
  const m = Math.floor(ms / 60000);
  const s = Math.round((ms % 60000) / 1000);
  return m > 0 ? `${m} min ${s} s` : `${s} s`;
}

/**
 * Risk order, deliberately NOT by CVSS: roughly 58 % of published CVEs are
 * rated high or critical, so CVSS alone ranks almost nothing.
 *
 * Confirmed in-the-wild exploitation (CISA KEV, under 2 % of CVEs) is the
 * strongest signal available, so it outranks severity — an actively exploited
 * medium deserves attention before a high nobody has ever exploited.
 *
 * With ONE correction that matters here more than in a pure SCA tool: KEV and
 * EPSS only exist for published CVEs. A leaked private key, a hardcoded
 * credential, an injection found by static analysis — none of them can ever
 * carry a KEV flag. Ranking on KEV alone would therefore push every secret and
 * every SAST finding below any exploited dependency, which is the opposite of
 * the right answer when the secret is still valid. So `critical` forms an
 * absolute first tier, and the exploitation signal orders everything below it.
 */
function riskRank(f: FindingRow): number {
  const sev = SEV_ORDER.indexOf(f.severity as Severity);
  const tier = sev === 0 ? 0 : f.kevListed ? 1 : sev + 1;
  const epss = f.epssScore == null ? 1 : 1 - f.epssScore;
  return tier * 1000 + sev * 100 + epss * 10;
}

export function buildReportHtml(r: ReportInput): string {
  const counts = SEV_ORDER.map((s) => ({
    s,
    n: r.findings.filter((f) => f.severity === s).length,
  }));
  const total = r.findings.length;
  const ranked = [...r.findings].sort((a, b) => riskRank(a) - riskRank(b));

  const ranPillars = new Set(r.scanners.filter((s) => s.status !== "skipped").map((s) => s.pillar));
  const requested = r.requestedPillars ?? [...new Set(r.scanners.map((s) => s.pillar))];
  const notRun = requested.filter((p) => !ranPillars.has(p));
  const failed = r.scanners.filter((s) => FAILED_STATES.has(s.status ?? ""));

  const bar = counts
    .filter((c) => c.n > 0)
    .map(
      (c) =>
        `<span style="display:inline-block;height:10px;width:${((c.n / Math.max(1, total)) * 100).toFixed(1)}%;background:${SEV_COLOR[c.s]}"></span>`,
    )
    .join("");

  return `<!doctype html>
<html lang="fr"><head><meta charset="utf-8">
<title>Relevé d'audit — ${esc(r.fullName ?? r.runId)}</title>
<style>
  @page { size: A4; margin: 18mm 16mm; }
  * { box-sizing: border-box; }
  body { font: 11pt/1.55 "Iowan Old Style", Georgia, serif; color: #14181f; background: #fff;
         margin: 0 auto; max-width: 190mm; padding: 12mm 0; }
  .mono { font-family: ui-monospace, "SF Mono", Menlo, monospace; }
  h1 { font-size: 22pt; line-height: 1.15; margin: 0 0 4mm; font-weight: 400; }
  h2 { font-size: 13pt; font-weight: 600; margin: 10mm 0 3mm; padding-bottom: 1.5mm;
       border-bottom: 1px solid #14181f; page-break-after: avoid; }
  h3 { font-size: 11pt; font-weight: 600; margin: 6mm 0 2mm; page-break-after: avoid; }
  p { margin: 0 0 3mm; }
  .lbl { font-family: ui-monospace, Menlo, monospace; font-size: 7.5pt; letter-spacing: .1em;
         text-transform: uppercase; color: #5c6675; }
  .meta { display: grid; grid-template-columns: repeat(2, 1fr); gap: 2mm 8mm; margin: 4mm 0 0;
          border-top: 1px solid #dde2e9; border-bottom: 1px solid #dde2e9; padding: 3mm 0; }
  .meta div { font-size: 9.5pt; }
  table { border-collapse: collapse; width: 100%; font-size: 9.5pt; margin: 3mm 0; }
  th, td { text-align: left; padding: 1.8mm 2mm; border-bottom: 1px solid #dde2e9; vertical-align: top; }
  th { font-family: ui-monospace, Menlo, monospace; font-size: 7.5pt; letter-spacing: .07em;
       text-transform: uppercase; color: #5c6675; font-weight: 500; }
  .sev { font-family: ui-monospace, Menlo, monospace; font-size: 8pt; text-transform: uppercase;
         letter-spacing: .05em; white-space: nowrap; }
  .finding { page-break-inside: avoid; border-left: 2.5pt solid #dde2e9; padding: 0 0 3mm 4mm; margin: 5mm 0; }
  .finding .head { font-weight: 600; font-size: 11pt; }
  .kv { font-size: 8.5pt; color: #5c6675; margin: 1mm 0 2mm; }
  .ai { background: #f4f6f9; border-left: 2pt solid #1f4d8f; padding: 2.5mm 3mm; margin: 2mm 0; font-size: 10pt; }
  .ai .lbl { color: #1f4d8f; }
  .warn { background: #f8ebe8; border-left: 2pt solid #b3261e; padding: 2.5mm 3mm; margin: 3mm 0; font-size: 10pt; }
  .score { display: flex; align-items: baseline; gap: 4mm; margin: 3mm 0; }
  .score .n { font-size: 34pt; line-height: 1; font-family: ui-monospace, Menlo, monospace; }
  ul { margin: 0 0 3mm; padding-left: 5mm; }
  li { margin-bottom: 1.2mm; }
  .foot { margin-top: 10mm; padding-top: 3mm; border-top: 1px solid #dde2e9; font-size: 8.5pt; color: #5c6675; }
</style></head><body>

<div class="lbl">Relevé d'audit outillé · Document confidentiel · ${esc(r.runId)}</div>
<h1>${esc(r.fullName ?? "Cible non nommée")}</h1>

<div class="meta">
  <div><span class="lbl">Commit</span><br><span class="mono">${esc(r.commitSha ?? "non déclaré")}</span></div>
  <div><span class="lbl">Référence</span><br><span class="mono">${esc(r.ref ?? "branche par défaut")}</span></div>
  <div><span class="lbl">Début</span><br>${esc(fmtDate(r.startedAt))}</div>
  <div><span class="lbl">Durée</span><br>${esc(duration(r.startedAt, r.finishedAt))}</div>
  <div><span class="lbl">Émis le</span><br>${esc(fmtDate(r.generatedAt))}</div>
  <div><span class="lbl">Barème</span><br>version ${esc(r.scoringVersion ?? "non déclarée")}</div>
</div>

<h2>1 · Verdict</h2>
${
  r.riskScore != null
    ? `<div class="score"><span class="n">${r.riskScore}</span><span>sur 100${
        r.summary ? ` · note ${esc(r.summary.overallGrade)}` : ""
      }</span></div>`
    : `<p>Aucun score : le relevé ne s'est pas terminé normalement.</p>`
}
<div style="display:flex;width:100%;margin:2mm 0">${bar || '<span class="lbl">aucun finding</span>'}</div>
<table><thead><tr><th>Gravité</th><th>Nombre</th><th>Part</th></tr></thead><tbody>
${counts
  .map(
    (c) =>
      `<tr><td class="sev" style="color:${SEV_COLOR[c.s]}">${SEV_FR[c.s]}</td><td class="mono">${c.n}</td><td class="mono">${
        total ? ((c.n / total) * 100).toFixed(0) : 0
      } %</td></tr>`,
  )
  .join("")}
</tbody></table>
${
  counts[0]!.n > 0
    ? `<div class="warn"><span class="lbl">Plafond appliqué</span><br>${counts[0]!.n} finding(s) de gravité critique ouverts. Le barème plafonne la note à F tant qu'un critique reste ouvert, quel que soit le reste du relevé.</div>`
    : ""
}

<h2>2 · Périmètre</h2>
<p><strong>Analysé :</strong> l'arbre de travail du dépôt au commit indiqué ci-dessus, dans un espace de travail éphémère détruit à la fin du relevé.</p>
<p><strong>Piliers demandés :</strong> ${requested.length ? esc(requested.join(", ")) : "non déclarés"}.</p>
${
  notRun.length
    ? `<p><strong>Piliers demandés mais non exécutés :</strong> ${esc(notRun.join(", "))}. Ces piliers n'ont produit aucune mesure — leur absence de finding ne signifie donc rien.</p>`
    : ""
}
${
  r.excludedPaths?.length
    ? `<p><strong>Chemins exclus :</strong> <span class="mono">${esc(r.excludedPaths.join(", "))}</span>.</p>`
    : ""
}
<p><strong>Hors périmètre par construction :</strong> la logique métier, le chaînage d'exploitation, l'architecture, les contrôles organisationnels, et tout composant hébergé hors du dépôt analysé.</p>
${
  r.kloc != null
    ? `<p><strong>Volumétrie :</strong> ${r.kloc.toFixed(1)} milliers de lignes de code${
        r.klocMeasured ? " (mesurées)" : " (valeur supposée, aucune mesure disponible pour ce relevé)"
      }. Le score est normalisé par cette valeur.</p>`
    : `<p><strong>Volumétrie :</strong> non mesurée pour ce relevé. Le score n'est donc pas normalisé par la taille du dépôt.</p>`
}

<h2>3 · Méthodologie et couverture</h2>
<p>Chaque moteur s'exécute dans un conteneur isolé, sans accès réseau sauf mention contraire, sur une copie en lecture seule. Ce qui suit décrit ce qui a été cherché, pilier par pilier — y compris là où rien n'a été trouvé.</p>
${requested
  .map((p) => {
    const m = PILLAR_METHOD[p];
    const tools = r.scanners.filter((s) => s.pillar === p);
    const found = r.findings.filter((f) => f.pillar === p).length;
    return `<h3>${esc(m?.name ?? p)}</h3>
      <p>${esc(m?.looked ?? "Méthodologie non documentée pour ce pilier.")}</p>
      <p class="kv">Moteurs : ${
        tools.length
          ? tools
              .map(
                (t) =>
                  `<span class="mono">${esc(t.tool)}${t.version ? ` ${esc(t.version)}` : ""}</span> — ${esc(
                    t.status ?? "état inconnu",
                  )}${errorReason(t.error) ? ` (${esc(errorReason(t.error)!)})` : ""}`,
              )
              .join(" · ")
          : "aucun moteur exécuté"
      }<br>Résultat : ${found} finding(s).</p>`;
  })
  .join("")}
${
  failed.length
    ? `<div class="warn"><span class="lbl">Couverture incomplète</span><br>${failed
        .map((f) => `<span class="mono">${esc(f.tool)}</span> (${esc(f.status ?? "")})`)
        .join(", ")} — ces moteurs n'ont pas terminé. Le périmètre qu'ils couvrent n'a pas été mesuré.</div>`
    : ""
}

<h2>4 · Limitations</h2>
<ul>
  <li>Ce document est un <strong>audit outillé</strong>, pas un test d'intrusion. Aucun opérateur humain n'a tenté d'exploiter les défauts relevés ni de les chaîner.</li>
  <li>L'absence de finding n'est pas une preuve d'absence de faille : c'est l'absence de détection par ces moteurs, dans cette version, à cette date.</li>
  <li>La couverture des vulnérabilités connues dépend de la fraîcheur des bases utilisées${
    r.vulnFeedsSnapshot ? `, dont l'instantané date du ${esc(fmtDate(r.vulnFeedsSnapshot))}` : ""
  }.</li>
  ${
    r.osvDb
      ? `<li>Le verdict sur les dépendances repose sur une base hors ligne de ${r.osvDb.advisories.toLocaleString(
          "fr-FR",
        )} avis couvrant ${r.osvDb.covered.length} écosystème(s) — <span class="mono">${esc(
          r.osvDb.covered.join(", "),
        )}</span>${
          r.osvDb.oldest ? `, la plus ancienne archive datant du ${esc(fmtDate(r.osvDb.oldest))}` : ""
        }. Une dépendance d'un écosystème absent de cette liste n'a pas été confrontée à quoi que ce soit${
          r.osvDb.missing.length
            ? ` — écosystèmes indisponibles pour ce relevé : <span class="mono">${esc(
                r.osvDb.missing.join(", "),
              )}</span>`
            : ""
        }.</li>`
      : `<li>La provenance de la base de dépendances n'a pas pu être établie pour ce relevé. L'absence de vulnérabilité signalée sur les dépendances ne doit donc pas être lue comme un résultat daté.</li>`
  }
  <li>Les explications et les propositions de correctif sont rédigées par un modèle de langage à partir de la sortie brute des moteurs. Le score, lui, est calculé par une formule déterministe et versionnée : le modèle n'y touche pas.</li>
  <li>Le résultat vaut pour le commit indiqué. Toute modification ultérieure du code invalide ce relevé.</li>
</ul>

<h2>5 · Échelle de gravité</h2>
<table><thead><tr><th>Niveau</th><th>Ce que cela signifie</th></tr></thead><tbody>
<tr><td class="sev" style="color:${SEV_COLOR.critical}">critique</td><td>Exploitable à distance sans authentification, ou exposition directe d'un secret valide. À traiter avant toute mise en production.</td></tr>
<tr><td class="sev" style="color:${SEV_COLOR.high}">élevé</td><td>Exploitable sous condition réaliste, avec un impact sérieux sur la confidentialité ou l'intégrité.</td></tr>
<tr><td class="sev" style="color:${SEV_COLOR.medium}">moyen</td><td>Impact réel mais limité, ou exploitation exigeant un accès préalable.</td></tr>
<tr><td class="sev" style="color:${SEV_COLOR.low}">faible</td><td>Écart aux bonnes pratiques, sans chemin d'exploitation direct.</td></tr>
<tr><td class="sev" style="color:${SEV_COLOR.info}">information</td><td>Observation. Aucune action requise à ce titre.</td></tr>
</tbody></table>
<p class="kv">Les findings sont classés par risque réel : exploitation confirmée dans la nature d'abord, puis probabilité d'exploitation estimée, puis gravité. Le score CVSS seul ne hiérarchise presque rien, la majorité des vulnérabilités publiées étant notées élevées ou critiques.</p>

${
  r.summary
    ? `<h2>6 · Synthèse</h2>
<div class="ai"><span class="lbl">Section rédigée par un modèle · le score et la note ne sont pas de lui</span>
<p style="margin-top:2mm"><strong>${esc(r.summary.headline)}</strong></p>
<p>${esc(r.summary.riskPosture)}</p></div>
${
  r.summary.keyRisks?.length
    ? `<h3>Risques principaux</h3><ul>${r.summary.keyRisks
        .map(
          (k) =>
            `<li><strong>${esc(k.title)}</strong> <span class="sev" style="color:${
              SEV_COLOR[k.severity as Severity] ?? "#5b6470"
            }">${esc(SEV_FR[k.severity] ?? k.severity)}</span> — ${esc(k.why)}</li>`,
        )
        .join("")}</ul>`
    : ""
}
${
  r.summary.remediationRoadmap?.length
    ? `<h3>Ordre de remédiation</h3><table><thead><tr><th>Étape</th><th>Effort</th><th>Impact</th></tr></thead><tbody>${r.summary.remediationRoadmap
        .map(
          (s) =>
            `<tr><td>${esc(s.step)}</td><td class="mono">${esc(s.effort)}</td><td class="mono">${esc(s.impact)}</td></tr>`,
        )
        .join("")}</tbody></table>`
    : ""
}`
    : ""
}

<h2>7 · Findings</h2>
${
  total === 0
    ? `<p>Aucun finding relevé par les moteurs exécutés. Voir la section 3 pour ce qui a réellement été couvert, et la section 4 pour ce que cette absence ne prouve pas.</p>`
    : `<table><thead><tr><th>Titre</th><th>Pilier</th><th>Gravité</th><th>Moteur</th></tr></thead><tbody>
${ranked
  .map(
    (f) =>
      `<tr><td>${esc(f.title)}${f.kevListed ? ' <span class="sev" style="color:#b3261e">exploité</span>' : ""}</td><td class="mono">${esc(
        f.pillar,
      )}</td><td class="sev" style="color:${SEV_COLOR[f.severity as Severity] ?? "#5b6470"}">${esc(
        SEV_FR[f.severity] ?? f.severity,
      )}</td><td class="mono">${esc(f.tool)}</td></tr>`,
  )
  .join("")}
</tbody></table>
${ranked
  .map((f) => {
    const bits: string[] = [`moteur ${esc(f.tool)}`, `pilier ${esc(f.pillar)}`];
    if (f.location) bits.push(esc(f.location));
    if (f.vulnIds.length) bits.push(f.vulnIds.map(esc).join(", "));
    if (f.cvssScore != null) bits.push(`CVSS ${f.cvssScore}`);
    if (f.epssScore != null) bits.push(`EPSS ${(f.epssScore * 100).toFixed(1)} %`);
    if (f.kevListed) bits.push("exploité dans la nature (CISA KEV)");
    return `<div class="finding" style="border-left-color:${SEV_COLOR[f.severity as Severity] ?? "#dde2e9"}">
  <div class="head">${esc(f.title)}</div>
  <div class="kv">${bits.join(" · ")}</div>
  <p>${esc(f.description)}</p>
  ${
    f.aiExplanation
      ? `<div class="ai"><span class="lbl">Analyse rédigée${f.aiNeedsHuman ? " · revue humaine conseillée" : ""}</span>
      <p style="margin:1.5mm 0 0">${esc(f.aiExplanation)}</p>
      ${f.aiRemediation ? `<p style="margin:1.5mm 0 0"><strong>Correctif proposé —</strong> ${esc(f.aiRemediation)}</p>` : ""}</div>`
      : ""
  }
</div>`;
  })
  .join("")}`
}

<h2>8 · Moteurs exécutés</h2>
<table><thead><tr><th>Moteur</th><th>Pilier</th><th>Version</th><th>État</th><th>Findings</th></tr></thead><tbody>
${
  r.scanners.length
    ? r.scanners
        .map(
          (s) =>
            `<tr><td class="mono">${esc(s.tool)}</td><td class="mono">${esc(s.pillar)}</td><td class="mono">${esc(
              s.version ?? s.imageRef ?? "—",
            )}</td><td class="mono">${esc(s.status ?? "—")}</td><td class="mono">${
              s.findingCount ?? "—"
            }</td></tr>`,
        )
        .join("")
    : `<tr><td colspan="5">Aucun moteur déclaré.</td></tr>`
}
</tbody></table>

<div class="foot">
  Relevé <span class="mono">${esc(r.runId)}</span> · barème version ${esc(r.scoringVersion ?? "non déclarée")} ·
  émis le ${esc(fmtDate(r.generatedAt))}. Le code source analysé n'est pas conservé : l'espace de travail
  est détruit à la fin du relevé. Ce document contient des informations exploitables — le diffuser revient
  à diffuser une carte des défauts de la cible.
</div>
</body></html>`;
}
