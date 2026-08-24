import { createHash } from "node:crypto";
import type { Severity } from "@auditer/types";
import {
  baseCss,
  countLabel,
  esc,
  fmtDate,
  fmtDay,
  fmtIsoDay,
  pillarLabel,
  scanStatusLabel,
  SEV_COLOR,
  SEV_FR,
  SEV_ORDER,
} from "./report-common.js";

/**
 * The attestation — ONE page, signed, and the document that actually sells.
 *
 * It is what the client shows to THEIR clients, to a tender committee, to an
 * insurer or to an auditor. It must therefore carry no exploitable detail at
 * all: severity totals, never a title, never a location, never an identifier.
 *
 * ─────────────────────────────────────────────────────────────────────────
 * THE GUARD-RAIL THIS FILE EXISTS AROUND
 *
 * An attestation attests to an ENGAGEMENT, not to a level of security. Where
 * Cure53 writes "twenty-eight workdays were allocated", we cannot write
 * man-days — there are none, and inventing a number that stands for human
 * effort would be the exact lie this document must not contain.
 *
 * The honest substitute is the DECLARED TOOLED COVERAGE: which engines ran,
 * at which versions, against which vulnerability-database snapshot, over which
 * pillars — and which pillars were NOT covered. That list is verifiable, it is
 * proportional to what was bought, and a reader can price it themselves.
 *
 * Two words never appear in this document, in any form: the name of a manual
 * penetration engagement, and any assertion of compliance. The prestation is
 * "audit AUTOMATISÉ multi-moteurs, avec triage et rédaction assistés par IA".
 * Anything more flattering is a claim we cannot defend on the day it matters.
 * ─────────────────────────────────────────────────────────────────────────
 */

export interface AttestationEngine {
  tool: string;
  version: string | null;
  pillar: string;
  status: string | null;
}

export interface AttestationInput {
  runId: string;
  /** Issue of this document, not of the run. Bumped on every re-issue. */
  documentVersion?: string;
  issuedAt: string;
  clientName: string | null;
  /** Repository or product under audit. */
  projectName: string | null;
  ref: string | null;
  commitSha: string | null;
  /** Pillars that produced a measurement, and those that did not. */
  pillarsCovered: string[];
  pillarsNotCovered: string[];
  windowStart: string | null;
  windowEnd: string | null;
  engines: AttestationEngine[];
  /** Date of the EPSS/KEV snapshot the run was enriched against. */
  vulnFeedsSnapshot: string | null;
  scoringVersion: string | null;
  /** Open findings per severity. Counts only — no detail, ever. */
  counts: Record<Severity, number>;
  /** Dated remediation status against the previous relevé. Null on a first run. */
  remediation: {
    fixedSinceLast: number;
    stillOpen: number;
    newSinceLast: number;
    previousAt: string | null;
  } | null;
  /** Months the document may be presented. Three by default. */
  validityMonths?: number;
  signatory?: { name: string; role: string; organization?: string | null } | null;
  excludedPaths?: string[];
}

/**
 * Hard bound on the engine list. The one-page budget is only a guarantee if
 * every variable-length block has a ceiling, and this is the one that grows —
 * the registry ships nine adapters today and will ship more. Beyond the cap the
 * count is stated and the detail is referred to the technical report, which is
 * where an exhaustive list belongs anyway.
 */
const MAX_ENGINE_ROWS = 10;

/**
 * The engine list is the single tallest block of the page and it is also the
 * one that cannot be cut — it IS the declared coverage. Splitting it across two
 * columns halves its height while keeping every row, which is what buys the
 * one-page budget without amputating the substance.
 */
function engineTable(rows: AttestationEngine[]): string {
  return `<table class="engines"><thead><tr><th>Moteur</th><th>Version</th><th>Pilier</th><th>État</th></tr></thead><tbody>
${rows
  .map(
    (e) =>
      `<tr><td class="mono">${esc(e.tool)}</td><td class="mono">${esc(e.version ?? "—")}</td><td>${esc(
        pillarLabel(e.pillar),
      )}</td><td>${esc(scanStatusLabel(e.status))}</td></tr>`,
  )
  .join("")}
</tbody></table>`;
}

/**
 * Integrity code printed on the document. A deterministic digest of the facts
 * the attestation asserts — run, commit, issue date, totals — so a recipient
 * who doubts a PDF can ask the issuer to recompute it. It is a tamper hint,
 * not a signature: it proves the fields agree with each other, not who wrote
 * them.
 */
function verificationCode(r: AttestationInput): string {
  const payload = [
    r.runId,
    r.commitSha ?? "",
    fmtIsoDay(r.issuedAt),
    SEV_ORDER.map((s) => `${s}=${r.counts[s] ?? 0}`).join(","),
    r.pillarsCovered.join("+"),
  ].join("|");
  const hex = createHash("sha256").update(payload).digest("hex").slice(0, 16).toUpperCase();
  return hex.replace(/(.{4})(?=.)/g, "$1-");
}

function addMonths(iso: string, months: number): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  d.setMonth(d.getMonth() + months);
  return d.toISOString();
}

export function buildAttestationHtml(r: AttestationInput): string {
  const version = r.documentVersion ?? "1.0";
  const reference = `AUD-${fmtIsoDay(r.issuedAt).slice(0, 4)}-${r.runId.slice(0, 8).toUpperCase()}`;
  const validityMonths = r.validityMonths ?? 3;
  const validUntil = addMonths(r.issuedAt, validityMonths);
  const total = SEV_ORDER.reduce((s, sev) => s + (r.counts[sev] ?? 0), 0);
  const engines = r.engines.slice(0, MAX_ENGINE_ROWS);
  const enginesHidden = r.engines.length - engines.length;

  return `<!doctype html>
<html lang="fr"><head><meta charset="utf-8">
<title>Attestation d'audit ${esc(reference)}</title>
<style>${baseCss("compact")}
  body { padding: 0; }
  .head { display: flex; justify-content: space-between; align-items: flex-start;
          border-bottom: 2.5pt solid #14181f; padding-bottom: 2mm; margin-bottom: 2mm; }
  .head .name { font-family: ui-monospace, Menlo, monospace; font-size: 14pt; letter-spacing: .18em;
                font-weight: 600; text-transform: lowercase; }
  .head .ref { text-align: right; font-family: ui-monospace, Menlo, monospace; font-size: 7.2pt;
               line-height: 1.5; color: #5c6675; }
  h1 { font-size: ${(r.clientName?.length ?? 0) > 42 ? "11.5pt" : "14pt"}; margin: 0 0 1mm; }
  .sub { font-size: 8.2pt; color: #5c6675; margin: 0 0 2mm; }
  .two { display: grid; grid-template-columns: 1fr 1fr; gap: 0 6mm; align-items: start; }
  /* The engine list is the page's tallest block and the one that must stay
     whole. Row padding, not row count, is what it can afford to give up. */
  .engines td, .engines th { padding: .4mm 1.5mm; }
  .engines { margin: 1.5mm 0; }
  .two h2:first-child { margin-top: 0; }
  .box { border: 1px solid #14181f; padding: 1.4mm 2mm; margin: 1.2mm 0; page-break-inside: avoid; }
  .box .lbl { display: block; margin-bottom: .8mm; }
  .sevrow { display: flex; gap: 2mm; margin: 1.5mm 0; }
  .sevrow div { flex: 1; border-top: 1.5pt solid #14181f; padding-top: .8mm; }
  .sevrow .n { font-family: ui-monospace, Menlo, monospace; font-size: 11pt; line-height: 1.1; }
  .sign { display: grid; grid-template-columns: 1.3fr 1fr; gap: 6mm; margin-top: 2mm;
          border-top: 1px solid #14181f; padding-top: 1.5mm; page-break-inside: avoid; }
  .sign .line { border-bottom: 1px solid #14181f; height: 4mm; margin-bottom: .8mm; }
  .code { font-family: ui-monospace, Menlo, monospace; font-size: 8pt; letter-spacing: .08em; }
  ul { padding-left: 4mm; margin-bottom: 1.5mm; }
  li { margin-bottom: .6mm; }
</style></head><body>

<div class="head">
  <div>
    <div class="name">auditer</div>
    <div class="lbl">Attestation d'exécution d'audit outillé</div>
  </div>
  <div class="ref">
    Référence ${esc(reference)} · version ${esc(version)}<br>
    Émise le ${esc(fmtDay(r.issuedAt))}<br>
    Relevé ${esc(r.runId)}
  </div>
</div>

<h1>${esc(r.clientName ?? "Client non déclaré")}</h1>
<p class="sub">Atteste de l'exécution d'un audit outillé sur le périmètre et à la date décrits ci-dessous.</p>

<div class="two">
<div>
<h2>Périmètre audité</h2>
<p><strong>${esc(r.projectName ?? "Dépôt non nommé")}</strong><br>
<span class="lbl">Référence git</span> <span class="mono">${esc(r.ref ?? "branche par défaut")}</span><br>
<span class="lbl">Empreinte de commit</span> <span class="mono">${esc(r.commitSha ?? "non déclarée")}</span><br>
<span class="lbl">Fenêtre d'exécution</span> ${esc(fmtDate(r.windowStart))} → ${esc(fmtDate(r.windowEnd))}</p>
<p><span class="lbl">Piliers couverts</span><br>${
    r.pillarsCovered.length
      ? esc(r.pillarsCovered.map(pillarLabel).join(" · "))
      : "aucun — aucun contrôle n'a produit de mesure"
  }</p>
</div>
<div>
<h2>Hors périmètre</h2>
<ul>
${
  r.pillarsNotCovered.length
    ? `<li><strong>Piliers non couverts :</strong> ${esc(r.pillarsNotCovered.map(pillarLabel).join(", "))} — aucune mesure produite.</li>`
    : "<li>Tous les piliers demandés ont produit une mesure.</li>"
}
${
  r.excludedPaths?.length
    ? `<li><strong>Chemins exclus :</strong> <span class="mono">${esc(
        r.excludedPaths.slice(0, 4).join(", "),
      )}</span>${r.excludedPaths.length > 4 ? ` et ${r.excludedPaths.length - 4} autre(s)` : ""}.</li>`
    : ""
}
  <li>Tout composant, service ou environnement hébergé <strong>hors du dépôt analysé</strong>.</li>
  <li>Toute version du code <strong>autre que le commit indiqué</strong>.</li>
  <li>Les tiers, sous-traitants et fournisseurs du client.</li>
</ul>
</div>
</div>

<h2>Nature de la prestation et couverture outillée déclarée</h2>
<p><strong>Audit automatisé multi-moteurs, avec triage et rédaction assistés par intelligence artificielle.</strong> Les défauts sont détectés par des moteurs déterministes exécutés en environnement isolé ; un modèle de langage explique, hiérarchise et rédige. Le modèle ne détecte rien et ne calcule pas la note, qui suit une formule versionnée${
    r.scoringVersion ? ` (barème ${esc(r.scoringVersion)})` : ""
  }. Aucune tentative d'exploitation, aucun accès manuel, aucune manipulation des systèmes du client. <strong>En lieu et place d'un volume de jours-homme, que cette prestation ne comporte pas</strong>, la mesure de ce qui a été exécuté est la liste ci-dessous — vérifiable, et proportionnelle à ce qui a été acheté.</p>
${
  engines.length
    ? `<div class="two">${engineTable(engines.slice(0, Math.ceil(engines.length / 2)))}${engineTable(
        engines.slice(Math.ceil(engines.length / 2)),
      )}</div>`
    : `<p>Aucun moteur déclaré pour ce relevé — aucune couverture n'est donc attestée.</p>`
}
<p class="kv">${
    enginesHidden > 0
      ? `Et ${enginesHidden} moteur${enginesHidden > 1 ? "s" : ""} supplémentaire${
          enginesHidden > 1 ? "s" : ""
        }, détaillé${enginesHidden > 1 ? "s" : ""} au rapport technique. `
      : ""
  }Instantané des bases de vulnérabilités : <strong>${esc(
    fmtDay(r.vulnFeedsSnapshot),
  )}</strong> — les correspondances de vulnérabilités connues ne valent qu'à cette date. Référentiels : catalogue OSV (composants tiers), EPSS (FIRST.org) et catalogue KEV (CISA) pour les signaux d'exploitation, jeux de règles versionnés des moteurs pour l'analyse statique.</p>

<h2>Résultats agrégés</h2>
<div class="sevrow">
${SEV_ORDER.map(
  (s) =>
    `<div><span class="lbl">${SEV_FR[s]}</span><br><span class="n" style="color:${SEV_COLOR[s]}">${
      r.counts[s] ?? 0
    }</span></div>`,
).join("")}
<div><span class="lbl">total</span><br><span class="n">${total}</span></div>
</div>
<p class="kv">Décomptes de points ouverts après triage. Aucun intitulé, aucun emplacement, aucun identifiant : ce document est fait pour être transmis, et un détail exploitable transmis est une carte des défauts du client.</p>
${
  r.remediation
    ? `<p><span class="lbl">Statut de remédiation au ${esc(fmtDay(r.issuedAt))}</span><br>
${esc(countLabel(r.remediation.fixedSinceLast, "point", "fermé"))} et ${esc(
        countLabel(r.remediation.newSinceLast, "point", "apparu"),
      )} depuis le relevé du ${esc(fmtDay(r.remediation.previousAt))} ; ${esc(
        countLabel(r.remediation.stillOpen, "point", "ouvert"),
      )} à cette date.</p>`
    : `<p><span class="lbl">Statut de remédiation</span><br>Premier relevé de ce périmètre : aucun état antérieur auquel se comparer.</p>`
}

<div class="box">
<span class="lbl">Ce que cette attestation n'atteste pas</span>
Ni un niveau de sécurité, ni l'absence de vulnérabilité, ni une conformité, à aucune norme ni aucun règlement. Ne sont couverts ni la <strong>logique métier</strong>, ni le <strong>chaînage d'exploitation</strong>, ni la <strong>revue d'architecture</strong>, ni les <strong>contrôles organisationnels</strong> (accès, sauvegardes, réponse à incident, sous-traitants). L'absence de point relevé signifie l'absence de détection par les moteurs listés, dans ces versions, à cette date — jamais l'absence de défaut. Ce document peut en revanche être versé comme <strong>élément de preuve de la procédure de test et d'évaluation régulière</strong> prévue à l'article 32(1)(d) du RGPD, et rien de plus large.
</div>

<p><span class="lbl">Validité</span> Décrit le commit indiqué ; toute modification ultérieure du code la rend inexacte. Ne doit plus être présentée après le <strong>${esc(
    fmtDay(validUntil),
  )}</strong> (${validityMonths} mois), même sans modification. <span class="lbl">Rapport complet</span> Le rapport technique, qui localise et décrit chaque point, est disponible auprès du client sous accord de confidentialité ; il n'est pas joint au présent document et ne doit pas l'être. <span class="lbl">Conservation</span> Le code source audité n'est pas conservé : l'espace de travail est détruit à la fin du relevé.</p>

<div class="sign">
  <div>
    <span class="lbl">Pour auditer${
      r.signatory?.organization && r.signatory.organization.toLowerCase() !== "auditer"
        ? ` · ${esc(r.signatory.organization)}`
        : ""
    }</span>
    <div class="line"></div>
    ${
      r.signatory
        ? `${esc(r.signatory.name)}<br><span class="kv">${esc(r.signatory.role)} · ${esc(fmtDay(r.issuedAt))}</span>`
        : `<span class="kv">Nom, qualité et date du signataire</span>`
    }
  </div>
  <div>
    <span class="lbl">Code de vérification</span>
    <div class="code">${esc(verificationCode(r))}</div>
    <span class="kv">Empreinte des éléments attestés (relevé, commit, date, décomptes, piliers couverts), recalculable par l'émetteur.</span>
  </div>
</div>
</body></html>`;
}
