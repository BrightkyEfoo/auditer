import type { Severity } from "@auditer/types";
import type { DeltaResult } from "@auditer/audit-engine";
import {
  baseCss,
  brandHeader,
  esc,
  fmtDay,
  fmtDayCount,
  frenchAgo,
  frenchDuration,
  neutralize,
  pillarLabel,
  SEV_COLOR,
  SEV_FR,
  SEV_FR_PLURAL,
  SEV_ORDER,
  signed,
  spellFr,
} from "./report-common.js";

/**
 * The executive note — TWO PAGES, for someone who will never open the technical
 * relevé and should not have to.
 *
 * Three constraints, all of them load-bearing:
 *
 *   1. No CVSS, no CVE identifier, no engine name. Not a style rule: the moment
 *      a director reads `CVE-2024-3094` they conclude the document was written
 *      for someone else and hand it back. Every free-text string that enters
 *      this document goes through `neutralize()` first, because the model that
 *      wrote some of them was never told about this constraint.
 *
 *   2. The TREND is the biggest block. The first question an executive asks is
 *      "how bad is it"; the second — the one that decides whether anything gets
 *      funded — is "is it getting better or worse". A relevé that cannot answer
 *      the second question is a snapshot, not a report.
 *
 *   3. The last section says what was NOT verified. Commercially this looks
 *      backwards. It is the strongest section in the document: it separates us
 *      from tools that tick every box, it is the legal difference between an
 *      opinion and an overreach, and it is the quote for the human engagement
 *      that follows.
 *
 * Nothing here asserts compliance. The regulatory paragraph says what a dated,
 * repeated relevé CONTRIBUTES to — an element of proof of the regular-testing
 * procedure required by article 32(1)(d) — and stops there. "RGPD compliance:
 * 94 %" is a claim we are not entitled to make and would be the sentence that
 * ends up in front of a judge.
 */

/** What the audit found, per pillar, after triage. */
export interface ExecPillarRow {
  pillar: string;
  counts: Record<Severity, number>;
}

export interface ExecReportInput {
  runId: string;
  /** The audited organisation, as the client names itself. */
  clientName: string | null;
  /** The product or repository, in the client's words where possible. */
  projectName: string | null;
  generatedAt: string;
  /** ISO date of the relevé this note summarises. */
  runAt: string | null;
  riskScore: number | null;
  grade: string | null;
  /** Open findings only — accepted risk and false positives are excluded. */
  counts: Record<Severity, number>;
  byPillar: ExecPillarRow[];
  /** Comparison with the previous relevé. Null on a first run. */
  delta: DeltaResult | null;
  /** Pillars asked for, and those that actually produced a measurement. */
  requestedPillars: string[];
  measuredPillars: string[];
  /** Optional one-sentence verdict written by a human; neutralized on the way in. */
  verdictOverride?: string | null;
}

/**
 * Business consequence per pillar, written once, in the vocabulary of the
 * reader. Deterministic on purpose: the sentence a director acts on must not
 * be regenerated differently every month by a model.
 */
const BUSINESS: Record<string, { heading: string; consequence: string }> = {
  secrets: {
    heading: "Accès direct à vos systèmes par un identifiant publié",
    consequence:
      "Un identifiant technique se trouve dans l'historique du code : il n'y a rien à forcer, quiconque obtient une copie du dépôt s'en sert tel quel. Conséquences constatées dans ce cas de figure : accès aux données clients, envoi de courriels depuis vos adresses, facturation d'un service tiers sur votre compte.",
  },
  sca: {
    heading: "Indisponibilité ou compromission par un composant tiers",
    consequence:
      "Le produit s'appuie sur des composants externes dont certaines versions sont publiquement connues comme défaillantes — les défauts les plus exploités, parce que documentés et automatisables. Conséquences : interruption de service, ou prise de contrôle du serveur qui héberge l'application.",
  },
  sast: {
    heading: "Fuite ou altération de données par le code applicatif",
    consequence:
      "À certains endroits, le code utilise des données venues de l'extérieur sans les contrôler suffisamment. Conséquences les plus fréquentes : lecture des données d'un autre client, modification d'un montant ou d'un statut, contournement d'un contrôle d'accès.",
  },
  hygiene: {
    heading: "Compromission élargie par la configuration d'hébergement",
    consequence:
      "La configuration de déploiement accorde plus de droits que nécessaire ou expose des services qui devraient rester internes. Elle ne crée pas l'incident : elle décide de son ampleur, et transforme un incident circonscrit en incident général.",
  },
  dast: {
    heading: "Exposition publique du service en ligne",
    consequence:
      "Le service répond publiquement à des sollicitations qu'il devrait refuser. La reconnaissance préalable à une attaque en devient facile et gratuite pour l'attaquant.",
  },
  quality: {
    heading: "Coût et délai de correction",
    consequence:
      "La duplication et la complexité mesurées dépassent les seuils usuels. Ce n'est pas une faille : c'est le facteur qui multiplie le temps nécessaire pour corriger les autres, et le risque d'erreur à chaque correction.",
  },
  ux: {
    heading: "Perte d'usage et exposition réglementaire",
    consequence:
      "Des critères mesurables d'accessibilité et de performance ne sont pas tenus. Des utilisateurs abandonnent avant la fin du parcours, et le service est en écart en cas de contrôle sur l'accessibilité numérique.",
  },
};

/**
 * Flat-rate remediation effort, in developer-days, per pillar and severity.
 *
 * A fixed scale, not an estimate: rotating a leaked key is half a day whoever
 * does it, while an access-control defect in application code is not. Printed
 * next to its own disclaimer, because a number a director reads becomes a
 * budget line whether or not it was meant to.
 */
const EFFORT_DAYS: Record<string, Partial<Record<Severity, number>>> = {
  secrets: { critical: 1, high: 0.5, medium: 0.5, low: 0.25 },
  sca: { critical: 0.5, high: 0.5, medium: 0.25, low: 0.25 },
  sast: { critical: 2, high: 1.5, medium: 0.5, low: 0.25 },
  hygiene: { critical: 1, high: 0.5, medium: 0.25, low: 0.25 },
  dast: { critical: 1.5, high: 1, medium: 0.5, low: 0.25 },
  quality: { critical: 1, high: 0.5, medium: 0.25, low: 0 },
  ux: { critical: 1, high: 0.5, medium: 0.25, low: 0 },
};

/** Severity weight used only to rank which pillars get a paragraph. */
const RANK: Record<Severity, number> = { critical: 1000, high: 100, medium: 10, low: 1, info: 0 };

function effortFor(pillar: string, counts: Record<Severity, number>, severities: Severity[]): number {
  const scale = EFFORT_DAYS[pillar] ?? EFFORT_DAYS.sast!;
  return severities.reduce((sum, s) => sum + (counts[s] ?? 0) * (scale[s] ?? 0), 0);
}

/** "deux risques critiques et cinq risques élevés" — never "2 crit / 5 high". */
function riskPhrase(counts: Record<Severity, number>): string {
  const parts = (["critical", "high", "medium"] as Severity[])
    .filter((s) => (counts[s] ?? 0) > 0)
    .map((s) => `${spellFr(counts[s]!)} risque${counts[s]! > 1 ? "s" : ""} ${SEV_FR_PLURAL[s]}`);
  if (parts.length === 0) return "aucun risque critique, élevé ou moyen";
  if (parts.length === 1) return parts[0]!;
  return `${parts.slice(0, -1).join(", ")} et ${parts[parts.length - 1]}`;
}

function verdictSentence(r: ExecReportInput): string {
  if (r.verdictOverride) return neutralize(r.verdictOverride);
  const subject = r.projectName ?? "le périmètre audité";
  const when = r.runAt ? `Le relevé du ${fmtDay(r.runAt)}` : "Ce relevé";
  const note = r.grade ? `, note ${r.grade}${r.riskScore != null ? ` (${r.riskScore}/100)` : ""},` : "";
  const found = riskPhrase(r.counts);
  if ((r.counts.critical ?? 0) > 0) {
    return `${when}${note} relève sur ${subject} ${found} : une remise en production en l'état expose l'entreprise, et les points critiques doivent être traités avant tout autre travail.`;
  }
  if ((r.counts.high ?? 0) > 0) {
    return `${when}${note} relève sur ${subject} ${found} : la situation est tenable à court terme, elle ne doit pas rester en l'état.`;
  }
  return `${when}${note} ne relève sur ${subject} ${found} ouvert à cette date — sous réserve de ce que ce relevé ne couvre pas, énoncé en dernière section.`;
}

/**
 * The trend headline: the sentence the reader repeats to their board.
 * French agrees from two, so "zéro risque critique" stays singular while
 * "trois risques élevés" does not — an agreement error in the one sentence
 * meant to be quoted verbatim costs more credibility than it should.
 */
function trendSentence(d: DeltaResult): string {
  const crit = d.counts.find((c) => c.severity === "critical")!;
  const high = d.counts.find((c) => c.severity === "high")!;
  const ago = frenchAgo(d.elapsedDays);
  const line = (sev: Severity, c: { current: number; previous: number }) => {
    const many = c.current > 1;
    const label = many ? SEV_FR_PLURAL[sev] : SEV_FR[sev];
    return `${spellFr(c.current)} risque${many ? "s" : ""} ${label} ouvert${many ? "s" : ""}, contre ${spellFr(
      c.previous,
    )} ${ago}`;
  };
  if (crit.current > 0 || crit.previous > 0) {
    return `${line("critical", crit)} ; ${line("high", high)}.`;
  }
  return `${line("high", high)}. Aucun risque critique ouvert de part et d'autre.`;
}

const DIRECTION_FR: Record<DeltaResult["direction"], { word: string; cls: string }> = {
  improving: { word: "En amélioration", cls: "good" },
  worsening: { word: "En aggravation", cls: "warn" },
  stable: { word: "Stable", cls: "note" },
};

/** Things this product cannot verify, whatever the pillars requested. */
const NEVER_COVERED = [
  "La <strong>logique métier</strong> : qu'un client ne puisse pas lire le dossier d'un autre, qu'une remise ne devienne pas négative. Ces règles n'existent que dans votre métier ; aucun outil ne les connaît.",
  "L'<strong>enchaînement</strong> de plusieurs défauts anodins en un scénario d'attaque réel, et la <strong>revue d'architecture</strong> — comment les composants se font confiance, et ce qui se passe quand l'un d'eux tombe. Deux travaux humains, qui n'ont pas eu lieu.",
  "Les <strong>contrôles organisationnels</strong> : accès, départs de salariés, sauvegardes réellement restaurées, réponse à incident, engagements de vos sous-traitants.",
  "La <strong>conformité juridique</strong> : ce document n'en atteste aucune et ne peut pas en tenir lieu.",
];

export function buildExecReportHtml(r: ExecReportInput): string {
  const d = r.delta;
  const notMeasured = r.requestedPillars.filter((p) => !r.measuredPillars.includes(p));

  // Rank pillars by the worst thing in them, keep at most three. The brief asks
  // for three to five; three is what fits the two pages once the trend block —
  // which matters more than a fourth paragraph — has taken its room. Four is
  // where this note starts turning into the technical report.
  const ranked = [...r.byPillar]
    .map((p) => ({
      ...p,
      weight: SEV_ORDER.reduce((s, sev) => s + (p.counts[sev] ?? 0) * RANK[sev], 0),
    }))
    .filter((p) => p.weight > 0)
    .sort((a, b) => b.weight - a.weight)
    .slice(0, 3);

  const highSeverities: Severity[] = ["critical", "high"];
  const urgentDays = r.byPillar.reduce((s, p) => s + effortFor(p.pillar, p.counts, highSeverities), 0);
  const mediumDays = r.byPillar.reduce((s, p) => s + effortFor(p.pillar, p.counts, ["medium"]), 0);
  const urgentCount = (r.counts.critical ?? 0) + (r.counts.high ?? 0);
  const secretsOpen = r.byPillar.find((p) => p.pillar === "secrets");
  const secretsUrgent = secretsOpen
    ? (secretsOpen.counts.critical ?? 0) + (secretsOpen.counts.high ?? 0)
    : 0;

  /* ── Decisions. Two or three, each with a number attached, because a
        decision without a cost is not a decision — it is a wish. ───────── */
  const decisions: { title: string; body: string; days: string }[] = [];
  if (urgentCount > 0) {
    // Name only the levels actually present: "critiques et élevés" with zero
    // criticals open reads as a document that did not look at its own numbers.
    const levels =
      (r.counts.critical ?? 0) > 0 && (r.counts.high ?? 0) > 0
        ? "critiques et élevés"
        : (r.counts.critical ?? 0) > 0
          ? "critiques"
          : "élevés";
    decisions.push({
      title: `Autoriser la correction des ${spellFr(urgentCount)} point${urgentCount > 1 ? "s" : ""} ${levels}`,
      body: "Identifiés, localisés et documentés dans le rapport technique : aucune étude préalable à financer.",
      days: `${fmtDayCount(urgentDays)} de développement`,
    });
  }
  if (secretsUrgent > 0) {
    decisions.push({
      title: `Faire renouveler les ${spellFr(secretsUrgent)} identifiants exposés`,
      body: "Un identifiant publié reste valable tant qu'il n'est pas renouvelé, même retiré du code. Le retirer sans le renouveler ne ferme rien.",
      days: `${fmtDayCount(Math.max(0.5, secretsUrgent * 0.5))} de développement`,
    });
  }
  if (decisions.length < 3) {
    decisions.push({
      title: "Programmer un relevé de contrôle à trente jours",
      body: "Un relevé mesure un état ; deux relevés mesurent une trajectoire, et c'est elle qui se défend devant un client, un assureur ou une autorité.",
      days: "0,5 jour de mise en place, puis automatique",
    });
  }
  if (decisions.length < 3 && mediumDays > 0) {
    decisions.push({
      title: "Inscrire les points moyens dans le prochain cycle",
      body: "Sans échéance ils deviennent le fonds de roulement du prochain relevé, et c'est leur ancienneté qui finit par se voir.",
      days: `${fmtDayCount(mediumDays)} de développement`,
    });
  }

  return `<!doctype html>
<html lang="fr"><head><meta charset="utf-8">
<title>Note de direction — ${esc(r.projectName ?? r.runId)}</title>
<style>${baseCss("note")}
  .verdict { font-size: 11pt; line-height: 1.38; margin: 2mm 0 1.5mm; }
  .trend { border: 1.5pt solid #14181f; padding: 2.5mm; margin: 2mm 0 2.5mm; page-break-inside: avoid; }
  .trend .head { font-size: 11.5pt; line-height: 1.32; font-weight: 600; margin: 1.2mm 0 2mm; }
  .movers { display: grid; grid-template-columns: repeat(3, 1fr); gap: 3mm; margin: 2mm 0 0; }
  .movers div { border-top: 1px solid #dde2e9; padding-top: 1.2mm; }
  .movers .n { font-family: ui-monospace, Menlo, monospace; font-size: 14pt; line-height: 1.1; }
  /* Deliberately NOT page-break-inside:avoid. With six unbreakable blocks the
     first page ended a third empty and the document ran to three pages — the
     two-page budget is worth more than a paragraph never straddling a fold. */
  .risk { margin: 0 0 2mm; }
  .risk .h { font-weight: 600; }
  .dec { border-left: 2.5pt solid #14181f; padding: 0 0 .5mm 3mm; margin: 0 0 2mm; }
  .dec .h { font-weight: 600; }
  .dec .cost { font-family: ui-monospace, Menlo, monospace; font-size: 8.4pt; color: #5c6675; }
</style></head><body>

${brandHeader("Note de direction", `Relevé ${r.runId.slice(0, 8)}`)}
<h1>${esc(r.projectName ?? "Périmètre non nommé")}</h1>
<div class="meta">
  <div><span class="lbl">Destinataire</span><br>${esc(r.clientName ?? "Direction")}</div>
  <div><span class="lbl">Relevé du</span><br>${esc(fmtDay(r.runAt))}</div>
  <div><span class="lbl">Émis le</span><br>${esc(fmtDay(r.generatedAt))}</div>
  <div><span class="lbl">Diffusion</span><br>Confidentiel · direction et mandataires</div>
</div>

<h2>1 · Le verdict</h2>
<p class="verdict">${esc(verdictSentence(r))}</p>

<h2>2 · La tendance</h2>
${
  d && d.hasBaseline
    ? `<div class="trend">
  <span class="lbl">${esc(DIRECTION_FR[d.direction].word)} · ${esc(
    d.elapsedDays != null ? `${frenchDuration(d.elapsedDays)} depuis le relevé précédent` : "intervalle non daté",
  )}</span>
  <div class="head">${esc(trendSentence(d))}</div>
  <div class="movers">
    <div><span class="lbl">Corrigés</span><br><span class="n">${d.fixed.length}</span><br>
      <span class="kv">depuis le relevé précédent</span></div>
    <div><span class="lbl">Apparus</span><br><span class="n">${d.introduced.length}</span><br>
      <span class="kv">absents du relevé précédent</span></div>
    <div><span class="lbl">Toujours ouverts</span><br><span class="n">${d.persisting.length}</span><br>
      <span class="kv">${
        d.oldestOpen?.ageDays != null
          ? `le plus ancien depuis ${esc(frenchDuration(d.oldestOpen.ageDays))}`
          : "ancienneté non datée"
      }</span></div>
  </div>
</div>
<table><thead><tr><th>Niveau de risque</th><th>Ce relevé</th><th>Relevé précédent</th><th>Évolution</th></tr></thead><tbody>
${d.counts
  .filter((c) => c.severity === "critical" || c.severity === "high" || c.severity === "medium")
  .map(
    (c) =>
      `<tr><td class="sev" style="color:${SEV_COLOR[c.severity]}">${SEV_FR[c.severity]}</td><td class="num">${c.current}</td><td class="num">${c.previous}</td><td class="num" style="color:${
        c.delta > 0 ? SEV_COLOR.critical : c.delta < 0 ? SEV_COLOR.low : "#5c6675"
      }">${c.delta === 0 ? "=" : signed(c.delta)}</td></tr>`,
  )
  .join("")}
</tbody></table>
${
  d.meanTimeToFixCriticalDays != null
    ? `<p class="kv">Délai moyen de correction des points critiques fermés : <strong>${esc(
        frenchDuration(d.meanTimeToFixCriticalDays),
      )}</strong>, sur ${spellFr(d.fixedCriticalSample)} point${
        d.fixedCriticalSample > 1 ? "s" : ""
      } — borne haute, l'instrument date le relevé qui cesse de voir un défaut, pas la correction qui le ferme.</p>`
    : ""
}
${
  d.unmeasured.length
    ? `<div class="warn"><span class="lbl">À ne pas lire comme un progrès</span><br>${spellFr(
        d.unmeasured.length,
      )} point${d.unmeasured.length > 1 ? "s ont disparu" : " a disparu"} d'un contrôle qui n'a pas été rejoué cette fois. ${
        d.unmeasured.length > 1 ? "Ils ne sont" : "Il n'est"
      } pas corrigé${d.unmeasured.length > 1 ? "s" : ""} : ${
        d.unmeasured.length > 1 ? "ils ne sont" : "il n'est"
      } pas mesuré${d.unmeasured.length > 1 ? "s" : ""}.</div>`
    : ""
}`
    : `<div class="note"><span class="lbl">Premier relevé</span><br>Il n'y a pas encore de tendance à montrer : ce relevé est le point de départ. Sa valeur augmente au deuxième, où il devient une trajectoire — et c'est la trajectoire, pas l'état, qui se défend devant un client, un assureur ou une autorité.</div>
<p>État de départ : ${esc(riskPhrase(r.counts))} ouvert${(r.counts.critical ?? 0) + (r.counts.high ?? 0) + (r.counts.medium ?? 0) > 1 ? "s" : ""} à ce jour.</p>`
}

<h2>3 · Ce que cela veut dire pour l'activité</h2>
${
  ranked.length === 0
    ? `<p>Aucun point ouvert de niveau critique, élevé ou moyen sur les contrôles qui ont été exécutés. La section 6 dit ce que cette absence ne prouve pas.</p>`
    : ranked
        .map((p) => {
          const b = BUSINESS[p.pillar];
          const worst = SEV_ORDER.find((s) => (p.counts[s] ?? 0) > 0) ?? "info";
          const n = SEV_ORDER.reduce((s, sev) => s + (p.counts[sev] ?? 0), 0);
          return `<div class="risk">
  <div class="h">${esc(b?.heading ?? pillarLabel(p.pillar))} <span class="sev" style="color:${SEV_COLOR[worst]}">${SEV_FR[worst]}</span></div>
  <p>${b?.consequence ?? "Points relevés sans traduction métier documentée pour ce domaine."}</p>
  <p class="kv">${n} point${n > 1 ? "s" : ""} relevé${n > 1 ? "s" : ""} sur ce sujet · effort estimé ${esc(
    fmtDayCount(effortFor(p.pillar, p.counts, ["critical", "high", "medium"])),
  )}</p>
</div>`;
        })
        .join("")
}

<h2>4 · Ce que coûte l'inaction</h2>
<p>En décembre 2025, la CNIL a prononcé une sanction de <strong>1,7 million d'euros</strong> contre Nexpublica France. Le manquement retenu ne portait pas sur l'existence de vulnérabilités — tout système en a — mais sur le fait qu'elles avaient été <strong>identifiées par des audits antérieurs et laissées sans correction</strong>. Le plafond prévu par l'article 32 du RGPD, qui impose des mesures de sécurité appropriées, est de <strong>10 millions d'euros ou 2 % du chiffre d'affaires annuel mondial</strong>, le montant le plus élevé étant retenu.</p>
<div class="note">Un rapport d'audit non suivi d'effet est donc une pièce à charge. À l'inverse, une série de relevés datés, comparables et suivis constitue un <strong>élément de preuve de la procédure de test et d'évaluation régulière</strong> exigée par l'article 32(1)(d). Un élément de preuve, pas une conformité : nous n'en attestons aucune, et personne ne le peut à partir d'un audit outillé.</div>

<h2>5 · Ce que nous vous demandons de décider</h2>
${decisions
  .slice(0, 3)
  .map(
    (dec) => `<div class="dec">
  <div class="h">${esc(dec.title)}</div>
  <p>${esc(dec.body)}</p>
  <div class="cost">${esc(dec.days)}</div>
</div>`,
  )
  .join("")}
<p class="kv">Barème forfaitaire par type de défaut, pas chiffrage de votre projet : ces durées donnent un ordre de grandeur, elles n'engagent pas une équipe.</p>

<h2>6 · Ce que nous n'avons pas vérifié</h2>
<p>Section volontaire : un outil qui coche toutes les cases ne protège personne. Une liste d'angles morts publiée est ce qui distingue un audit d'un rapport de scan.</p>
${
  notMeasured.length
    ? `<div class="warn"><span class="lbl">Contrôles demandés qui n'ont pas abouti</span><br>${esc(
        notMeasured.map(pillarLabel).join(", "),
      )}. Aucune mesure n'a été produite sur ${notMeasured.length > 1 ? "ces sujets" : "ce sujet"} : l'absence de point relevé n'y signifie rien.</div>`
    : ""
}
<ul>
${NEVER_COVERED.map((x) => `<li>${x}</li>`).join("")}
  <li>Aucun opérateur humain n'a tenté de s'introduire dans vos systèmes ni d'exploiter les défauts relevés : ce document décrit ce que des moteurs d'analyse ont détecté, à une date, sur une version précise du code.</li>
</ul>
<p><strong>Cette liste est le devis de la suite</strong> : ce qu'une intervention humaine apporte par-dessus ce relevé, et qu'aucun outil ne remplace.</p>

<div class="foot">
  Relevé <span class="mono">${esc(r.runId)}</span> · ${esc(
    fmtDay(r.generatedAt),
  )} · sans détail exploitable. Rapport technique diffusé séparément, sous restriction.
</div>
</body></html>`;
}
