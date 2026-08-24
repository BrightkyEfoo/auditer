import type { Severity } from "@auditer/types";
import type { DeltaEntry, DeltaResult } from "@auditer/audit-engine";
import type { HistoryPoint } from "./delta.js";
import {
  baseCss,
  brandHeader,
  esc,
  fmtDay,
  frenchAgo,
  frenchDuration,
  pillarLabel,
  SEV_COLOR,
  SEV_FR,
  signed,
  spellFr,
} from "./report-common.js";

/**
 * The progression report — the only deliverable that speaks to all five readers
 * of an audit at once, because "is it getting better or worse" is a question a
 * developer, a CTO, a director, a client and an auditor all ask in the same
 * words.
 *
 * What makes it defensible rather than decorative:
 *
 *   - The comparison is by FINGERPRINT, not by title or line number, so a
 *     refactor does not present itself as fifty fixes and fifty regressions.
 *   - The AGE of an open finding is printed. Age is the governance metric: a
 *     medium open for fourteen months says more about how an organisation
 *     handles risk than a critical opened yesterday.
 *   - Accepted risk and assumed false positives get their own section, dated
 *     and counted. A decision not to fix is a legitimate decision — provided it
 *     is written down somewhere other than in a ticket nobody reopens.
 *   - Findings that vanished from a control that DID NOT RUN are listed apart
 *     and never counted as fixed.
 *
 * The remediation delay for criticals is labelled as an upper bound every time
 * it appears: we know which relevé stopped seeing a finding, not which commit
 * closed it.
 */

export interface DeltaReportInput {
  runId: string;
  clientName: string | null;
  projectName: string | null;
  commitSha: string | null;
  generatedAt: string;
  scoringVersion: string | null;
  delta: DeltaResult;
  /** Oldest first, current last. */
  history: HistoryPoint[];
  requestedPillars: string[];
  measuredPillars: string[];
}

/** How many rows of a bucket get printed before the tail is summarised. */
const MAX_ROWS = 25;

function ageCell(e: DeltaEntry): string {
  return e.ageDays == null
    ? `<span class="kv">non daté</span>`
    : esc(frenchDuration(e.ageDays));
}

/**
 * `ageHeader` differs per bucket and is not cosmetic: in the fixed list the
 * number is how long the finding STAYED open, in the others it is how long it
 * has been open. One header for both would misdescribe half the tables in the
 * document.
 */
function rows(entries: DeltaEntry[], ageHeader = "Ouvert depuis"): string {
  const shown = entries.slice(0, MAX_ROWS);
  const hidden = entries.length - shown.length;
  const body = shown
    .map(
      (e) =>
        `<tr><td>${esc(e.title)}</td><td class="mono">${esc(pillarLabel(e.pillar))}</td><td class="sev" style="color:${
          SEV_COLOR[e.severity]
        }">${SEV_FR[e.severity]}</td><td class="num">${ageCell(e)}</td></tr>`,
    )
    .join("");
  const tail = hidden
    ? `<tr><td colspan="4" class="kv">et ${hidden} autre${hidden > 1 ? "s" : ""} — la liste complète figure au rapport technique.</td></tr>`
    : "";
  return `<table><thead><tr><th>Intitulé</th><th>Domaine</th><th>Gravité</th><th>${esc(
    ageHeader,
  )}</th></tr></thead><tbody>${body}${tail}</tbody></table>`;
}

/**
 * Score history as a bar chart drawn in CSS. No image, no script, no font to
 * fetch: the document must render identically from a mail attachment in 2029.
 */
function sparkline(history: HistoryPoint[]): string {
  const withScore = history.filter((h) => h.riskScore != null);
  if (withScore.length < 2) return "";
  const bars = history
    .map((h) => {
      const v = h.riskScore ?? 0;
      const color = h.critical > 0 ? SEV_COLOR.critical : v >= 75 ? SEV_COLOR.low : SEV_COLOR.medium;
      return `<div class="bar"><span style="height:${Math.max(3, v)}%;background:${color}"></span>
        <span class="v${h.isCurrent ? " cur" : ""}">${h.riskScore ?? "—"}</span>
        <span class="d">${esc(fmtDay(h.at).replace(/ \d{4}$/, ""))}</span></div>`;
    })
    .join("");
  return `<div class="spark">${bars}</div>`;
}

/** Warns when the scale changed under the comparison — two scores from two
 *  formulas are two different numbers wearing the same clothes. */
function scoringDrift(history: HistoryPoint[]): string | null {
  const versions = [...new Set(history.map((h) => h.scoringVersion).filter(Boolean))];
  if (versions.length < 2) return null;
  return `Les relevés de cette série n'ont pas tous été notés avec le même barème (${versions
    .map((v) => esc(String(v)))
    .join(", ")}). Les notes ne sont pas directement comparables entre elles ; le décompte des points ouverts, lui, l'est.`;
}

export function buildDeltaReportHtml(r: DeltaReportInput): string {
  const d = r.delta;
  const notMeasured = r.requestedPillars.filter((p) => !r.measuredPillars.includes(p));
  const drift = scoringDrift(r.history);
  const openBySeverity = (sev: Severity) =>
    [...d.introduced, ...d.persisting].filter((f) => f.severity === sev).length;

  return `<!doctype html>
<html lang="fr"><head><meta charset="utf-8">
<title>Rapport de progression — ${esc(r.projectName ?? r.runId)}</title>
<style>${baseCss("report")}
  .spark { display: flex; align-items: flex-end; gap: 4mm; height: 34mm; margin: 4mm 0 2mm;
           padding-bottom: 8mm; border-bottom: 1px solid #14181f; }
  .spark .bar { flex: 1; height: 100%; display: flex; flex-direction: column; justify-content: flex-end;
                align-items: center; position: relative; }
  .spark .bar > span:first-child { width: 60%; display: block; }
  .spark .v { font-family: ui-monospace, Menlo, monospace; font-size: 8.5pt; margin-top: 1mm; }
  .spark .v.cur { font-weight: 700; }
  .spark .d { position: absolute; bottom: -7mm; font-size: 7pt; color: #5c6675; white-space: nowrap; }
  .cards { display: grid; grid-template-columns: repeat(4, 1fr); gap: 3mm; margin: 3mm 0 4mm; }
  .cards div { border-top: 1.5pt solid #14181f; padding-top: 1.5mm; }
  .cards .n { font-family: ui-monospace, Menlo, monospace; font-size: 19pt; line-height: 1.1; }
  .verdict { font-size: 12.5pt; line-height: 1.4; margin: 3mm 0; }
</style></head><body>

${brandHeader("Rapport de progression", `Relevé ${r.runId.slice(0, 8)}`)}
<h1>${esc(r.projectName ?? "Périmètre non nommé")}</h1>
<div class="meta">
  <div><span class="lbl">Client</span><br>${esc(r.clientName ?? "non déclaré")}</div>
  <div><span class="lbl">Relevé courant</span><br>${esc(fmtDay(d.currentAt))}</div>
  <div><span class="lbl">Relevé de référence</span><br>${esc(
    d.hasBaseline ? fmtDay(d.previousAt) : "aucun — premier relevé",
  )}</div>
  <div><span class="lbl">Intervalle</span><br>${esc(
    d.elapsedDays != null ? frenchDuration(d.elapsedDays) : "non daté",
  )}</div>
</div>

<h2>1 · Note et tendance</h2>
${
  d.hasBaseline
    ? `<p class="verdict">${esc(
        d.direction === "improving"
          ? "La charge de risque pondérée diminue entre les deux relevés."
          : d.direction === "worsening"
            ? "La charge de risque pondérée augmente entre les deux relevés."
            : "La charge de risque pondérée est inchangée entre les deux relevés.",
      )} ${esc(
        `${spellFr(d.openCurrent)} point${d.openCurrent > 1 ? "s" : ""} ouvert${
          d.openCurrent > 1 ? "s" : ""
        }, contre ${spellFr(d.openPrevious)} ${frenchAgo(d.elapsedDays)}.`,
      )}</p>`
    : `<p class="verdict">Premier relevé de cette série : il n'y a pas encore de tendance. Ce document existe pour être comparé au suivant.</p>`
}
${sparkline(r.history)}
${
  r.history.length > 1
    ? `<table><thead><tr><th>Relevé</th><th>Note</th><th>Critiques ouverts</th><th>Élevés ouverts</th><th>Total ouvert</th></tr></thead><tbody>
${r.history
  .map(
    (h) =>
      `<tr><td>${esc(fmtDay(h.at))}${h.isCurrent ? " <span class=\"lbl\">courant</span>" : ""}</td><td class="num">${
        h.riskScore ?? "—"
      }</td><td class="num">${h.critical}</td><td class="num">${h.high}</td><td class="num">${h.open}</td></tr>`,
  )
  .join("")}
</tbody></table>`
    : ""
}
${drift ? `<div class="warn"><span class="lbl">Barème hétérogène</span><br>${drift}</div>` : ""}

<div class="cards">
  <div><span class="lbl">Corrigés</span><br><span class="n" style="color:${SEV_COLOR.low}">${d.fixed.length}</span></div>
  <div><span class="lbl">Nouveaux</span><br><span class="n" style="color:${SEV_COLOR.high}">${d.introduced.length}</span></div>
  <div><span class="lbl">Toujours ouverts</span><br><span class="n">${d.persisting.length}</span></div>
  <div><span class="lbl">Non mesurés</span><br><span class="n" style="color:${SEV_COLOR.info}">${d.unmeasured.length}</span></div>
</div>

<table><thead><tr><th>Gravité</th><th>Ce relevé</th><th>Relevé précédent</th><th>Évolution</th></tr></thead><tbody>
${d.counts
  .map(
    (c) =>
      `<tr><td class="sev" style="color:${SEV_COLOR[c.severity]}">${SEV_FR[c.severity]}</td><td class="num">${c.current}</td><td class="num">${
        d.hasBaseline ? c.previous : "—"
      }</td><td class="num" style="color:${
        c.delta > 0 ? SEV_COLOR.critical : c.delta < 0 ? SEV_COLOR.low : "#5c6675"
      }">${d.hasBaseline ? (c.delta === 0 ? "=" : signed(c.delta)) : "—"}</td></tr>`,
  )
  .join("")}
</tbody></table>

<h2>2 · Corrigé depuis le dernier relevé</h2>
${
  !d.hasBaseline
    ? `<p>Sans relevé de référence, rien ne peut être déclaré corrigé.</p>`
    : d.fixed.length === 0
      ? `<p>Aucun point fermé depuis le relevé du ${esc(fmtDay(d.previousAt))}.</p>`
      : `<p>${spellFr(d.fixed.length)} point${d.fixed.length > 1 ? "s" : ""} présent${
          d.fixed.length > 1 ? "s" : ""
        } au relevé précédent ${d.fixed.length > 1 ? "ne sont" : "n'est"} plus détecté${
          d.fixed.length > 1 ? "s" : ""
        }, par un contrôle qui a bien été rejoué. La colonne d'ancienneté indique le temps écoulé entre la première apparition et la fermeture.</p>
${rows(d.fixed, "Resté ouvert")}`
}

<h2>3 · Nouveau depuis le dernier relevé</h2>
${
  !d.hasBaseline
    ? `<p>Sans relevé de référence, aucun point ne peut être déclaré nouveau : les ${d.persisting.length} points ouverts constituent l'état de départ.</p>`
    : d.introduced.length === 0
      ? `<p>Aucun point nouveau depuis le relevé du ${esc(fmtDay(d.previousAt))}.</p>`
      : `<p>Ces empreintes n'existaient pas au relevé précédent. Un intitulé identique à un point ancien reste un point NOUVEAU si son empreinte diffère — c'est le cas quand le défaut a été déplacé plutôt que corrigé.</p>
${rows(d.introduced)}`
}

<h2>4 · Toujours ouvert, et depuis quand</h2>
${
  d.persisting.length === 0
    ? `<p>Aucun point ouvert de part et d'autre.</p>`
    : `<p>L'ancienneté est la mesure de gouvernance de cette section. Un point moyen ouvert depuis un an documente une manière de traiter le risque ; un point critique ouvert depuis trois jours documente une semaine chargée.</p>
${rows(d.persisting)}
${
  d.oldestOpen?.ageDays != null
    ? `<p class="kv">Point ouvert le plus ancien : ${esc(frenchDuration(d.oldestOpen.ageDays))} (${esc(
        SEV_FR[d.oldestOpen.severity],
      )}, ${esc(pillarLabel(d.oldestOpen.pillar))}).</p>`
    : ""
}`
}

<h2>5 · Risque accepté et faux positifs assumés</h2>
<p>Ces points ne sont pas comptés dans les totaux ouverts. Ils sont listés parce qu'une décision de ne pas corriger n'a de valeur que si elle est écrite, datée et relue au relevé suivant.</p>
${
  d.accepted.length === 0 && d.falsePositives.length === 0
    ? `<p>Aucune décision de triage enregistrée sur ce périmètre.</p>`
    : `${
        d.accepted.length
          ? `<h3>Risque accepté — ${d.accepted.length}</h3>${rows(d.accepted)}`
          : ""
      }${
        d.falsePositives.length
          ? `<h3>Faux positifs assumés — ${d.falsePositives.length}</h3>${rows(d.falsePositives)}
<p class="kv">Un faux positif qui disparaît d'un relevé n'est jamais compté comme une correction : il n'y avait rien à corriger.</p>`
          : ""
      }`
}

<h2>6 · Délai de correction des points critiques</h2>
${
  d.meanTimeToFixCriticalDays != null
    ? `<p>Délai moyen constaté : <strong>${esc(
        frenchDuration(d.meanTimeToFixCriticalDays),
      )}</strong>, mesuré sur ${spellFr(d.fixedCriticalSample)} point${
        d.fixedCriticalSample > 1 ? "s" : ""
      } critique${d.fixedCriticalSample > 1 ? "s" : ""} fermé${d.fixedCriticalSample > 1 ? "s" : ""}.</p>
<p class="kv">C'est une <strong>borne supérieure</strong>, et elle doit être lue comme telle : l'instrument connaît le relevé qui a cessé de voir le défaut, pas le commit qui l'a réparé. L'intervalle réel est contenu dans celui-ci. Un échantillon de ${
        d.fixedCriticalSample
      } ${d.fixedCriticalSample > 1 ? "points" : "point"} ne fait pas une statistique ; il fait un ordre de grandeur.</p>`
    : `<p>Aucun point critique n'a été fermé entre les deux relevés — le délai moyen n'est donc pas défini. Il n'est pas de zéro.</p>`
}
${
  openBySeverity("critical") > 0
    ? `<div class="warn"><span class="lbl">Compteur en cours</span><br>${spellFr(
        openBySeverity("critical"),
      )} point${openBySeverity("critical") > 1 ? "s" : ""} critique${
        openBySeverity("critical") > 1 ? "s" : ""
      } ${openBySeverity("critical") > 1 ? "restent" : "reste"} ouvert${
        openBySeverity("critical") > 1 ? "s" : ""
      } à la date de ce relevé. Leur délai de correction n'est pas encore mesurable ; il court.</div>`
    : ""
}

<h2>7 · Ce que cette comparaison ne dit pas</h2>
<ul>
  <li>La comparaison se fait par <strong>empreinte de contenu</strong> (outil, règle, emplacement normalisé, ou composant et version pour les dépendances). Elle survit à un renommage de fichier et à un décalage de lignes ; elle ne survit pas à une réécriture profonde, où un même défaut apparaît comme fermé puis rouvert.</li>
  ${
    d.unmeasured.length
      ? `<li><strong>${d.unmeasured.length} point${d.unmeasured.length > 1 ? "s" : ""} classé${
          d.unmeasured.length > 1 ? "s" : ""
        } « non mesuré${d.unmeasured.length > 1 ? "s" : ""} »</strong> : présent${
          d.unmeasured.length > 1 ? "s" : ""
        } au relevé précédent, absent${d.unmeasured.length > 1 ? "s" : ""} de celui-ci, mais issu${
          d.unmeasured.length > 1 ? "s" : ""
        } d'un contrôle qui n'a pas été rejoué. Les compter comme corrigés ferait passer une panne de moteur pour un progrès. ${
          d.unmeasured.length > 1 ? "Les voici" : "Le voici"
        }, nommé${d.unmeasured.length > 1 ? "s" : ""} plutôt que résumé${
          d.unmeasured.length > 1 ? "s" : ""
        } à un compteur :</li>`
      : ""
  }
  ${
    notMeasured.length
      ? `<li>Contrôles demandés sans mesure produite sur ce relevé : ${esc(
          notMeasured.map(pillarLabel).join(", "),
        )}. La comparaison est aveugle sur ces domaines.</li>`
      : ""
  }
  <li>Un point fermé signifie « plus détecté par ces moteurs, dans cette version, à cette date ». Ce n'est pas une preuve de correction, et cela n'a jamais été mesuré par une contre-vérification humaine.</li>
  <li>La direction de la tendance est calculée sur les mêmes poids de gravité que la note (critique 40, élevé 20, moyen 8, faible 3, information 0,5), afin qu'un afflux de points mineurs ne puisse pas masquer la fermeture d'un point majeur — ni l'inverse.</li>
</ul>
${d.unmeasured.length ? rows(d.unmeasured, "Vu ouvert pendant") : ""}

<div class="foot">
  Rapport de progression · relevé <span class="mono">${esc(r.runId)}</span>${
    r.commitSha ? ` · commit <span class="mono">${esc(r.commitSha.slice(0, 12))}</span>` : ""
  } · barème ${esc(r.scoringVersion ?? "non déclaré")} · émis le ${esc(fmtDay(r.generatedAt))}.
  Ce document nomme des défauts sans les localiser ni les reproduire ; il reste néanmoins confidentiel.
</div>
</body></html>`;
}
