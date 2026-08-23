import type { ExecutiveSummary, Severity } from "@auditer/types";

/**
 * Builds a self-contained, print-ready HTML audit report from the deterministic
 * score + AI executive summary + findings. Self-contained (inline CSS, no
 * assets) so it renders identically as a stored artifact or when a browser
 * prints it to PDF. AI-authored sections are labeled.
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
  scanners: { tool: string; pillar: string }[];
  generatedAt: string;
}

const SEV_COLOR: Record<Severity, string> = {
  critical: "#dc2626",
  high: "#ea580c",
  medium: "#d97706",
  low: "#65a30d",
  info: "#6b7280",
};
const SEV_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

function esc(s: string): string {
  return s.replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!,
  );
}

export function buildReportHtml(r: ReportInput): string {
  const counts = SEV_ORDER.map((s) => ({
    s,
    n: r.findings.filter((f) => f.severity === s).length,
  }));

  const findingsBySev = [...r.findings].sort(
    (a, b) => SEV_ORDER.indexOf(a.severity as Severity) - SEV_ORDER.indexOf(b.severity as Severity),
  );

  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"/>
<title>Audit report — ${esc(r.fullName ?? r.runId)}</title>
<style>
  @page { margin: 20mm; }
  * { box-sizing: border-box; }
  body { font: 14px/1.55 -apple-system, Segoe UI, Roboto, sans-serif; color: #111827; margin: 0; padding: 32px; }
  h1 { font-size: 26px; margin: 0 0 4px; }
  h2 { font-size: 18px; margin: 28px 0 10px; border-bottom: 1px solid #e5e7eb; padding-bottom: 4px; }
  .muted { color: #6b7280; font-size: 12px; }
  .score { display: flex; align-items: baseline; gap: 12px; margin: 16px 0; }
  .score .n { font-size: 48px; font-weight: 800; }
  .counts { display: flex; gap: 8px; flex-wrap: wrap; margin: 12px 0; }
  .chip { color: #fff; border-radius: 999px; padding: 3px 10px; font-size: 12px; font-weight: 600; }
  .pillars { width: 100%; border-collapse: collapse; margin: 8px 0; }
  .pillars td, .pillars th { text-align: left; padding: 6px 8px; border-bottom: 1px solid #f3f4f6; font-size: 13px; }
  .finding { border: 1px solid #e5e7eb; border-radius: 8px; padding: 12px 14px; margin: 10px 0; page-break-inside: avoid; }
  .finding .head { display: flex; align-items: center; gap: 8px; }
  .dot { width: 10px; height: 10px; border-radius: 999px; display: inline-block; }
  .ai { border-left: 3px solid #2563eb; background: #eff6ff; padding: 8px 12px; margin-top: 8px; border-radius: 4px; }
  .ai .label { font-size: 10px; font-weight: 700; text-transform: uppercase; color: #1d4ed8; letter-spacing: .04em; }
  code { background: #f3f4f6; padding: 1px 4px; border-radius: 3px; font-size: 12px; }
  .roadmap li { margin: 4px 0; }
</style></head>
<body>
  <h1>Security audit report</h1>
  <div class="muted">${esc(r.fullName ?? "")}${r.commitSha ? ` · commit ${esc(r.commitSha.slice(0, 8))}` : ""} · run ${esc(r.runId)} · ${esc(r.generatedAt)}</div>

  <div class="score">
    <span class="n">${r.riskScore ?? "—"}</span>
    <span class="muted">overall risk score${r.scoringVersion ? ` · scoring v${esc(r.scoringVersion)}` : ""}</span>
  </div>

  <div class="counts">
    ${counts
      .map(
        (c) =>
          `<span class="chip" style="background:${SEV_COLOR[c.s]}">${c.s}: ${c.n}</span>`,
      )
      .join("")}
  </div>

  ${
    r.summary
      ? `<h2>Executive summary <span class="muted">(AI-authored · ${esc(r.summary.model)})</span></h2>
  <p>${esc(r.summary.headline)}</p>
  <p>${esc(r.summary.riskPosture)}</p>
  ${
    r.summary.keyRisks.length
      ? `<h3>Key risks</h3><ul>${r.summary.keyRisks
          .map((k) => `<li><b>[${esc(k.severity)}]</b> ${esc(k.title)} — ${esc(k.why)}</li>`)
          .join("")}</ul>`
      : ""
  }
  ${
    r.summary.remediationRoadmap.length
      ? `<h3>Remediation roadmap</h3><ol class="roadmap">${r.summary.remediationRoadmap
          .map((s) => `<li>${esc(s.step)} <span class="muted">(effort ${esc(s.effort)}, impact ${esc(s.impact)})</span></li>`)
          .join("")}</ol>`
      : ""
  }`
      : ""
  }

  <h2>Scope &amp; methodology</h2>
  <table class="pillars">
    <tr><th>Pillar</th><th>Score</th><th>Grade</th></tr>
    ${r.pillars
      .map((p) => `<tr><td>${esc(p.pillar)}</td><td>${p.score}</td><td>${esc(p.grade)}</td></tr>`)
      .join("")}
  </table>
  <p class="muted">Scanners: ${r.scanners.map((s) => `${esc(s.tool)} (${esc(s.pillar)})`).join(", ") || "—"}.
  Vulnerability databases reflect their snapshot at scan time — coverage is best-effort, not exhaustive.</p>

  <h2>Findings (${r.findings.length})</h2>
  ${
    findingsBySev
      .map(
        (f) => `<div class="finding">
      <div class="head">
        <span class="dot" style="background:${SEV_COLOR[(f.severity as Severity) ?? "info"]}"></span>
        <b>${esc(f.title)}</b>
        <span class="muted">${esc(f.tool)}${f.cvssScore != null ? ` · CVSS ${f.cvssScore}` : ""}${f.vulnIds.length ? ` · ${esc(f.vulnIds.join(", "))}` : ""}</span>
      </div>
      <p class="muted">${esc(f.description)}</p>
      ${
        f.aiExplanation
          ? `<div class="ai"><div class="label">AI assessment${f.aiNeedsHuman ? " · needs human review" : ""}</div>
             <div>${esc(f.aiExplanation)}</div>${f.aiRemediation ? `<div><b>Fix:</b> ${esc(f.aiRemediation)}</div>` : ""}</div>`
          : ""
      }
    </div>`,
      )
      .join("") || "<p class='muted'>No findings.</p>"
  }
</body></html>`;
}
