import type { Finding, RunScore, ExecutiveSummary } from "@auditer/types";
import { ExecutiveSummary as ExecutiveSummarySchema } from "@auditer/types";
import { AiClient, MODELS } from "./client.js";

/**
 * Executive report synthesis (Opus tier). Narrates over the DETERMINISTIC score
 * + deduped findings. It never invents findings or recomputes the score — the
 * grade is passed in and the model must echo it.
 */

const REPORT_TOOL_SCHEMA: Record<string, unknown> = {
  type: "object",
  additionalProperties: false,
  required: ["headline", "overallGrade", "riskPosture", "keyRisks", "remediationRoadmap"],
  properties: {
    headline: { type: "string" },
    overallGrade: { type: "string", enum: ["A", "B", "C", "D", "F"] },
    riskPosture: { type: "string" },
    keyRisks: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: ["title", "severity", "why"],
        properties: {
          title: { type: "string" },
          severity: { type: "string", enum: ["critical", "high", "medium", "low", "info"] },
          why: { type: "string" },
        },
      },
    },
    remediationRoadmap: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: ["step", "effort", "impact"],
        properties: {
          step: { type: "string" },
          effort: { type: "string", enum: ["low", "medium", "high"] },
          impact: { type: "string", enum: ["low", "medium", "high"] },
        },
      },
    },
  },
};

const SYSTEM = `You are a principal security auditor writing the executive summary of a professional audit report.

You are given a DETERMINISTIC overall grade + score and the top findings (already deduplicated and severity-ranked). Write the summary for a technical decision-maker.

Hard rules:
- The grade is authoritative. Echo overallGrade exactly as given; do not re-grade.
- Do not invent findings, CVEs, or numbers not present in the input.
- Prioritize by real-world risk. Be direct and specific.
- Order the remediation roadmap most-impactful-first.
- Return only the structured tool call.`;

/**
 * Only ever called for a graded run — orchestrator.ts refuses to synthesise a
 * summary when `score.overall` is null, because an audit that measured nothing
 * has nothing to summarise. The non-null assertions below rest on that gate.
 */
function buildContext(score: RunScore, top: Finding[]): string {
  const lines: string[] = [
    `OVERALL GRADE: ${score.grade} (score ${score.overall}/100, scoring v${score.scoringVersion})`,
    // State the normalization, including when it did not happen: an unqualified
    // grade over an assumed repo size would read as a measured one.
    score.klocSource === "measured"
      ? `Size: ${score.kloc.toFixed(1)} kLOC (measured) — the score is density-normalized for this size.`
      : `Size: NOT MEASURED (the quality pillar did not run). The score used a ${score.kloc} kLOC placeholder, so it is not size-normalized — say so if you comment on repository size.`,
    `Severity totals: ${JSON.stringify(score.counts)}`,
    `Pillar grades: ${score.pillars.map((p) => `${p.pillar}=${p.grade}(${p.score})`).join(", ")}`,
    "",
    "TOP FINDINGS (deduped, ranked):",
  ];
  for (const f of top.slice(0, 25)) {
    lines.push(
      `- [${f.severity}] ${f.title} (${f.tool}, ${f.pillar})` +
        (f.vulnIds.length ? ` ${f.vulnIds.join(",")}` : "") +
        (f.ai?.explanation ? ` — ${f.ai.explanation.slice(0, 200)}` : ""),
    );
  }
  return lines.join("\n");
}

export async function synthesizeReport(
  ai: AiClient,
  score: RunScore,
  topFindings: Finding[],
): Promise<ExecutiveSummary> {
  const raw = await ai.structured<Record<string, unknown>>({
    tier: "synth",
    system: SYSTEM,
    cacheSystem: false,
    userContent: buildContext(score, topFindings),
    toolName: "write_executive_summary",
    toolDescription: "Write the executive summary of the audit report.",
    inputSchema: REPORT_TOOL_SCHEMA,
    maxTokens: 4000,
  });

  const parsed = ExecutiveSummarySchema.safeParse({
    ...raw,
    overallGrade: score.grade!, // force authoritative grade regardless of model
    model: MODELS.synth,
  });
  if (!parsed.success) {
    return {
      headline: `Audit complete — overall grade ${score.grade}.`,
      overallGrade: score.grade!,
      riskPosture: "Automated summary unavailable; see findings below.",
      keyRisks: [],
      remediationRoadmap: [],
      model: MODELS.synth,
    };
  }
  return parsed.data;
}
