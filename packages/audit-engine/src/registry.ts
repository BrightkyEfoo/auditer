import type { Pillar } from "@auditer/types";
import type { ScannerAdapter } from "./ports/adapter.js";
import { GitleaksAdapter } from "./scanners/gitleaks.js";
import { OsvScannerAdapter } from "./scanners/osv-scanner.js";
import { SemgrepAdapter } from "./scanners/semgrep.js";
import { JscpdAdapter } from "./scanners/jscpd.js";
import { SccAdapter } from "./scanners/scc.js";
import { TrivyConfigAdapter } from "./scanners/trivy-config.js";
import { HadolintAdapter } from "./scanners/hadolint.js";
import { NucleiAdapter } from "./scanners/nuclei.js";
import { LighthouseAdapter } from "./scanners/lighthouse.js";

/**
 * ScannerRegistry — the plugin catalog. Each new pillar/tool registers one
 * adapter here; the orchestrator resolves adapters by id or pillar and stays
 * scanner-agnostic. Wave 2/3 adapters (Semgrep, Trivy, ZAP, Lighthouse, ...)
 * slot in with no orchestrator change.
 */
export class ScannerRegistry {
  private readonly byId = new Map<string, ScannerAdapter>();

  register(adapter: ScannerAdapter): this {
    this.byId.set(adapter.id, adapter);
    return this;
  }

  get(id: string): ScannerAdapter | undefined {
    return this.byId.get(id);
  }

  all(): ScannerAdapter[] {
    return [...this.byId.values()];
  }

  /** Adapters for the requested pillars, in registration order. */
  forPillars(pillars: Pillar[]): ScannerAdapter[] {
    const set = new Set(pillars);
    return this.all().filter((a) => set.has(a.pillar));
  }
}

/** The default registry with all currently-shipped adapters (Wave 1 + 2). */
export function defaultRegistry(): ScannerRegistry {
  return new ScannerRegistry()
    // Wave 1 — no-network, lead the v1
    .register(new GitleaksAdapter()) // secrets
    .register(new OsvScannerAdapter()) // sca
    // Wave 2 — static analysis
    .register(new SemgrepAdapter()) // sast
    .register(new JscpdAdapter()) // quality — duplication
    .register(new SccAdapter()) // quality — LOC/complexity metrics (feeds kLOC)
    .register(new TrivyConfigAdapter()) // hygiene
    .register(new HadolintAdapter()) // hygiene
    // Wave 3 — network pillars (verified targets + egress-scoped only)
    .register(new NucleiAdapter()) // dast
    .register(new LighthouseAdapter()); // ux
}
