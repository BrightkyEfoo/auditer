"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { api, type Repo } from "@/lib/api";

const ALL_PILLARS = [
  { id: "secrets", label: "Secrets", ready: true },
  { id: "sca", label: "CVE / Dependencies", ready: true },
  { id: "sast", label: "SAST + Quality", ready: false },
  { id: "hygiene", label: "Repo hygiene / IaC", ready: false },
  { id: "dast", label: "DAST (pentest)", ready: false },
  { id: "ux", label: "UX / perf / a11y", ready: false },
];

export default function Dashboard() {
  const router = useRouter();
  const [repos, setRepos] = useState<Repo[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [repoId, setRepoId] = useState<string>("");
  const [pillars, setPillars] = useState<string[]>(["secrets", "sca"]);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api.listRepos().then(setRepos).catch((e) => setError(String(e)));
  }, []);

  function toggle(p: string) {
    setPillars((cur) => (cur.includes(p) ? cur.filter((x) => x !== p) : [...cur, p]));
  }

  async function run() {
    if (!repoId || pillars.length === 0) return;
    setBusy(true);
    try {
      const { runId } = await api.createAudit({ repositoryId: repoId, pillars });
      router.push(`/audits/${runId}`);
    } catch (e) {
      setError(String(e));
      setBusy(false);
    }
  }

  return (
    <main className="space-y-8">
      <section>
        <h1 className="mb-1 text-2xl font-semibold">Run an audit</h1>
        <p className="text-sm text-neutral-500">
          Connect a repo, pick pillars, and get a triaged report.
        </p>
      </section>

      {error && (
        <div className="rounded-md border border-red-300 bg-red-50 p-3 text-sm text-red-700">
          {error}
        </div>
      )}

      <section className="space-y-3">
        <label className="block text-sm font-medium">Repository</label>
        {repos.length === 0 ? (
          <p className="text-sm text-neutral-500">
            No repositories imported yet. Connect a VCS provider and import one.
          </p>
        ) : (
          <select
            value={repoId}
            onChange={(e) => setRepoId(e.target.value)}
            className="w-full max-w-md rounded-md border border-neutral-300 bg-white px-3 py-2 text-sm dark:bg-neutral-900"
          >
            <option value="">Select a repository…</option>
            {repos.map((r) => (
              <option key={r.id} value={r.id}>
                {r.fullName} {r.primaryLanguage ? `(${r.primaryLanguage})` : ""}
              </option>
            ))}
          </select>
        )}
      </section>

      <section className="space-y-3">
        <label className="block text-sm font-medium">Pillars</label>
        <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
          {ALL_PILLARS.map((p) => (
            <button
              key={p.id}
              onClick={() => toggle(p.id)}
              className={`rounded-md border px-3 py-2 text-left text-sm transition ${
                pillars.includes(p.id)
                  ? "border-neutral-900 bg-neutral-900 text-white dark:border-white dark:bg-white dark:text-black"
                  : "border-neutral-300 bg-white dark:bg-neutral-900"
              }`}
            >
              <div className="font-medium">{p.label}</div>
              <div className="text-xs opacity-70">{p.ready ? "v1" : "coming"}</div>
            </button>
          ))}
        </div>
      </section>

      <button
        onClick={run}
        disabled={busy || !repoId || pillars.length === 0}
        className="rounded-md bg-neutral-900 px-5 py-2.5 text-sm font-medium text-white disabled:opacity-40 dark:bg-white dark:text-black"
      >
        {busy ? "Queuing…" : "Run audit"}
      </button>
    </main>
  );
}
