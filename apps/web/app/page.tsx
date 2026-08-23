"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import {
  api,
  type Repo,
  type Connection,
  type RemoteRepo,
} from "@/lib/api";

const ALL_PILLARS = [
  { id: "secrets", label: "Secrets", ready: true },
  { id: "sca", label: "CVE / Dependencies", ready: true },
  { id: "sast", label: "SAST + Quality", ready: true },
  { id: "quality", label: "Code quality", ready: true },
  { id: "hygiene", label: "Repo hygiene / IaC", ready: true },
  { id: "dast", label: "DAST (pentest)", ready: true },
  { id: "ux", label: "UX / perf / a11y", ready: true },
];

export default function Dashboard() {
  const router = useRouter();
  const [connections, setConnections] = useState<Connection[]>([]);
  const [repos, setRepos] = useState<Repo[]>([]);
  const [remoteRepos, setRemoteRepos] = useState<RemoteRepo[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [repoId, setRepoId] = useState<string>("");
  const [pillars, setPillars] = useState<string[]>(["secrets", "sca"]);
  const [busy, setBusy] = useState(false);

  function refresh() {
    api.listConnections().then(setConnections).catch(() => {});
    api.listRepos().then(setRepos).catch((e) => setError(String(e)));
  }
  useEffect(refresh, []);

  async function browse(connectionId: string) {
    setError(null);
    try {
      setRemoteRepos(await api.listConnectionRepos(connectionId));
    } catch (e) {
      setError(String(e));
    }
  }

  async function importRepo(connectionId: string, r: RemoteRepo) {
    try {
      await api.importConnectionRepo(connectionId, r);
      refresh();
    } catch (e) {
      setError(String(e));
    }
  }

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
          Connect GitHub, import a repo, pick pillars, get a triaged report.
        </p>
      </section>

      {error && (
        <div className="rounded-md border border-red-300 bg-red-50 p-3 text-sm text-red-700">
          {error}
        </div>
      )}

      {/* 1. Connect */}
      <section className="space-y-3">
        <h2 className="text-sm font-medium">1 · Connect a provider</h2>
        {connections.length === 0 ? (
          <div className="flex flex-wrap gap-2">
            <a
              href="/api/connections/github/install"
              className="inline-flex items-center gap-2 rounded-md bg-neutral-900 px-4 py-2 text-sm font-medium text-white dark:bg-white dark:text-black"
            >
              Connect GitHub
            </a>
            <a
              href="/api/connections/gitlab/connect"
              className="inline-flex items-center gap-2 rounded-md border border-neutral-300 px-4 py-2 text-sm font-medium"
            >
              Connect GitLab
            </a>
          </div>
        ) : (
          <div className="space-y-2">
            {connections.map((c) => (
              <div
                key={c.id}
                className="flex items-center justify-between rounded-md border border-neutral-200 px-4 py-2 text-sm dark:border-neutral-800"
              >
                <span>
                  {c.provider} · {c.externalAccountId ?? c.kind}{" "}
                  <span className="text-neutral-400">({c.status})</span>
                </span>
                <button
                  onClick={() => browse(c.id)}
                  className="rounded border border-neutral-300 px-2 py-1 text-xs"
                >
                  Browse repos
                </button>
              </div>
            ))}
            <a href="/api/connections/github/install" className="text-xs text-neutral-500 underline">
              + connect another
            </a>
          </div>
        )}
      </section>

      {/* 2. Import remote repos */}
      {remoteRepos.length > 0 && (
        <section className="space-y-2">
          <h2 className="text-sm font-medium">2 · Import a repo</h2>
          <div className="max-h-56 space-y-1 overflow-auto">
            {remoteRepos.map((r) => (
              <div
                key={r.externalRepoId}
                className="flex items-center justify-between rounded border border-neutral-200 px-3 py-1.5 text-sm dark:border-neutral-800"
              >
                <span>
                  {r.fullName}{" "}
                  <span className="text-neutral-400">
                    {r.visibility}
                    {r.primaryLanguage ? ` · ${r.primaryLanguage}` : ""}
                  </span>
                </span>
                <button
                  onClick={() => importRepo(connections[0]!.id, r)}
                  className="rounded border border-neutral-300 px-2 py-0.5 text-xs"
                >
                  Import
                </button>
              </div>
            ))}
          </div>
        </section>
      )}

      {/* 3. Pick imported repo + pillars */}
      <section className="space-y-3">
        <h2 className="text-sm font-medium">3 · Audit an imported repo</h2>
        {repos.length === 0 ? (
          <p className="text-sm text-neutral-500">No repositories imported yet.</p>
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

        <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
          {ALL_PILLARS.map((p) => (
            <button
              key={p.id}
              onClick={() => toggle(p.id)}
              className={`rounded-md border px-3 py-2 text-left text-xs transition ${
                pillars.includes(p.id)
                  ? "border-neutral-900 bg-neutral-900 text-white dark:border-white dark:bg-white dark:text-black"
                  : "border-neutral-300 bg-white dark:bg-neutral-900"
              }`}
            >
              <div className="font-medium">{p.label}</div>
            </button>
          ))}
        </div>

        <button
          onClick={run}
          disabled={busy || !repoId || pillars.length === 0}
          className="rounded-md bg-neutral-900 px-5 py-2.5 text-sm font-medium text-white disabled:opacity-40 dark:bg-white dark:text-black"
        >
          {busy ? "Queuing…" : "Run audit"}
        </button>
      </section>
    </main>
  );
}
