"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import { PageHead } from "@/components/app/shell";
import { Button, ButtonLink, Chip, Empty, Label, Spinner, inputClass } from "@/components/ui";
import { PILLARS } from "@/lib/content";
import { api, type Connection, type RemoteRepo, type Repo } from "@/lib/api";
import { cn } from "@/lib/cn";

const PROVIDER_FR: Record<string, string> = {
  github_app: "GitHub",
  gitlab_oauth: "GitLab",
  gitlab_pat: "GitLab (jeton)",
};

/**
 * The working page: connect a provider, import repositories, configure and
 * launch a run. Kept as one screen because it is one task — splitting it across
 * routes would turn a four-minute job into four navigations.
 */
export default function ReposPage() {
  const router = useRouter();
  const [connections, setConnections] = useState<Connection[] | null>(null);
  const [repos, setRepos] = useState<Repo[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Import drawer state, scoped to the connection actually being browsed —
  // importing into "the first connection" is wrong the moment there are two.
  const [browsing, setBrowsing] = useState<Connection | null>(null);
  const [remote, setRemote] = useState<RemoteRepo[] | null>(null);
  const [query, setQuery] = useState("");
  const [importing, setImporting] = useState<string | null>(null);

  const [selected, setSelected] = useState<Repo | null>(null);
  const [pillars, setPillars] = useState<string[]>(["secrets", "sca"]);
  const [busy, setBusy] = useState(false);

  // Two-step deletion, held in the page rather than in a `confirm()` dialog —
  // the row stays visible while its removal is being confirmed, and the project
  // forbids native dialogs anyway.
  const [armed, setArmed] = useState<string | null>(null);
  const [deleting, setDeleting] = useState<string | null>(null);

  const refresh = useCallback(() => {
    api.listConnections().then(setConnections).catch(() => setConnections([]));
    api
      .listRepos()
      .then(setRepos)
      .catch((e) => {
        setRepos([]);
        setError(String(e));
      });
  }, []);
  useEffect(refresh, [refresh]);

  async function browse(c: Connection) {
    setBrowsing(c);
    setRemote(null);
    setError(null);
    try {
      setRemote(await api.listConnectionRepos(c.id));
    } catch (e) {
      setError(String(e));
      setRemote([]);
    }
  }

  async function importRepo(r: RemoteRepo) {
    if (!browsing) return;
    setImporting(r.externalRepoId);
    try {
      await api.importConnectionRepo(browsing.id, r);
      refresh();
    } catch (e) {
      setError(String(e));
    } finally {
      setImporting(null);
    }
  }

  /** Removes the repository AND its runs — the api deletes both, say so above. */
  async function removeRepo(r: Repo) {
    setDeleting(r.id);
    setError(null);
    try {
      await api.deleteRepo(r.id);
      // The configurator points at a row that no longer exists.
      setSelected((cur) => (cur?.id === r.id ? null : cur));
      refresh();
    } catch (e) {
      setError(String(e));
    } finally {
      setDeleting(null);
      setArmed(null);
    }
  }

  async function run() {
    if (!selected || pillars.length === 0) return;
    setBusy(true);
    setError(null);
    try {
      const { runId } = await api.createAudit({ repositoryId: selected.id, pillars });
      router.push(`/audits/${runId}`);
    } catch (e) {
      setError(String(e));
      setBusy(false);
    }
  }

  const imported = useMemo(
    () => new Set((repos ?? []).map((r) => r.fullName)),
    [repos],
  );
  const filtered = (remote ?? []).filter((r) =>
    r.fullName.toLowerCase().includes(query.trim().toLowerCase()),
  );
  const networkPillars = pillars.filter((p) => PILLARS.find((x) => x.id === p)?.network);

  return (
    <>
      <PageHead
        index="02"
        title="Dépôts"
        lede="Connectez un fournisseur, importez les dépôts à suivre, puis lancez un relevé."
      />

      {error && (
        <div className="border-b border-critical/40 bg-critical/5 px-6 py-3 lg:px-10">
          <p role="alert" className="font-mono text-data text-critical">
            {error}
          </p>
        </div>
      )}

      {/* ── Connections ────────────────────────────────────────────────── */}
      <section className="border-b border-line px-6 py-8 lg:px-10">
        <div className="flex items-baseline justify-between">
          <h2 className="h-md">Fournisseurs connectés</h2>
          <div className="flex gap-3">
            <ButtonLink href="/api/connections/github/install" size="sm">
              + GitHub
            </ButtonLink>
            <ButtonLink href="/api/connections/gitlab/connect" size="sm">
              + GitLab
            </ButtonLink>
          </div>
        </div>

        <div className="mt-6">
          {connections === null ? (
            <Spinner label="chargement des connexions" />
          ) : connections.length === 0 ? (
            <Empty
              title="Aucun fournisseur connecté"
              body="auditer n'accède qu'aux dépôts que vous désignez explicitement. L'installation GitHub vous laisse choisir dépôt par dépôt ; GitLab utilise une autorisation en lecture seule."
              action={
                <ButtonLink href="/api/connections/github/install" variant="primary">
                  Connecter GitHub
                </ButtonLink>
              }
            />
          ) : (
            <ul className="border-t border-line">
              {connections.map((c) => (
                <li
                  key={c.id}
                  className="flex flex-wrap items-center justify-between gap-4 border-b border-line py-4"
                >
                  <div className="flex items-center gap-4">
                    <span
                      aria-hidden
                      className={cn(
                        "h-1.5 w-1.5",
                        c.status === "active" ? "bg-acid" : "bg-high",
                      )}
                    />
                    <div>
                      <p className="font-mono text-data text-mineral">
                        {PROVIDER_FR[c.provider] ?? c.provider}
                        {c.externalAccountId ? ` · ${c.externalAccountId}` : ""}
                      </p>
                      <p className="mt-0.5 font-mono text-label uppercase text-mute">
                        état : {c.status}
                      </p>
                    </div>
                  </div>
                  <Button size="sm" onClick={() => browse(c)}>
                    Parcourir les dépôts
                  </Button>
                </li>
              ))}
            </ul>
          )}
        </div>
      </section>

      {/* ── Import drawer ──────────────────────────────────────────────── */}
      {browsing && (
        <section className="border-b border-line bg-slate px-6 py-8 lg:px-10">
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div>
              <Label className="text-acid">Importer depuis</Label>
              <p className="mt-1.5 font-mono text-data text-mineral">
                {PROVIDER_FR[browsing.provider] ?? browsing.provider}
                {browsing.externalAccountId ? ` · ${browsing.externalAccountId}` : ""}
              </p>
            </div>
            <Button variant="quiet" onClick={() => setBrowsing(null)}>
              Fermer
            </Button>
          </div>

          <input
            className={cn(inputClass, "mt-5 max-w-md")}
            placeholder="Filtrer par nom…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            aria-label="Filtrer les dépôts distants"
          />

          <div className="mt-5 max-h-80 overflow-auto border-t border-line">
            {remote === null ? (
              <div className="py-6">
                <Spinner label="lecture des dépôts distants" />
              </div>
            ) : filtered.length === 0 ? (
              <p className="py-6 font-mono text-label uppercase text-mute">
                {remote.length === 0 ? "aucun dépôt accessible" : "aucun dépôt ne correspond"}
              </p>
            ) : (
              <ul>
                {filtered.map((r) => {
                  const already = imported.has(r.fullName);
                  return (
                    <li
                      key={r.externalRepoId}
                      className="flex items-center justify-between gap-4 border-b border-line py-3"
                    >
                      <div className="min-w-0">
                        <p className="truncate font-mono text-data text-mineral">{r.fullName}</p>
                        <p className="mt-0.5 font-mono text-label uppercase text-mute">
                          {r.visibility}
                          {r.primaryLanguage ? ` · ${r.primaryLanguage}` : ""}
                        </p>
                      </div>
                      {already ? (
                        <Chip tone="acid">importé</Chip>
                      ) : (
                        <Button
                          size="sm"
                          disabled={importing === r.externalRepoId}
                          onClick={() => importRepo(r)}
                        >
                          {importing === r.externalRepoId ? "…" : "Importer"}
                        </Button>
                      )}
                    </li>
                  );
                })}
              </ul>
            )}
          </div>
        </section>
      )}

      {/* ── Imported repos + run configurator ──────────────────────────── */}
      <section className="grid grid-cols-12 gap-y-10">
        <div className="col-span-12 px-6 py-8 lg:col-span-7 lg:border-r lg:border-line lg:px-10">
          <h2 className="h-md">Dépôts suivis</h2>

          <div className="mt-6">
            {repos === null ? (
              <Spinner label="chargement des dépôts" />
            ) : repos.length === 0 ? (
              <Empty
                title="Aucun dépôt importé"
                body="Parcourez un fournisseur connecté ci-dessus pour importer vos premiers dépôts."
              />
            ) : (
              <ul className="border-t border-line">
                {repos.map((r) => {
                  const active = selected?.id === r.id;
                  const isArmed = armed === r.id;
                  return (
                    // The row is a <li> flex container, not one big <button>:
                    // the delete control is a second button and buttons cannot
                    // nest.
                    <li
                      key={r.id}
                      className={cn(
                        "group relative flex items-center gap-3 border-b border-line pr-1 transition-colors duration-[180ms]",
                        active ? "bg-slate" : "hover:bg-slate/60",
                      )}
                    >
                      <span
                        aria-hidden
                        className={cn(
                          "absolute inset-y-0 left-0 w-px origin-top bg-acid transition-transform duration-300 ease-out",
                          active ? "scale-y-100" : "scale-y-0 group-hover:scale-y-100",
                        )}
                      />
                      <button
                        onClick={() => setSelected(active ? null : r)}
                        aria-pressed={active}
                        className="flex min-w-0 flex-1 items-center justify-between gap-4 py-4 pl-4 text-left"
                      >
                        <span className="min-w-0">
                          <span className="block truncate font-mono text-data text-mineral">
                            {r.fullName}
                          </span>
                          <span className="mt-0.5 block font-mono text-label uppercase text-mute">
                            {r.provider === "gitlab" ? "GitLab" : "GitHub"} · {r.defaultBranch}
                            {r.primaryLanguage ? ` · ${r.primaryLanguage}` : ""}
                          </span>
                        </span>
                        <span
                          className={cn(
                            "shrink-0 font-mono text-label uppercase",
                            active ? "text-acid" : "text-line-bright group-hover:text-ash",
                          )}
                        >
                          {active ? "sélectionné" : "choisir"}
                        </span>
                      </button>

                      {isArmed ? (
                        <span className="flex shrink-0 items-center gap-2">
                          <span className="hidden font-mono text-label uppercase text-high sm:inline">
                            et ses relevés ?
                          </span>
                          <Button
                            variant="quiet"
                            size="sm"
                            onClick={() => setArmed(null)}
                            disabled={deleting === r.id}
                          >
                            Annuler
                          </Button>
                          <Button
                            variant="danger"
                            size="sm"
                            onClick={() => removeRepo(r)}
                            disabled={deleting === r.id}
                          >
                            {deleting === r.id ? "…" : "Supprimer"}
                          </Button>
                        </span>
                      ) : (
                        <Button
                          variant="quiet"
                          size="sm"
                          className="shrink-0"
                          onClick={() => setArmed(r.id)}
                          aria-label={`Supprimer ${r.fullName} et ses relevés`}
                        >
                          Supprimer
                        </Button>
                      )}
                    </li>
                  );
                })}
              </ul>
            )}
          </div>
        </div>

        {/* Configurator appears only once a repo is picked — progressive
            disclosure rather than a permanently half-disabled form. */}
        <div className="col-span-12 px-6 py-8 lg:col-span-5 lg:px-10">
          <div className="lg:sticky lg:top-8">
            <h2 className="h-md">Configurer le relevé</h2>

            {!selected ? (
              <p className="mt-6 border border-dashed border-line px-5 py-8 font-mono text-label uppercase leading-relaxed text-mute">
                Sélectionnez un dépôt à gauche pour choisir les piliers à mesurer.
              </p>
            ) : (
              <>
                <p className="mt-5 border-l border-acid pl-4 font-mono text-data text-mineral">
                  {selected.fullName}
                </p>

                <div className="mt-7">
                  <Label className="text-mute">Piliers — {pillars.length} sur 7</Label>
                  <ul className="mt-3 border-t border-line">
                    {PILLARS.map((p) => {
                      const on = pillars.includes(p.id);
                      return (
                        <li key={p.id}>
                          <button
                            onClick={() =>
                              setPillars((cur) =>
                                cur.includes(p.id)
                                  ? cur.filter((x) => x !== p.id)
                                  : [...cur, p.id],
                              )
                            }
                            aria-pressed={on}
                            className="flex w-full items-center gap-3 border-b border-line py-3 text-left"
                          >
                            <span
                              aria-hidden
                              className={cn(
                                "h-3.5 w-3.5 shrink-0 border transition-colors duration-[180ms]",
                                on ? "border-acid bg-acid" : "border-line-bright",
                              )}
                            />
                            <span className="min-w-0 flex-1">
                              <span
                                className={cn(
                                  "block font-mono text-data",
                                  on ? "text-mineral" : "text-mute",
                                )}
                              >
                                {p.name}
                              </span>
                              <span className="mt-0.5 block truncate font-mono text-label uppercase text-mute">
                                {p.tools.join(" · ")}
                              </span>
                            </span>
                            {p.network && <Chip tone="warn">réseau</Chip>}
                          </button>
                        </li>
                      );
                    })}
                  </ul>
                </div>

                {networkPillars.length > 0 && (
                  <p className="mt-5 border-l-2 border-high bg-high/5 px-4 py-3 text-data text-high">
                    Les piliers réseau ne s&apos;exécutent que sur une cible dont la propriété est
                    vérifiée par enregistrement DNS. Sans cible vérifiée, ils seront ignorés dans
                    ce relevé.
                  </p>
                )}

                <Button
                  variant="primary"
                  size="lg"
                  className="mt-7 w-full"
                  disabled={busy || pillars.length === 0}
                  onClick={run}
                >
                  {busy ? "mise en file…" : "Lancer le relevé"}
                </Button>

                <p className="mt-4 font-mono text-label uppercase leading-relaxed text-mute">
                  Le clone est éphémère et détruit à la fin. Votre code source n&apos;est jamais
                  écrit dans le stockage durable.
                </p>
              </>
            )}
          </div>
        </div>
      </section>
    </>
  );
}
