"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import { PageHead } from "@/components/app/shell";
import { Button, ButtonLink, Chip, Empty, Label, Spinner, inputClass } from "@/components/ui";
import { PILLARS } from "@/lib/content";
import { api, type Connection, type RemoteRepo, type Repo, type Target } from "@/lib/api";
import { cn } from "@/lib/cn";

const PROVIDER_FR: Record<string, string> = {
  github_app: "GitHub",
  gitlab_oauth: "GitLab",
  gitlab_pat: "GitLab (jeton)",
};

/**
 * Un état de connexion se lit par un humain, pas par un parseur.
 *
 * `reauth_required` est posé quand le secret enregistré n'est plus déchiffrable
 * — la clé qui l'enveloppait a disparu. Aucune reprise n'y changera rien, seule
 * une reconnexion répare, et l'écran doit donc le dire plutôt que d'afficher un
 * identifiant technique à côté d'un bouton qui échouera.
 */
const STATUS_FR: Record<string, string> = {
  active: "active",
  reauth_required: "à reconnecter — secret illisible",
  revoked: "révoquée",
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

  // Cibles réseau. Elles ne sont chargées et affichées que quand un pilier
  // réseau est retenu : hors de ce cas, elles n'ont rien à dire.
  const [targets, setTargets] = useState<Target[] | null>(null);
  const [targetId, setTargetId] = useState<string | null>(null);
  const [targetUrl, setTargetUrl] = useState("");
  const [creatingTarget, setCreatingTarget] = useState(false);
  const [verifying, setVerifying] = useState<string | null>(null);
  const [verifyHint, setVerifyHint] = useState<string | null>(null);

  // Two-step deletion, held in the page rather than in a `confirm()` dialog —
  // the row stays visible while its removal is being confirmed, and the project
  // forbids native dialogs anyway.
  const [armed, setArmed] = useState<string | null>(null);
  const [deleting, setDeleting] = useState<string | null>(null);

  const refreshTargets = useCallback(() => {
    api.listTargets().then(setTargets).catch(() => setTargets([]));
  }, []);

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
  useEffect(refreshTargets, [refreshTargets]);

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

  async function addTarget() {
    const value = targetUrl.trim();
    if (!value) return;
    setCreatingTarget(true);
    setError(null);
    setVerifyHint(null);
    try {
      const t = await api.createTarget({
        kind: "origin",
        value,
        repositoryId: selected?.id,
      });
      // La création est idempotente côté api : resaisir un hôte déjà connu
      // renvoie la cible EXISTANTE, éventuellement déjà vérifiée. On remplace
      // donc par identifiant au lieu d'empiler — sans quoi l'écran afficherait
      // deux fois la même cible et contredirait le service.
      setTargets((cur) => {
        const rest = (cur ?? []).filter((x) => x.id !== t.id);
        return [...rest, t];
      });
      setTargetId(t.id);
      setTargetUrl("");
    } catch (e) {
      setError(String(e));
    } finally {
      setCreatingTarget(false);
    }
  }

  // La vérification relit le DNS côté serveur. Un échec n'est PAS une erreur :
  // un enregistrement TXT met du temps à se propager, et le serveur renvoie
  // alors l'enregistrement attendu, qu'on réaffiche tel quel.
  async function verify(id: string) {
    setVerifying(id);
    setVerifyHint(null);
    setError(null);
    try {
      const res = await api.verifyTarget(id);
      if (res.verified) {
        setTargets((cur) =>
          (cur ?? []).map((t) =>
            t.id === id ? { ...t, verificationStatus: "verified" as const } : t,
          ),
        );
      } else {
        setVerifyHint(res.hint ?? "enregistrement TXT introuvable");
      }
    } catch (e) {
      setError(String(e));
    } finally {
      setVerifying(null);
    }
  }

  async function run() {
    if (!selected || pillars.length === 0) return;
    if (needsTarget && !verifiedTargetId) return;
    setBusy(true);
    setError(null);
    try {
      const { runId } = await api.createAudit({
        repositoryId: selected.id,
        pillars,
        // N'accompagne le relevé QUE si un pilier réseau est retenu : l'api
        // rattache le run à la cible, et un rattachement sans pilier réseau
        // ferait mentir le relevé sur ce qu'il a visé.
        ...(needsTarget && verifiedTargetId ? { targetId: verifiedTargetId } : {}),
      });
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
  const needsTarget = networkPillars.length > 0;
  const chosenTarget = (targets ?? []).find((t) => t.id === targetId) ?? null;
  const verifiedTargetId =
    chosenTarget && chosenTarget.verificationStatus === "verified" ? chosenTarget.id : null;

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
                        état : {STATUS_FR[c.status] ?? c.status}
                      </p>
                    </div>
                  </div>
                  {/* Une connexion dont le secret n'est plus déchiffrable ne
                      peut RIEN faire : proposer « Parcourir » renverrait une
                      erreur. On propose la seule action qui la répare. */}
                  {c.status === "reauth_required" ? (
                    <ButtonLink
                      href={
                        c.provider === "gitlab"
                          ? "/api/connections/gitlab/connect"
                          : "/api/connections/github/install"
                      }
                      size="sm"
                      variant="primary"
                    >
                      Reconnecter
                    </ButtonLink>
                  ) : (
                    <Button size="sm" onClick={() => browse(c)}>
                      Parcourir les dépôts
                    </Button>
                  )}
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

                {needsTarget && (
                  <div className="mt-7 border-l-2 border-high bg-high/5 px-4 py-4">
                    <Label className="text-high">
                      Cible réseau — requise par {networkPillars.join(" et ")}
                    </Label>
                    <p className="mt-2 max-w-[62ch] text-data text-high">
                      Un pilier réseau envoie du trafic à un hôte. Tant que sa propriété
                      n&apos;est pas prouvée par enregistrement DNS, cet hôte est un tiers et le
                      relevé est refusé — ce n&apos;est pas une préférence d&apos;interface, la
                      règle est tenue par l&apos;api et revérifiée par le worker.
                    </p>

                    {targets === null ? (
                      <div className="mt-4">
                        <Spinner label="chargement des cibles" />
                      </div>
                    ) : (
                      <ul className="mt-4 border-t border-high/30">
                        {targets.map((t) => {
                          const on = t.id === targetId;
                          const ok = t.verificationStatus === "verified";
                          return (
                            <li key={t.id} className="border-b border-high/30 py-3">
                              <div className="flex flex-wrap items-center justify-between gap-3">
                                <button
                                  onClick={() => {
                                    setTargetId(t.id);
                                    setVerifyHint(null);
                                  }}
                                  aria-pressed={on}
                                  className="flex min-w-0 flex-1 items-center gap-3 text-left"
                                >
                                  <span
                                    aria-hidden
                                    className={cn(
                                      "h-3.5 w-3.5 shrink-0 rounded-full border transition-colors duration-[180ms]",
                                      on ? "border-acid bg-acid" : "border-line-bright",
                                    )}
                                  />
                                  <span
                                    className={cn(
                                      "min-w-0 flex-1 truncate font-mono text-data",
                                      on ? "text-mineral" : "text-mute",
                                    )}
                                  >
                                    {t.value}
                                  </span>
                                </button>
                                <Chip tone={ok ? "acid" : "warn"}>
                                  {ok ? "vérifiée" : "non vérifiée"}
                                </Chip>
                                {!ok && (
                                  <Button
                                    variant="quiet"
                                    size="sm"
                                    disabled={verifying === t.id}
                                    onClick={() => verify(t.id)}
                                  >
                                    {verifying === t.id ? "lecture DNS…" : "Vérifier"}
                                  </Button>
                                )}
                              </div>

                              {!ok && t.verificationToken && t.apexDomain && (
                                <div className="mt-3 border border-high/30 bg-carbon px-4 py-3">
                                  <p className="font-mono text-label uppercase text-mute">
                                    Publier ce TXT sur {t.apexDomain}, puis vérifier
                                  </p>
                                  <p className="mt-1.5 break-all font-mono text-data text-mineral">
                                    {t.verificationToken}
                                  </p>
                                </div>
                              )}
                            </li>
                          );
                        })}
                      </ul>
                    )}

                    <div className="mt-4 flex flex-wrap gap-3">
                      <input
                        value={targetUrl}
                        onChange={(e) => setTargetUrl(e.target.value)}
                        onKeyDown={(e) => {
                          if (e.key === "Enter") addTarget();
                        }}
                        placeholder="https://exemple.com"
                        aria-label="URL ou hôte de la cible à ajouter"
                        className={cn(inputClass, "min-w-0 flex-1")}
                      />
                      <Button
                        variant="quiet"
                        size="sm"
                        disabled={creatingTarget || targetUrl.trim().length === 0}
                        onClick={addTarget}
                      >
                        {creatingTarget ? "…" : "Ajouter"}
                      </Button>
                    </div>

                    {verifyHint && (
                      <p
                        role="status"
                        className="mt-3 break-all font-mono text-label uppercase text-high"
                      >
                        {verifyHint}
                      </p>
                    )}

                    <p className="mt-3 max-w-[62ch] font-mono text-label uppercase leading-relaxed text-mute">
                      La vérification épingle aussi les adresses IP résolues, pour qu&apos;un
                      changement de DNS entre l&apos;autorisation et le scan soit détectable.
                    </p>
                  </div>
                )}

                <Button
                  variant="primary"
                  size="lg"
                  className="mt-7 w-full"
                  disabled={busy || pillars.length === 0 || (needsTarget && !verifiedTargetId)}
                  onClick={run}
                >
                  {busy ? "mise en file…" : "Lancer le relevé"}
                </Button>

                {needsTarget && !verifiedTargetId && (
                  <p className="mt-3 font-mono text-label uppercase text-high">
                    {chosenTarget
                      ? "cible retenue non vérifiée — publiez le TXT puis vérifiez"
                      : "choisissez une cible vérifiée, ou retirez les piliers réseau"}
                  </p>
                )}

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
