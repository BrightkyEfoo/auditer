"use client";

import { useState, type ReactNode } from "react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { Wordmark, Label } from "@/components/ui";
import { cn } from "@/lib/cn";
import type { SessionOrg, SessionUser } from "@/lib/session";

const NAV = [
  { href: "/tableau-de-bord", label: "Tableau de bord", index: "01" },
  { href: "/depots", label: "Dépôts", index: "02" },
  { href: "/audits", label: "Relevés", index: "03" },
  { href: "/reglages", label: "Réglages", index: "04" },
];

/**
 * Product chrome: a fixed rail on the left, content on the right. The rail is
 * an instrument panel — index, label, and the org identity as a readout — so
 * the app and the public site read as the same object.
 */
export function AppShell({
  user,
  org,
  children,
}: {
  user?: SessionUser;
  org?: SessionOrg;
  children: ReactNode;
}) {
  const pathname = usePathname();
  const router = useRouter();
  const [open, setOpen] = useState(false);

  const isActive = (href: string) => pathname === href || pathname.startsWith(`${href}/`);

  async function signOut() {
    await fetch("/api/auth/logout", { method: "POST" });
    router.refresh();
    router.push("/");
  }

  const rail = (
    <div className="flex h-full flex-col">
      <div className="border-b border-line px-6 py-5">
        <Link href="/" aria-label="auditer, accueil" className="text-mineral">
          <Wordmark />
        </Link>
      </div>

      <nav aria-label="Navigation principale" className="flex-1 py-4">
        {NAV.map((n) => {
          const active = isActive(n.href);
          return (
            <Link
              key={n.href}
              href={n.href}
              onClick={() => setOpen(false)}
              aria-current={active ? "page" : undefined}
              className={cn(
                "group relative flex items-center gap-3 px-6 py-3 font-mono text-label uppercase transition-colors duration-[180ms]",
                active ? "bg-slate text-mineral" : "text-mute hover:text-mineral",
              )}
            >
              {/* Active rail marker — the same acid hairline used for hover on
                  the public site, held open instead of traced. */}
              <span
                aria-hidden
                className={cn(
                  "absolute inset-y-0 left-0 w-px origin-top bg-acid transition-transform duration-300 ease-out",
                  active ? "scale-y-100" : "scale-y-0 group-hover:scale-y-100",
                )}
              />
              <span className={active ? "text-acid" : "text-line-bright"}>{n.index}</span>
              {n.label}
            </Link>
          );
        })}
      </nav>

      <div className="border-t border-line px-6 py-5">
        <Label className="text-mute">Organisation</Label>
        <p className="mt-2 truncate font-mono text-data text-mineral">{org?.name ?? "—"}</p>
        <p className="mt-4 truncate text-data text-mute">{user?.email}</p>
        <button
          onClick={signOut}
          className="ul-draw mt-3 font-mono text-label uppercase text-mute transition-colors duration-[180ms] hover:text-critical"
        >
          Se déconnecter
        </button>
      </div>
    </div>
  );

  return (
    <div className="min-h-svh lg:pl-[15rem]">
      {/* Desktop rail */}
      <aside className="fixed inset-y-0 left-0 z-40 hidden w-[15rem] border-r border-line bg-carbon lg:block">
        {rail}
      </aside>

      {/* Mobile bar + drawer */}
      <div className="sticky top-0 z-40 flex h-14 items-center justify-between border-b border-line bg-carbon px-5 lg:hidden">
        <Link href="/" aria-label="auditer, accueil" className="text-mineral">
          <Wordmark />
        </Link>
        <button
          onClick={() => setOpen((o) => !o)}
          aria-expanded={open}
          aria-label={open ? "Fermer la navigation" : "Ouvrir la navigation"}
          className="flex h-11 w-11 items-center justify-center font-mono text-label uppercase text-ash"
        >
          {open ? "Fermer" : "Menu"}
        </button>
      </div>
      {open && (
        <aside className="fixed inset-x-0 bottom-0 top-14 z-30 border-t border-line bg-carbon lg:hidden">
          {rail}
        </aside>
      )}

      <div className="min-w-0">{children}</div>
    </div>
  );
}

/**
 * Page header inside the app. Index + title + optional actions, on a hairline.
 * Every product page uses it, so the app never drifts into per-page headers.
 */
export function PageHead({
  index,
  title,
  lede,
  actions,
}: {
  index: string;
  title: string;
  lede?: string;
  actions?: ReactNode;
}) {
  return (
    <header className="border-b border-line px-6 py-8 lg:px-10 lg:py-10">
      <div className="flex flex-wrap items-end justify-between gap-6">
        <div className="min-w-0">
          <span className="font-mono text-label text-acid">[{index}]</span>
          <h1 className="h-lg mt-3">{title}</h1>
          {lede && <p className="mt-3 max-w-[62ch] text-data text-mute">{lede}</p>}
        </div>
        {actions && <div className="flex flex-wrap items-center gap-3">{actions}</div>}
      </div>
    </header>
  );
}
