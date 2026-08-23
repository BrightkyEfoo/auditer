"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { Wordmark, ButtonLink } from "@/components/ui";
import { cn } from "@/lib/cn";

const LINKS = [
  { href: "/#piliers", label: "Piliers" },
  { href: "/#moteur", label: "Moteur" },
  { href: "/securite", label: "Sécurité" },
  { href: "/tarifs", label: "Tarifs" },
];

/**
 * Thin header, hairline underneath, no CTA gradient. It only gains a ground
 * once the page has scrolled — over the hero it stays transparent so the
 * typographic poster reads full-bleed.
 */
export function SiteNav({ authenticated }: { authenticated: boolean }) {
  const [scrolled, setScrolled] = useState(false);
  const [open, setOpen] = useState(false);

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 24);
    onScroll();
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  // A full-screen menu that still scrolls the page behind it is a broken menu.
  useEffect(() => {
    document.body.style.overflow = open ? "hidden" : "";
    return () => {
      document.body.style.overflow = "";
    };
  }, [open]);

  return (
    <>
      <header
        className={cn(
          "fixed inset-x-0 top-0 z-50 transition-colors duration-300",
          scrolled ? "border-b border-line bg-carbon/92 backdrop-blur-sm" : "border-b border-transparent",
        )}
      >
        <div className="shell flex h-16 items-center justify-between">
          <Link href="/" aria-label="auditer, accueil" className="text-mineral">
            <Wordmark />
          </Link>

          <nav className="hidden items-center gap-8 md:flex">
            {LINKS.map((l) => (
              <a
                key={l.href}
                href={l.href}
                className="ul-draw font-mono text-label uppercase text-ash transition-colors duration-[180ms] hover:text-mineral"
              >
                {l.label}
              </a>
            ))}
          </nav>

          <div className="hidden items-center gap-3 md:flex">
            {authenticated ? (
              <ButtonLink href="/tableau-de-bord" variant="primary" size="sm">
                Tableau de bord
              </ButtonLink>
            ) : (
              <>
                <Link
                  href="/connexion"
                  className="ul-draw font-mono text-label uppercase text-ash transition-colors duration-[180ms] hover:text-mineral"
                >
                  Connexion
                </Link>
                <ButtonLink href="/inscription" variant="primary" size="sm">
                  Créer un compte
                </ButtonLink>
              </>
            )}
          </div>

          <button
            onClick={() => setOpen((o) => !o)}
            aria-expanded={open}
            aria-label={open ? "Fermer le menu" : "Ouvrir le menu"}
            className="flex h-11 w-11 items-center justify-center md:hidden"
          >
            <span className="relative block h-3 w-5">
              <span
                className={cn(
                  "absolute left-0 h-px w-5 bg-mineral transition-transform duration-300 ease-out",
                  open ? "top-1.5 rotate-45" : "top-0",
                )}
              />
              <span
                className={cn(
                  "absolute left-0 h-px w-5 bg-mineral transition-transform duration-300 ease-out",
                  open ? "top-1.5 -rotate-45" : "top-3",
                )}
              />
            </span>
          </button>
        </div>
      </header>

      {/* Mobile menu: full screen, oversized type. The nav becomes a moment of
          art direction rather than a cramped drawer. */}
      <div
        className={cn(
          "fixed inset-0 z-40 flex flex-col bg-carbon transition-opacity duration-300 md:hidden",
          open ? "opacity-100" : "pointer-events-none opacity-0",
        )}
      >
        <div className="shell flex flex-1 flex-col justify-center gap-1 pt-16">
          {LINKS.map((l, i) => (
            <a
              key={l.href}
              href={l.href}
              onClick={() => setOpen(false)}
              className="flex items-baseline gap-4 border-b border-line py-5"
            >
              <span className="font-mono text-label text-acid">[{String(i + 1).padStart(2, "0")}]</span>
              <span className="font-display text-[2rem] font-bold tracking-tightest">{l.label}</span>
            </a>
          ))}
        </div>
        <div className="shell flex flex-col gap-3 pb-12">
          {authenticated ? (
            <ButtonLink href="/tableau-de-bord" variant="primary" size="lg">
              Tableau de bord
            </ButtonLink>
          ) : (
            <>
              <ButtonLink href="/inscription" variant="primary" size="lg">
                Créer un compte
              </ButtonLink>
              <ButtonLink href="/connexion" size="lg">
                Connexion
              </ButtonLink>
            </>
          )}
        </div>
      </div>
    </>
  );
}
