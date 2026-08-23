import type { ReactNode } from "react";
import Link from "next/link";
import { redirect } from "next/navigation";
import { Wordmark } from "@/components/ui";
import { getSession } from "@/lib/session";

/**
 * Auth chrome: no site nav, no footer. The page is a single decision, so
 * everything that could pull attention off the form is removed.
 *
 * Already-authenticated visitors are bounced to the app rather than shown a
 * login form that would log them into the session they already have.
 */
export default async function AuthLayout({ children }: { children: ReactNode }) {
  if (await getSession()) redirect("/tableau-de-bord");

  return (
    <div className="flex min-h-svh flex-col">
      <header className="border-b border-line">
        <div className="shell flex h-16 items-center justify-between">
          <Link href="/" aria-label="auditer, accueil" className="text-mineral">
            <Wordmark />
          </Link>
          <Link
            href="/"
            className="ul-draw font-mono text-label uppercase text-mute transition-colors duration-[180ms] hover:text-mineral"
          >
            ← Retour au site
          </Link>
        </div>
      </header>
      <main className="flex-1">{children}</main>
      <footer className="border-t border-line">
        <div className="shell flex flex-wrap gap-x-6 gap-y-2 py-5 font-mono text-label uppercase text-mute">
          <Link href="/legal/confidentialite" className="ul-draw hover:text-mineral">
            Confidentialité
          </Link>
          <Link href="/legal/cgu" className="ul-draw hover:text-mineral">
            Conditions d&apos;utilisation
          </Link>
          <Link href="/securite" className="ul-draw hover:text-mineral">
            Sécurité
          </Link>
        </div>
      </footer>
    </div>
  );
}
