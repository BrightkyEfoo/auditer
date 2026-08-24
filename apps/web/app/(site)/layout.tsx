import type { ReactNode } from "react";
import { SiteNav } from "@/components/site/nav";
import { SiteFooter } from "@/components/site/footer";
import { getSession } from "@/lib/session";

/**
 * Public site chrome. The session is read server-side purely so the header can
 * offer "Tableau de bord" instead of "Créer un compte" without a flash — the
 * marketing pages themselves are identical for everyone.
 */
export default async function SiteLayout({ children }: { children: ReactNode }) {
  const session = await getSession();
  return (
    <>
      {/* First focusable element on the page. Visually hidden until focused,
          then it lands in the top-left as a real, styled control. There was no
          skip link anywhere in the project — for a product that sells
          accessibility auditing, that was the wrong thing to be missing. */}
      <a
        href="#contenu"
        className="sr-only focus:not-sr-only focus:fixed focus:left-4 focus:top-4 focus:z-[60] focus:border focus:border-acid focus:bg-void focus:px-4 focus:py-2 focus:font-mono focus:text-label focus:uppercase focus:text-acid"
      >
        Aller au contenu
      </a>
      <SiteNav authenticated={session !== null} />
      <main id="contenu">{children}</main>
      <SiteFooter />
    </>
  );
}
