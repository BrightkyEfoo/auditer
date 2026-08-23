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
      <SiteNav authenticated={session !== null} />
      <main id="contenu">{children}</main>
      <SiteFooter />
    </>
  );
}
