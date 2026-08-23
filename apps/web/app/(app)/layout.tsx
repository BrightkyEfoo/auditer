import type { ReactNode } from "react";
import type { Metadata } from "next";
import { redirect } from "next/navigation";
import { AppShell } from "@/components/app/shell";
import { getSession } from "@/lib/session";

export const metadata: Metadata = {
  // The product is behind auth; nothing here belongs in an index.
  robots: { index: false, follow: false },
};

/**
 * The auth gate for the whole product. Checking here rather than per page means
 * a new route cannot ship unprotected by omission.
 */
export default async function AppLayout({ children }: { children: ReactNode }) {
  const session = await getSession();
  if (!session) redirect("/connexion");

  return (
    <AppShell user={session.user} org={session.org}>
      {children}
    </AppShell>
  );
}
