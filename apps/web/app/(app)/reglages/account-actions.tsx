"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Button, Field, inputClass } from "@/components/ui";
import { api } from "@/lib/api";
import { cn } from "@/lib/cn";

/**
 * The destructive half of the settings page. Client-side because every action
 * here needs a confirmation step and an error to show in place.
 *
 * No `confirm()` anywhere: a native dialog is unstyled, unreadable on mobile,
 * blocked by some browsers, and — worse for an irreversible action — dismissed
 * by muscle memory. Confirmation is done in the page, where the consequence is
 * still visible while it is being confirmed.
 */

/* ── Révocation d'une connexion ──────────────────────────────────────────── */

export function RevokeConnection({
  connectionId,
  label,
}: {
  connectionId: string;
  label: string;
}) {
  const router = useRouter();
  const [armed, setArmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function revoke() {
    setBusy(true);
    setError(null);
    try {
      await api.deleteConnection(connectionId);
      router.refresh();
    } catch (e) {
      setError(String(e));
      setBusy(false);
      setArmed(false);
    }
  }

  if (!armed) {
    return (
      <div className="flex flex-col items-end gap-1.5">
        <Button variant="quiet" size="sm" onClick={() => setArmed(true)}>
          Révoquer
        </Button>
        {error && (
          <p role="alert" className="font-mono text-label uppercase text-critical">
            échec de la révocation
          </p>
        )}
      </div>
    );
  }

  return (
    <div className="flex flex-col items-end gap-2">
      <p className="font-mono text-label uppercase text-high">
        Révoquer {label} ? Les dépôts importés par cet accès et leurs relevés seront supprimés.
      </p>
      <div className="flex gap-2">
        <Button variant="quiet" size="sm" onClick={() => setArmed(false)} disabled={busy}>
          Annuler
        </Button>
        <Button variant="danger" size="sm" onClick={revoke} disabled={busy}>
          {busy ? "révocation…" : "Confirmer"}
        </Button>
      </div>
    </div>
  );
}

/* ── Suppression du compte ───────────────────────────────────────────────── */

/**
 * The typed address is compared here only to keep the button disabled — the
 * comparison that counts is the server's, in AccountController. A guard that
 * lives only in the browser guards nothing once the request is replayed.
 */
export function DeleteAccount({ email }: { email: string }) {
  const router = useRouter();
  const [typed, setTyped] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const matches = typed.trim().toLowerCase() === email.trim().toLowerCase();

  async function remove() {
    if (!matches) return;
    setBusy(true);
    setError(null);
    try {
      await api.deleteAccount(typed);
      // Hard navigation, not router.push: the session cookie was cleared by the
      // response and every cached server component still holds data for an
      // account that no longer exists.
      window.location.href = "/";
    } catch (e) {
      setError(
        String(e).includes("403")
          ? "L'adresse saisie ne correspond pas à celle du compte."
          : "La suppression a échoué. Réessayez, ou écrivez-nous si cela persiste.",
      );
      setBusy(false);
      router.refresh();
    }
  }

  return (
    <div className="mt-6 max-w-md">
      <Field
        label="Confirmation — saisissez votre adresse e-mail"
        hint={`Tapez exactement ${email} pour débloquer la suppression.`}
        error={error ?? undefined}
      >
        <input
          type="email"
          autoComplete="off"
          spellCheck={false}
          value={typed}
          onChange={(e) => setTyped(e.target.value)}
          placeholder={email}
          aria-label="Adresse e-mail de confirmation"
          className={cn(inputClass, matches && "border-critical")}
        />
      </Field>

      <Button
        variant="danger"
        className="mt-5"
        disabled={!matches || busy}
        onClick={remove}
      >
        {busy ? "suppression…" : "Supprimer définitivement le compte"}
      </Button>
    </div>
  );
}
