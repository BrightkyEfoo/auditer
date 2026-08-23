"use client";

import { useState, type FormEvent } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { Button, ButtonLink, Field, inputClass, Label } from "@/components/ui";

const MIN_PASSWORD = 12;

/** api error codes → wording the user can act on. Never leak which half failed. */
const MESSAGES: Record<string, string> = {
  email_taken: "Un compte existe déjà avec cette adresse. Connectez-vous plutôt.",
  invalid_credentials: "Adresse e-mail ou mot de passe incorrect.",
  rate_limited: "Trop de tentatives depuis cette adresse. Réessayez dans quelques minutes.",
};

/** Length is the only honest single-axis strength signal; no fake entropy score. */
function strength(pw: string): { level: 0 | 1 | 2 | 3; text: string } {
  if (pw.length === 0) return { level: 0, text: `${MIN_PASSWORD} caractères minimum` };
  if (pw.length < MIN_PASSWORD)
    return { level: 1, text: `Encore ${MIN_PASSWORD - pw.length} caractère(s)` };
  const varied = /[a-z]/.test(pw) && /[A-Z0-9]/.test(pw) && /[^A-Za-z0-9]/.test(pw);
  if (pw.length >= 20 || (pw.length >= 16 && varied))
    return { level: 3, text: "Solide. Une phrase de passe, c'est encore mieux." };
  return { level: 2, text: "Acceptable. Allongez-le plutôt que de le compliquer." };
}

export function CredentialsForm({ mode }: { mode: "signup" | "login" }) {
  const router = useRouter();
  const signup = mode === "signup";

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [name, setName] = useState("");
  const [accepted, setAccepted] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const s = strength(password);
  const canSubmit =
    email.includes("@") && password.length >= MIN_PASSWORD && (!signup || accepted) && !busy;

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!canSubmit) return;
    setBusy(true);
    setError(null);
    try {
      const res = await fetch(`/api/auth/${signup ? "register" : "login"}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(
          signup ? { email, password, name: name.trim() || undefined } : { email, password },
        ),
      });
      if (!res.ok) {
        const code =
          res.status === 429
            ? "rate_limited"
            : ((await res.json().catch(() => ({}))) as { error?: string }).error;
        setError(MESSAGES[code ?? ""] ?? "La demande a échoué. Réessayez.");
        setBusy(false);
        return;
      }
      // Server components read the session cookie, so the cache must be
      // invalidated before navigating or the shell renders logged-out.
      router.refresh();
      router.push("/tableau-de-bord");
    } catch {
      setError("Service injoignable. Vérifiez votre connexion.");
      setBusy(false);
    }
  }

  return (
    <div>
      {/* OAuth first: for a dev tool it is both the fastest path and the one
          that already grants repo access. */}
      <div className="grid gap-3 sm:grid-cols-2">
        <ButtonLink href="/api/auth/github" className="justify-center">
          Continuer avec GitHub
        </ButtonLink>
        <ButtonLink href="/api/auth/gitlab" className="justify-center">
          Continuer avec GitLab
        </ButtonLink>
      </div>

      <div className="my-8 flex items-center gap-4">
        <span className="h-px flex-1 bg-line" />
        <Label className="text-mute">ou par e-mail</Label>
        <span className="h-px flex-1 bg-line" />
      </div>

      <form onSubmit={submit} className="space-y-5" noValidate>
        {signup && (
          <Field label="Nom" hint="Affiché dans votre organisation. Optionnel.">
            <input
              className={inputClass}
              value={name}
              onChange={(e) => setName(e.target.value)}
              autoComplete="name"
              placeholder="Ada Lovelace"
            />
          </Field>
        )}

        <Field label="Adresse e-mail">
          <input
            className={inputClass}
            type="email"
            required
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            autoComplete="email"
            placeholder="vous@exemple.com"
          />
        </Field>

        <Field label="Mot de passe" hint={signup ? s.text : undefined}>
          <input
            className={inputClass}
            type="password"
            required
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete={signup ? "new-password" : "current-password"}
            minLength={signup ? MIN_PASSWORD : undefined}
            placeholder="••••••••••••"
          />
          {signup && (
            <div className="mt-2 flex gap-1" aria-hidden>
              {[1, 2, 3].map((i) => (
                <span
                  key={i}
                  className={`h-0.5 flex-1 transition-colors duration-300 ${
                    s.level >= i ? (s.level === 1 ? "bg-high" : "bg-acid") : "bg-line"
                  }`}
                />
              ))}
            </div>
          )}
        </Field>

        {signup && (
          <label className="flex cursor-pointer items-start gap-3 pt-1">
            <input
              type="checkbox"
              checked={accepted}
              onChange={(e) => setAccepted(e.target.checked)}
              className="mt-0.5 h-4 w-4 shrink-0 appearance-none border border-line-bright bg-void checked:border-acid checked:bg-acid focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-acid"
            />
            <span className="text-data text-ash">
              J&apos;accepte les{" "}
              <Link href="/legal/cgu" className="ul-draw text-acid">
                conditions d&apos;utilisation
              </Link>{" "}
              et la{" "}
              <Link href="/legal/confidentialite" className="ul-draw text-acid">
                politique de confidentialité
              </Link>
              .
            </span>
          </label>
        )}

        {error && (
          <p role="alert" className="border-l-2 border-critical bg-critical/5 px-4 py-3 text-data text-critical">
            {error}
          </p>
        )}

        <Button type="submit" variant="primary" size="lg" disabled={!canSubmit} className="w-full">
          {busy ? "…" : signup ? "Créer mon compte" : "Se connecter"}
        </Button>
      </form>

      <p className="mt-8 border-t border-line pt-5 font-mono text-label uppercase text-mute">
        {signup ? (
          <>
            Déjà un compte ?{" "}
            <Link href="/connexion" className="ul-draw text-acid">
              Connexion
            </Link>
          </>
        ) : (
          <>
            Pas encore de compte ?{" "}
            <Link href="/inscription" className="ul-draw text-acid">
              Créer un compte
            </Link>
          </>
        )}
      </p>
    </div>
  );
}
