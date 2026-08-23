"use client";

import { useEffect, useState } from "react";

/** Shows the signed-in state or a "Sign in with GitHub" button. */
export function AuthBadge() {
  const [state, setState] = useState<"loading" | "in" | "out">("loading");

  useEffect(() => {
    fetch("/api/auth/session", { cache: "no-store" })
      .then((r) => r.json())
      .then((d: { authenticated?: boolean }) => setState(d.authenticated ? "in" : "out"))
      .catch(() => setState("out"));
  }, []);

  if (state === "loading") return <span className="text-xs text-neutral-400">…</span>;

  if (state === "in") {
    return (
      <button
        onClick={async () => {
          await fetch("/api/auth/logout", { method: "POST" });
          location.reload();
        }}
        className="rounded-md border border-neutral-300 px-3 py-1.5 text-xs"
      >
        Sign out
      </button>
    );
  }

  return (
    <a
      href="/api/auth/github"
      className="rounded-md bg-neutral-900 px-3 py-1.5 text-xs font-medium text-white dark:bg-white dark:text-black"
    >
      Sign in with GitHub
    </a>
  );
}
