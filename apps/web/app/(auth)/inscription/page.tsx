import type { Metadata } from "next";
import { CredentialsForm } from "@/components/site/credentials-form";
import { SectionMark, Label } from "@/components/ui";

export const metadata: Metadata = {
  title: "Créer un compte",
  description:
    "Créez votre compte auditer et lancez votre premier relevé. Gratuit pendant la phase actuelle, sans carte bancaire.",
  robots: { index: true, follow: false },
};

const AFTER = [
  {
    k: "Vous connectez un dépôt",
    v: "GitHub App ou OAuth GitLab. Vous choisissez les dépôts exposés, un par un — jamais l'organisation entière par défaut.",
  },
  {
    k: "Vous choisissez les piliers",
    v: "Les cinq piliers statiques ne demandent rien de plus. Le pentest et l'audit UX exigent une cible dont vous prouvez la propriété.",
  },
  {
    k: "Vous lisez le relevé",
    v: "Score, findings triés par gravité, explication et remédiation pour chacun, export HTML. Le triage que vous posez survit aux relevés suivants.",
  },
];

export default function SignupPage() {
  return (
    <div className="shell grid grid-cols-12 gap-y-16 py-[clamp(3rem,8vh,6rem)]">
      <div className="col-span-12 lg:col-span-5">
        <SectionMark index="00">Inscription</SectionMark>
        <h1 className="h-lg mt-9 max-w-[14ch]">Mettez votre premier dépôt sous instrument.</h1>
        <p className="mt-5 max-w-[46ch] text-data text-mute">
          Gratuit pendant la phase actuelle. Sans carte bancaire. Votre code source n&apos;est
          jamais conservé.
        </p>
        <div className="mt-10">
          <CredentialsForm mode="signup" />
        </div>
      </div>

      {/* Reassurance column. Placed beside the form rather than under it: the
          objection to answer at signup is "what do you do with my code", and
          answering it after the button is answering it too late. */}
      <aside className="col-span-12 lg:col-span-6 lg:col-start-7">
        <div className="border border-line-bright bg-slate">
          <header className="border-b border-line px-6 py-4">
            <Label className="text-acid">Ce qui se passe ensuite</Label>
          </header>
          <ol className="divide-y divide-line">
            {AFTER.map((a, i) => (
              <li key={a.k} className="px-6 py-5">
                <div className="flex items-baseline gap-3">
                  <span className="font-mono text-label text-acid">
                    {String(i + 1).padStart(2, "0")}
                  </span>
                  <span className="font-display font-bold tracking-display text-mineral">{a.k}</span>
                </div>
                <p className="mt-2 pl-8 text-data text-mute">{a.v}</p>
              </li>
            ))}
          </ol>
        </div>

        <dl className="mt-6 grid grid-cols-1 gap-px border border-line bg-line sm:grid-cols-2">
          {[
            ["Code source conservé", "0 octet"],
            ["Isolation des scanners", "Noyau gVisor"],
            ["Jetons d'accès", "Chiffrés AES-256-GCM"],
            ["Traceurs publicitaires", "Aucun"],
          ].map(([k, v]) => (
            <div key={k} className="bg-carbon px-5 py-4">
              <dt className="label text-mute">{k}</dt>
              <dd className="mt-1.5 font-mono text-data text-acid">{v}</dd>
            </div>
          ))}
        </dl>
      </aside>
    </div>
  );
}
