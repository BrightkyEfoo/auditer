import type { Metadata } from "next";
import { CredentialsForm } from "@/components/site/credentials-form";
import { SectionMark } from "@/components/ui";

export const metadata: Metadata = {
  title: "Connexion",
  description: "Accédez à vos relevés auditer.",
  robots: { index: false, follow: false },
};

export default function LoginPage() {
  return (
    <div className="shell flex min-h-[70svh] items-center py-[clamp(3rem,8vh,6rem)]">
      <div className="mx-auto w-full max-w-[30rem]">
        <SectionMark index="00">Connexion</SectionMark>
        <h1 className="h-lg mt-9">Reprenons le relevé.</h1>
        <p className="mt-4 text-data text-mute">
          Connectez-vous avec le fournisseur utilisé à l&apos;inscription, ou avec votre adresse
          e-mail.
        </p>
        <div className="mt-10">
          <CredentialsForm mode="login" />
        </div>
      </div>
    </div>
  );
}
