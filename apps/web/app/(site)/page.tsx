import { Hero } from "@/components/site/hero";
import { Engines, Pillars, Engine, Guarantees } from "@/components/site/sections";
import { Pipeline } from "@/components/site/pipeline";
import type { Metadata } from "next";

/**
 * L'accueil hérite du titre et de la description du layout racine — ils sont
 * écrits pour elle. Seule la canonique doit être posée ici : une canonique
 * relative dans le layout racine s'appliquerait à TOUTES les pages et les
 * ferait toutes pointer vers l'accueil, ce qui les désindexerait.
 */
export const metadata: Metadata = {
  alternates: { canonical: "/" },
};

export default function Landing() {
  return (
    <>
      <Hero />
      <Engines />
      <Pillars />
      <Pipeline />
      <Engine />
      <Guarantees />
    </>
  );
}
