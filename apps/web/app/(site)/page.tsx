import { Hero } from "@/components/site/hero";
import { Engines, Pillars, Engine, Guarantees } from "@/components/site/sections";
import { Pipeline } from "@/components/site/pipeline";

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
