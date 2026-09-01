"use client";

import { useEffect } from "react";
import Lenis from "lenis";

/**
 * Smooth scroll, à l'échelle du document.
 *
 * Le défilement natif s'arrête net ; celui-ci décélère. Sur une page dont la
 * composition repose sur des ruptures de rythme — sections denses puis vides —
 * c'est ce qui fait lire la page comme une séquence plutôt que comme une pile.
 * C'est aussi ce qui donne leur sens aux reveals et aux parallaxes déjà en
 * place : ils sont réglés sur `--ease-out`, et un scroll qui s'arrête
 * brutalement les tronque.
 *
 * TROIS PRÉCAUTIONS, qui sont la raison d'être de ce fichier plutôt que d'un
 * `new Lenis()` posé dans le layout.
 *
 * 1. `prefers-reduced-motion` : on ne démarre RIEN. Détourner le défilement de
 *    quelqu'un qui a demandé moins d'animation est la version la plus intrusive
 *    du défaut, parce qu'elle touche le geste de lecture lui-même.
 *
 * 2. Pointeur grossier : sur tactile, le défilement natif porte l'inertie du
 *    système et les gestes de la plateforme. Le remplacer donne toujours une
 *    sensation plus mauvaise que l'original, jamais meilleure.
 *
 * 3. Conteneurs à défilement propre : la trace d'exécution d'un relevé est une
 *    liste `overflow-auto` de hauteur bornée. Lenis capte les événements de
 *    molette au niveau du document ; sans `data-lenis-prevent` sur ces
 *    conteneurs, molette dans la trace ferait défiler la PAGE et la trace
 *    resterait immobile. L'attribut est posé sur le conteneur lui-même
 *    (voir run-trace.tsx), pas ici — mais c'est ici qu'il faut savoir pourquoi.
 */
export function SmoothScroll() {
  useEffect(() => {
    const coarse = window.matchMedia("(pointer: coarse)").matches;
    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (coarse || reduced) return;

    const lenis = new Lenis({
      // Assez long pour qu'on sente la décélération, assez court pour qu'un
      // clavier ou une molette rapide ne donnent pas l'impression de nager.
      duration: 0.9,
      // Même famille de courbe que `--ease-out` du système : la page et ses
      // éléments décélèrent ensemble au lieu de se contredire.
      easing: (t: number) => Math.min(1, 1.001 - Math.pow(2, -10 * t)),
      // Le tactile garde son défilement natif (voir précaution 2) ; ceci ne
      // couvre que les appareils hybrides à pointeur fin.
      smoothWheel: true,
      touchMultiplier: 1.5,
    });

    let raf = 0;
    const frame = (time: number) => {
      lenis.raf(time);
      raf = requestAnimationFrame(frame);
    };
    raf = requestAnimationFrame(frame);

    return () => {
      cancelAnimationFrame(raf);
      lenis.destroy();
    };
  }, []);

  return null;
}
