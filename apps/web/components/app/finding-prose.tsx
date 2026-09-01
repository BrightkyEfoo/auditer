import { Fragment, type ReactNode } from "react";
import { cn } from "@/lib/cn";

/**
 * Rendu du texte d'un finding : description du moteur, analyse et correctif
 * rédigés par le modèle.
 *
 * LE DÉFAUT QUE CELA FERME. Ces textes partaient dans un `<p>` unique. Or ils
 * arrivent structurés : un message de semgrep porte des retours à la ligne, un
 * correctif rédigé porte des listes à puces et des extraits de code entre
 * accents graves. En HTML, une suite de retours à la ligne s'effondre en un
 * seul espace — tout se retrouvait aggloméré en un pavé, et le lecteur devait
 * reconstituer la structure de tête, sur le contenu même qu'il vient chercher.
 *
 * POURQUOI PAS UN MOTEUR MARKDOWN. Deux raisons, et la seconde est la plus
 * importante. D'abord le poids : une dépendance markdown pour trois
 * constructions coûterait plus que ce qu'elle rend. Ensuite et surtout, la
 * SÉCURITÉ. Ce texte est écrit par un modèle à partir de la sortie d'outils
 * exécutés sur du code hostile par hypothèse ; le rendre en HTML — ce que fait
 * tout moteur markdown, via `dangerouslySetInnerHTML` — transformerait la
 * moindre faille d'échappement en XSS stockée, dans notre propre origine, sur
 * un produit qui vend l'audit de sécurité. Ici rien n'est jamais interprété
 * comme du HTML : on construit des éléments React, et le texte reste du texte.
 *
 * TROIS CONSTRUCTIONS, PAS PLUS. Blocs de code délimités par trois accents
 * graves, listes à puces, paragraphes — plus le code en ligne entre accents
 * simples. Le reste (gras, italique, titres, liens) est délibérément ignoré et
 * s'affiche tel quel : un rendu partiel qui invente de la mise en forme là où
 * le modèle n'en voulait pas est pire qu'un rendu sobre.
 */

/** Découpe une ligne sur les accents graves et rend les segments impairs en
 *  code. Un accent non refermé laisse la ligne intacte — pas de demi-rendu. */
function inline(text: string, keyBase: string): ReactNode {
  const parts = text.split("`");
  if (parts.length < 3 || parts.length % 2 === 0) return text;
  return parts.map((part, i) =>
    i % 2 === 1 ? (
      <code
        key={`${keyBase}-${i}`}
        className="border border-line bg-void px-1 py-0.5 font-mono text-[0.9em] text-mineral"
      >
        {part}
      </code>
    ) : (
      <Fragment key={`${keyBase}-${i}`}>{part}</Fragment>
    ),
  );
}

type Block =
  | { kind: "code"; lines: string[] }
  | { kind: "list"; items: string[] }
  | { kind: "para"; text: string };

/** Regroupe les lignes en blocs. Un seul passage, pas d'analyse récursive :
 *  le vocabulaire est volontairement plat. */
function parse(src: string): Block[] {
  const blocks: Block[] = [];
  const lines = src.replace(/\r\n/g, "\n").split("\n");

  let i = 0;
  while (i < lines.length) {
    const line = lines[i] ?? "";

    if (line.trimStart().startsWith("```")) {
      const code: string[] = [];
      i++;
      while (i < lines.length && !(lines[i] ?? "").trimStart().startsWith("```")) {
        code.push(lines[i] ?? "");
        i++;
      }
      i++; // consomme la clôture, absente si le modèle l'a oubliée
      blocks.push({ kind: "code", lines: code });
      continue;
    }

    if (/^\s*[-*•]\s+/.test(line)) {
      const items: string[] = [];
      while (i < lines.length && /^\s*[-*•]\s+/.test(lines[i] ?? "")) {
        items.push((lines[i] ?? "").replace(/^\s*[-*•]\s+/, ""));
        i++;
      }
      blocks.push({ kind: "list", items });
      continue;
    }

    if (line.trim() === "") {
      i++;
      continue;
    }

    // Un paragraphe court jusqu'à la ligne vide, la puce ou le bloc de code
    // suivants. Les retours à la ligne internes sont conservés : dans une
    // sortie de moteur, un retour porte souvent un chemin de fichier ou une
    // seconde occurrence, pas un habillage.
    const para: string[] = [];
    while (
      i < lines.length &&
      (lines[i] ?? "").trim() !== "" &&
      !/^\s*[-*•]\s+/.test(lines[i] ?? "") &&
      !(lines[i] ?? "").trimStart().startsWith("```")
    ) {
      para.push(lines[i] ?? "");
      i++;
    }
    blocks.push({ kind: "para", text: para.join("\n") });
  }

  return blocks;
}

export function FindingProse({
  text,
  className,
  tone = "ash",
}: {
  text: string;
  className?: string;
  /** `mineral` pour un correctif — ce qu'on veut lire en premier. */
  tone?: "ash" | "mineral";
}) {
  const blocks = parse(text);
  const body = tone === "mineral" ? "text-mineral" : "text-ash";

  return (
    <div className={cn("max-w-[80ch] space-y-3 text-data", body, className)}>
      {blocks.map((b, i) => {
        if (b.kind === "code") {
          return (
            <pre
              key={i}
              // `text-data` et non `text-label` : ce dernier porte un
              // interlettrage de 0.12em et une hauteur de ligne de 1, réglés
              // pour des étiquettes de trois mots. Sur plusieurs lignes de
              // code, l'interlettrage désaligne les colonnes et la hauteur de
              // ligne colle les lignes entre elles.
              className="overflow-x-auto border border-line bg-void p-3 font-mono text-data leading-relaxed text-ash"
            >
              {b.lines.join("\n")}
            </pre>
          );
        }
        if (b.kind === "list") {
          return (
            <ul key={i} className="space-y-1.5">
              {b.items.map((item, j) => (
                <li key={j} className="flex gap-3">
                  <span aria-hidden className="shrink-0 font-mono text-acid">
                    ·
                  </span>
                  <span className="min-w-0">{inline(item, `${i}-${j}`)}</span>
                </li>
              ))}
            </ul>
          );
        }
        return (
          // `whitespace-pre-line` : conserve les retours à la ligne du texte
          // source tout en laissant le navigateur replier les lignes longues.
          <p key={i} className="whitespace-pre-line">
            {inline(b.text, String(i))}
          </p>
        );
      })}
    </div>
  );
}
