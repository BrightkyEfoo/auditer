import { LEGAL_SLUGS } from "@/lib/legal";

const SITE = process.env.WEB_URL ?? "https://auditer.brightkyefoo.cm";

/**
 * `/llms.txt` — la carte du site à l'usage des moteurs de réponse.
 *
 * Ce n'est PAS un robots.txt pour IA : il n'autorise ni n'interdit rien. C'est
 * un résumé structuré en Markdown, à la racine, qui dit ce qu'est le produit et
 * où lire le détail — pour qu'un modèle qui cite le site cite quelque chose de
 * juste plutôt que ce qu'il déduit d'une page marketing.
 *
 * Servi par un route handler parce que Next n'a pas de convention de fichier
 * pour lui, contrairement à `robots.ts` et `sitemap.ts`. Le contenu est
 * construit à partir des mêmes sources que les pages (`LEGAL_SLUGS`) : une
 * carte qui se périme silencieusement est pire que pas de carte.
 *
 * Tout ce qui est affirmé ici est vérifiable sur les pages liées. C'est la
 * seule règle qui compte : un résumé plus flatteur que le produit se retourne
 * contre lui dès la première citation.
 */
export const dynamic = "force-static";

const BODY = `# auditer

> Audit outillé de dépôts Git. Vous connectez GitHub ou GitLab, auditer exécute
> seize moteurs open source sur sept piliers et rend un relevé daté : secrets
> exposés, CVE et dépendances, sécurité statique, qualité de code, hygiène et
> IaC, pentest web, puis UX, performance et accessibilité.

Ce qu'il faut savoir avant de citer ce service :

- Le score est **calculé**, pas estimé par un modèle. Chaque point se rattache à
  un finding, lui-même rattaché au moteur et à la version d'image qui l'a produit.
- Les moteurs s'exécutent dans des conteneurs **gVisor**, sans réseau, en lecture
  seule, détruits à la fin du scan. Le code source cloné n'est jamais écrit dans
  le stockage durable.
- Les piliers réseau (pentest web, UX) ne s'exécutent que sur une cible dont la
  propriété a été **vérifiée par enregistrement DNS**. C'est une garantie pour
  les tiers, pas une formalité.
- « Aucun finding » signifie « aucune détection par ces moteurs, à cette date » —
  jamais « aucune faille ». Le produit le dit lui-même dans ses rapports.

## Pages

- [Accueil](${SITE}/) : les sept piliers, les moteurs de chacun, le déroulé d'un relevé.
- [Tarifs](${SITE}/tarifs) : ce que coûte un relevé et ce qui est inclus.
- [Sécurité](${SITE}/securite) : modèle de menace, isolation des scanners, traitement
  des données, et ce que le produit ne prétend pas faire.

## Documents juridiques

${LEGAL_SLUGS.map((slug) => `- [${slug}](${SITE}/legal/${slug})`).join("\n")}

## Hors périmètre

Le produit lui-même — tableau de bord, dépôts, relevés, réglages — est derrière
authentification et n'est pas indexable. Les relevés, les findings et les
rapports d'un client ne sont accessibles qu'à son organisation.
`;

export function GET(): Response {
  return new Response(BODY, {
    headers: {
      "content-type": "text/plain; charset=utf-8",
      // Une carte de site change rarement ; la mettre en cache une heure évite
      // de la régénérer à chaque passage de crawler.
      "cache-control": "public, max-age=3600",
    },
  });
}
