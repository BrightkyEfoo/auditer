/**
 * Marketing + product copy that is shared between the public site and the app
 * (pillar names, tool lists). Single source so a pillar renamed here is renamed
 * everywhere — and so the site never claims a scanner the engine does not
 * actually run.
 *
 * `tools` MUST stay in sync with packages/audit-engine/src/registry.ts. What is
 * listed is what runs; nothing aspirational belongs on this page.
 */

export interface PillarInfo {
  id: string;
  index: string;
  name: string;
  claim: string;
  detail: string;
  tools: string[];
  /** Network access required — drives the "cible vérifiée" warning in the UI. */
  network?: boolean;
}

export const PILLARS: PillarInfo[] = [
  {
    id: "secrets",
    index: "01",
    name: "Secrets exposés",
    claim: "Tout l'historique, pas le dernier commit.",
    detail:
      "Clone non superficiel, toutes les branches et les objets orphelins. Une clé retirée il y a huit mois est toujours dans les objets git — et toujours valide.",
    tools: ["gitleaks"],
  },
  {
    id: "sca",
    index: "02",
    name: "CVE & dépendances",
    claim: "La base OSV en local, hors ligne.",
    detail:
      "Lecture des lockfiles, résolution transitive, correspondance sur la base OSV embarquée. Aucun paquet n'est installé, aucun script n'est exécuté.",
    tools: ["osv-scanner"],
  },
  {
    id: "sast",
    index: "03",
    name: "Sécurité statique",
    claim: "Des règles versionnées, pas un registre distant.",
    detail:
      "Jeux de règles OWASP et CWE figés dans l'image du scanner. Injection, désérialisation, chemins de fichiers, cryptographie faible, contrôle d'accès.",
    tools: ["semgrep"],
  },
  {
    id: "quality",
    index: "04",
    name: "Qualité de code",
    claim: "La dette se mesure, elle ne se ressent pas.",
    detail:
      "Duplication de blocs, complexité, densité de défauts par millier de lignes. Les chiffres sont comparés d'un relevé au suivant, pas jugés dans l'absolu.",
    tools: ["jscpd"],
  },
  {
    id: "hygiene",
    index: "05",
    name: "Hygiène & IaC",
    claim: "Le dépôt lui-même est une surface d'attaque.",
    detail:
      "Dockerfile, manifestes Kubernetes, Terraform, workflows CI, permissions de jetons. La faille est souvent dans le pipeline, pas dans le code.",
    tools: ["trivy config", "hadolint"],
  },
  {
    id: "dast",
    index: "06",
    name: "Pentest web",
    claim: "Sur une cible dont vous prouvez la propriété.",
    detail:
      "Vérification DNS de la propriété du domaine, ré-résolution et épinglage des IP au démarrage du scan, sortie réseau restreinte à la cible. Sans preuve, le scan n'existe pas.",
    tools: ["nuclei"],
    network: true,
  },
  {
    id: "ux",
    index: "07",
    name: "UX, perf & a11y",
    claim: "Ce que vos utilisateurs subissent, chiffré.",
    detail:
      "Core Web Vitals, parcours réels au navigateur, violations WCAG 2.1 AA. Un site inaccessible est un site cassé, pas un site perfectible.",
    tools: ["lighthouse"],
    network: true,
  },
];

/** Exactly the adapters wired in the engine registry. Do not pad this list. */
export const ENGINES = [
  "gitleaks",
  "osv-scanner",
  "semgrep",
  "jscpd",
  "trivy",
  "hadolint",
  "nuclei",
  "lighthouse",
];

export interface StepInfo {
  index: string;
  title: string;
  body: string;
  stamp: string;
}

export const PIPELINE: StepInfo[] = [
  {
    index: "01",
    title: "Connexion",
    body: "GitHub App ou OAuth GitLab. Les jetons sont chiffrés par enveloppe avant d'atteindre la base ; la clé maîtresse ne quitte jamais le coffre.",
    stamp: "AES-256-GCM",
  },
  {
    index: "02",
    title: "Clone éphémère",
    body: "Le dépôt est cloné dans un espace de travail jetable, monté en lecture seule, puis détruit. Votre code source n'entre jamais dans le stockage durable.",
    stamp: "0 octet persisté",
  },
  {
    index: "03",
    title: "Sandbox",
    body: "Chaque moteur tourne dans son propre conteneur gVisor : noyau isolé, réseau coupé, système de fichiers en lecture seule, toutes les capacités retirées.",
    stamp: "runsc · cap-drop=ALL",
  },
  {
    index: "04",
    title: "Normalisation",
    body: "Toutes les sorties sont converties en SARIF puis en un modèle de finding unique, empreinté, puis dédupliqué entre outils avant toute analyse.",
    stamp: "SARIF 2.1.0",
  },
  {
    index: "05",
    title: "Relevé",
    body: "Le score est calculé par une formule versionnée. L'IA rédige l'explication et la remédiation ; elle ne touche jamais au chiffre.",
    stamp: "scoring v1",
  },
];

export interface GuaranteeInfo {
  title: string;
  body: string;
  stamp: string;
}

export const GUARANTEES: GuaranteeInfo[] = [
  {
    title: "Votre code n'est jamais stocké",
    body: "Le clone vit dans un répertoire éphémère détruit à la fin du run. Seuls les findings, les rapports et les journaux d'exécution sont conservés.",
    stamp: "SYS.01",
  },
  {
    title: "Isolation noyau, pas conteneur",
    body: "gVisor intercale un noyau applicatif entre le scanner et l'hôte. Un moteur compromis ne voit pas le noyau de la machine.",
    stamp: "SYS.02",
  },
  {
    title: "Cloisonnement en base",
    body: "PostgreSQL applique une politique de sécurité au niveau ligne, refus par défaut. Un filtre oublié dans le code ne peut pas faire fuiter une autre organisation.",
    stamp: "SYS.03",
  },
  {
    title: "Sortie réseau verrouillée",
    body: "Les scanners tournent sans réseau. Les rares étapes qui en ont besoin passent par un proxy qui bloque les adresses privées et les métadonnées cloud.",
    stamp: "SYS.04",
  },
  {
    title: "Images figées par empreinte",
    body: "Chaque moteur est épinglé sur un digest, jamais sur un tag mouvant. La version qui a produit votre relevé est celle qui est inscrite dedans.",
    stamp: "SYS.05",
  },
  {
    title: "L'IA ne reçoit pas d'ordres de votre code",
    body: "Le contenu du dépôt est encadré comme donnée non fiable, la sortie du modèle est contrainte par un schéma, et aucun outil à effet de bord ne lui est accessible.",
    stamp: "SYS.06",
  },
];
