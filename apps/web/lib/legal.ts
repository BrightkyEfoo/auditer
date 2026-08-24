/**
 * Legal documents as data. Kept out of JSX so the wording can be reviewed (and
 * replaced by a lawyer) without touching layout, and so every document carries
 * the same mandatory stamps: version, date, applicable law.
 *
 * IMPORTANT — the identity of the publisher below uses explicit placeholders.
 * They are marked so they cannot be mistaken for real registration data; fill
 * them before any commercial launch.
 *
 * THE ONE RULE FOR EDITING THIS FILE
 * Every sentence here describes what the code DOES, never what we would like it
 * to do. A published promise with no implementation behind it is the single
 * legal exposure a product like this can create out of nothing, and this file
 * has already been caught doing it once: it announced four deletions and an
 * export that did not exist, and three retention periods that nothing enforced.
 *
 * So, concretely, before changing a sentence here:
 *   - a duration must exist as a constant in packages/retention/src/purge.ts
 *     and be applied by runRetentionPurge();
 *   - an action "depuis l'interface" must have BOTH an endpoint and a control
 *     in the app that reaches it;
 *   - a cadence must exist as a scheduler somewhere. "Chaque nuit à 03h30 UTC"
 *     is true only because apps/worker/src/retention-scheduler.ts registers a
 *     BullMQ Job Scheduler at that pattern; delete that file and this sentence
 *     becomes a lie the same day;
 *   - if a mechanism exists but is triggered by hand, SAY SO. "Nous le faisons
 *     à la main" is a sentence a regulator can live with. "C'est automatique",
 *     when it is not, is not.
 */

/** A paragraph, or a bulleted list of items. */
export type Block = string | string[];

export interface LegalSection {
  heading: string;
  body: Block[];
}

export interface LegalDoc {
  index: string;
  title: string;
  summary: string;
  version: string;
  updated: string;
  law: string;
  sections: LegalSection[];
}

/** Publisher identity, repeated across documents — declared once. */
export const PUBLISHER = {
  service: "auditer",
  entity: "[RAISON SOCIALE À COMPLÉTER]",
  form: "[FORME JURIDIQUE À COMPLÉTER]",
  registration: "[NUMÉRO D'IMMATRICULATION À COMPLÉTER]",
  address: "[ADRESSE DU SIÈGE À COMPLÉTER], Douala, Cameroun",
  publisher: "Brightky Efoo",
  email: "legal@auditer.brightkyefoo.cm",
  dpo: "privacy@auditer.brightkyefoo.cm",
  host: "OVH SAS — 2 rue Kellermann, 59100 Roubaix, France",
  domain: "auditer.brightkyefoo.cm",
} as const;

export const LEGAL_DOCS: Record<string, LegalDoc> = {
  confidentialite: {
    index: "L2",
    title: "Politique de confidentialité",
    summary:
      "Ce que nous collectons, ce que nous ne gardons pas — à commencer par votre code source —, combien de temps nous conservons le reste, à qui nous le transmettons, et comment exercer vos droits.",
    // 1.2 — la purge de rétention est planifiée (BullMQ, chaque nuit à 03h30
    // UTC). La version précédente devait écrire qu'aucun ordonnanceur ne la
    // déclenchait ; ce n'est plus vrai, donc la phrase est partie.
    version: "1.2",
    updated: "24 août 2026",
    law: "RGPD (Règlement UE 2016/679), droit camerounais",
    sections: [
      {
        heading: "Ce que nous collectons",
        body: [
          "Nous collectons le strict nécessaire pour exécuter un audit et vous en rendre compte. Rien n’est collecté à des fins publicitaires ou de revente.",
          [
            "Compte : adresse email, mot de passe haché en scrypt (jamais conservé en clair), nom d’affichage, organisation de rattachement. Si vous vous inscrivez via GitHub ou GitLab, l’identifiant public du compte et l’adresse email associée.",
            "Dépôts importés : nom, propriétaire, identifiant, visibilité, branche par défaut, URL de clonage. Ce sont des métadonnées, pas du contenu.",
            "Jetons d’accès VCS : jeton d’installation de la GitHub App, ou jetons OAuth GitLab (accès et rafraîchissement). Ils sont stockés chiffrés, jamais en clair.",
            "Findings : titre, description, règle déclenchée, gravité, chemin de fichier, numéros de ligne, extrait de preuve caviardé, explication et remédiation rédigées pour vous.",
            "Rapports générés et métadonnées de run : date, durée, piliers exécutés, versions des moteurs, statut, score.",
            "Journaux d’exécution des scanners et journaux techniques : horodatage, identifiant de run, code de sortie, messages d’erreur. Ils servent au diagnostic et à la détection d’abus.",
          ],
          "Nous ne posons aucun cookie publicitaire, n’intégrons aucun traceur tiers et n’utilisons aucun outil externe de mesure d’audience. Nous ne construisons donc aucune donnée de navigation, et aucun profil publicitaire n’existe chez nous — il n’y a rien à vous montrer parce qu’il n’y a rien à collecter.",
        ],
      },
      {
        heading: "Ce que nous ne conservons pas : votre code source",
        body: [
          "C’est le point le plus important de cette politique, alors soyons précis sur le cycle de vie du clone.",
          [
            "Au démarrage d’un run, le dépôt est cloné dans un répertoire éphémère, créé pour ce run et pour lui seul.",
            "Les moteurs d’analyse lisent ce répertoire en lecture seule, depuis des conteneurs isolés et sans accès réseau.",
            "À la fin du run — qu’il réussisse, échoue ou soit annulé — le répertoire est détruit.",
            "Le code source n’est jamais écrit dans le stockage objet durable. Il n’existe aucune sauvegarde de votre code chez nous, donc rien à restituer et rien à fuiter.",
          ],
          "Ce qui survit au run, ce sont les findings, les rapports générés, les métadonnées de run et les journaux d’exécution des scanners. Un finding contient un chemin de fichier, des numéros de ligne et un extrait de preuve caviardé : assez pour retrouver le problème dans votre dépôt, pas assez pour reconstituer votre code.",
        ],
      },
      {
        heading: "Finalités et bases légales",
        body: [
          "Chaque traitement repose sur une base légale explicite au sens de l’article 6 du RGPD.",
          [
            "Fournir le service — créer votre compte, importer vos dépôts, exécuter les audits, produire les rapports : exécution du contrat qui nous lie.",
            "Sécuriser le service — journaux techniques, détection d’abus, limitation de débit, attestations de propriété de domaine avant tout scan réseau : intérêt légitime à protéger l’infrastructure, nos utilisateurs et les tiers qui pourraient être visés à tort.",
            "Communications de service — nous n’envoyons à ce jour aucun courriel automatique : ni vérification d’adresse, ni réinitialisation de mot de passe, ni notification de fin de relevé. Le service ne comporte pas de mécanisme d’envoi. Votre adresse identifie le compte, sert à confirmer une suppression, et nous permet de vous joindre à la main s’il le faut. Le jour où un envoi automatique existera, ce paragraphe sera corrigé avant sa mise en service.",
            "Obligations comptables et réponse à une réquisition régulière d’autorité : obligation légale.",
            "Toute finalité sortant de ce cadre, par exemple une lettre d’information produit, repose sur votre consentement, donné par un acte positif et révocable à tout moment sans justification.",
          ],
          "Le service est gratuit dans sa phase actuelle : nous n’effectuons aucun traitement à finalité de facturation, et ne détenons aucune donnée de paiement.",
        ],
      },
      {
        heading: "Durées de conservation",
        body: [
          "Nous n’avons aucun intérêt à garder des données au-delà de leur utilité : chaque donnée conservée est une donnée à protéger. Les durées sont les suivantes.",
          [
            "Compte et données d’identification : tant que le compte est actif. La suppression, déclenchée depuis les réglages, est immédiate et définitive dans la base : le compte, l’organisation, les dépôts importés, les relevés, les findings, les rapports et les fichiers stockés associés disparaissent dans la foulée. Il n’y a ni corbeille, ni délai de grâce, ni restauration possible.",
            "Findings, rapports et métadonnées de relevé : 24 mois à compter du relevé, afin que vous puissiez suivre l’évolution d’un dépôt dans le temps. Passé ce délai, le relevé entier est effacé. Vous n’avez pas à attendre cette échéance : la suppression d’un relevé ou d’un dépôt est immédiate depuis l’interface.",
            "Journaux d’exécution des scanners et journaux techniques : 90 jours. Sont concernés la sortie brute des moteurs, les journaux de conteneur et les messages d’erreur attachés à chaque exécution.",
            "Jetons d’accès VCS : jusqu’à révocation, qui se fait depuis les réglages. Le chiffré est alors écrasé et la connexion supprimée. La révocation chez GitHub ou GitLab, elle, se fait chez eux : nous n’avons pas le pouvoir de désinstaller une application à votre place.",
            "Attestations d’autorisation des scans réseau : 24 mois, parce qu’elles constituent la preuve de l’autorisation d’un scan et protègent la cible, qui est un tiers. Elles survivent volontairement à la suppression du compte et expirent sur leur propre horloge.",
            "Sessions : 30 jours, la durée du cookie. Les sessions expirées sont effacées de la base par la purge quotidienne décrite ci-dessous.",
            "Code source cloné : la durée du run, et rien de plus. Voir la section précédente.",
          ],
          "Ces durées ne sont pas déclaratives : une tâche automatique les applique chaque nuit, à 03h30 UTC — 04h30 à Douala. Elle efface les relevés de plus de 24 mois avec les findings, les rapports et les fichiers qui en dépendent ; les journaux d’exécution de plus de 90 jours, aussi bien les sorties des moteurs conservées comme fichiers que les messages d’erreur attachés à chaque exécution ; les fichiers dont l’échéance propre est dépassée ; les attestations d’autorisation de plus de 24 mois ; et les sessions expirées.",
          "Deux précisions, parce qu’une purge quotidienne n’est pas une purge instantanée. La tâche passe une fois par jour : une donnée peut donc survivre à son échéance jusqu’au passage suivant, vingt-quatre heures au plus. Et si des analyses sont en cours à l’heure prévue, elle patiente pour ne pas les ralentir — deux heures au maximum, après quoi elle s’exécute quand même : une échéance de conservation ne se négocie pas contre la charge du serveur.",
          "Chaque suppression est consignée dans le journal d’activité de votre organisation, avec le décompte de ce qui est parti, catégorie par catégorie ; un passage qui ne trouve rien à effacer chez vous n’y écrit rien. Ce journal fait partie de votre export JSON : vous pouvez donc vérifier vous-même que ces échéances sont tenues, plutôt que de nous croire sur parole.",
          "Ce qui, en revanche, ne dépend d’aucune purge : la suppression d’un dépôt, d’un relevé, d’une connexion ou du compte est exécutée au moment où vous la demandez, dans la seconde.",
        ],
      },
      {
        heading: "Sous-traitants et transferts",
        body: [
          "Nous ne vendons aucune donnée. Nous ne transmettons à un tiers que ce qui est nécessaire au fonctionnement du service. La liste ci-dessous est complète à la date de cette version.",
          [
            "Anthropic (API Claude), États-Unis — rédaction des explications et des remédiations attachées aux findings.",
            "OVH SAS, Roubaix, France — hébergement de l’application, des bases de données et des exécutions d’analyse.",
            "GitHub et GitLab — non pas destinataires, mais sources : nous lisons les dépôts que vous désignez, dans la limite des permissions que vous accordez, et vous pouvez révoquer cet accès chez eux à tout moment.",
          ],
          "Ce qui est transmis à Anthropic, précisément : des extraits de code limités autour du finding, le titre du finding, la règle déclenchée et sa gravité. Le modèle rédige l’explication et la remédiation, dans une sortie contrainte par un schéma. Le contenu du dépôt lui est présenté comme donnée non fiable, afin qu’une instruction dissimulée dans votre code ne puisse pas détourner le traitement.",
          "Ce qui n’est pas transmis à Anthropic : le dépôt complet, vos jetons d’accès, vos identifiants de compte, votre adresse email. Le modèle ne calcule pas le score de l’audit — le score est calculé chez nous, de façon déterministe, à partir des findings.",
          "Le recours à Anthropic constitue un transfert de données hors Union européenne. Il est encadré par les clauses contractuelles types adoptées par la Commission européenne.",
          "Nous ne détenons à ce jour aucune certification ISO 27001 ni rapport SOC 2. Nous préférons l’écrire noir sur blanc plutôt que de laisser le doute travailler en notre faveur.",
        ],
      },
      {
        heading: "Sécurité des traitements",
        body: [
          "Les mécanismes ci-dessous ne sont pas des intentions. Ils sont en place, et chacun ferme un risque précis.",
          [
            "Les moteurs d’analyse s’exécutent dans des conteneurs gVisor (runsc) éphémères : réseau coupé par défaut, système de fichiers en lecture seule, toutes les capacités Linux retirées, utilisateur non-root, images épinglées par empreinte. Un moteur compromis par un dépôt hostile n’a ni réseau pour exfiltrer, ni écriture pour persister.",
            "Les jetons d’accès VCS sont chiffrés par enveloppe en AES-256-GCM, la clé maîtresse ne quittant jamais un coffre (OpenBao Transit). Une copie de la base de données ne suffit donc pas à les déchiffrer.",
            "Le cloisonnement entre organisations est posé à deux niveaux. Chaque ligne porte l’identifiant de son organisation, et toute requête est ouverte dans une transaction qui déclare l’organisation appelante puis filtre sur elle. Des politiques de Row-Level Security PostgreSQL, en refus par défaut, sont installées sur toutes les tables concernées et constituent le filet : elles s’appliquent intégralement au processus qui exécute les analyses. Nous ne prétendons pas qu’aujourd’hui tous nos processus soient soumis à ce filet — celui qui sert l’interface se connecte encore avec un rôle qui le contourne, et son cloisonnement repose donc sur le filtrage applicatif décrit ci-dessus. Nous préférons l’écrire.",
            "Les mots de passe sont hachés en scrypt. Les sessions reposent sur un cookie opaque HttpOnly, SameSite=Lax, dont seul un hachage SHA-256 est conservé côté serveur : une fuite de la table de sessions ne rend aucune session rejouable.",
            "Avant tout scan réseau, la propriété du domaine cible doit être prouvée par un enregistrement DNS TXT. Les adresses IP sont ré-résolues et épinglées au démarrage du scan, ce qui referme la fenêtre entre la vérification et l’exécution.",
          ],
        ],
      },
      {
        heading: "Vos droits",
        body: [
          "Le RGPD vous reconnaît les droits suivants sur vos données personnelles.",
          [
            "Accès : obtenir la confirmation qu’un traitement existe et une copie des données que nous détenons sur vous.",
            "Rectification : faire corriger une donnée inexacte ou incomplète.",
            "Effacement : demander la suppression de votre compte et des données qui s’y rattachent.",
            "Portabilité : recevoir vos données dans un format structuré, couramment utilisé et lisible par machine.",
            "Opposition : vous opposer à un traitement fondé sur notre intérêt légitime, pour des raisons tenant à votre situation particulière.",
            "Limitation : demander le gel d’un traitement le temps qu’une contestation soit tranchée.",
          ],
          "Une partie de ces droits s’exerce directement depuis l’interface, sans nous écrire : export de vos données au format JSON depuis les réglages, suppression d’un dépôt et de ses relevés depuis la page Dépôts, suppression d’un relevé et de ses findings depuis la page du relevé, révocation d’une connexion et destruction du jeton chiffré depuis les réglages, suppression du compte depuis les réglages. Ces cinq actions sont exécutées immédiatement et sont irréversibles ; la suppression du compte demande la ressaisie de votre adresse e-mail, vérifiée sur nos serveurs.",
          `Pour le reste, écrivez à ${PUBLISHER.dpo} depuis l’adresse email de votre compte. Si nous avons un doute raisonnable sur votre identité, nous pouvons demander un élément de vérification supplémentaire — et rien d’autre que ce qui est nécessaire à cette vérification.`,
          "Nous répondons dans un délai d’un mois à compter de la réception de la demande. Ce délai peut être prolongé de deux mois si la demande est complexe ou multiple ; dans ce cas, nous vous en informons avec le motif avant la fin du premier mois.",
          "Si votre demande porte sur des données figurant dans le dépôt d’une organisation cliente, c’est cette organisation qui en est responsable de traitement, et nous ne pouvons pas décider à sa place. Nous lui transmettons votre demande sans délai et lui fournissons les moyens techniques d’y répondre.",
        ],
      },
      {
        heading: "Réclamation auprès d’une autorité de contrôle",
        body: [
          `Si vous estimez que vos droits ne sont pas respectés, écrivez-nous d’abord à ${PUBLISHER.dpo} : la plupart des différends se règlent à ce stade, et plus vite.`,
          "Vous pouvez à tout moment saisir une autorité de contrôle. Si vous résidez dans l’Union européenne, il s’agit de l’autorité de protection des données de votre pays de résidence, de votre lieu de travail, ou du lieu où la violation alléguée a eu lieu. En France, c’est la CNIL.",
          "Saisir une autorité ne vous prive d’aucun recours juridictionnel, et n’exige pas de nous avoir écrit au préalable.",
        ],
      },
      {
        heading: "Modifications de la politique",
        body: [
          "Cette politique porte un numéro de version et une date de mise à jour. Les deux figurent en tête de page, afin que vous puissiez constater qu’un texte a changé.",
          "Toute modification substantielle — nouvelle finalité, nouveau sous-traitant, allongement d’une durée de conservation — est annoncée par email aux titulaires de compte au moins 30 jours avant son entrée en vigueur.",
          "Les corrections de forme sont publiées directement, avec incrément du numéro de version.",
        ],
      },
    ],
  },

  cgu: {
    index: "L3",
    title: "Conditions générales d’utilisation",
    summary:
      "Les règles d’usage du service : ce qu’un audit automatisé prouve et ne prouve pas, et à quelles conditions strictes vous pouvez lancer un scan réseau sur une cible.",
    version: "1.1",
    updated: "24 août 2026",
    law: "Droit camerounais, RGPD applicable aux résidents de l’UE",
    sections: [
      {
        heading: "Objet et acceptation",
        body: [
          `Les présentes conditions régissent l’accès au service ${PUBLISHER.service}, accessible à l’adresse ${PUBLISHER.domain}, et son utilisation. Elles forment un contrat entre vous — ou l’organisation que vous représentez — et ${PUBLISHER.entity}.`,
          "Créer un compte, importer un dépôt ou lancer un audit vaut acceptation pleine et entière de ces conditions. Si vous ne les acceptez pas, n’utilisez pas le service.",
          "Si vous agissez pour le compte d’une organisation, vous déclarez disposer du pouvoir de l’engager. Les actes réalisés depuis un compte rattaché à une organisation engagent cette organisation.",
          "La politique de confidentialité, la politique cookies et l’accord de sous-traitance complètent ces conditions et en font partie intégrante.",
        ],
      },
      {
        heading: "Compte et éligibilité",
        body: [
          [
            "Vous devez avoir 16 ans révolus. Le service n’est pas destiné aux mineurs de moins de 16 ans, et nous ne collectons pas sciemment leurs données. Si nous constatons un tel compte, nous le supprimons.",
            "Les informations fournies à l’inscription doivent être exactes et tenues à jour. Une adresse email valide est nécessaire : c’est le seul moyen dont nous disposons pour vous joindre, et c’est elle que vous ressaisissez pour confirmer la suppression de votre compte. Le service n’envoie aujourd’hui aucun courriel automatique — ni vérification d’adresse, ni réinitialisation de mot de passe : toute correspondance de notre part est envoyée à la main.",
            "Un compte est personnel. Vous êtes responsable de la confidentialité de vos identifiants et de toute action menée depuis votre compte, y compris par un tiers à qui vous les auriez confiés.",
            `Prévenez-nous sans délai à ${PUBLISHER.email} si vous soupçonnez un accès non autorisé. Nous pouvons alors invalider toutes vos sessions actives.`,
          ],
          "L’inscription se fait par adresse email et mot de passe, ou via GitHub ou GitLab. Connecter un compte VCS nous donne accès aux dépôts que vous désignez, dans la limite des permissions accordées. Vous pouvez révoquer cet accès à tout moment depuis GitHub ou GitLab, sans passer par nous.",
        ],
      },
      {
        heading: "Ce que le service fait et ne fait pas",
        body: [
          "Le service exécute des moteurs d’analyse sur le code que vous lui désignez, sur sept piliers : secrets exposés, vulnérabilités connues des dépendances, sécurité statique, qualité de code, hygiène de dépôt et infrastructure as code, test de pénétration web, ainsi qu’expérience utilisateur, performance et accessibilité.",
          "Ce que le service ne fait pas — ce paragraphe mérite deux lectures :",
          [
            "Un audit automatisé ne remplace pas un audit humain. Il reconnaît des motifs connus ; il ne raisonne ni sur votre logique métier, ni sur vos règles d’autorisation, ni sur votre modèle de menace.",
            "L’absence de finding ne prouve pas l’absence de faille. Un rapport sans alerte signifie que les moteurs exécutés, dans leurs versions du jour, n’ont rien détecté sur le périmètre analysé. Rien de plus, et surtout pas que votre application est sûre.",
            "Le rapport est une aide à la décision. Il ne constitue ni une garantie de conformité réglementaire, ni une certification, ni un avis juridique, ni une attestation de sécurité opposable à un tiers ou à un assureur.",
            "Les moteurs produisent des faux positifs et des faux négatifs. La qualification finale d’un finding, et la décision de corriger ou non, vous appartiennent.",
            "Les explications et remédiations sont rédigées par un modèle de langage à partir du finding et d’extraits de code limités. Elles doivent être relues avant toute application en production. Le score, lui, est calculé de façon déterministe à partir des findings, sans intervention du modèle.",
          ],
          "Vous restez responsable de la sécurité de vos systèmes. Le service vous aide à voir ; il ne décide ni ne corrige à votre place.",
        ],
      },
      {
        heading: "Usage autorisé du test de pénétration (DAST)",
        body: [
          "Cette section est la plus importante de ces conditions. Lancer un scan réseau sur une cible que l’on ne possède pas, sans autorisation, constitue une infraction pénale dans la plupart des juridictions, y compris au Cameroun et dans l’Union européenne.",
          "En lançant un scan sur une cible, vous déclarez et garantissez :",
          [
            "Que vous êtes propriétaire du domaine et de l’infrastructure ciblés, ou que vous disposez d’un mandat écrit, explicite et en cours de validité émanant de leur propriétaire.",
            "Que ce mandat couvre la nature des tests exécutés et la période pendant laquelle vous les lancez.",
            "Que vous n’utiliserez pas le service pour tester une cible appartenant à un tiers en dehors de ce cadre, y compris à des fins de démonstration ou de recherche.",
          ],
          "La vérification de propriété est obligatoire et technique : avant tout scan réseau, vous devez publier un enregistrement DNS TXT sur le domaine cible. Sans cette preuve, le scan ne démarre pas — ce n’est pas une case à cocher, c’est un contrôle exécuté par le service. Au démarrage du scan, les adresses IP sont ré-résolues et épinglées, afin qu’un changement DNS opéré entre la vérification et l’exécution ne puisse pas rediriger les requêtes vers un tiers.",
          "Ces garde-fous techniques ne vous exonèrent de rien. Vous êtes seul responsable, civilement et pénalement, d’un scan lancé sur une cible que vous ne possédez pas ou pour laquelle vous ne disposez pas d’un mandat. Vous nous garantissez contre toute réclamation, plainte ou action d’un tiers née d’un tel scan, et prenez à votre charge les frais de défense correspondants.",
          "Pour chaque scan, nous conservons une attestation immuable : la cible, la preuve de propriété présentée, les adresses IP épinglées, l’identité du compte à l’origine du lancement, la date et l’heure. Cette attestation vous protège autant qu’elle nous protège. Elle est produite à toute autorité qui en fait la demande régulière.",
          "Nous pouvons suspendre un scan en cours, un compte ou une organisation entière, sans préavis, en cas de doute sérieux sur l’autorisation. Nous préférons interrompre à tort un utilisateur légitime que laisser partir une requête vers un tiers qui n’a rien demandé.",
        ],
      },
      {
        heading: "Usages interdits",
        body: [
          "Sont notamment interdits :",
          [
            "Tenter de sortir de la sandbox d’exécution, d’y escalader des privilèges, ou de détourner les moteurs d’analyse pour exécuter du code arbitraire sur notre infrastructure.",
            "Scanner, analyser ou tester une cible ou un dépôt appartenant à un tiers sans l’autorisation décrite à la section précédente.",
            "Tenter d’accéder aux données, aux findings, aux rapports ou aux jetons d’une autre organisation, ou de contourner de quelque manière que ce soit le cloisonnement multi-tenant.",
            "Revendre, sous-licencier, louer ou reconditionner le service, en tout ou partie, sous une autre marque.",
            "Soumettre au service du contenu conçu pour détourner ses traitements automatisés, y compris des instructions dissimulées visant le modèle de langage.",
            "Dégrader le service : charge disproportionnée, contournement des limites de débit, création de comptes en série, exécution de runs sans objet réel.",
            "Utiliser le service en violation d’une loi applicable, d’un droit de tiers ou d’une sanction internationale.",
          ],
          "Une violation peut entraîner la suspension immédiate, la résiliation du compte, et s’il y a lieu un signalement aux autorités compétentes. Les tentatives d’évasion de la sandbox et les scans non autorisés sont traités comme des incidents de sécurité, pas comme des erreurs d’usage.",
        ],
      },
      {
        heading: "Propriété intellectuelle et licence limitée",
        body: [
          "Le service, son interface, son code, ses textes et sa charte graphique demeurent notre propriété ou celle de nos concédants. Nous vous accordons une licence personnelle, non exclusive, non transférable et révocable, strictement limitée à l’usage du service conformément à ces conditions.",
          "Votre code, vos dépôts, vos findings et vos rapports vous appartiennent. Nous n’acquérons aucun droit de propriété sur ce contenu. Nous n’en faisons aucun autre usage que l’exécution du service que vous demandez, et nous ne l’utilisons pas pour entraîner un modèle.",
          "Les moteurs d’analyse sont des logiciels tiers distribués sous licences libres et exécutés sans modification, dans des processus séparés. Leurs licences respectives s’appliquent à eux ; la liste des moteurs et de leurs versions figure dans chaque rapport produit.",
          "Vous pouvez librement diffuser un rapport généré pour vos dépôts, y compris à un client ou à un auditeur. Rappelez-lui alors ce qu’un rapport prouve et ce qu’il ne prouve pas.",
        ],
      },
      {
        heading: "Disponibilité, gratuité de la phase actuelle et évolution tarifaire",
        body: [
          "Le service est fourni en l’état et selon disponibilité. Nous ne souscrivons aucun engagement de niveau de service : des interruptions pour maintenance, incident ou évolution sont possibles. Nous cherchons à annoncer celles qui sont planifiées.",
          "Le service est gratuit pendant sa phase actuelle. Aucune donnée de paiement n’est collectée. La gratuité n’emporte de notre part aucune renonciation à nos droits, et n’ouvre droit à aucun dédommagement en cas d’indisponibilité.",
          "Une tarification pourra être introduite. Dans ce cas :",
          [
            "Nous prévenons les titulaires de compte par email au moins 30 jours avant l’entrée en vigueur des nouveaux tarifs.",
            "Aucun montant ne sera prélevé sans une acceptation explicite de votre part. L’absence de réponse ne vaut pas acceptation.",
            "À défaut d’acceptation, le compte bascule en lecture seule ou est clôturé, à votre choix. L’export JSON de vos données reste disponible depuis les réglages tant que le compte existe : nous ne clôturons pas un compte sans vous avoir laissé le temps de le télécharger. Passé la clôture, il n’y a plus rien à exporter, puisque la suppression n’est pas différée.",
          ],
        ],
      },
      {
        heading: "Limitation de responsabilité",
        body: [
          "Nous mettons en œuvre les mesures décrites dans la politique de confidentialité et dans l’accord de sous-traitance. Nous ne garantissons pas que le service détectera toute vulnérabilité, ni qu’il sera exempt d’erreur, ni qu’il sera disponible sans interruption.",
          "Dans la limite permise par le droit applicable, nous ne répondons pas des dommages indirects : perte d’exploitation, perte de données, atteinte à l’image, manque à gagner, ni des conséquences d’une décision prise sur la seule foi d’un rapport automatisé.",
          "Le service étant fourni gratuitement dans sa phase actuelle, notre responsabilité totale, toutes causes confondues, ne peut excéder le montant que vous nous avez versé au titre du service — soit zéro.",
          "Ces limitations ne s’appliquent ni en cas de faute lourde ou de dol de notre part, ni aux dommages corporels, ni à aucune responsabilité que le droit applicable interdit d’écarter.",
        ],
      },
      {
        heading: "Suspension et résiliation",
        body: [
          "Vous pouvez fermer votre compte à tout moment depuis les réglages, sans motif et sans préavis. L’opération demande la ressaisie de votre adresse e-mail, vérifiée sur nos serveurs, puis efface immédiatement le compte, l’organisation, les dépôts importés, les relevés, les findings, les rapports et les fichiers stockés associés ; les jetons d’accès chiffrés sont détruits. Elle est irréversible et rien n’est conservé pour vous être restitué ensuite : exportez vos données avant si vous en avez besoin. Seules subsistent les attestations d’autorisation des scans réseau que vous avez lancés, qui protègent leurs cibles et expirent au bout de 24 mois.",
          "Nous pouvons suspendre ou résilier un compte dans les cas suivants :",
          [
            "Violation de ces conditions, en particulier des sections sur l’usage autorisé du test de pénétration et sur les usages interdits.",
            "Doute sérieux sur l’autorisation d’un scan en cours ou programmé.",
            "Usage portant atteinte à un tiers, à l’infrastructure ou aux autres utilisateurs.",
            "Obligation légale ou injonction d’une autorité compétente.",
          ],
          "Sauf urgence ou obligation contraire, nous notifions la mesure et son motif, et laissons 30 jours pour exporter vos données. En cas de risque immédiat pour un tiers, la suspension est immédiate et la notification suit.",
          "L’arrêt définitif du service serait annoncé au moins 60 jours à l’avance, l’export restant possible pendant toute cette période.",
        ],
      },
      {
        heading: "Droit applicable et règlement des litiges",
        body: [
          "Ces conditions sont régies par le droit camerounais. Le RGPD s’applique aux personnes concernées résidant dans l’Union européenne, et rien ici ne réduit les droits que des dispositions impératives leur reconnaissent.",
          `En cas de différend, adressez-nous une réclamation écrite à ${PUBLISHER.email}, en exposant les faits et ce que vous attendez. Nous répondons sous 30 jours et cherchons une solution amiable.`,
          "À défaut d’accord, le litige relève des tribunaux compétents de Douala, sauf si une règle impérative de protection du consommateur vous ouvre une autre juridiction — auquel cas cette règle prévaut.",
        ],
      },
      {
        heading: "Modification des conditions",
        body: [
          "Nous pouvons modifier ces conditions. La version en vigueur, son numéro et sa date figurent en tête de page.",
          "Une modification substantielle est annoncée par email aux titulaires de compte au moins 30 jours avant son entrée en vigueur. Continuer à utiliser le service après cette date vaut acceptation. Si vous refusez, fermez votre compte avant l’échéance et exportez vos données.",
          "Les corrections de forme prennent effet à leur publication, avec incrément du numéro de version.",
        ],
      },
    ],
  },

  cookies: {
    index: "L4",
    title: "Politique cookies",
    summary:
      "Nous posons un seul cookie, strictement nécessaire à votre session, et aucun traceur. Ce document est court parce qu’il n’y a rien d’autre à déclarer.",
    version: "1.1",
    updated: "24 août 2026",
    law: "RGPD (Règlement UE 2016/679), directive ePrivacy 2002/58/CE",
    sections: [
      {
        heading: "Le seul cookie que nous posons",
        body: [
          "Le service dépose un unique cookie, indispensable pour vous garder connecté d’une page à l’autre.",
          [
            "Nom : auditer_session",
            "Finalité : maintenir votre session authentifiée entre deux requêtes",
            "Type : strictement nécessaire à la fourniture du service",
            "Durée : 30 jours",
            "Contenu : un identifiant opaque, sans aucune donnée personnelle lisible",
            "Attributs : HttpOnly, SameSite=Lax",
            `Émetteur : ${PUBLISHER.domain}, cookie interne, jamais partagé avec un tiers`,
          ],
          "Le jeton porté par ce cookie n’est pas stocké tel quel côté serveur : nous n’en conservons qu’un hachage SHA-256. Un accès à notre base ne permet donc pas de rejouer une session. L’attribut HttpOnly empêche un script de lire le cookie, et SameSite=Lax limite son envoi lors des navigations depuis un autre site.",
        ],
      },
      {
        heading: "Ce que nous ne posons pas",
        body: [
          [
            "Aucun cookie publicitaire, aucun cookie de reciblage.",
            "Aucun traceur tiers, aucun pixel espion, aucune balise de suivi.",
            "Aucun outil externe de mesure d’audience ou d’analytics.",
            "Aucun partage de données de navigation avec un tiers — il n’y a pas de données de navigation à partager.",
          ],
          "Conséquence directe : nous n’affichons pas de bandeau de consentement. Un cookie strictement nécessaire à la fourniture d’un service expressément demandé par l’utilisateur est exempté de consentement. Comme c’est le seul que nous posons, il n’y a rien à vous demander, et un bandeau qui ne servirait qu’à se donner l’air conforme serait malhonnête.",
          "Si nous devions un jour poser un cookie non essentiel, nous demanderions votre consentement avant de le déposer, et cette page serait mise à jour avant toute mise en service.",
        ],
      },
      {
        heading: "Cookies déposés par des tiers lors des connexions OAuth",
        body: [
          "Quand vous vous connectez via GitHub ou GitLab, ou quand vous autorisez l’accès à vos dépôts, votre navigateur est redirigé vers leurs pages. Pendant ce passage, ces services déposent leurs propres cookies.",
          [
            "Ces cookies sont posés sur les domaines de GitHub ou de GitLab, pas sur le nôtre.",
            "Ils servent leur authentification et leur sécurité, pas le fonctionnement de notre service.",
            `Ils ne sont pas lisibles depuis ${PUBLISHER.domain} : un cookie reste cloisonné au domaine qui l’a posé.`,
            "Nous n’avons aucun contrôle sur leur nature, leur durée ni leur finalité, et nous n’en recevons pas le contenu.",
          ],
          "Leur usage relève des politiques de GitHub et de GitLab, à consulter chez eux. Une fois la redirection terminée, vous revenez sur notre domaine, où seul le cookie de session s’applique.",
        ],
      },
      {
        heading: "Comment refuser ou supprimer",
        body: [
          "Tout navigateur permet de bloquer les cookies d’un site ou de les supprimer, depuis ses paramètres de confidentialité. Vous pouvez aussi simplement vous déconnecter : la session est alors invalidée côté serveur et le cookie retiré.",
          "La conséquence est immédiate et sans contournement : sans ce cookie, impossible de rester connecté. Vous pourrez consulter les pages publiques, mais pas accéder à un dépôt, lancer un audit ni lire un rapport.",
          "Nous n’avons prévu aucun mécanisme de repli — pas d’identifiant de session passé dans l’URL, par exemple — parce que ces solutions de remplacement sont moins sûres que le cookie qu’elles remplacent.",
          `Pour supprimer non pas le cookie mais les données associées à votre compte, la page Réglages du service propose l’export puis la suppression, exécutés immédiatement. Le détail des durées figure dans la politique de confidentialité ; pour tout le reste, écrivez à ${PUBLISHER.dpo}.`,
        ],
      },
    ],
  },

  dpa: {
    index: "L5",
    title: "Accord de sous-traitance (RGPD)",
    summary:
      "Le contrat exigé par l’article 28 du RGPD lorsque vous nous confiez des dépôts susceptibles de contenir des données personnelles : vous restez responsable de traitement, nous agissons sur vos instructions.",
    version: "1.1",
    updated: "24 août 2026",
    law: "RGPD (Règlement UE 2016/679), article 28",
    sections: [
      {
        heading: "Rôles des parties",
        body: [
          "Le présent accord complète les conditions générales d’utilisation. Il s’applique dès que vous confiez au service des dépôts susceptibles de contenir des données à caractère personnel — c’est-à-dire, en pratique, à peu près tous.",
          [
            "Vous — le client, personne physique ou morale titulaire du compte ou de l’organisation — êtes responsable de traitement. Vous déterminez les finalités et les moyens : quels dépôts sont importés, quand un audit est lancé, sur quelle cible, et ce que deviennent les rapports.",
            `Nous — ${PUBLISHER.entity}, éditeur de ${PUBLISHER.service} — sommes sous-traitant au sens de l’article 28 du RGPD. Nous traitons ces données pour votre compte et sur vos instructions.`,
          ],
          "Pour les données de votre propre compte — adresse email, mot de passe haché, journaux de connexion — c’est nous qui sommes responsables de traitement. Elles relèvent de la politique de confidentialité, pas du présent accord.",
          "En cas de contradiction entre cet accord et les conditions générales sur un point de protection des données, le présent accord prévaut.",
        ],
      },
      {
        heading: "Objet, durée, nature et finalité du traitement",
        body: [
          [
            "Objet : l’analyse automatisée de dépôts de code et, le cas échéant, de cibles web dont vous avez prouvé la propriété.",
            "Nature des opérations : clonage éphémère, lecture, analyse statique et dynamique, extraction de findings, production de rapports, génération d’explications et de remédiations, conservation et mise à disposition des résultats.",
            "Finalité : fournir le service d’audit que vous demandez. Aucune autre finalité n’est poursuivie.",
            "Durée : celle de votre compte, augmentée des durées de conservation annoncées dans la politique de confidentialité et rappelées à la section sur le sort des données.",
          ],
          "Le code source cloné n’est traité que pendant la durée du run, dans un répertoire éphémère détruit à la fin de celui-ci. Il n’est jamais écrit dans le stockage objet durable. Ce qui subsiste, ce sont les findings, les rapports, les métadonnées de run et les journaux d’exécution des scanners.",
        ],
      },
      {
        heading: "Catégories de données et de personnes concernées",
        body: [
          "Vous restez maître de ce que vous nous soumettez. Mais un dépôt de code contient presque toujours des données personnelles, souvent sans que personne l’ait décidé.",
          [
            "Métadonnées git : noms et adresses email des auteurs et committers, présents dans l’historique et repris par certains moteurs.",
            "Adresses email, noms, identifiants ou numéros de téléphone codés en dur dans le code, dans des fixtures, des jeux d’essai ou des commentaires.",
            "Secrets détectés : clés d’API, jetons, mots de passe, chaînes de connexion. Nominatifs ou non, ils sont traités comme des données sensibles et l’extrait de preuve conservé est caviardé.",
            "Données de test reproduisant des données de production, y compris, si vous en placez, des catégories particulières au sens de l’article 9 du RGPD.",
            "Chemins de fichiers et noms de répertoires pouvant contenir des noms de personnes.",
            "Pour les scans réseau : le domaine cible, les adresses IP épinglées, et les réponses du serveur analysé.",
          ],
          "Personnes concernées : vos collaborateurs et contributeurs, les auteurs de commits présents dans l’historique du dépôt, et toute personne dont les données figurent dans le contenu que vous soumettez.",
          "Nous vous recommandons de ne pas soumettre de données de production ni de catégories particulières de données. Le service n’en a pas besoin pour fonctionner, et chaque donnée que vous ne nous confiez pas est une donnée qu’aucune de nos mesures n’aura à protéger.",
        ],
      },
      {
        heading: "Instructions documentées",
        body: [
          "Nous ne traitons les données que sur instruction documentée de votre part. Vos instructions sont constituées par le présent accord, les conditions générales, et vos actions dans l’interface ou l’API : importer un dépôt, lancer un relevé, choisir des piliers, supprimer un dépôt, supprimer un relevé et ses findings, révoquer une connexion, exporter vos données, supprimer le compte.",
          "Nous n’utilisons vos données pour aucune finalité propre. Nous ne les vendons pas, ne les monétisons pas, et ne les utilisons pas pour entraîner un modèle.",
          "Si une instruction nous paraît constituer une violation du RGPD ou d’une autre disposition relative à la protection des données, nous vous en informons sans délai et pouvons en suspendre l’exécution jusqu’à clarification.",
          "Si le droit auquel nous sommes soumis nous impose un traitement allant au-delà de vos instructions, nous vous en informons avant de le mettre en œuvre, sauf si ce droit interdit une telle information pour des motifs importants d’intérêt public.",
        ],
      },
      {
        heading: "Confidentialité du personnel",
        body: [
          "L’accès aux données traitées pour votre compte est limité aux personnes qui en ont besoin pour exploiter le service, et à elles seules.",
          [
            "Chaque personne ayant accès est tenue par une obligation de confidentialité écrite, qui survit à la fin de sa mission.",
            "Les accès sont nominatifs et tracés, et revus à chaque changement de mission ou départ.",
            "Aucun accès en clair aux jetons VCS : le déchiffrement passe par le coffre et laisse une trace.",
            "En exploitation courante, le code source de vos dépôts n’est consultable par personne : il n’existe que dans le répertoire éphémère d’un run, détruit à la fin de celui-ci.",
          ],
        ],
      },
      {
        heading: "Mesures de sécurité (article 32)",
        body: [
          "Les mesures suivantes sont en place. Elles sont décrites ici avec assez de précision pour que vous puissiez les reprendre dans votre registre des traitements ou votre analyse d’impact.",
          [
            "Isolation d’exécution : les moteurs d’analyse tournent dans des conteneurs gVisor (runsc) éphémères, réseau coupé par défaut, système de fichiers en lecture seule, toutes les capacités Linux retirées, utilisateur non-root, images épinglées par empreinte.",
            "Chiffrement des secrets : les jetons d’accès VCS sont chiffrés par enveloppe en AES-256-GCM, la clé maîtresse résidant dans un coffre (OpenBao Transit) qu’elle ne quitte pas.",
            "Cloisonnement des clients : chaque ligne porte l’identifiant de son organisation et toute requête est ouverte dans une transaction qui déclare l’organisation appelante puis filtre sur elle. Des politiques de Row-Level Security PostgreSQL en refus par défaut sont installées sur toutes les tables concernées et s’appliquent intégralement au processus d’analyse ; le processus qui sert l’interface se connecte encore avec un rôle qui les contourne, et son cloisonnement repose donc sur le filtrage applicatif. Nous le signalons plutôt que de laisser supposer l’inverse.",
            "Authentification : mots de passe hachés en scrypt, sessions portées par un cookie opaque HttpOnly SameSite=Lax dont seul un hachage SHA-256 est conservé côté serveur.",
            "Minimisation : le code source n’est jamais persisté, et les extraits de preuve attachés aux findings sont caviardés.",
            "Contrôle des scans réseau : preuve de propriété du domaine par enregistrement DNS TXT, adresses IP ré-résolues et épinglées au démarrage du scan.",
            "Localisation : hébergement dans l’Union européenne, chez OVH SAS à Roubaix (France).",
          ],
          "Nous ne détenons à ce jour ni certification ISO 27001 ni rapport SOC 2, et nous ne prétendons pas le contraire. Les mesures ci-dessus sont vérifiables techniquement ; elles ne sont attestées par aucun tiers.",
        ],
      },
      {
        heading: "Sous-traitants ultérieurs",
        body: [
          "Vous autorisez le recours aux sous-traitants ultérieurs listés ci-dessous. Cette liste est complète à la date de la présente version.",
          [
            "OVH SAS — Roubaix, France — hébergement de l’application, des bases de données et des exécutions d’analyse. Données concernées : l’ensemble des données conservées. Aucun transfert hors Union européenne.",
            "Anthropic (API Claude) — États-Unis — rédaction des explications et des remédiations attachées aux findings. Données transmises : extraits de code limités autour du finding, titre du finding, règle déclenchée, gravité. Transfert encadré par les clauses contractuelles types de la Commission européenne.",
          ],
          "Ce qui n’est jamais transmis à Anthropic : le dépôt complet, les jetons d’accès VCS, les identifiants de compte, les adresses email des utilisateurs. Le modèle ne calcule pas le score de l’audit, sa sortie est contrainte par un schéma, et le contenu du dépôt lui est présenté comme donnée non fiable afin qu’une instruction dissimulée dans un fichier ne puisse pas détourner le traitement.",
          "Chaque sous-traitant ultérieur est lié par des obligations de protection au moins équivalentes à celles du présent accord. Nous demeurons pleinement responsables envers vous de l’exécution de leurs obligations.",
          "Nous vous informons par email de tout ajout ou remplacement de sous-traitant ultérieur au moins 30 jours avant sa mise en service. Vous pouvez vous y opposer dans ce délai pour un motif raisonnable et documenté tenant à la protection des données. À défaut de solution acceptable pour les deux parties, vous pouvez résilier sans frais et obtenir la suppression ou la restitution de vos données.",
        ],
      },
      {
        heading: "Assistance au responsable de traitement",
        body: [
          "Compte tenu de la nature du traitement et des informations dont nous disposons, nous vous assistons sur les points suivants.",
          [
            "Droits des personnes concernées : si une personne nous saisit directement au sujet du contenu de l’un de vos dépôts, nous ne répondons pas à votre place. Nous vous transmettons la demande sans délai et vous fournissons les moyens techniques d’y répondre, qui existent tous dans l’interface : export JSON de l’organisation, suppression d’un relevé et de ses findings, suppression d’un dépôt et de ses relevés, révocation d’une connexion.",
            "Analyse d’impact relative à la protection des données (article 35) et consultation préalable de l’autorité (article 36) : nous vous fournissons les informations techniques nécessaires, dont celles de la section Mesures de sécurité.",
            "Sécurité du traitement (article 32) : nous vous communiquons la description des mesures en vigueur et vous informons de leurs évolutions substantielles.",
            "Notification aux autorités et communication aux personnes (articles 33 et 34) : nous vous fournissons les éléments dont nous disposons pour vous permettre de notifier dans les délais qui vous sont impartis.",
          ],
          "Cette assistance est fournie sans frais tant que le service est gratuit.",
        ],
      },
      {
        heading: "Notification de violation de données",
        body: [
          "En cas de violation de données à caractère personnel affectant les données que nous traitons pour votre compte, nous vous en informons sans retard injustifié et au plus tard 48 heures après en avoir eu connaissance.",
          "La notification est adressée par email au contact déclaré sur votre organisation et contient, dans la limite de ce qui est connu à ce stade :",
          [
            "La nature de la violation, les catégories de données concernées et le volume approximatif de données et de personnes touchées.",
            "Les conséquences probables de la violation.",
            "Les mesures prises ou proposées pour y remédier et en limiter les effets.",
            "Le point de contact chez nous pour le suivi du dossier.",
          ],
          "Si toutes les informations ne peuvent être fournies en une seule fois, nous les communiquons par étapes, sans retard supplémentaire, plutôt que d’attendre un tableau complet.",
          "Il vous revient, en qualité de responsable de traitement, de notifier l’autorité de contrôle dans les 72 heures et, le cas échéant, d’informer les personnes concernées. Notre délai de 48 heures est calé pour vous laisser le temps de le faire.",
          "Nous ne notifions jamais une autorité de contrôle à votre place ni en votre nom, sauf si vous nous en donnez l’instruction écrite.",
        ],
      },
      {
        heading: "Sort des données en fin de contrat",
        body: [
          "À la fin de la prestation — clôture du compte, résiliation, arrêt du service — vous choisissez entre la suppression et la restitution. L’ordre compte, et il vous appartient : la restitution se fait avant, jamais après.",
          [
            "Restitution : un export JSON de votre compte, de votre organisation, de vos connexions (sans les jetons), dépôts, cibles, relevés, findings, rapports, décisions de triage et journal d’activité, disponible à tout moment depuis les réglages tant que le compte existe. Il n’est pas « mis à disposition pendant 30 jours » après la clôture : la suppression n’étant pas différée, il n’y aurait plus rien à mettre à disposition.",
            "Suppression : immédiate lorsqu’elle est déclenchée depuis les réglages. Sur demande écrite, nous l’exécutons sous 30 jours.",
            "Sauvegardes : nous n’exploitons aucune copie de sauvegarde pour restituer ou reconstituer des données supprimées. Les copies résiduelles qui subsisteraient dans une sauvegarde disparaissent avec sa rotation ; nous ne datons pas cette rotation ici, faute de pouvoir vous la garantir.",
            "Jetons d’accès VCS : le chiffré est écrasé au moment de la révocation ou de la clôture, avant toute autre opération, et sans attendre aucun délai.",
            "Code source : rien à supprimer, puisque rien n’a été conservé au-delà de la durée du relevé.",
            "Attestations d’autorisation des scans réseau : conservées 24 mois à compter du scan, y compris après la clôture. Elles ne vous concernent pas seul — elles établissent qu’une cible tierce avait bien été autorisée — et c’est pourquoi elles ne suivent pas le compte.",
          ],
          "Nous ne conservons ensuite que ce qu’une obligation légale impose de conserver, pour la seule durée de cette obligation et sans autre traitement que celui qu’elle exige.",
          "À défaut de choix exprimé de votre part dans les 30 jours suivant la fin de la prestation, la suppression s’applique par défaut.",
        ],
      },
      {
        heading: "Audit et mise à disposition des informations",
        body: [
          `Nous mettons à votre disposition les informations nécessaires pour démontrer le respect des obligations de l’article 28. Écrivez à ${PUBLISHER.dpo} : nous répondons sous 30 jours.`,
          [
            "Documentation technique des mesures de sécurité, à jour de la version en vigueur.",
            "Liste des sous-traitants ultérieurs, avec les catégories de données transmises à chacun.",
            "Éléments de traçabilité des accès aux données de votre organisation, sur demande motivée.",
          ],
          "Vous pouvez diligenter un audit, vous-même ou par un auditeur indépendant tenu au secret, au plus une fois par an — sauf incident de sécurité avéré ou demande d’une autorité de contrôle, cas où cette limite ne s’applique pas.",
          "L’audit se tient pendant les heures ouvrées, sur préavis raisonnable de 30 jours, selon un périmètre convenu par écrit. Il ne doit ni dégrader le service, ni exposer les données d’autres clients : c’est la contrepartie du cloisonnement qui protège les vôtres.",
          "Les tests d’intrusion sur notre infrastructure sont soumis à notre accord écrit préalable, avec un périmètre et une fenêtre d’exécution convenus — exactement l’exigence que nous vous imposons pour vos propres cibles.",
        ],
      },
    ],
  },

  mentions: {
    index: "L1",
    title: "Mentions légales",
    summary:
      "Qui édite ce service, qui l'héberge, et comment nous joindre. Ces informations sont exigées de tout service en ligne accessible au public.",
    version: "1.0",
    updated: "23 août 2026",
    law: "Droit camerounais, RGPD applicable aux résidents de l'UE",
    sections: [
      {
        heading: "Éditeur du service",
        body: [
          `Le service ${PUBLISHER.service}, accessible à l'adresse ${PUBLISHER.domain}, est édité par ${PUBLISHER.entity}, ${PUBLISHER.form}, immatriculée sous le numéro ${PUBLISHER.registration}, dont le siège est situé ${PUBLISHER.address}.`,
          `Directeur de la publication : ${PUBLISHER.publisher}. Contact : ${PUBLISHER.email}.`,
        ],
      },
      {
        heading: "Hébergement",
        body: [
          `L'infrastructure applicative et les données sont hébergées par ${PUBLISHER.host}.`,
          "Les traitements d'analyse (exécution des moteurs de scan) s'exécutent sur cette même infrastructure, dans des conteneurs isolés et éphémères décrits sur la page sécurité.",
        ],
      },
      {
        heading: "Propriété intellectuelle",
        body: [
          "La structure du service, son interface, ses textes et sa charte graphique sont protégés. Toute reproduction non autorisée est interdite.",
          "Les moteurs d'analyse utilisés sont des logiciels tiers distribués sous licences libres (MIT, Apache-2.0, BSD, LGPL, GPL selon l'outil). Ils sont exécutés sans modification, dans des processus séparés, et leurs licences respectives s'appliquent à eux. La liste des moteurs et de leurs versions figure dans chaque rapport produit.",
          "Votre code source, vos dépôts et les rapports générés à partir d'eux vous appartiennent. Nous n'acquérons aucun droit sur ce contenu.",
        ],
      },
      {
        heading: "Signalement d'une vulnérabilité",
        body: [
          `Si vous découvrez une faille de sécurité dans le service, écrivez à ${PUBLISHER.email} avec les éléments de reproduction. Nous accusons réception sous 72 heures.`,
          "Nous nous engageons à ne pas engager de poursuites contre une personne qui signale une faille de bonne foi, sans exfiltration de données ni dégradation du service.",
        ],
      },
    ],
  },
};

/** Ordered slugs — drives the footer, the sitemap and the static params. */
export const LEGAL_SLUGS = ["confidentialite", "cgu", "cookies", "dpa", "mentions"] as const;
