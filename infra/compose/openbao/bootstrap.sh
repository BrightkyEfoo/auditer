#!/bin/sh
# Amorçage et descellement du coffre, à chaque démarrage de la pile.
#
# CE QUE CE SCRIPT FERME. Le coffre tournait en `server -dev`, dont le stockage
# est EN MÉMOIRE. Mesuré : un jeton GitLab scellé le 2026-08-25 à 04h29, un
# conteneur openbao recréé le 2026-09-02 à 18h06, et depuis, à chaque appel :
#
#   transit decrypt/auditer-kek failed: 400
#   {"errors":["cipher: message authentication failed"]}
#
# La KEK meurt avec le conteneur, et tout secret scellé avant devient
# définitivement illisible. Ce n'est pas une panne rare : c'est la garantie que
# chaque redémarrage de l'hôte déconnecte tous les comptes GitHub et GitLab.
#
# Le coffre passe donc en stockage fichier sur un volume nommé. Un stockage
# durable impose un descellement, et un descellement manuel laisserait le
# produit à terre après chaque reboot — exactement ce qu'un correctif précédent
# a fermé. Le descellement est donc automatique, à partir d'une clé conservée
# dans le .env du serveur.
#
# CE QUE ÇA COÛTE, dit franchement : la clé de descellement vit à côté du
# coffre. Un attaquant qui obtient l'hôte obtient les deux. La frontière qui
# reste est celle que les pages légales publiées revendiquent — « une copie de
# la base de données ne suffit pas à les déchiffrer » — et celle-là tient : les
# chiffrés sont en base, la clé n'y est pas.
set -eu

BAO_ADDR="${BAO_ADDR:-http://openbao:8200}"
export BAO_ADDR
KEY_NAME="${OPENBAO_TRANSIT_KEY:-auditer-kek}"

log() { echo "[openbao] $*"; }
fatal() { echo "[openbao] $*" >&2; exit 1; }

# `bao status` : 0 descellé, 2 scellé, 1 injoignable. On attend qu'il réponde,
# quel que soit son état de scellement.
log "attente du coffre sur $BAO_ADDR"
i=0
while :; do
  set +e; bao status >/dev/null 2>&1; code=$?; set -e
  [ "$code" -eq 0 ] || [ "$code" -eq 2 ] && break
  i=$((i + 1))
  [ "$i" -gt 120 ] && fatal "coffre injoignable après 120 s"
  sleep 1
done

# `bao operator init -status` : 0 initialisé, 2 non initialisé.
set +e; bao operator init -status >/dev/null 2>&1; init_status=$?; set -e

if [ "$init_status" -ne 0 ]; then
  # Deux cas arrivent ici, et un seul est bénin.
  #
  #   - Premier déploiement : normal, on initialise.
  #   - Volume perdu alors qu'une clé de descellement existe déjà : le stockage
  #     a disparu, donc TOUS les secrets déjà scellés sont morts. Repartir en
  #     silence rejouerait l'incident que ce fichier existe pour fermer, en
  #     laissant croire que tout va bien.
  #
  # Dans les deux cas on initialise puis on ÉCHOUE : les nouvelles valeurs sont
  # affichées une seule fois, et rien ne démarre tant qu'un humain ne les a pas
  # enregistrées. Un coffre neuf dont personne ne détient la clé de descellement
  # est un coffre qu'on ne pourra plus ouvrir au prochain redémarrage.
  log "coffre NON INITIALISÉ — initialisation en cours"
  out="$(bao operator init -key-shares=1 -key-threshold=1 -format=json)"
  unseal="$(echo "$out" | sed -n 's/.*"unseal_keys_b64": *\[ *"\([^"]*\)".*/\1/p')"
  root="$(echo "$out" | sed -n 's/.*"root_token": *"\([^"]*\)".*/\1/p')"
  [ -n "$unseal" ] && [ -n "$root" ] || fatal "initialisation illisible"

  # Les valeurs sont ÉCRITES SUR LE VOLUME, jamais imprimées. Ce script tourne
  # dans un déploiement dont la sortie est archivée par GitHub Actions et
  # lisible par quiconque a accès au dépôt ; un jeton racine n'a rien à y faire.
  # Le fichier vit sur le même hôte que le coffre, c'est-à-dire à l'intérieur de
  # la frontière qu'on a déjà acceptée en descellant automatiquement. Il va sur
  # un volume À PART : le stockage du coffre n'a pas à être inscriptible par un
  # autre conteneur.
  creds=/bootstrap/credentials.txt
  umask 077
  # L'écriture DOIT réussir : sans elle le coffre reste initialisé et scellé,
  # sans que personne ne détienne la clé de descellement — un coffre neuf qu'on
  # ne pourra plus jamais ouvrir. C'est arrivé une fois, en « Permission
  # denied », le conteneur ne tournant pas en root ; d'où le `user: "0:0"` dans
  # le compose et ce garde-fou.
  : > "$creds" 2>/dev/null || fatal \
    "coffre initialisé mais $creds non inscriptible — clé de descellement PERDUE, détruire le volume et recommencer"
  {
    echo "# Généré le $(date -u +%Y-%m-%dT%H:%M:%SZ) par openbao/bootstrap.sh."
    echo "# À reporter en secrets du dépôt GitHub, puis à SUPPRIMER ce fichier."
    echo "OPENBAO_TOKEN=$root"
    echo "OPENBAO_UNSEAL_KEY=$unseal"
  } > "$creds"

  echo
  echo "=================================================================="
  echo " COFFRE INITIALISÉ — action requise avant que le produit démarre"
  echo "=================================================================="
  echo " Les identifiants sont sur le serveur, pas dans ce journal :"
  echo
  echo "   docker compose -p auditer -f infra/compose/docker-compose.server.yml \\"
  echo "     run --rm --entrypoint cat openbao-init $creds"
  echo
  echo " Reporter OPENBAO_TOKEN et OPENBAO_UNSEAL_KEY en secrets du dépôt,"
  echo " relancer le déploiement, puis supprimer le fichier."
  if [ -n "${OPENBAO_UNSEAL_KEY:-}" ]; then
    echo
    echo " ATTENTION : une clé de descellement était déjà configurée alors que"
    echo " le coffre était vide — le volume a été perdu. Tous les jetons scellés"
    echo " auparavant sont IRRÉCUPÉRABLES ; les connexions concernées se"
    echo " marqueront « à reconnecter » au premier appel."
  fi
  echo
  exit 1
fi

# ── Descellement ────────────────────────────────────────────────────────────
if bao status 2>/dev/null | grep -q "Sealed *true"; then
  [ -n "${OPENBAO_UNSEAL_KEY:-}" ] || fatal \
    "coffre scellé et OPENBAO_UNSEAL_KEY absent — impossible de démarrer sans intervention"
  bao operator unseal "$OPENBAO_UNSEAL_KEY" >/dev/null
  log "descellé"
else
  log "déjà descellé"
fi

# ── Moteur transit + clé ────────────────────────────────────────────────────
# Idempotent : `secrets enable` échoue si déjà activé, `write -f` sur une clé
# existante est un no-op. NE JAMAIS ajouter de rotation ou de suppression ici —
# détruire une version de clé rend illisibles les chiffrés qu'elle enveloppe,
# ce qui est précisément l'incident d'origine.
[ -n "${BAO_TOKEN:-}" ] || fatal "BAO_TOKEN absent — le jeton du coffre est requis"
bao secrets enable transit >/dev/null 2>&1 || true
bao write -f "transit/keys/$KEY_NAME" >/dev/null
log "transit prêt (clé $KEY_NAME)"
