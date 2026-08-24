# nuclei avec un CORPUS DE TEMPLATES embarqué à /templates.
#
# Le pilier DAST était silencieusement mort, et de la pire façon : l'image amont
# (vérifié sur v3.4.10) n'installe QUE le binaire — `COPY --from=builder
# /app/bin/nuclei` sur une alpine, aucun template. nuclei va donc chercher
# nuclei-templates sur GitHub au premier lancement, ce que ce bac à sable
# interdit deux fois : la sortie réseau est limitée par proxy au seul hôte
# audité, et le conteneur tourne en 65534 sans HOME inscriptible. Un run à zéro
# template ne sonde rien, n'affiche rien et sort en 0 — le scan était donc
# enregistré « réussi » et le pilier DAST se lisait PROPRE alors qu'il n'avait
# jamais eu lieu.
#
# Embarquer le corpus (plutôt que de le télécharger au scan) est ce qui rend le
# verdict reproductible : deux analyses de la même cible au même digest d'image
# exécutent exactement les mêmes templates, et non « ceux du jour ».
#
# Licence : nuclei-templates est MIT (voir /templates/LICENSE.md dans l'image).
# Aucun filtrage par fichier n'est nécessaire, contrairement au corpus SAST.
#
# Construction :
#   docker build -t auditer/nuclei:3.4.10-t10.4.8-1 infra/docker/scanners/nuclei

FROM alpine/git:latest AS templates

# Épinglé par TAG **et** par commit. Le tag seul ne suffit pas : un tag peut
# être redéplacé, et deux analyses de la même cible rendraient alors des
# verdicts différents sans que rien ne le signale. La vérification ci-dessous
# fait échouer la construction si le tag ne pointe plus sur ce commit.
ARG TEMPLATES_TAG=v10.4.8
ARG TEMPLATES_SHA=e5f19e6144135e107962bb943231413796fd7fe7

RUN git clone --depth 1 --branch "$TEMPLATES_TAG" \
      https://github.com/projectdiscovery/nuclei-templates.git /templates \
 && GOT="$(git -C /templates rev-parse HEAD)" \
 && if [ "$GOT" != "$TEMPLATES_SHA" ]; then \
      echo "nuclei-templates $TEMPLATES_TAG pointe sur $GOT, attendu $TEMPLATES_SHA" >&2; \
      exit 1; \
    fi \
 && rm -rf /templates/.git \
 # Plancher de sanité : le corpus v10 compte plus de 10 000 templates. En
 # dessous de 3 000, la copie est cassée ou le dépôt a changé de forme — mieux
 # vaut casser la construction qu'expédier une image qui sondera trois URLs.
 && COUNT="$(find /templates -name '*.yaml' | wc -l)" \
 && echo "templates: $COUNT" \
 && if [ "$COUNT" -lt 3000 ]; then echo "corpus trop petit: $COUNT" >&2; exit 1; fi \
 && printf '%s\n%s\n' "$TEMPLATES_TAG" "$TEMPLATES_SHA" > /templates/AUDITER_VERSION

FROM projectdiscovery/nuclei@sha256:aeb5ea2db32a252b8135707d2ad0e89b90e19a18ea7816d38759bc51efb46b97

COPY --from=templates /templates /templates
COPY run-nuclei /usr/local/bin/run-nuclei
RUN chmod +x /usr/local/bin/run-nuclei

# nuclei écrit sa configuration et ses caches sous $HOME. Le rootfs est monté en
# lecture seule ; /scratch est le tmpfs que le runner accorde à chaque scan.
ENV HOME=/scratch

USER 65534:65534
ENTRYPOINT ["/usr/local/bin/run-nuclei"]
