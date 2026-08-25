-- Journal durable des événements d'un relevé.
--
-- La progression ne vivait que sur un canal Valkey de publication, qui ne
-- rejoue rien : actualiser la page ou perdre le réseau une seconde effaçait
-- définitivement les transitions de phase et les notes d'exécution. Les lignes
-- `scans` conservent l'état des moteurs, pas le récit qui les entoure.
--
-- `seq` est le compteur monotone par relevé déjà servi comme identifiant SSE.
-- L'unicité (auditRunId, seq) rend l'écriture idempotente si BullMQ relance un
-- job : le même événement ne peut pas être inscrit deux fois.
CREATE TABLE "run_events" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "auditRunId" TEXT NOT NULL,
    "seq" INTEGER NOT NULL,
    "type" TEXT NOT NULL,
    "payload" JSONB NOT NULL,
    "at" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "run_events_pkey" PRIMARY KEY ("id")
);

CREATE INDEX "run_events_organizationId_idx" ON "run_events"("organizationId");

-- L'index de lecture de la reprise : « les événements de ce relevé après ce
-- seq », dans l'ordre. C'est la seule requête que fait le contrôleur SSE.
CREATE INDEX "run_events_auditRunId_seq_idx" ON "run_events"("auditRunId", "seq");

CREATE UNIQUE INDEX "run_events_auditRunId_seq_key" ON "run_events"("auditRunId", "seq");

ALTER TABLE "run_events" ADD CONSTRAINT "run_events_auditRunId_fkey" FOREIGN KEY ("auditRunId") REFERENCES "audit_runs"("id") ON DELETE CASCADE ON UPDATE CASCADE;
