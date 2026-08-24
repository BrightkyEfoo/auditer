import { Module } from "@nestjs/common";
import { PrismaService } from "./infra/prisma.service.js";
import { RedisService } from "./infra/redis.service.js";
import { QueueService } from "./infra/queue.service.js";
import { AuthGuard } from "./auth/auth.guard.js";
import { SessionService } from "./auth/session.service.js";
import { AuthController } from "./auth/auth.controller.js";
import { AuditsService } from "./audits/audits.service.js";
import { AuditsController } from "./audits/audits.controller.js";
import { SseController } from "./sse/sse.controller.js";
import { ReposController } from "./repos/repos.controller.js";
import { ConnectionsController } from "./connections/connections.controller.js";
import { ReportsController } from "./reports/reports.controller.js";
import { TriageController } from "./triage/triage.controller.js";
import { TargetsController } from "./targets/targets.controller.js";
import { TargetsService } from "./targets/targets.service.js";
import { OverviewController } from "./overview/overview.controller.js";
import { HealthController } from "./health/health.controller.js";
import { AccountController } from "./account/account.controller.js";
import { AccountService } from "./account/account.service.js";
import { RetentionController } from "./account/retention.controller.js";
import { RetentionService } from "./account/retention.service.js";

@Module({
  controllers: [
    AuthController,
    AuditsController,
    SseController,
    ReposController,
    ConnectionsController,
    ReportsController,
    TriageController,
    TargetsController,
    OverviewController,
    HealthController,
    // Erasure + portability (GDPR art. 17 and 20) and the retention purge that
    // makes the durations published in apps/web/lib/legal.ts enforceable.
    AccountController,
    RetentionController,
  ],
  providers: [
    PrismaService,
    RedisService,
    QueueService,
    AuditsService,
    TargetsService,
    SessionService,
    AuthGuard,
    AccountService,
    RetentionService,
  ],
})
export class AppModule {}
