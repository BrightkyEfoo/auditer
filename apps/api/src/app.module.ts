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
import { ReportsController } from "./reports/reports.controller.js";
import { TriageController } from "./triage/triage.controller.js";
import { TargetsController } from "./targets/targets.controller.js";
import { TargetsService } from "./targets/targets.service.js";
import { HealthController } from "./health/health.controller.js";

@Module({
  controllers: [
    AuthController,
    AuditsController,
    SseController,
    ReposController,
    ReportsController,
    TriageController,
    TargetsController,
    HealthController,
  ],
  providers: [
    PrismaService,
    RedisService,
    QueueService,
    AuditsService,
    TargetsService,
    SessionService,
    AuthGuard,
  ],
})
export class AppModule {}
