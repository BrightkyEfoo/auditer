import { Controller, Get } from "@nestjs/common";

@Controller("api/health")
export class HealthController {
  @Get()
  health(): { ok: true; service: string } {
    return { ok: true, service: "api" };
  }
}
