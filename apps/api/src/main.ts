import "reflect-metadata";
import { NestFactory } from "@nestjs/core";
import { Logger } from "@nestjs/common";
import { AppModule } from "./app.module.js";

async function bootstrap(): Promise<void> {
  const app = await NestFactory.create(AppModule, { bufferLogs: false });

  app.enableCors({
    origin: process.env.WEB_URL ?? "http://localhost:3000",
    credentials: true,
  });
  // Request validation is done with Zod pipes (see common/zod.pipe.ts), so no
  // global class-validator ValidationPipe is registered.

  const port = Number(process.env.API_PORT ?? 3001);
  await app.listen(port);
  new Logger("bootstrap").log(`api listening on :${port}`);
}

void bootstrap();
