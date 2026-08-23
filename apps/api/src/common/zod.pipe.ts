import {
  type PipeTransform,
  Injectable,
  BadRequestException,
} from "@nestjs/common";
import type { ZodSchema } from "zod";

/** Validate a request body against a Zod schema (contract-derived). */
@Injectable()
export class ZodBody<T> implements PipeTransform {
  constructor(private readonly schema: ZodSchema<T>) {}
  transform(value: unknown): T {
    const parsed = this.schema.safeParse(value);
    if (!parsed.success) {
      throw new BadRequestException({
        message: "validation failed",
        issues: parsed.error.issues,
      });
    }
    return parsed.data;
  }
}
