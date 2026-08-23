import Anthropic from "@anthropic-ai/sdk";

/**
 * The AI layer's low-level client.
 *
 * Model tiering (IDs pinned from the authoritative `claude-api` skill):
 *   - bulk    → Haiku 4.5  : high-volume triage/dedup confirmation
 *   - judge   → Sonnet 5   : false-positive reasoning, exploitability
 *   - synth   → Opus 5     : executive report writing
 *
 * Guardrails baked in here:
 *   - Structured output is FORCED via a single tool + tool_choice — the model
 *     can only return schema-shaped JSON, and the tool has NO side effects.
 *   - Repo/finding content is caller-wrapped in <untrusted_repo_content>; this
 *     client never grants a tool that could act on it.
 *   - Every call reports token usage to an injectable ledger sink keyed on the
 *     Anthropic request id.
 */

export const MODELS = {
  bulk: "claude-haiku-4-5",
  judge: "claude-sonnet-5",
  synth: "claude-opus-5",
} as const;
export type ModelTier = keyof typeof MODELS;

export interface UsageRecord {
  requestId?: string;
  modelId: string;
  inputTokens: number;
  outputTokens: number;
  cacheReadTokens: number;
  cacheWriteTokens: number;
}
export type UsageSink = (u: UsageRecord) => void;

export interface AiClientOpts {
  apiKey?: string;
  onUsage?: UsageSink;
}

export interface ToolCallParams {
  tier: ModelTier;
  system: string;
  /** Whether to mark the system prompt cacheable (shared across a run). */
  cacheSystem?: boolean;
  userContent: string;
  toolName: string;
  toolDescription: string;
  /** JSON Schema for the forced tool input (the structured output shape). */
  inputSchema: Record<string, unknown>;
  maxTokens?: number;
}

export class AiClient {
  private readonly anthropic: Anthropic;
  private readonly onUsage?: UsageSink;

  constructor(opts: AiClientOpts = {}) {
    this.anthropic = new Anthropic({
      apiKey: opts.apiKey ?? process.env.ANTHROPIC_API_KEY,
    });
    this.onUsage = opts.onUsage;
  }

  /**
   * Force the model to return exactly one structured object. Returns the raw
   * parsed `input` of the forced tool call (caller validates with Zod).
   */
  async structured<T = unknown>(p: ToolCallParams): Promise<T> {
    const systemBlock = p.cacheSystem
      ? [
          {
            type: "text" as const,
            text: p.system,
            cache_control: { type: "ephemeral" as const },
          },
        ]
      : p.system;

    const res = await this.anthropic.messages.create({
      model: MODELS[p.tier],
      max_tokens: p.maxTokens ?? 2048,
      system: systemBlock,
      tools: [
        {
          name: p.toolName,
          description: p.toolDescription,
          input_schema: p.inputSchema as Anthropic.Tool.InputSchema,
        },
      ],
      tool_choice: { type: "tool", name: p.toolName },
      messages: [{ role: "user", content: p.userContent }],
    });

    this.reportUsage(res);

    const block = res.content.find((b) => b.type === "tool_use");
    if (!block || block.type !== "tool_use") {
      throw new Error("ai: model did not return the forced tool call");
    }
    return block.input as T;
  }

  private reportUsage(res: Anthropic.Message): void {
    if (!this.onUsage) return;
    const u = res.usage;
    this.onUsage({
      requestId: (res as unknown as { _request_id?: string })._request_id,
      modelId: res.model,
      inputTokens: u.input_tokens ?? 0,
      outputTokens: u.output_tokens ?? 0,
      cacheReadTokens: u.cache_read_input_tokens ?? 0,
      cacheWriteTokens: u.cache_creation_input_tokens ?? 0,
    });
  }
}

/** Wrap untrusted repo/finding content so the model treats it as data. */
export function untrusted(content: string): string {
  return `<untrusted_repo_content>\n${content}\n</untrusted_repo_content>`;
}
