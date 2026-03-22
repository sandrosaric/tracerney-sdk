/**
 * ILLMProvider
 * Outbound port: defines the contract for LLM calls
 * Implemented by: OpenRouterProvider, OpenAI, Anthropic adapters, etc.
 */

export interface LLMMessage {
  readonly role: "user" | "assistant" | "system";
  readonly content: string;
}

export interface LLMTool {
  readonly type: "function";
  readonly function: {
    readonly name: string;
    readonly description?: string;
    readonly parameters?: Record<string, unknown>;
  };
}

export interface ToolCall {
  readonly id: string;
  readonly function: {
    readonly name: string;
    readonly arguments?: string | Record<string, unknown>;
  };
  readonly type?: "function";
}

export interface LLMChoice {
  readonly message: {
    readonly content: string | null;
    readonly role: "assistant";
    readonly tool_calls?: readonly ToolCall[];
  };
  readonly finish_reason: "stop" | "tool_calls" | "length" | "content_filter" | null;
  readonly index: number;
}

export interface TokenUsage {
  readonly prompt_tokens: number;
  readonly completion_tokens: number;
  readonly total_tokens: number;
}

export interface LLMResponse {
  readonly id?: string;
  readonly choices: readonly LLMChoice[];
  readonly usage?: TokenUsage;
  readonly model?: string;
}

export interface LLMRequest {
  readonly messages: readonly LLMMessage[];
  readonly model: string;
  readonly tools?: readonly LLMTool[];
  readonly temperature?: number;
  readonly maxTokens?: number;
  readonly [key: string]: unknown; // Allow pass-through of provider-specific parameters
}

export class ProviderError extends Error {
  constructor(
    message: string,
    public readonly providerName: string,
    public readonly statusCode?: number,
    public readonly cause?: unknown
  ) {
    super(message);
    this.name = "ProviderError";
  }
}

export interface ILLMProvider {
  /**
   * The name of this provider (for telemetry)
   */
  readonly providerName: string;

  /**
   * Execute an LLM call
   * Throws ProviderError on failure
   */
  complete(request: LLMRequest): Promise<LLMResponse>;
}
