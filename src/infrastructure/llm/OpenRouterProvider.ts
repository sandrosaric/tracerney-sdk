/**
 * OpenRouter LLM Provider
 * Adapter: implements ILLMProvider for OpenRouter
 * Uses native fetch — zero dependencies (no openai npm package)
 */

import {
  ILLMProvider,
  LLMRequest,
  LLMResponse,
  ProviderError,
} from "../../application/ports/ILLMProvider";

export interface OpenRouterConfig {
  apiKey: string;
  baseUrl?: string; // Defaults to https://openrouter.ai/api/v1
  siteUrl?: string; // Maps to HTTP-Referer header (recommended by OpenRouter)
  siteTitle?: string; // Maps to X-Title header (recommended by OpenRouter)
  defaultModel?: string; // Default model when not specified in request
  timeoutMs?: number; // Request timeout (default 30000ms)
}

export class OpenRouterProvider implements ILLMProvider {
  readonly providerName = "openrouter";

  private readonly baseUrl: string;
  private readonly timeoutMs: number;

  constructor(private readonly config: OpenRouterConfig) {
    this.baseUrl = config.baseUrl ?? "https://openrouter.ai/api/v1";
    this.timeoutMs = config.timeoutMs ?? 30_000;

    if (!config.apiKey) {
      throw new Error("[OpenRouterProvider] apiKey is required");
    }
  }

  /**
   * Execute an LLM call via OpenRouter.
   * Implements ILLMProvider.complete()
   */
  async complete(request: LLMRequest): Promise<LLMResponse> {
    const model = request.model || this.config.defaultModel || "openai/gpt-4o";

    // Build the request body — OpenAI-compatible format
    const body = {
      model,
      messages: request.messages,
      ...(request.tools && { tools: request.tools }),
      ...(request.temperature !== undefined && { temperature: request.temperature }),
      ...(request.maxTokens !== undefined && { max_tokens: request.maxTokens }),
      // Pass through any additional provider-specific parameters
      ...Object.fromEntries(
        Object.entries(request).filter(
          ([key]) =>
            ![
              "messages",
              "model",
              "tools",
              "temperature",
              "maxTokens",
            ].includes(key)
        )
      ),
    };

    try {
      const response = await fetch(`${this.baseUrl}/chat/completions`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${this.config.apiKey}`,
          // OpenRouter required headers
          "HTTP-Referer": this.config.siteUrl ?? "",
          "X-Title": this.config.siteTitle ?? "Tracerny",
        },
        body: JSON.stringify(body),
        signal: this.createAbortSignal(),
      });

      if (!response.ok) {
        const errorBody = await response.text().catch(() => "");
        throw new ProviderError(
          `OpenRouter returned ${response.status}: ${response.statusText}\n${errorBody}`,
          "openrouter",
          response.status
        );
      }

      // Response shape is OpenAI-compatible — cast directly
      const data = (await response.json()) as LLMResponse;
      return data;
    } catch (error) {
      if (error instanceof ProviderError) {
        throw error;
      }

      if (error instanceof TypeError && error.message.includes("fetch")) {
        throw new ProviderError(
          `Network error: ${error.message}`,
          "openrouter",
          undefined,
          error
        );
      }

      throw new ProviderError(
        `OpenRouter call failed: ${error instanceof Error ? error.message : String(error)}`,
        "openrouter",
        undefined,
        error
      );
    }
  }

  /**
   * Create an AbortSignal for request timeout.
   * Node.js 17+ supports AbortSignal.timeout()
   */
  private createAbortSignal(): AbortSignal | undefined {
    // Try Node.js 17+ AbortSignal.timeout()
    if (AbortSignal && "timeout" in AbortSignal) {
      try {
        return (AbortSignal as any).timeout(this.timeoutMs);
      } catch {
        // Fallback if timeout() not available
      }
    }

    // Fallback: use AbortController with timer
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeoutMs);

    // Clean up timeout on early resolution
    const originalSignal = controller.signal;
    const wrappedSignal = new (class implements AbortSignal {
      readonly aborted = originalSignal.aborted;

      addEventListener: AbortSignal["addEventListener"] = (
        type: any,
        listener: any,
        options: any
      ) => {
        originalSignal.addEventListener(type, listener, options);
      };

      removeEventListener: AbortSignal["removeEventListener"] = (
        type: any,
        listener: any,
        options: any
      ) => {
        originalSignal.removeEventListener(type, listener, options);
      };

      dispatchEvent: AbortSignal["dispatchEvent"] = (event: any) => {
        clearTimeout(timeoutId);
        return originalSignal.dispatchEvent(event);
      };

      get onabort() {
        return originalSignal.onabort;
      }

      set onabort(handler) {
        originalSignal.onabort = handler;
      }

      get reason() {
        return (originalSignal as any).reason;
      }

      throwIfAborted() {
        originalSignal.throwIfAborted?.();
      }
    })();

    return wrappedSignal;
  }
}
