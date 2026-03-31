/**
 * Tracerney
 * Transparent Proxy Runtime Sentinel for Prompt Injection Defense
 *
 * @example
 * ```typescript
 * import { Tracerney } from 'tracerney';
 *
 * const shield = new Tracerney({
 *   allowedTools: ['search', 'calculator'],
 *   apiEndpoint: 'https://api.myapp.com/v1/signal',
 * });
 *
 * const response = await shield.wrap(() =>
 *   openai.chat.completions.create({...})
 * );
 * ```
 */

import { ShieldApplicationService, type WrapOptions, type ServiceStatus, type ScanResult } from "./application";
import { type SuspiciousTrace } from "./domain/pii/DeterministicFilter";
import { ShieldBlockError } from "./application/ShieldBlockError";
import { createToolPolicy } from "./domain/guard/ToolPolicy";
import { type LLMResponse } from "./application/ports/ILLMProvider";
import { BundledPatternRepository } from "./infrastructure/patterns/BundledPatternRepository";
import { HttpSignalSink } from "./infrastructure/telemetry/HttpSignalSink";
// import { HttpShadowLogSink } from "./infrastructure/telemetry/HttpShadowLogSink"; // Disabled
import { LLMSentinel } from "./infrastructure/sentinel/LLMSentinel";

/**
 * Public configuration for Tracerney
 */
export interface TracerneyOptions {
  /**
   * List of tool names the LLM is allowed to call
   */
  allowedTools?: string[];

  /**
   * Base URL for your Tracerney backend (RECOMMENDED)
   * Automatically constructs all required endpoints:
   * - Signal endpoint: {baseUrl}/api/v1/signal
   * - Verification endpoint: {baseUrl}/api/v1/verify-prompt
   * - Shadow log endpoint: {baseUrl}/api/v1/shadow-log
   * - Definitions endpoint: {baseUrl}/api/v1/definitions
   *
   * Example: https://myapp.com or http://localhost:3000
   *
   * If provided, individual endpoint URLs below are ignored.
   */
  baseUrl?: string;

  /**
   * Your backend's Signal Sink endpoint for receiving security events
   * Only needed if NOT using baseUrl
   * Example: https://myapp.com/api/v1/signal
   */
  apiEndpoint?: string;

  /**
   * API key for Signal Sink (optional, sent in Authorization header)
   */
  apiKey?: string;

  /**
   * URL to fetch pattern manifest from (for zero-day updates)
   * If not provided, bundled patterns are used
   */
  manifestUrl?: string;

  /**
   * Enable telemetry reporting (default: true)
   */
  enableTelemetry?: boolean;

  /**
   * Local path to cache manifest (useful in serverless, e.g., /tmp)
   */
  localManifestPath?: string;

  /**
   * Layer 2: Backend endpoint for LLM verification
   * SDK sends suspicious prompts here (backend calls OpenRouter internally)
   * Example: https://myapp.com/api/v1/verify-prompt
   */
  sentinelEndpoint?: string;

  /**
   * Endpoint for shadow log (records of potential attacks)
   * Example: https://myapp.com/api/v1/shadow-log
   */
  shadowLogEndpoint?: string;

  /**
   * Enable Layer 2 LLM Sentinel (default: true if sentinelEndpoint provided)
   */
  sentinelEnabled?: boolean;
}

/**
 * Tracerney Facade
 * Main entry point for the SDK
 * Wires all dependencies: domain + application + infrastructure
 */
export class Tracerney {
  private service: ShieldApplicationService;

  /**
   * Constructor: wires the full dependency graph
   */
  constructor(options: TracerneyOptions = {}) {
    // Step 0: Resolve endpoints from baseUrl if provided
    const resolvedOptions = this.resolveEndpoints(options);

    // Step 1: Build pattern repository
    // Always use bundled patterns (288 forensic patterns)
    // No remote updates - bundled patterns are production-ready
    const patternRepo = new BundledPatternRepository();

    // Step 2: Build telemetry sink
    const telemetrySink =
      options.enableTelemetry !== false && resolvedOptions.apiEndpoint
        ? new HttpSignalSink({
            endpoint: resolvedOptions.apiEndpoint,
            apiKey: resolvedOptions.apiKey,
          })
        : undefined;

    // Step 3: Create tool policy
    const toolPolicy = createToolPolicy(options.allowedTools ?? []);

    // Step 4: Build Layer 2 LLM Sentinel (if enabled)
    let sentinel = undefined;
    if (options.sentinelEnabled !== false && resolvedOptions.sentinelEndpoint) {
      sentinel = new LLMSentinel(resolvedOptions.sentinelEndpoint, resolvedOptions.apiKey);
    }

    // Step 5: Build shadow log sink (if endpoint provided)
    // DISABLED FOR NOW - will re-enable after fixing endpoint
    // let shadowLogSink = undefined;
    // if (resolvedOptions.shadowLogEndpoint) {
    //   shadowLogSink = new HttpShadowLogSink({
    //     endpoint: resolvedOptions.shadowLogEndpoint,
    //     apiKey: resolvedOptions.apiKey,
    //   });
    // }
    const shadowLogSink = undefined;

    // Step 6: Wire application service
    this.service = new ShieldApplicationService({
      patternRepository: patternRepo,
      telemetrySink,
      toolPolicy,
      sentinel,
      shadowLogSink,
      sdkVersion: "0.2.0",
    });
  }

  /**
   * Resolves baseUrl into individual endpoint URLs
   * baseUrl takes precedence over individual endpoint options
   * Defaults to tracerney.com if no baseUrl or endpoints provided
   */
  private resolveEndpoints(options: TracerneyOptions): TracerneyOptions {
    // Determine which baseUrl to use
    const baseUrl = options.baseUrl || 'https://tracerney-llm-senteniel.vercel.app';

    // Remove trailing slash for consistency
    const normalizedUrl = baseUrl.replace(/\/$/, '');

    return {
      ...options,
      apiEndpoint: `${normalizedUrl}/api/v1/signal`,
      sentinelEndpoint: `${normalizedUrl}/api/v1/verify-prompt`,
      shadowLogEndpoint: `${normalizedUrl}/api/v1/shadow-log`,
      manifestUrl: `${normalizedUrl}/api/v1/definitions`,
    };
  }

  /**
   * Main wrapper for LLM calls
   *
   * @param llmCall - Function that executes the LLM call
   * @param options - Optional: prompt for pre-LLM scanning, request context
   *
   * @throws ShieldBlockError if an injection or unauthorized tool is detected
   * @throws Other errors from the LLM provider or network failures
   *
   * @example
   * ```typescript
   * // With optional prompt for pre-LLM scanning (fixes Gap 3)
   * const response = await shield.wrap(
   *   () => openai.chat.completions.create({...}),
   *   { prompt: userInput }
   * );
   * ```
   */
  async wrap<T extends LLMResponse>(
    llmCall: () => Promise<T>,
    options?: WrapOptions
  ): Promise<T> {
    return this.service.wrap(llmCall, options);
  }

  /**
   * Scan a raw prompt for injection attempts (standalone use)
   *
   * @param prompt - The user input to scan
   * @throws ShieldBlockError if injection is detected
   *
   * @example
   * ```typescript
   * try {
   *   await shield.scanPrompt(userInput);
   *   // Safe to proceed
   * } catch (err) {
   *   if (err instanceof ShieldBlockError) {
   *     // Attack detected
   *   }
   * }
   * ```
   */
  async scanPrompt(prompt: string): Promise<ScanResult> {
    return this.service.scanPrompt(prompt);
  }

  /**
   * Layer 1: Scan any string (agent output, tool result, raw text) for suspicious content.
   *
   * The SDK is a high-precision sensor — it never decides for you.
   * Every match is returned as a SuspiciousTrace with a label and pre-computed redactedContent.
   * You choose the reaction.
   *
   * **The Suspicious Manifest:**
   * | Label                  | Trigger              | Recommended Action |
   * |------------------------|----------------------|--------------------|
   * | `SUSPICIOUS_PII`       | Email / Phone        | Usually Redact     |
   * | `SUSPICIOUS_SECRET`    | API keys / SSH       | Usually Block      |
   * | `SUSPICIOUS_EGRESS`    | External URL smuggle | Always Block       |
   * | `SUSPICIOUS_ENCODING`  | Zero-width / BiDi    | Audit / Block      |
   *
   * @example
   * ```typescript
   * const trace = tracerney.validate(agentOutput);
   *
   * if (trace.isSuspicious) {
   *   console.log(`Alert [${trace.label}]: ${trace.reason}`);
   *
   *   // Option A: Hard block
   *   if (trace.label === 'SUSPICIOUS_EGRESS') {
   *     throw new Error('Security Policy Violation');
   *   }
   *
   *   // Option B: Surgical scrub
   *   return trace.redactedContent;
   * }
   * ```
   */
  validate(text: string): SuspiciousTrace {
    return this.service.validate(text);
  }

  /**
   * Update allowed tools at runtime
   *
   * @param tools - New list of allowed tool names
   */
  setAllowedTools(tools: string[]): void {
    return this.service.setAllowedTools(tools);
  }

  /**
   * Get Shield status and diagnostics
   */
  getStatus(): ServiceStatus {
    return this.service.getStatus();
  }

  /**
   * Graceful shutdown: flushes telemetry and releases resources
   * Call this before process exit
   */
  destroy(): void {
    return this.service.destroy();
  }
}

// ============================================================================
// Public Exports
// ============================================================================

// Error class
export { ShieldBlockError };

// Types
export type { WrapOptions, ServiceStatus, LLMResponse };

// Domain layer types (for advanced usage)
export type {
  VanguardPattern,
  PatternCategory,
  InjectionThreat,
} from "./domain/detection";

export type { ToolPolicy, ToolViolation } from "./domain/guard";

export type {
  SecurityEvent,
  SecurityEventMetadata,
  ThreatSeverity,
  SecurityEventType,
} from "./domain/events";

// Application layer types
export type {
  ILLMProvider,
  LLMRequest,
  LLMMessage,
  LLMChoice,
  ToolCall,
  LLMTool,
  TokenUsage,
  ITelemetrySink,
  IPatternRepository,
} from "./application";

// Infrastructure adapter exports (for advanced/custom usage)
export { BundledPatternRepository, RemotePatternRepository } from "./infrastructure/patterns";
export type { RemotePatternRepositoryConfig } from "./infrastructure/patterns";

// Utility exports (for middleware & advanced use)
export { normalizePrompt, normalizePrompts, jitter } from "./application/utils";

export { HttpSignalSink } from "./infrastructure/telemetry";
export type { HttpSignalSinkConfig } from "./infrastructure/telemetry";

// Layer 1 Deterministic Filter exports
export { DeterministicFilter } from "./domain/pii/DeterministicFilter";
export type { SuspiciousTrace, FilterOutcome, PIIFinding, SuspiciousLabel } from "./domain/pii/DeterministicFilter";
export { PII_PATTERNS } from "./domain/pii/PIIPattern";
export type { PIIPattern, PIICategory } from "./domain/pii/PIIPattern";

// Layer 2 Sentinel exports
export { LLMSentinel } from "./infrastructure/sentinel/LLMSentinel";
export type { LLMSentinelOptions } from "./infrastructure/sentinel/LLMSentinel";

export { HttpShadowLogSink } from "./infrastructure/telemetry/HttpShadowLogSink";
export type { ShadowLogPayload } from "./infrastructure/telemetry/HttpShadowLogSink";

export { ShieldApplicationService } from "./application/ShieldApplicationService";
