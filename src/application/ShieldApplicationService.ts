/**
 * Shield Application Service
 * Core orchestrator: wires domain services + infrastructure adapters
 * Fixes all 5 integration gaps from the original design
 */

import { PatternMatcher } from "../domain/detection/PatternMatcher";
import { ToolGuard, type ToolCall } from "../domain/guard/ToolGuard";
import { createToolPolicy, type ToolPolicy } from "../domain/guard/ToolPolicy";
import {
  createSecurityEvent,
  SecurityEventType,
  ThreatSeverity,
  type SecurityEvent,
} from "../domain/events";
import { ILLMProvider, type LLMResponse } from "./ports/ILLMProvider";
import { ISentinel } from "./ports/ISentinel";
import { ITelemetrySink } from "./ports/ITelemetrySink";
import { IPatternRepository } from "./ports/IPatternRepository";
import { ShieldBlockError } from "./ShieldBlockError";
import { normalizePrompt, jitter } from "./utils";
import { HttpShadowLogSink, type ShadowLogPayload } from "../infrastructure/telemetry";
import { BUNDLED_PATTERNS } from "../infrastructure/patterns/bundled-patterns";
import { BundledPatternRepository } from "../infrastructure/patterns/BundledPatternRepository";

export interface ShieldApplicationServiceConfig {
  patternRepository: IPatternRepository;
  telemetrySink?: ITelemetrySink;
  toolPolicy: ToolPolicy;
  sdkVersion?: string;
  llmProvider?: ILLMProvider;
  sentinel?: ISentinel; // Layer 2: LLM-based detection
  shadowLogSink?: HttpShadowLogSink; // Shadow log for edge cases
}

export interface WrapOptions {
  prompt?: string; // FIX GAP 3: optional prompt for pre-LLM scan
  requestId?: string;
  modelName?: string;
  provider?: string;
}

export interface ScanResult {
  suspicious: boolean; // Layer 1 detected pattern match
  patternName?: string; // Which pattern was triggered
  severity?: string; // Threat severity
  blocked: boolean; // Only true if Layer 2 confirmed attack
}

export interface ServiceStatus {
  patternMatcher: {
    ready: boolean;
    stats?: unknown;
  };
  toolGuard: {
    allowedTools: readonly string[];
  };
  telemetry: {
    enabled: boolean;
    status?: unknown;
  };
}

export class ShieldApplicationService {
  private patternMatcher: PatternMatcher;
  private toolGuard: ToolGuard;
  private telemetrySink?: ITelemetrySink;
  private llmProvider?: ILLMProvider;
  private sentinel?: ISentinel; // Layer 2: LLM sentinel
  // private shadowLogSink?: HttpShadowLogSink; // Disabled for now
  private readonly sdkVersion: string;

  constructor(private readonly config: ShieldApplicationServiceConfig) {
    this.toolGuard = new ToolGuard(config.toolPolicy);
    this.telemetrySink = config.telemetrySink;
    this.llmProvider = config.llmProvider;
    this.sentinel = config.sentinel; // Layer 2
    // this.shadowLogSink = config.shadowLogSink; // Disabled for now
    this.sdkVersion = config.sdkVersion ?? "0.2.0";

    // Initialize patterns synchronously (bundled patterns always available)
    this.patternMatcher = new PatternMatcher(BUNDLED_PATTERNS);

    // Load remote patterns in background if configured (zero-day updates)
    this.updateRemotePatterns();
  }

  /**
   * Update patterns from remote repository in background.
   * Non-blocking; fails gracefully, falling back to bundled patterns.
   */
  private updateRemotePatterns(): void {
    // Only load remote if not using bundled repository
    if (this.config.patternRepository instanceof BundledPatternRepository === false) {
      this.config.patternRepository
        .getPatterns()
        .then((patterns) => {
          if (patterns && patterns.length > 0) {
            this.patternMatcher = new PatternMatcher(patterns);
          }
        })
        .catch((err) => {
          console.warn(
            "[Tracerney] Remote pattern load failed, using bundled patterns:",
            err
          );
        });
    }
  }

  /**
   * Main wrapper method for LLM calls.
   * Fixes Gap 2 (latencyMs now stored) and Gap 3 (prompt parameter for pre-LLM scan)
   *
   * @param llmCall - The LLM function to execute
   * @param options - Optional: prompt for pre-LLM scan, request context
   */
  async wrap<T extends LLMResponse>(
    llmCall: () => Promise<T>,
    options?: WrapOptions
  ): Promise<T> {
    const requestId = options?.requestId ?? this.generateRequestId();
    const startTime = Date.now();

    try {
      // FIX GAP 3: Pre-LLM scan if prompt is provided
      // Uses Layer 1 (Regex) for suspicious detection + Layer 2 (LLM) for confirmation
      if (options?.prompt) {
        const scanResult = await this.scanPrompt(options.prompt, requestId);
        // scanPrompt throws ShieldBlockError only if Layer 2 confirms attack
        // Layer 1 just marks suspicious=true, doesn't block
      }

      // Execute the LLM call
      const response = await llmCall();

      // FIX GAP 2: Compute and store latencyMs in event metadata
      const latencyMs = Date.now() - startTime;

      // Validate tool calls against policy
      const toolCalls = response.choices?.[0]?.message?.tool_calls;
      const violation = this.toolGuard.validate(toolCalls, requestId);

      if (violation) {
        const event = createSecurityEvent(
          requestId,
          SecurityEventType.UNAUTHORIZED_TOOL,
          ThreatSeverity.CRITICAL,
          `Tool '${violation.toolName}' is not in allow list`,
          {
            toolName: violation.toolName,
            blockLatencyMs: latencyMs, // FIX GAP 2: now included
            modelName: options?.modelName,
            provider: options?.provider,
          },
          startTime
        );
        this.report(event);
        throw new ShieldBlockError(
          `Tracerney Block: Unauthorized tool '${violation.toolName}'`,
          event
        );
      }

      return response;
    } catch (error) {
      // Re-throw our blocks as-is
      if (error instanceof ShieldBlockError) {
        throw error;
      }
      // Let other errors (LLM failures, network issues) propagate
      throw error;
    }
  }

  /**
   * Scan a raw prompt pre-LLM for inline use.
   * Returns result object with suspicious flag and blocking decision.
   * Only throws if Layer 2 (LLM Sentinel) confirms attack.
   *
   * Hardened Middleware:
   * - Layer 1 (Regex): Fast, pattern-based detection (marks suspicious, doesn't block)
   * - Layer 2 (LLM Sentinel): Verifies suspicious prompts (only this blocks)
   * - Jitter: Add random delay to obfuscate timing
   */
  async scanPrompt(prompt: string, requestId?: string): Promise<ScanResult> {
    if (!prompt) {
      return { suspicious: false, blocked: false }; // Empty prompt is clean
    }

    const rid = requestId ?? this.generateRequestId();
    const startTime = Date.now();

    try {
      // Normalize prompt to prevent Unicode/whitespace evasion
      const normalizedPrompt = normalizePrompt(prompt);

      // Layer 1: Regex patterns (detection only, doesn't block)
      const threat = this.patternMatcher.match(normalizedPrompt);
      const isSuspicious = !!threat;

      // If Layer 1 detects something suspicious, check Layer 2
      if (isSuspicious && threat) {
        // Layer 2: LLM Sentinel makes final decision
        if (this.sentinel) {
          try {
            const sentinelResult = await this.sentinel.check(normalizedPrompt, rid);

            if (sentinelResult.action === "BLOCK") {
              // Only throw if Layer 2 confirms it's an attack
              const blockLatencyMs = Date.now() - startTime;
              const event = createSecurityEvent(
                rid,
                SecurityEventType.PROMPT_INJECTION,
                ThreatSeverity.HIGH,
                `LLM Sentinel confirmed: ${sentinelResult.class} (confidence: ${sentinelResult.confidence}, fingerprint: ${sentinelResult.fingerprint})`,
                {
                  patternName: threat.patternName,
                  requestSnippet: prompt.substring(0, 100),
                  blockLatencyMs,
                  threatClass: sentinelResult.class,
                  fingerprint: sentinelResult.fingerprint,
                }
              );

              this.report(event);
              throw new ShieldBlockError("Tracerney Block: LLM Sentinel Confirmed", event);
            }

            // Layer 2 passed - suspicious but allowed (e.g., educational context)
            return {
              suspicious: true,
              patternName: threat.patternName,
              severity: threat.severity,
              blocked: false,
            };
          } catch (error) {
            // If sentinel throws (network error, etc), check if it's our block or a system error
            if (error instanceof ShieldBlockError) {
              throw error;
            }
            // Other errors: treat as suspicious but don't block (Layer 2 unavailable)
            return {
              suspicious: true,
              patternName: threat.patternName,
              severity: threat.severity,
              blocked: false,
            };
          }
        } else {
          // No sentinel configured - just mark as suspicious
          return {
            suspicious: true,
            patternName: threat.patternName,
            severity: threat.severity,
            blocked: false,
          };
        }
      }

      // Layer 1 passed - prompt is clean
      return { suspicious: false, blocked: false };
    } finally {
      // Jitter: Add random delay to obfuscate timing (always runs, masked from caller)
      await jitter();
    }
  }

  /**
   * Update tool policy at runtime
   */
  setAllowedTools(tools: readonly string[]): void {
    const policy = createToolPolicy(tools);
    this.toolGuard.updatePolicy(policy);
  }

  /**
   * Get service status for diagnostics
   */
  getStatus(): ServiceStatus {
    return {
      patternMatcher: {
        ready: this.patternMatcher !== null,
        stats: this.patternMatcher?.stats(),
      },
      toolGuard: {
        allowedTools: this.toolGuard.getAllowedTools(),
      },
      telemetry: {
        enabled: this.telemetrySink !== undefined,
        status: this.telemetrySink?.getStatus(),
      },
    };
  }

  /**
   * Report a security event (non-blocking)
   */
  private report(event: SecurityEvent): void {
    if (this.telemetrySink) {
      this.telemetrySink.queue(event);
    }
  }

  /**
   * Graceful shutdown: flush telemetry, release resources
   */
  destroy(): void {
    this.telemetrySink?.destroy();
  }

  /**
   * Generate a unique request ID
   */
  private generateRequestId(): string {
    return `req_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;
  }
}
