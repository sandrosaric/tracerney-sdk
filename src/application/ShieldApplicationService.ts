/**
 * Shield Application Service
 * Core orchestrator: wires domain services + infrastructure adapters
 * Fixes all 5 integration gaps from the original design
 */

import { PatternMatcher } from "../domain/detection/PatternMatcher";
import { DeterministicFilter, type SuspiciousTrace, type FilterOutcome } from "../domain/pii/DeterministicFilter";
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
  suspicious: boolean;       // true if any pattern matched
  patternName?: string;      // Which pattern was triggered
  severity?: string;         // Threat severity
  blocked: boolean;          // true if either layer blocked
  blockedBy?: "layer1" | "layer2";
  /** Egress/PII label when DeterministicFilter fired — developer decides the penalty */
  label?: string;            // e.g. "SUSPICIOUS_EGRESS" | "SUSPICIOUS_SECRET" | "SUSPICIOUS_PII"
  reason?: string;           // e.g. "Detected 1 finding(s): Markdown Image with URL Query Params"
}

export type { SuspiciousTrace };

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
  private readonly deterministicFilter: DeterministicFilter; // Layer 1: outbound PII filter
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

    // Layer 1: deterministic outbound filter (singleton, stateless)
    this.deterministicFilter = new DeterministicFilter();

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
      const rawResponse = await llmCall();

      // ── Layer 1 (Outbound): Deterministic Filter ─────────────────────────
      // Synchronous regex pass — <5ms, runs before the caller ever sees the text.
      //
      // The filter is a SENSOR, not a policy enforcer.
      // It labels every finding with a SuspiciousLabel and pre-computes redactedContent.
      // ShieldApplicationService acts on the label:
      //
      //   SUSPICIOUS_EGRESS   → throw (active exfiltration, caller gets nothing)
      //   SUSPICIOUS_SECRET   → emit PII_LEAK alert, return redacted response
      //   SUSPICIOUS_ENCODING → emit PII_LEAK alert, return redacted response
      //   SUSPICIOUS_PII      → return redacted response silently
      const { response, outcome: filterOutcome } =
        this.deterministicFilter.filterResponse(rawResponse);

      const latencyMs = Date.now() - startTime;
      const trace = filterOutcome.trace;

      if (trace.isSuspicious && trace.label) {
        if (trace.label === "SUSPICIOUS_EGRESS") {
          // Active exfiltration — kill the process, caller gets nothing.
          const event = createSecurityEvent(
            requestId,
            SecurityEventType.SUSPICIOUS_EGRESS,
            ThreatSeverity.CRITICAL,
            `Layer 1: ${trace.reason}`,
            {
              patternName: trace.findings[0]?.patternName,
              blockLatencyMs: latencyMs,
              modelName: options?.modelName,
              provider: options?.provider,
            },
            startTime
          );
          this.report(event);
          throw new ShieldBlockError("Tracerney Block: Suspicious Egress Detected", event);
        }

        if (trace.label === "SUSPICIOUS_SECRET" || trace.label === "SUSPICIOUS_ENCODING") {
          // Accidental leak of high-value data — alert, but return the scrubbed response.
          const event = createSecurityEvent(
            requestId,
            SecurityEventType.PII_LEAK,
            ThreatSeverity.HIGH,
            `Layer 1: ${trace.reason}`,
            {
              patternName: trace.findings[0]?.patternName,
              blockLatencyMs: latencyMs,
              modelName: options?.modelName,
              provider: options?.provider,
            },
            startTime
          );
          this.report(event);
        }
        // SUSPICIOUS_PII (email/phone) → return scrubbed response silently, no event.
      }

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
   *
   * Forensic routing:
   *
   *   Layer 1 — The Executioner (CRITICAL / HIGH severity)
   *     Binary violations: API keys, SSH keys, PII, unauthorized domains.
   *     There is no context that makes exporting a raw AWS key acceptable.
   *     Stop immediately. Do not waste tokens on Layer 2.
   *     Throws ShieldBlockError instantly.
   *
   *   Layer 2 — The Jury (MEDIUM / LOW severity)
   *     Inconclusive threats: complex encoding, obfuscated payloads, ambiguous tone.
   *     Probabilistic — needs a reasoning model to verify.
   *     Passed to LLM Sentinel only when Layer 1 is inconclusive.
   */
  async scanPrompt(prompt: string, requestId?: string): Promise<ScanResult> {
    if (!prompt) {
      return { suspicious: false, blocked: false };
    }

    const rid = requestId ?? this.generateRequestId();
    const startTime = Date.now();

    try {
      const normalizedPrompt = normalizePrompt(prompt);

      // ── Egress / PII / Secret check (runs first) ─────────────────────────
      // Scans for exfiltration patterns, secrets, and PII embedded in the prompt.
      // The SDK marks it SUSPICIOUS and surfaces the label — developer owns the penalty.
      const egressTrace = this.deterministicFilter.validate(normalizedPrompt);
      if (egressTrace.isSuspicious && egressTrace.label) {
        const blockLatencyMs = Date.now() - startTime;
        const event = createSecurityEvent(
          rid,
          SecurityEventType.SUSPICIOUS_EGRESS,
          ThreatSeverity.CRITICAL,
          `${egressTrace.label}: ${egressTrace.reason}`,
          {
            patternName: egressTrace.findings[0]?.patternName,
            requestSnippet: prompt.substring(0, 100),
            blockLatencyMs,
          }
        );
        this.report(event);
        // Return suspicious — do NOT throw. Developer decides: block, redact, or log.
        return {
          suspicious: true,
          patternName: egressTrace.findings[0]?.patternName,
          severity: "critical",
          blocked: false,
          label: egressTrace.label,
          reason: egressTrace.reason,
        };
      }

      // Layer 1: deterministic regex scan
      const threat = this.patternMatcher.match(normalizedPrompt);

      if (!threat) {
        return { suspicious: false, blocked: false };
      }

      const isBinary =
        threat.severity === ThreatSeverity.CRITICAL ||
        threat.severity === ThreatSeverity.HIGH;

      if (isBinary) {
        // ── Layer 1: Executioner ─────────────────────────────────────────────
        // Binary violation — stop immediately. No Layer 2, no second opinion.
        const blockLatencyMs = Date.now() - startTime;
        const event = createSecurityEvent(
          rid,
          SecurityEventType.PROMPT_INJECTION,
          ThreatSeverity.CRITICAL,
          `Layer 1 stopped: ${threat.patternName} [${threat.severity}]`,
          {
            patternName: threat.patternName,
            requestSnippet: prompt.substring(0, 100),
            blockLatencyMs,
          }
        );
        this.report(event);
        throw new ShieldBlockError("Tracerney Block: Layer 1 Violation", event);
      }

      // ── Layer 2: Jury ──────────────────────────────────────────────────────
      // Inconclusive threat (MEDIUM / LOW) — needs a reasoning model to judge.
      if (this.sentinel) {
        try {
          const sentinelResult = await this.sentinel.check(normalizedPrompt, rid);

          if (sentinelResult.action === "BLOCK") {
            const blockLatencyMs = Date.now() - startTime;
            const event = createSecurityEvent(
              rid,
              SecurityEventType.PROMPT_INJECTION,
              ThreatSeverity.HIGH,
              `Layer 2 confirmed: ${sentinelResult.class} (confidence: ${sentinelResult.confidence}, fingerprint: ${sentinelResult.fingerprint})`,
              {
                patternName: threat.patternName,
                requestSnippet: prompt.substring(0, 100),
                blockLatencyMs,
                threatClass: sentinelResult.class,
                fingerprint: sentinelResult.fingerprint,
              }
            );
            this.report(event);
            throw new ShieldBlockError("Tracerney Block: Layer 2 Confirmed", event);
          }

          // Layer 2 cleared it — suspicious but allowed
          return {
            suspicious: true,
            patternName: threat.patternName,
            severity: threat.severity,
            blocked: false,
          };
        } catch (error) {
          if (error instanceof ShieldBlockError) throw error;
          // Layer 2 unavailable — mark suspicious but don't block
          return {
            suspicious: true,
            patternName: threat.patternName,
            severity: threat.severity,
            blocked: false,
          };
        }
      }

      // No sentinel configured — surface the finding, let developer decide
      return {
        suspicious: true,
        patternName: threat.patternName,
        severity: threat.severity,
        blocked: false,
      };
    } finally {
      await jitter();
    }
  }

  /**
   * Layer 1: Scan any string for suspicious content.
   * Returns a SuspiciousTrace — the SDK never decides for you.
   */
  validate(text: string): SuspiciousTrace {
    return this.deterministicFilter.validate(text);
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
