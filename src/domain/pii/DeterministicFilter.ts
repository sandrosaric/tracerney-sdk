/**
 * Deterministic Filter
 * Domain service: Layer 1 outbound intelligent gatekeeper.
 *
 * Philosophy — The SDK is a HIGH-PRECISION SENSOR, not a policy enforcer.
 *
 * Every match is surfaced as a SuspiciousTrace. The developer owns the reaction:
 *
 *   const trace = tracerney.validate(agentOutput);
 *
 *   if (trace.isSuspicious) {
 *     console.log(`Alert: ${trace.reason}`);
 *
 *     // Option A: Hard Block
 *     // throw new Error("Security Policy Violation");
 *
 *     // Option B: Surgical Scrub
 *     // return trace.redactedContent;
 *   }
 *
 * See the "Suspicious Manifest" in PIIPattern.ts for the label-to-action guide.
 *
 * Pure synchronous — no I/O, no async. Target latency <5ms.
 */

import {
  PII_PATTERNS,
  CATEGORY_TO_LABEL,
  LABEL_PRIORITY,
  type PIICategory,
  type PIIPattern,
  type SuspiciousLabel,
} from "./PIIPattern";
import type { LLMResponse, LLMChoice } from "../../application/ports/ILLMProvider";

// ─── Public types ─────────────────────────────────────────────────────────────

export type { SuspiciousLabel };

export interface PIIFinding {
  readonly patternId: string;
  readonly patternName: string;
  readonly category: PIICategory;
  /** Semantic label — use this for routing decisions */
  readonly label: SuspiciousLabel;
  /** How many times this pattern matched */
  readonly count: number;
}

/**
 * The result of a single validate() call.
 *
 * isSuspicious    — true if any pattern fired; false means clean.
 * label           — highest-severity label across all findings (null when clean).
 * reason          — human-readable summary for logging, e.g. "Detected 2 finding(s): Email Address, AWS Access Key ID"
 * redactedContent — pre-computed version of the input with all matches replaced.
 *                   Present regardless of isSuspicious (equals original text when clean).
 *                   Use it if you want surgical scrubbing. Throw if you want a hard block.
 * findings        — granular list for detailed logging or telemetry.
 */
export interface SuspiciousTrace {
  readonly isSuspicious: boolean;
  readonly label: SuspiciousLabel | null;
  readonly reason: string;
  readonly redactedContent: string;
  readonly findings: readonly PIIFinding[];
}

/** @internal Used by ShieldApplicationService.wrap() */
export interface FilterOutcome {
  readonly trace: SuspiciousTrace;
  /** Response with redactedContent applied to all choice messages */
  readonly redactedResponse?: unknown;
}

// ─── Service ──────────────────────────────────────────────────────────────────

export class DeterministicFilter {
  private readonly patterns: readonly PIIPattern[];

  constructor(patterns: readonly PIIPattern[] = PII_PATTERNS) {
    this.patterns = patterns;
  }

  /**
   * Scan a plain string and return a SuspiciousTrace.
   * Always returns — never throws. The caller decides what to do.
   */
  validate(text: string): SuspiciousTrace {
    if (!text || typeof text !== "string") {
      return {
        isSuspicious: false,
        label: null,
        reason: "Clean",
        redactedContent: text ?? "",
        findings: [],
      };
    }

    let redacted = text;
    const findings: PIIFinding[] = [];

    for (const p of this.patterns) {
      p.pattern.lastIndex = 0;
      const matches = redacted.match(p.pattern);
      if (!matches || matches.length === 0) continue;

      p.pattern.lastIndex = 0;
      redacted = redacted.replace(p.pattern, p.redactAs);

      findings.push({
        patternId: p.id,
        patternName: p.name,
        category: p.category,
        label: CATEGORY_TO_LABEL[p.category],
        count: matches.length,
      });
    }

    if (findings.length === 0) {
      return {
        isSuspicious: false,
        label: null,
        reason: "Clean",
        redactedContent: text,
        findings: [],
      };
    }

    // Derive the highest-severity label across all findings
    const dominantLabel = findings.reduce<SuspiciousLabel>((best, f) => {
      return LABEL_PRIORITY[f.label] > LABEL_PRIORITY[best] ? f.label : best;
    }, findings[0].label);

    const reason = `Detected ${findings.length} finding(s): ${findings.map((f) => f.patternName).join(", ")}`;

    return {
      isSuspicious: true,
      label: dominantLabel,
      reason,
      redactedContent: redacted,
      findings,
    };
  }

  /**
   * Scan all text content in an LLMResponse.
   * Returns a merged SuspiciousTrace (highest label across all choices)
   * and a new response with redactedContent applied — never mutates the original.
   */
  filterResponse<T extends LLMResponse>(response: T): {
    response: T;
    outcome: FilterOutcome;
  } {
    if (!response?.choices?.length) {
      const cleanTrace: SuspiciousTrace = {
        isSuspicious: false,
        label: null,
        reason: "Clean",
        redactedContent: "",
        findings: [],
      };
      return { response, outcome: { trace: cleanTrace } };
    }

    const allFindings: PIIFinding[] = [];
    let anyRedacted = false;
    const sanitizedChoices: LLMChoice[] = [];

    for (const choice of response.choices) {
      const content = choice.message?.content;
      if (!content) {
        sanitizedChoices.push(choice as LLMChoice);
        continue;
      }

      const trace = this.validate(content);
      if (trace.isSuspicious) {
        anyRedacted = true;
        allFindings.push(...trace.findings);
        sanitizedChoices.push({
          ...choice,
          message: { ...choice.message, content: trace.redactedContent },
        } as LLMChoice);
      } else {
        sanitizedChoices.push(choice as LLMChoice);
      }
    }

    const sanitizedResponse = anyRedacted
      ? ({ ...response, choices: sanitizedChoices } as T)
      : response;

    if (allFindings.length === 0) {
      const cleanTrace: SuspiciousTrace = {
        isSuspicious: false,
        label: null,
        reason: "Clean",
        redactedContent: "",
        findings: [],
      };
      return { response: sanitizedResponse, outcome: { trace: cleanTrace } };
    }

    const dominantLabel = allFindings.reduce<SuspiciousLabel>((best, f) => {
      return LABEL_PRIORITY[f.label] > LABEL_PRIORITY[best] ? f.label : best;
    }, allFindings[0].label);

    const mergedTrace: SuspiciousTrace = {
      isSuspicious: true,
      label: dominantLabel,
      reason: `Detected ${allFindings.length} finding(s): ${allFindings.map((f) => f.patternName).join(", ")}`,
      redactedContent: "",
      findings: allFindings,
    };

    return {
      response: sanitizedResponse,
      outcome: { trace: mergedTrace, redactedResponse: sanitizedResponse },
    };
  }
}
