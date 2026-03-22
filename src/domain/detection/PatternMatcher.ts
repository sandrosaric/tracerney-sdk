/**
 * Pattern Matcher
 * Domain service: pure injection detection logic, no I/O side effects
 */

import { VanguardPattern } from "./VanguardPattern";
import { InjectionThreat, createInjectionThreat } from "./InjectionThreat";

export interface PatternMatcherStats {
  readonly totalPatterns: number;
  readonly bySeverity: {
    readonly critical: number;
    readonly high: number;
    readonly medium: number;
    readonly low: number;
  };
  readonly byCategory: Record<string, number>;
}

export class PatternMatcher {
  constructor(private readonly patterns: readonly VanguardPattern[]) {
    if (!patterns || patterns.length === 0) {
      throw new Error("[PatternMatcher] At least one pattern is required");
    }
  }

  /**
   * Scan a prompt against all patterns.
   * Returns on first match (early exit for <2ms latency).
   * Returns null if no match found.
   */
  match(prompt: string): InjectionThreat | null {
    if (!prompt || typeof prompt !== "string") {
      return null;
    }

    // Early exit on first match
    for (const pattern of this.patterns) {
      if (pattern.pattern.test(prompt)) {
        return createInjectionThreat(
          pattern.id,
          pattern.name,
          pattern.category,
          pattern.severity,
          pattern.description
        );
      }
    }

    return null;
  }

  /**
   * Scan a prompt and return all matches.
   * Used for audit/analysis purposes.
   */
  matchAll(prompt: string): InjectionThreat[] {
    if (!prompt || typeof prompt !== "string") {
      return [];
    }

    const matches: InjectionThreat[] = [];
    for (const pattern of this.patterns) {
      if (pattern.pattern.test(prompt)) {
        matches.push(
          createInjectionThreat(
            pattern.id,
            pattern.name,
            pattern.category,
            pattern.severity,
            pattern.description
          )
        );
      }
    }
    return matches;
  }

  /**
   * Get statistics about the loaded patterns
   */
  stats(): PatternMatcherStats {
    return {
      totalPatterns: this.patterns.length,
      bySeverity: {
        critical: this.patterns.filter((p) => p.severity === "critical").length,
        high: this.patterns.filter((p) => p.severity === "high").length,
        medium: this.patterns.filter((p) => p.severity === "medium").length,
        low: this.patterns.filter((p) => p.severity === "low").length,
      },
      byCategory: this.patterns.reduce(
        (acc, p) => {
          acc[p.category] = (acc[p.category] || 0) + 1;
          return acc;
        },
        {} as Record<string, number>
      ),
    };
  }
}
