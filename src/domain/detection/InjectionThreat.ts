/**
 * Injection Threat
 * Domain value object: represents a confirmed pattern match
 */

import { ThreatSeverity } from "../events/ThreatSeverity";
import { PatternCategory } from "./VanguardPattern";

export interface InjectionThreat {
  readonly patternId: string;
  readonly patternName: string;
  readonly category: PatternCategory;
  readonly severity: ThreatSeverity;
  readonly description: string;
  readonly matchedAt: number; // Unix ms timestamp
}

/**
 * Factory to create an InjectionThreat from a matched pattern
 */
export function createInjectionThreat(
  patternId: string,
  patternName: string,
  category: PatternCategory,
  severity: ThreatSeverity,
  description: string,
  matchedAt?: number
): InjectionThreat {
  return {
    patternId,
    patternName,
    category,
    severity,
    description,
    matchedAt: matchedAt ?? Date.now(),
  };
}
