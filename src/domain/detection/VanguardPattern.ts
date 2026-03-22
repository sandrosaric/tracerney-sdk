/**
 * Vanguard Pattern
 * Domain value object: immutable pattern definition for injection detection
 */

import { ThreatSeverity } from "../events/ThreatSeverity";

export type PatternCategory =
  | "system_override"
  | "prompt_leak"
  | "privilege_escalation"
  | "data_exfiltration"
  | "code_injection"
  | "unknown";

export interface VanguardPattern {
  readonly id: string;
  readonly name: string;
  readonly pattern: RegExp;
  readonly severity: ThreatSeverity;
  readonly description: string;
  readonly category: PatternCategory;
}

/**
 * Factory to create a VanguardPattern with validation
 */
export function createVanguardPattern(
  id: string,
  name: string,
  pattern: RegExp,
  severity: ThreatSeverity,
  description: string,
  category: PatternCategory
): VanguardPattern {
  if (!id || !name || !pattern || !description) {
    throw new Error("[VanguardPattern] All required fields must be non-empty");
  }
  return {
    id,
    name,
    pattern,
    severity,
    description,
    category,
  };
}
