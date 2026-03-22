/**
 * Threat Severity Levels
 * Domain value object (enum)
 */

export enum ThreatSeverity {
  LOW = "low",
  MEDIUM = "medium",
  HIGH = "high",
  CRITICAL = "critical",
}

export type ThreatSeverityString = keyof typeof ThreatSeverity;

export function isThreatSeverity(value: unknown): value is ThreatSeverity {
  return Object.values(ThreatSeverity).includes(value as ThreatSeverity);
}
