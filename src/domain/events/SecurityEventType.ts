/**
 * Security Event Types
 * Domain value object (enum)
 */

export enum SecurityEventType {
  PROMPT_INJECTION = "PROMPT_INJECTION",
  UNAUTHORIZED_TOOL = "UNAUTHORIZED_TOOL",
  PATTERN_MATCH = "PATTERN_MATCH",
  SCHEMA_VIOLATION = "SCHEMA_VIOLATION",
  /** Layer 1: agent attempted to exfiltrate data to an unauthorized destination */
  SUSPICIOUS_EGRESS = "SUSPICIOUS_EGRESS",
  /** Layer 1: agent response contained PII/secrets that were redacted before delivery */
  PII_LEAK = "PII_LEAK",
}

export type SecurityEventTypeString = keyof typeof SecurityEventType;

export function isSecurityEventType(value: unknown): value is SecurityEventType {
  return Object.values(SecurityEventType).includes(value as SecurityEventType);
}
