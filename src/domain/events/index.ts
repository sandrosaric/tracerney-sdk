/**
 * Events Bounded Context
 * Barrel export
 */

export { ThreatSeverity, isThreatSeverity } from "./ThreatSeverity";
export type { ThreatSeverityString } from "./ThreatSeverity";

export { SecurityEventType, isSecurityEventType } from "./SecurityEventType";
export type { SecurityEventTypeString } from "./SecurityEventType";

export { createSecurityEvent } from "./SecurityEvent";
export type { SecurityEvent, SecurityEventMetadata } from "./SecurityEvent";
