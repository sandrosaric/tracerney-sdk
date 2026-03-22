/**
 * Security Event
 * Domain entity: represents a security incident that was blocked
 * Has identity (eventId), immutable after construction
 */

import { SecurityEventType } from "./SecurityEventType";
import { ThreatSeverity } from "./ThreatSeverity";

export interface SecurityEventMetadata {
  readonly toolName?: string;
  readonly patternName?: string;
  readonly requestSnippet?: string; // First 100 chars, anonymized
  readonly blockLatencyMs?: number; // FIX GAP 2: now populated when events are created
  readonly modelName?: string;
  readonly provider?: string;
}

export interface SecurityEvent {
  readonly id: string; // Unique event ID
  readonly requestId: string; // Request context
  readonly type: SecurityEventType;
  readonly severity: ThreatSeverity;
  readonly timestamp: number; // Unix ms
  readonly blockReason: string;
  readonly metadata: SecurityEventMetadata;
  readonly anonymized: boolean;
}

/**
 * Factory function to construct a SecurityEvent with a unique ID
 */
export function createSecurityEvent(
  requestId: string,
  type: SecurityEventType,
  severity: ThreatSeverity,
  blockReason: string,
  metadata: SecurityEventMetadata,
  timestamp?: number
): SecurityEvent {
  return {
    id: `event_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`,
    requestId,
    type,
    severity,
    timestamp: timestamp ?? Date.now(),
    blockReason,
    metadata,
    anonymized: true,
  };
}
