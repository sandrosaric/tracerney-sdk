/**
 * ITelemetrySink
 * Outbound port: defines the contract for reporting security events
 * Implemented by: HttpSignalSink, NoOpSink, etc.
 */

import { SecurityEvent } from "../../domain/events/SecurityEvent";

export interface TelemetrySinkStatus {
  readonly enabled: boolean;
  readonly queuedEvents: number;
  readonly isPosting: boolean;
}

export interface ITelemetrySink {
  /**
   * Queue a security event for async delivery.
   * Returns immediately — never throws.
   * Fire-and-forget pattern.
   */
  queue(event: SecurityEvent): void;

  /**
   * Flush all queued events to the sink.
   * Awaitable for graceful shutdown.
   * Throws on persistent send failure (after retries).
   */
  flush(): Promise<void>;

  /**
   * Destroy the sink and release resources.
   * Should attempt a final flush if possible.
   */
  destroy(): void;

  /**
   * Get sink status (for diagnostics).
   */
  getStatus(): TelemetrySinkStatus;
}
