/**
 * Http Signal Sink
 * Adapter: implements ITelemetrySink for HTTP-based telemetry reporting
 * Non-blocking async queue with batching and periodic flush
 */

import { SecurityEvent } from "../../domain/events/SecurityEvent";
import { ITelemetrySink, type TelemetrySinkStatus } from "../../application/ports/ITelemetrySink";

export interface HttpSignalSinkConfig {
  endpoint: string;
  apiKey?: string;
  batchSize?: number;
  flushIntervalMs?: number;
}

export class HttpSignalSink implements ITelemetrySink {
  private eventQueue: SecurityEvent[] = [];
  private isPosting = false;
  private failureCount = 0;
  private readonly batchSize: number;
  private readonly flushIntervalMs: number;
  private flushTimer?: NodeJS.Timeout;

  constructor(
    private readonly config: HttpSignalSinkConfig,
    private readonly sdkVersion: string = "0.2.0"
  ) {
    this.batchSize = config.batchSize ?? 10;
    this.flushIntervalMs = config.flushIntervalMs ?? 5000;

    this.startFlushTimer();
  }

  /**
   * Queue a security event for async delivery.
   * Non-blocking — returns immediately.
   */
  queue(event: SecurityEvent): void {
    this.eventQueue.push(event);

    // Auto-flush if batch is full
    if (this.eventQueue.length >= this.batchSize) {
      this.flush().catch((err) => {
        console.error("[Tracerney] Signal flush failed:", err);
      });
    }
  }

  /**
   * Start periodic flush timer
   */
  private startFlushTimer(): void {
    this.flushTimer = setInterval(() => {
      if (this.eventQueue.length > 0) {
        this.flush().catch((err) => {
          console.error("[Tracerney] Periodic flush failed:", err);
        });
      }
    }, this.flushIntervalMs);

    // Allow process to exit even if timer is running
    if (this.flushTimer.unref) {
      this.flushTimer.unref();
    }
  }

  /**
   * Flush all queued events.
   * Uses process.nextTick() for non-blocking execution.
   */
  async flush(): Promise<void> {
    if (this.eventQueue.length === 0 || this.isPosting) {
      return;
    }

    this.isPosting = true;
    const eventsToSend = [...this.eventQueue];
    this.eventQueue = [];

    // Fire and forget via process.nextTick or setTimeout
    if (typeof process !== "undefined" && process.nextTick) {
      process.nextTick(() => {
        this.send(eventsToSend).catch((err) => {
          console.error("[Tracerney] Signal send failed:", err);
          // Restore events on failure
          this.eventQueue.unshift(...eventsToSend);
        });
      });
    } else {
      // Fallback for browser environments
      setTimeout(() => {
        this.send(eventsToSend).catch((err) => {
          console.error("[Tracerney] Signal send failed:", err);
          this.eventQueue.unshift(...eventsToSend);
        });
      }, 0);
    }

    // Return immediately — send happens in background
  }

  /**
   * Internal: Send events to the HTTP endpoint
   */
  private async send(events: SecurityEvent[]): Promise<void> {
    try {
      const payload = {
        events,
        sdkVersion: this.sdkVersion,
        environment:
          typeof process !== "undefined" && process.env?.NODE_ENV === "production"
            ? "production"
            : "development",
      };

      const response = await fetch(this.config.endpoint, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(this.config.apiKey && { Authorization: `Bearer ${this.config.apiKey}` }),
        },
        body: JSON.stringify(payload),
      });

      if (!response.ok) {
        throw new Error(
          `Signal endpoint returned ${response.status}: ${response.statusText}`
        );
      }

      // Success - reset failure counter
      this.failureCount = 0;
    } catch (error) {
      this.failureCount++;
      throw error;
    } finally {
      this.isPosting = false;
    }
  }

  /**
   * Graceful shutdown
   */
  destroy(): void {
    if (this.flushTimer) {
      clearInterval(this.flushTimer);
    }

    if (this.eventQueue.length > 0) {
      console.warn(
        `[Tracerney] Destroying HttpSignalSink with ${this.eventQueue.length} unsent events`
      );
    }
  }

  /**
   * Get sink status
   */
  getStatus(): TelemetrySinkStatus {
    return {
      enabled: true,
      queuedEvents: this.eventQueue.length,
      isPosting: this.isPosting,
    };
  }
}
