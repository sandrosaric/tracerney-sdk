/**
 * HttpShadowLogSink - Sends shadow log entries to backend
 *
 * Separate from HttpSignalSink.
 * Shadow logs are potential/undetected attacks for admin review.
 * Sent asynchronously, fire-and-forget (non-blocking).
 */

export interface ShadowLogPayload {
  id: string;
  prompt: string;
  keywords: string[];
  verdict: 'YES' | 'NO' | 'ERROR';
  latencyMs: number;
  model: string;
  timestamp: string;
}

export class HttpShadowLogSink {
  private endpoint: string;
  private apiKey?: string;

  constructor(options: { endpoint: string; apiKey?: string }) {
    this.endpoint = options.endpoint;
    this.apiKey = options.apiKey;
  }

  /**
   * Send shadow log entry to backend
   * Non-blocking, returns immediately
   */
  async log(entry: ShadowLogPayload): Promise<void> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };

    if (this.apiKey) {
      headers['Authorization'] = `Bearer ${this.apiKey}`;
    }

    try {
      const response = await fetch(this.endpoint, {
        method: 'POST',
        headers,
        body: JSON.stringify(entry),
      });

      if (!response.ok) {
        console.warn(`[ShadowLogSink] Server returned ${response.status}`);
      }
    } catch (error) {
      console.error('[ShadowLogSink] Failed to send:', error);
      // Silently fail - don't block main execution
    }
  }
}
