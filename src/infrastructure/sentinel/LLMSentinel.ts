/**
 * LLMSentinel - Layer 2 detection via backend
 *
 * When Layer 1 (regex) doesn't match, this performs a keyword tripwire check.
 * If any suspicion keywords found, sends to BACKEND which calls OpenRouter.
 *
 * Security: API key stays on backend server
 * Cost: Centralized LLM calls (not per-user)
 * Speed: ~500ms round-trip to backend + LLM
 */

import { ISentinel } from '../../application/ports/ISentinel';
import { randomUUID } from 'crypto';

export interface LLMSentinelOptions {
  suspicionKeywords?: string[];
}

export class LLMSentinel implements ISentinel {
  private readonly sentinelEndpoint: string;
  private readonly apiKey?: string;
  private readonly suspicionKeywords: string[];

  private static readonly DEFAULT_KEYWORDS = [
    'ignore', 'bypass', 'forget', 'system', 'prompt', 'jailbreak', 'override',
    'instructions', 'previous', 'secret', 'leak', 'dump', 'disable', 'circumvent',
    'disregard', 'safety', 'constraints', 'limitations', 'restrictions', 'guidelines',
    'unrestricted', 'imagine', 'pretend', 'unfiltered', 'execute', 'eval', 'exec',
    'import', 'require', 'subprocess', 'shell', 'command', 'code', 'exploit',
    'vulnerability', 'breach', 'attack', 'hacking', 'unauthorized', 'admin',
    'root', 'sudo', 'developer', 'debug', 'trace', 'internal', 'hidden',
    'access', 'token', 'credential', 'password', 'apikey', 'secret', 'private',
  ];

  // Heuristic fragments: 3+ hits triggers Layer 2 escalation
  private static readonly ESCALATION_FRAGMENTS = [
    'system:',
    'json_format',
    'as a developer',
    'forget everything',
    'ignore all',
    'bypass this',
    'my instructions',
    'new instructions',
    'act as',
    'pretend you',
    'you are now',
    'without restrictions',
    'no safety',
    'reveal your',
    'show your',
    'what would you',
    'how would you',
    'if you could',
    'really you are',
    'deep down you',
  ];

  /**
   * @param sentinelEndpoint URL to backend /api/v1/verify-prompt
   * @param apiKey SDK API key (for backend auth)
   * @param options Optional configuration
   */
  constructor(
    sentinelEndpoint: string,
    apiKey?: string,
    options: LLMSentinelOptions = {}
  ) {
    this.sentinelEndpoint = sentinelEndpoint;
    this.apiKey = apiKey;
    this.suspicionKeywords = options.suspicionKeywords || LLMSentinel.DEFAULT_KEYWORDS;
  }

  async check(
    prompt: string,
    requestId?: string
  ): Promise<{
    action: "BLOCK" | "ALLOW";
    confidence: number;
    class: string;
    fingerprint: string;
  }> {
    const startTime = Date.now();
    const id = requestId || randomUUID();

    try {
      // Step 1: Keyword tripwire check (synchronous, local)
      const triggeredKeywords = this.findKeywords(prompt);

      // Step 1.5: Heuristic fragment escalation
      // If 3+ forensic fragments detected, escalate to backend even if keywords are low
      const fragmentHits = this.countEscalationFragments(prompt);
      const shouldEscalate = triggeredKeywords.length > 0 || fragmentHits >= 3;

      // Only call backend if keywords found OR 3+ fragments detected
      if (!shouldEscalate) {
        return {
          action: "ALLOW",
          confidence: 0.05,
          class: "safe",
          fingerprint: this.generateFingerprint(prompt, id),
        };
      }

      // Step 2: Send to backend for LLM verification
      const backendResult = await this.verifyWithBackend(prompt, triggeredKeywords, id);

      return {
        action: backendResult.blocked ? "BLOCK" : "ALLOW",
        confidence: backendResult.confidence,
        class: backendResult.threatClass,
        fingerprint: backendResult.fingerprint,
      };
    } catch (error) {
      console.error('[Sentinel] Backend verification failed:', error);

      // On error, fail open (allow through) - don't block on infrastructure failure
      return {
        action: "ALLOW",
        confidence: 0.0,
        class: "verification_error",
        fingerprint: this.generateFingerprint(prompt, id),
      };
    }
  }

  /**
   * Find which suspicion keywords are in the prompt
   */
  private findKeywords(prompt: string): string[] {
    const lower = prompt.toLowerCase();
    return this.suspicionKeywords.filter((kw) => lower.includes(kw));
  }

  /**
   * Count heuristic escalation fragments (Pete's "Wide Net" strategy)
   * 3+ hits triggers Layer 2 escalation even without exact keyword matches
   */
  private countEscalationFragments(prompt: string): number {
    const lower = prompt.toLowerCase();
    return LLMSentinel.ESCALATION_FRAGMENTS.filter((fragment) =>
      lower.includes(fragment)
    ).length;
  }

  /**
   * Call backend /api/v1/verify-prompt to check with LLM
   */
  private async verifyWithBackend(
    prompt: string,
    keywords: string[],
    requestId: string
  ): Promise<{
    blocked: boolean;
    confidence: number;
    model: string;
    threatClass: string;
    fingerprint: string;
  }> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };

    if (this.apiKey) {
      headers['Authorization'] = `Bearer ${this.apiKey}`;
    }

    const response = await fetch(this.sentinelEndpoint, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        prompt, // Send full prompt for context
        keywords,
        requestId,
      }),
    });

    if (!response.ok) {
      throw new Error(
        `Backend sentinel failed: ${response.status} ${response.statusText}`
      );
    }

    const result = (await response.json()) as {
      action?: "BLOCK" | "ALLOW";
      confidence?: number;
      model?: string;
      class?: string;
      fingerprint?: string;
    };

    return {
      blocked: result.action === "BLOCK",
      confidence: result.confidence ?? 0.5,
      model: result.model ?? 'unknown',
      threatClass: result.class ?? 'unknown',
      fingerprint: result.fingerprint ?? this.generateFingerprint(prompt, requestId),
    };
  }

  /**
   * Generate a fingerprint hash for threat tracking
   */
  private generateFingerprint(prompt: string, requestId: string): string {
    const crypto = require('crypto');
    const hash = crypto.createHash('sha256');
    hash.update(`${prompt}:${requestId}`);
    return hash.digest('hex').substring(0, 6);
  }
}
