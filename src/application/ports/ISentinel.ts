/**
 * ISentinel - Port for Layer 2 LLM-based attack detection
 *
 * Called when Layer 1 (regex) finds no match.
 * Provides a second opinion via fast LLM model.
 */

export interface ISentinel {
  /**
   * Check if a prompt contains a prompt injection attack
   * @param prompt The user input to evaluate
   * @param requestId Optional request ID for logging
   * @returns Result with action, confidence score, threat class, and fingerprint
   */
  check(
    prompt: string,
    requestId?: string
  ): Promise<{
    action: "BLOCK" | "ALLOW";
    confidence: number; // 0.0 to 1.0
    class: string; // e.g., "jailbreak_llm_detected", "prompt_injection"
    fingerprint: string; // Hash/identifier for the detected threat
  }>;
}
