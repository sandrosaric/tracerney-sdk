/**
 * Latency jitter to obfuscate security layer timing
 *
 * Prevents attackers from timing responses to identify which security layer
 * blocked their attack or determine if the system is even protecting them.
 *
 * Default range: 300-500ms (adds consistent overhead to all outcomes)
 */

export async function jitter(minMs: number = 300, maxMs: number = 500): Promise<void> {
  const delay = Math.random() * (maxMs - minMs) + minMs;
  return new Promise((resolve) => setTimeout(resolve, delay));
}
