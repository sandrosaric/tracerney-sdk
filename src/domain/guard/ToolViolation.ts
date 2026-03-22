/**
 * Tool Violation
 * Domain value object: result of a policy breach
 */

export interface ToolViolation {
  readonly toolName: string;
  readonly requestId: string;
  readonly detectedAt: number; // Unix ms
}

/**
 * Factory to create a ToolViolation
 */
export function createToolViolation(
  toolName: string,
  requestId: string,
  detectedAt?: number
): ToolViolation {
  return {
    toolName,
    requestId,
    detectedAt: detectedAt ?? Date.now(),
  };
}
