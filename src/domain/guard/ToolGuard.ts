/**
 * Tool Guard
 * Domain service: pure tool call validation, no I/O side effects
 * Does NOT throw — callers decide what to do with violations
 */

import { ToolPolicy, isToolAllowed } from "./ToolPolicy";
import { ToolViolation, createToolViolation } from "./ToolViolation";

export interface ToolCall {
  readonly id: string;
  readonly function: {
    readonly name: string;
    readonly arguments?: string | Record<string, unknown>;
  };
  readonly type?: "function";
}

export class ToolGuard {
  constructor(private policy: ToolPolicy) {
    if (!policy || !policy.allowedTools) {
      throw new Error("[ToolGuard] Policy is required");
    }
  }

  /**
   * Validate a set of tool calls against the policy.
   * Returns null if all tools are compliant.
   * Returns the first violation found.
   * Does NOT throw.
   */
  validate(
    toolCalls: readonly ToolCall[] | undefined,
    requestId: string
  ): ToolViolation | null {
    if (!toolCalls || toolCalls.length === 0) {
      return null; // No tools called — compliant
    }

    for (const toolCall of toolCalls) {
      const toolName = toolCall.function.name;

      if (!isToolAllowed(this.policy, toolName)) {
        return createToolViolation(toolName, requestId);
      }
    }

    return null; // All tools are allowed
  }

  /**
   * Update the policy at runtime
   */
  updatePolicy(policy: ToolPolicy): void {
    if (!policy || !policy.allowedTools) {
      throw new Error("[ToolGuard] Policy is required");
    }
    this.policy = policy;
  }

  /**
   * Get current allowed tools (for diagnostics)
   */
  getAllowedTools(): readonly string[] {
    return Array.from(this.policy.allowedTools);
  }
}
