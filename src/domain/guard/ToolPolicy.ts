/**
 * Tool Policy
 * Domain value object: the allow-list rule set
 */

export interface ToolPolicy {
  readonly allowedTools: ReadonlySet<string>;
}

/**
 * Factory to create a ToolPolicy from an array
 */
export function createToolPolicy(allowedTools: readonly string[]): ToolPolicy {
  return {
    allowedTools: new Set(allowedTools),
  };
}

/**
 * Check if a tool is allowed by the policy
 */
export function isToolAllowed(policy: ToolPolicy, toolName: string): boolean {
  return policy.allowedTools.has(toolName);
}
