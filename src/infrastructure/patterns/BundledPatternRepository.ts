/**
 * Bundled Pattern Repository
 * Adapter: implements IPatternRepository for local bundled patterns
 * Supports Free tier (258 patterns) and Pro tier (258 + 675 Garak patterns)
 * Synchronous internally, async interface for compatibility
 */

import { IPatternRepository } from "../../application/ports/IPatternRepository";
import { VanguardPattern } from "../../domain/detection/VanguardPattern";
import { BUNDLED_PATTERNS, BUNDLED_MANIFEST_VERSION } from "./bundled-patterns";
import { PRO_PATTERNS } from "./pro-patterns";

export interface BundledRepositoryConfig {
  tier?: "free" | "pro";
}

export class BundledPatternRepository implements IPatternRepository {
  private tier: "free" | "pro";
  readonly sourceIdentifier: string;

  constructor(config?: BundledRepositoryConfig) {
    this.tier = config?.tier ?? "free";
    const tierLabel = this.tier === "pro" ? "pro" : "free";
    this.sourceIdentifier = `bundled-${tierLabel}@${BUNDLED_MANIFEST_VERSION}`;
  }

  /**
   * Load bundled patterns based on tier.
   * Free: 258 core patterns
   * Pro: 258 core + 675 Garak patterns (933 total)
   * Synchronous internally, but wrapped in Promise for interface compatibility.
   */
  async getPatterns(): Promise<readonly VanguardPattern[]> {
    if (this.tier === "pro") {
      return [...BUNDLED_PATTERNS, ...PRO_PATTERNS];
    }
    return BUNDLED_PATTERNS;
  }

  /**
   * Switch tier at runtime
   */
  setTier(tier: "free" | "pro"): void {
    this.tier = tier;
  }

  /**
   * Get current tier
   */
  getTier(): "free" | "pro" {
    return this.tier;
  }
}
