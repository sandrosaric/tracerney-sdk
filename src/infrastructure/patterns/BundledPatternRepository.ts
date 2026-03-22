/**
 * Bundled Pattern Repository
 * Adapter: implements IPatternRepository for local bundled patterns
 * Synchronous internally, async interface for compatibility
 */

import { IPatternRepository } from "../../application/ports/IPatternRepository";
import { VanguardPattern } from "../../domain/detection/VanguardPattern";
import { BUNDLED_PATTERNS, BUNDLED_MANIFEST_VERSION } from "./bundled-patterns";

export class BundledPatternRepository implements IPatternRepository {
  readonly sourceIdentifier = `bundled@${BUNDLED_MANIFEST_VERSION}`;

  /**
   * Load bundled patterns.
   * Synchronous internally, but wrapped in Promise for interface compatibility.
   */
  async getPatterns(): Promise<readonly VanguardPattern[]> {
    return BUNDLED_PATTERNS;
  }
}
