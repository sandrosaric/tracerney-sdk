/**
 * IPatternRepository
 * Outbound port: defines the contract for loading detection patterns
 * Implemented by: BundledPatternRepository, RemotePatternRepository
 */

import { VanguardPattern } from "../../domain/detection/VanguardPattern";

export interface IPatternRepository {
  /**
   * Load patterns.
   * May be synchronous (bundled) or asynchronous (remote).
   * Returns readonly array for immutability.
   */
  getPatterns(): Promise<readonly VanguardPattern[]>;

  /**
   * Source identifier for diagnostics.
   * Examples: "bundled@0.1.0", "remote:https://api.tracerney.dev/manifest.json"
   */
  readonly sourceIdentifier: string;
}
