/**
 * Remote Pattern Repository
 * Adapter: implements IPatternRepository for remote manifest fetching
 * Fixes Gap 1: takes fallback repository in constructor, uses explicit fallback on failure
 */

import { IPatternRepository } from "../../application/ports/IPatternRepository";
import { VanguardPattern, PatternCategory } from "../../domain/detection/VanguardPattern";
import { ThreatSeverity } from "../../domain/events/ThreatSeverity";

const DEFAULT_CACHE_TTL = 24 * 60 * 60 * 1000; // 24 hours
const DEFAULT_STALE_WHILE_REVALIDATE = 7 * 24 * 60 * 60 * 1000; // 7 days

/**
 * Serialized pattern format from manifest JSON
 * Regex patterns are stored as strings with separate flags field
 */
interface SerializedPattern {
  readonly id: string;
  readonly name: string;
  readonly pattern: string;
  readonly flags?: string;
  readonly severity: string;
  readonly description: string;
  readonly category: PatternCategory;
}

export interface RemoteManifestDefinition {
  readonly version: string;
  readonly releaseDate: number;
  readonly patterns: readonly (VanguardPattern | SerializedPattern)[];
  readonly checksum?: string;
}

export interface RemotePatternRepositoryConfig {
  manifestUrl: string;
  fallbackRepository: IPatternRepository; // FIX GAP 1: explicit fallback
  cacheTTLMs?: number;
  staleWhileRevalidateMs?: number;
}

export class RemotePatternRepository implements IPatternRepository {
  readonly sourceIdentifier: string;

  private localManifest: RemoteManifestDefinition | null = null;
  private cachedPatterns: readonly VanguardPattern[] | null = null;
  private metadata: {
    version: string;
    fetchedAt: number;
    expiresAt: number;
  } | null = null;
  private isFetching = false;
  private readonly cacheTTL: number;
  private readonly staleWhileRevalidate: number;

  constructor(private readonly config: RemotePatternRepositoryConfig) {
    this.sourceIdentifier = `remote:${config.manifestUrl}`;
    this.cacheTTL = config.cacheTTLMs ?? DEFAULT_CACHE_TTL;
    this.staleWhileRevalidate = config.staleWhileRevalidateMs ?? DEFAULT_STALE_WHILE_REVALIDATE;
  }

  /**
   * Deserialize patterns from JSON manifest
   * Converts string patterns to RegExp objects
   */
  private deserializePatterns(patterns: readonly (VanguardPattern | SerializedPattern)[]): VanguardPattern[] {
    return patterns.map((p) => {
      // If already a VanguardPattern (has RegExp), return as-is
      if (p.pattern instanceof RegExp) {
        return p as VanguardPattern;
      }

      // Convert serialized pattern to VanguardPattern
      const serialized = p as SerializedPattern;
      const regex = new RegExp(serialized.pattern, serialized.flags ?? "");
      const severity = this.parseSeverity(serialized.severity);

      return {
        id: serialized.id,
        name: serialized.name,
        pattern: regex,
        severity,
        description: serialized.description,
        category: serialized.category,
      };
    });
  }

  /**
   * Convert string severity to ThreatSeverity enum
   */
  private parseSeverity(severity: string): ThreatSeverity {
    switch (severity.toLowerCase()) {
      case "critical":
        return ThreatSeverity.CRITICAL;
      case "high":
        return ThreatSeverity.HIGH;
      case "medium":
        return ThreatSeverity.MEDIUM;
      case "low":
      default:
        return ThreatSeverity.LOW;
    }
  }

  /**
   * Get patterns: three-tier strategy
   * 1. Fresh cache: return immediately
   * 2. Stale cache: return stale version, fetch new in background
   * 3. No cache: fetch new, fall back to bundled repository on failure
   */
  async getPatterns(): Promise<readonly VanguardPattern[]> {
    // Tier 1: Fresh cached version
    if (this.cachedPatterns && this.isFresh()) {
      return this.cachedPatterns;
    }

    // Tier 2: Stale cache but usable
    if (this.cachedPatterns && this.isStale()) {
      // Background refresh (non-blocking)
      this.fetchManifest().catch((err) => {
        console.debug("[Tracerney] Background manifest update failed:", err);
      });
      return this.cachedPatterns;
    }

    // Tier 3: No cache or expired — must fetch
    if (!this.isFetching) {
      try {
        await this.fetchManifest();
        return this.cachedPatterns!;
      } catch (err) {
        // FIX GAP 1: explicit fallback to bundled repository on fetch failure
        console.warn(
          "[Tracerney] Remote manifest fetch failed, falling back to bundled patterns:",
          err
        );
        return this.config.fallbackRepository.getPatterns();
      }
    }

    // Fetch already in progress, use bundled fallback
    return this.config.fallbackRepository.getPatterns();
  }

  /**
   * Fetch manifest from remote URL
   */
  private async fetchManifest(): Promise<RemoteManifestDefinition> {
    if (this.isFetching) {
      throw new Error("[RemotePatternRepository] Manifest fetch already in progress");
    }

    this.isFetching = true;

    try {
      const response = await fetch(this.config.manifestUrl, {
        method: "GET",
        headers: {
          Accept: "application/json",
          "Cache-Control": "max-age=3600",
        },
      });

      if (!response.ok) {
        throw new Error(
          `[RemotePatternRepository] Fetch returned ${response.status}: ${response.statusText}`
        );
      }

      const manifest: RemoteManifestDefinition = (await response.json()) as RemoteManifestDefinition;

      // Validate
      if (!manifest.version || !Array.isArray(manifest.patterns)) {
        throw new Error("[RemotePatternRepository] Invalid manifest structure");
      }

      // Optional checksum verification (placeholder)
      if (manifest.checksum && manifest.checksum !== "auto-calculated-by-server") {
        const hash = await this.computeHash(JSON.stringify(manifest.patterns));
        if (hash !== manifest.checksum) {
          throw new Error("[RemotePatternRepository] Checksum verification failed");
        }
      }

      // Deserialize patterns from JSON format
      this.cachedPatterns = this.deserializePatterns(manifest.patterns);
      this.localManifest = manifest;
      this.updateMetadata(manifest.version);

      return manifest;
    } finally {
      this.isFetching = false;
    }
  }

  private isFresh(): boolean {
    if (!this.metadata) return false;
    return Date.now() < this.metadata.expiresAt;
  }

  private isStale(): boolean {
    if (!this.metadata) return true;
    const now = Date.now();
    return (
      now >= this.metadata.expiresAt &&
      now < this.metadata.fetchedAt + this.staleWhileRevalidate
    );
  }

  private updateMetadata(version: string): void {
    const now = Date.now();
    this.metadata = {
      version,
      fetchedAt: now,
      expiresAt: now + this.cacheTTL,
    };
  }

  private async computeHash(data: string): Promise<string> {
    // Placeholder — in real implementation, use Node.js crypto or SubtleCrypto
    let hash = 0;
    for (let i = 0; i < data.length; i++) {
      const char = data.charCodeAt(i);
      hash = (hash << 5) - hash + char;
      hash = hash & hash;
    }
    return Math.abs(hash).toString(16);
  }

  getStatus() {
    return {
      currentVersion: this.metadata?.version || null,
      cachedAt: this.metadata?.fetchedAt || null,
      expiresAt: this.metadata?.expiresAt || null,
      isFresh: this.isFresh(),
      isStale: this.isStale(),
      isFetching: this.isFetching,
    };
  }
}
