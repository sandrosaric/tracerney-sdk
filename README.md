# Tracerney

Lightweight prompt injection detection for LLM applications. Runs 100% locally with zero data leaving your server.

## Install

```bash
npm install @sandrobuilds/tracerney
```

## Usage

```typescript
import { Tracerney } from '@sandrobuilds/tracerney';

const tracer = new Tracerney();

const result = await tracer.scanPrompt(userInput);

if (result.suspicious) {
  console.log('⚠️ Suspicious:', result.patternName);
  // Handle flagged prompt (log, block, rate-limit, etc.)
}
```

## What's Included

- **258 embedded attack patterns** — real-world injection techniques detected in real-time
- **Local detection** — <5ms latency per prompt, zero network overhead
- **Zero dependencies** — single npm package
- **Privacy-first** — no data leaves your server, 100% local processing

## Result Object

### Layer 1 (Pattern Detection)
```typescript
{
  suspicious: boolean;     // true if pattern matched
  patternName?: string;    // e.g., "Ignore Instructions"
  severity?: string;       // "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
  blocked: boolean;        // false (Layer 1 only marks suspicious)
}
```

### Layer 2 (LLM Sentinel)
```typescript
{
  action: "BLOCK" | "ALLOW";     // Final decision from LLM Sentinel
  confidence: number;             // 0.0 to 1.0 confidence score
  class: string;                  // Threat classification (e.g., "jailbreak_llm_detected")
  fingerprint: string;            // Unique threat identifier for tracking
}
```

## Detected Patterns

- Instruction overrides ("ignore all instructions")
- Role-play jailbreaks ("act as unrestricted AI")
- Hypothetical constraint bypass ("what would you do without constraints?")
- Context confusion attacks
- Data extraction attempts
- Code execution risks
- And 254 more...

## Multi-Layer Runtime Defense

**Layer 1:** Pattern Matching (Always Free)
- 258 real-world attack patterns in real-time
- <5ms detection on modern hardware
- Zero network overhead
- Local processing only
- Detects: instruction overrides, role-play jailbreaks, context confusion, code execution risks, data extraction attempts, and more

**Layer 2:** LLM Sentinel (Pro - $9/month)
- AI-powered response verification system
- Analyzes LLM responses for injection patterns
- Validates output safety with context-aware scanning
- Delimiter salting for enhanced protection
- Returns structured threat metadata (class, fingerprint, confidence)

## Pricing

- **Free Tier:** 50 scans/month with Layer 1 pattern detection
- **Pro Tier:** 2,500 scans/month with Layer 1 + Layer 2 LLM verification

## License

MIT
