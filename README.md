# Tracerney

Lightweight prompt injection detection for LLM applications. Runs 100% locally.

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

- **259 embedded attack patterns** — covers known injection techniques
- **Local detection** — <5ms latency, zero network calls
- **Zero dependencies** — single npm package
- **No data collection** — all detection happens in your process

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

**Layer 1:** Pattern-based detection with 259 embedded patterns
- Fast local detection (<5ms)
- Zero network overhead
- Blocks known attack techniques
- Marks suspicious prompts

**Layer 2:** LLM Sentinel (Backend Verification)
- Backend LLM verification for novel attacks
- Context-aware analysis via OpenRouter
- Returns structured threat metadata (class, fingerprint, confidence)
- Rate limiting to prevent cost spikes
- Only escalates suspicious Layer 1 matches

## License

MIT
