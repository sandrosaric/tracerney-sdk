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

- **238 embedded attack patterns** — covers known injection techniques
- **Local detection** — <5ms latency, zero network calls
- **Zero dependencies** — single npm package
- **No data collection** — all detection happens in your process

## Result Object

```typescript
{
  suspicious: boolean;     // true if pattern matched
  patternName?: string;    // e.g., "Ignore Instructions"
  severity?: string;       // "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
  blocked: boolean;        // false (Layer 1 only)
}
```

## Detected Patterns

- Instruction overrides ("ignore all instructions")
- Role-play jailbreaks ("act as unrestricted AI")
- Context confusion attacks
- Data extraction attempts
- Code execution risks
- And 233 more...

## License

MIT
