# Tracerney

Lightweight prompt injection detection for LLM applications. Runs 100% locally with zero data leaving your server.

> 🚀 **Explore the full platform at [tracerney.com](https://www.tracerney.com)** — includes dashboard, analytics, API management, and team collaboration tools.

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
- **AI-powered response verification** — LLM-based analysis for novel attack patterns
- **Context-aware scanning** — understands your application's specific security policies
- **Delimiter salting** — prevents prompt injection through response boundaries
- **Zero prompt storage** — responses are analyzed in-memory, never saved or logged
- **Structured threat metadata** — detailed fingerprints for audit trails and tracking
- **Advanced rate limiting** — prevents cost spikes with intelligent throttling

## Pricing & Usage

- **Free Tier:** 50 scans/month with Layer 1 pattern detection
- **Pro Tier:** 2,500 scans/month with Layer 1 + Layer 2 LLM verification ($9/month)

---

## Ready for Advanced Protection?

Layer 2 (LLM Sentinel) adds AI-powered verification with **context-aware** threat detection and **zero prompt storage** — all responses are analyzed in-memory and immediately discarded.

**[Start Your Free Trial or Upgrade to Pro](https://www.tracerney.com/docs)** at tracerney.com

Includes:
- Dashboard with threat analytics
- API key management
- Team collaboration features
- Detailed threat fingerprints for compliance
- Priority support for Pro members

---

## License

MIT
