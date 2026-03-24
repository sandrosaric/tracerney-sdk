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

## Layer 2: LLM Sentinel Deep Dive

Layer 2 adds advanced security with LLM Sentinel, an AI-powered verification system that analyzes LLM responses for injection patterns and validates output safety. Combines local pattern detection (Layer 1) with server-side verification for defense-in-depth protection.

### How Layer 1 & Layer 2 Work Together

| **Layer 1: Pattern Detection (Free SDK)** | **Layer 2: LLM Sentinel (Pro)** |
|---|---|
| Local pattern matching | Server-side verification |
| 258 attack patterns | Output validation |
| <5ms latency | JSON safety checks |
| No data leaves device | Delimiter salting |
| Zero network calls | Context-aware analysis |

### Enabling Layer 2

Initialize Tracerney with Layer 2 LLM Sentinel (Pro plan required):

```typescript
const tracer = new Tracerney({
  apiKey: process.env.TRACERNEY_API_KEY,
  sentinelEnabled: true,
});
```

That's it! Layer 2 is automatically configured to use the hosted LLM Sentinel service. Your API key authenticates requests and verifies your Pro subscription.

### Custom Layer 2 Configuration (Advanced)

Want to self-host Layer 2 or use a custom implementation? Override the sentinel endpoint:

```typescript
const tracer = new Tracerney({
  apiKey: process.env.TRACERNEY_API_KEY,
  sentinelEnabled: true,
  baseUrl: process.env.TRACERNEY_BASE_URL, // e.g., http://localhost:3000 or https://myapp.com
  sentinelEndpoint: process.env.TRACERNEY_SENTINEL_ENDPOINT, // e.g., /api/v1/verify-prompt
});
```

**Self-hosting Layer 2?** You can build your own verification endpoint using the same pattern as our hosted service. Contact support for self-hosting guidance.

### Scanning with Layer 2

With Layer 2 enabled, `scanPrompt` validates both input and LLM responses. Handle errors appropriately:

```typescript
try {
  // Scan input (Layer 1 + Layer 2)
  const result = await tracer.scanPrompt(userInput);
  // If we get here, input is safe. Call LLM
  const llmResponse = await llm.chat(userInput);
  // Verify LLM output wasn't compromised
  const outputCheck = await tracer.verifyOutput(llmResponse);
  return llmResponse;
} catch (err) {
  if (err instanceof ShieldBlockError) {
    return NextResponse.json(
      { error: "Input content is flagged as suspicious" },
      { status: 400 }
    );
  }
  throw err;
}
```

### API Response Format

The verify-prompt endpoint returns structured responses. Success (HTTP 200) includes classification, confidence, and fingerprint. Errors include specific error codes and messages.

#### ✅ Content is Safe (HTTP 200)
```json
{
  "action": "ALLOW",
  "confidence": 0.15,
  "class": "safe_content",
  "fingerprint": "a3f7k2"
}
```

#### 🔴 Content is Blocked (HTTP 200)
```json
{
  "action": "BLOCK",
  "confidence": 0.99,
  "class": "jailbreak_semantic_pattern",
  "fingerprint": "c1p5n3"
}
```

#### ⚠️ Quota Exceeded (HTTP 402)
```json
{
  "blocked": true,
  "reason": "scan_limit_exceeded",
  "scansUsed": 50,
  "limit": 50,
  "message": "Free plan limit reached (50/month)..."
}
```

---

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
