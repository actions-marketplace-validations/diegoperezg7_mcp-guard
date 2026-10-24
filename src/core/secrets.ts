/**
 * Credential detectors. Provider formats are matched by prefix and length;
 * every candidate must also look random (entropy) and must not look like a
 * documentation placeholder, so `sk-xxxxxxxx...` or `password: changeme`
 * does not fire.
 */
export interface SecretHit {
  kind: string;
  /** Redacted: first four characters and the length. Raw secrets never reach a report. */
  redacted: string;
  index: number;
  length: number;
}

/** Where a secret sits in a text, so evidence windows can avoid cutting through one. */
export interface SecretSpan {
  kind: string;
  start: number;
  end: number;
}

interface SecretPattern {
  kind: string;
  re: RegExp;
  /** Capture group holding the secret itself (defaults to the whole match). */
  group?: number;
  /** Bits per character the secret part needs; omitted for fixed markers such as key headers. */
  minEntropy?: number;
}

// The `d` flag gives capture-group offsets, needed to redact only the secret part.
const PATTERNS: readonly SecretPattern[] = [
  { kind: "private key", re: /-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----/dg },
  { kind: "AWS access key id", re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/dg, minEntropy: 3 },
  {
    kind: "GitHub token",
    re: /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b/dg,
    minEntropy: 3,
  },
  { kind: "Slack token", re: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/dg, minEntropy: 3 },
  { kind: "Stripe live key", re: /\b[rs]k_live_[A-Za-z0-9]{20,}\b/dg, minEntropy: 3 },
  { kind: "Google API key", re: /\bAIza[0-9A-Za-z_-]{35}\b/dg, minEntropy: 3 },
  {
    kind: "LLM provider API key",
    re: /\bsk-(?:proj-|ant-[a-z0-9]+-)?([A-Za-z0-9_-]{32,})\b/dg,
    group: 1,
    minEntropy: 3.5,
  },
  {
    kind: "JSON Web Token",
    re: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/dg,
    minEntropy: 3.5,
  },
  {
    kind: "password in a URL",
    re: /\b[a-z][a-z0-9+.-]{0,20}:\/\/[^\s:@/]{1,256}:([^\s@/]{6,256})@[^\s/]+/dgi,
    group: 1,
    minEntropy: 2.5,
  },
  {
    kind: "hard-coded secret",
    re: /\b(?:api[_-]?key|secret(?:[_-]?key)?|access[_-]?token|auth[_-]?token|password|passwd)\b["']?\s{0,8}[:=]\s{0,8}["']?([A-Za-z0-9_\-/+=.]{16,512})/dgi,
    group: 1,
    minEntropy: 3.5,
  },
];

/** Values people put in docs and examples instead of a real credential. */
const PLACEHOLDER =
  /x{4,}|X{4,}|\*{3,}|\.{3}|0{6,}|1234|abcd|example|sample|dummy|placeholder|redacted|changeme|your[_-]?|<[^>]*>|\$\{|\{\{/i;

export function secretSpans(text: string): SecretSpan[] {
  const spans: SecretSpan[] = [];
  for (const p of PATTERNS) {
    for (const m of text.matchAll(p.re)) {
      const g = p.group ?? 0;
      const secret = m[g];
      const range = m.indices?.[g];
      if (secret === undefined || !range) continue;
      if (p.minEntropy !== undefined) {
        if (shannonEntropy(secret) < p.minEntropy || PLACEHOLDER.test(secret)) continue;
      }
      if (spans.some((s) => s.start < range[1] && range[0] < s.end)) continue;
      spans.push({ kind: p.kind, start: range[0], end: range[1] });
    }
  }
  return spans.sort((a, b) => a.start - b.start);
}

export function findSecrets(text: string): SecretHit[] {
  return secretSpans(text).map((s) => ({
    kind: s.kind,
    redacted: redact(text.slice(s.start, s.end)),
    index: s.start,
    length: s.end - s.start,
  }));
}

/** Evidence never carries a raw credential, whatever rule produced it. */
export function redactSecrets(text: string): string {
  let out = text;
  for (const s of secretSpans(text).reverse()) {
    out = `${out.slice(0, s.start)}${text.slice(s.start, s.start + 4)}...[redacted]${out.slice(s.end)}`;
  }
  return out;
}

export function redact(secret: string): string {
  return `${secret.slice(0, 4)}... (${secret.length} chars, redacted)`;
}

/** Bits per character. Random base64 sits near 6, English words near 3. */
export function shannonEntropy(s: string): number {
  if (!s) return 0;
  const counts = new Map<string, number>();
  for (const ch of s) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let h = 0;
  for (const n of counts.values()) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}
