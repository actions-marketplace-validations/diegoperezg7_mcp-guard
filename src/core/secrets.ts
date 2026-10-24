/**
 * Credential detectors. Provider formats are matched by prefix and length;
 * the generic `key = value` form also needs enough entropy, so that
 * `password: <your password here>` in documentation does not fire.
 */
export interface SecretHit {
  kind: string;
  /** Redacted: first four characters and the length. Raw secrets never reach a report. */
  redacted: string;
  index: number;
  length: number;
}

interface SecretPattern {
  kind: string;
  re: RegExp;
  /** Capture group holding the secret itself (defaults to the whole match). */
  group?: number;
  minEntropy?: number;
}

const PATTERNS: readonly SecretPattern[] = [
  { kind: "private key", re: /-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----/g },
  { kind: "AWS access key id", re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g },
  { kind: "GitHub token", re: /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b/g },
  { kind: "Slack token", re: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g },
  { kind: "Stripe live key", re: /\b[rs]k_live_[A-Za-z0-9]{20,}\b/g },
  { kind: "Google API key", re: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { kind: "LLM provider API key", re: /\bsk-(?:proj-|ant-[a-z0-9]+-)?[A-Za-z0-9_-]{32,}\b/g },
  {
    kind: "JSON Web Token",
    re: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
  },
  {
    kind: "password in a URL",
    re: /\b[a-z][a-z0-9+.-]*:\/\/[^\s:@/]+:([^\s@/]{6,})@[^\s/]+/gi,
    group: 1,
    minEntropy: 2.5,
  },
  {
    kind: "hard-coded secret",
    re: /\b(?:api[_-]?key|secret(?:[_-]?key)?|access[_-]?token|auth[_-]?token|password|passwd)\b["']?\s*[:=]\s*["']?([A-Za-z0-9_\-/+=.]{16,})/gi,
    group: 1,
    minEntropy: 3.5,
  },
];

export function findSecrets(text: string): SecretHit[] {
  const hits: SecretHit[] = [];
  const seen = new Set<string>();
  for (const p of PATTERNS) {
    for (const m of text.matchAll(p.re)) {
      const secret = m[p.group ?? 0] ?? m[0];
      if (p.minEntropy !== undefined && shannonEntropy(secret) < p.minEntropy) continue;
      if (seen.has(secret)) continue;
      seen.add(secret);
      hits.push({
        kind: p.kind,
        redacted: redact(secret),
        index: m.index ?? 0,
        length: m[0].length,
      });
    }
  }
  return hits;
}

/** Evidence never carries a raw credential, whatever rule produced it. */
export function redactSecrets(text: string): string {
  let out = text;
  for (const p of PATTERNS) {
    out = out.replace(p.re, (...m: unknown[]) => {
      const whole = m[0] as string;
      const secret = (p.group ? (m[p.group] as string | undefined) : undefined) ?? whole;
      if (p.minEntropy !== undefined && shannonEntropy(secret) < p.minEntropy) return whole;
      return whole.replace(secret, `${secret.slice(0, 4)}...[redacted]`);
    });
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
