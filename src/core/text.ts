import { redactSecrets } from "./secrets.js";
import type { FindingLocation, JsonSchema, ServerInventory } from "./types.js";

/** One piece of text a model will read, and where it came from. */
export interface TextField {
  location: FindingLocation;
  text: string;
}

/**
 * Every string a client forwards to the model: names, titles, descriptions and
 * the whole input/output schema (property names, defaults, enum values,
 * examples). Poisoned instructions hide in schemas as often as in descriptions.
 */
export function* textFields(server: ServerInventory): Generator<TextField> {
  const at = (kind: FindingLocation["kind"], name: string, field: string, text?: string) =>
    text ? { location: { server: server.name, kind, name, field }, text } : undefined;
  const emit = function* (f: TextField | undefined) {
    if (f) yield f;
  };

  yield* emit(at("server", server.name, "instructions", server.instructions));

  for (const tool of server.tools) {
    yield* emit(at("tool", tool.name, "name", tool.name));
    yield* emit(at("tool", tool.name, "title", tool.title ?? tool.annotations?.title));
    yield* emit(at("tool", tool.name, "description", tool.description));
    for (const [schemaKey, schema] of [
      ["inputSchema", tool.inputSchema],
      ["outputSchema", tool.outputSchema],
    ] as const) {
      if (!schema) continue;
      for (const s of schemaStrings(schema, schemaKey))
        yield* emit(at("tool", tool.name, s.path, s.text));
    }
  }
  for (const r of server.resources) {
    yield* emit(at("resource", r.uri, "name", r.name));
    yield* emit(at("resource", r.uri, "title", r.title));
    yield* emit(at("resource", r.uri, "description", r.description));
  }
  for (const t of server.resourceTemplates) {
    yield* emit(at("resource-template", t.uriTemplate, "name", t.name));
    yield* emit(at("resource-template", t.uriTemplate, "description", t.description));
  }
  for (const p of server.prompts) {
    yield* emit(at("prompt", p.name, "name", p.name));
    yield* emit(at("prompt", p.name, "description", p.description));
    for (const a of p.arguments ?? []) {
      yield* emit(at("prompt", p.name, `arguments.${a.name}.description`, a.description));
    }
  }
}

const STRING_KEYWORDS = ["description", "title", "default"] as const;

function* schemaStrings(schema: unknown, path: string): Generator<{ path: string; text: string }> {
  if (Array.isArray(schema)) {
    for (const [i, s] of schema.entries()) yield* schemaStrings(s, `${path}[${i}]`);
    return;
  }
  if (!schema || typeof schema !== "object") return;
  const s = schema as JsonSchema;
  for (const key of STRING_KEYWORDS) {
    const v = s[key];
    if (typeof v === "string") yield { path: `${path}.${key}`, text: v };
  }
  for (const key of ["enum", "examples"] as const) {
    const values = s[key];
    if (!Array.isArray(values)) continue;
    for (const [i, v] of values.entries()) {
      if (typeof v === "string") yield { path: `${path}.${key}[${i}]`, text: v };
    }
  }
  if (typeof s.const === "string") yield { path: `${path}.const`, text: s.const };
  if (s.properties && typeof s.properties === "object") {
    for (const [name, sub] of Object.entries(s.properties)) {
      const p = `${path}.properties.${name}`;
      yield { path: `${p}(name)`, text: name };
      yield* schemaStrings(sub, p);
    }
  }
  for (const key of ["items", "anyOf", "oneOf", "allOf", "additionalProperties"] as const) {
    if (s[key] && typeof s[key] === "object") yield* schemaStrings(s[key], `${path}.${key}`);
  }
}

// ---------------------------------------------------------------- Unicode

/**
 * Characters that render as nothing (or reorder what is rendered) but still
 * reach the model: zero-width and bidi controls (Trojan Source), Unicode tag
 * characters (which smuggle a full ASCII string), variation selectors used for
 * the same purpose, and C0/C1 control codes other than tab and newline.
 */
const INVISIBLE =
  // Matching control characters is the point of this pattern.
  // eslint-disable-next-line no-control-regex
  /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F\u00AD\u180E\u200B-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u2069\uFEFF]|[\u{E0000}-\u{E007F}]|[\u{E0100}-\u{E01EF}]/gu;

export interface InvisibleHit {
  count: number;
  codepoints: string[];
  /** ASCII hidden with Unicode tag characters, if any. */
  smuggled?: string;
}

export function findInvisible(text: string): InvisibleHit | undefined {
  const matches = text.match(INVISIBLE);
  if (!matches) return undefined;
  const codepoints = [...new Set(matches.map(codepoint))];
  let smuggled = "";
  for (const ch of matches) {
    const cp = ch.codePointAt(0) ?? 0;
    if (cp >= 0xe0020 && cp <= 0xe007e) smuggled += String.fromCharCode(cp - 0xe0000);
  }
  return { count: matches.length, codepoints, ...(smuggled ? { smuggled } : {}) };
}

function codepoint(ch: string): string {
  return `U+${(ch.codePointAt(0) ?? 0).toString(16).toUpperCase().padStart(4, "0")}`;
}

/**
 * What the model effectively reads: tag-character runs decoded to ASCII and
 * other invisible characters removed, so "ig<U+200B>nore previous" or a
 * hidden tag sentence cannot slip past the text patterns.
 */
export function decodeHidden(text: string): string {
  return text
    .replace(/[\u{E0000}-\u{E007F}]+/gu, (run) =>
      [...run].map((ch) => String.fromCharCode((ch.codePointAt(0) ?? 0) - 0xe0000)).join(""),
    )
    .replace(INVISIBLE, "");
}

/** Replaces invisible characters with their code point so evidence is reviewable. */
export function reveal(text: string): string {
  return text
    .replace(/[\u{E0000}-\u{E007F}]+/gu, (run) => {
      const decoded = [...run]
        .map((ch) => String.fromCharCode((ch.codePointAt(0) ?? 0) - 0xe0000))
        .join("");
      return `<tags:${JSON.stringify(decoded.replace(/[^\x20-\x7e]/g, "?"))}>`;
    })
    .replace(INVISIBLE, (ch) => `<${codepoint(ch)}>`);
}

// ---------------------------------------------------------------- patterns

export interface PatternHit {
  label: string;
  match: string;
  index: number;
}

export interface LabeledPattern {
  label: string;
  re: RegExp;
}

export function firstHit(
  text: string,
  patterns: readonly LabeledPattern[],
): PatternHit | undefined {
  for (const { label, re } of patterns) {
    const m = re.exec(text);
    if (m) return { label, match: m[0], index: m.index };
  }
  return undefined;
}

/** A window of text around a match, single-line, for evidence. */
export function excerpt(text: string, index: number, length: number, radius = 60): string {
  const start = Math.max(0, index - radius);
  const end = Math.min(text.length, index + length + radius);
  const body = redactSecrets(reveal(text.slice(start, end)))
    .replace(/\s+/g, " ")
    .trim();
  return `${start > 0 ? "..." : ""}${body}${end < text.length ? "..." : ""}`;
}

/** Instructions aimed at the model rather than at a human reading the docs. */
export const MODEL_DIRECTED: readonly LabeledPattern[] = [
  {
    label: "override of prior instructions",
    re: /\b(ignore|disregard|forget|override)\s+(all\s+|any\s+|the\s+|your\s+)*(previous|prior|above|earlier|preceding|system|original)\s+(instructions?|prompts?|messages?|rules|guidelines|directions)/i,
  },
  {
    label: "concealment from the user",
    re: /\b(do\s+not|don'?t|never|must\s+not)\s+(tell|inform|mention|reveal|show|notify|alert|disclose)\b[^.\n]{0,40}\b(user|human|operator)\b/i,
  },
  {
    label: "concealment from the user",
    re: /\bwithout\s+(asking|telling|informing|notifying|alerting)\s+(the\s+)?(user|human)\b/i,
  },
  {
    label: "concealment from the user",
    re: /\b(user|human)\s+(must|should)\s*(not|n'?t)\s+(know|see|notice|be\s+told|be\s+aware)\b/i,
  },
  {
    label: "role or prompt hijack",
    re: /\b(you\s+are\s+now\s+(a|an|in)\b|new\s+system\s+prompt|(reveal|print|repeat|output)\s+(your|the)\s+system\s+prompt)/i,
  },
  {
    label: "instruction block markup",
    re: /<\s*\/?\s*(important|system|instructions?|secret|hidden|admin|assistant)\s*>/i,
  },
];

/**
 * Weaker signals: imperative phrasing aimed at the assistant. Legitimate tools
 * say "always call X first" too, which is why this only produces a low finding
 * and is what the optional LLM judge is asked about.
 */
export const MODEL_DIRECTED_WEAK: readonly LabeledPattern[] = [
  {
    label: "imperative to the assistant",
    re: /\b(the\s+)?(assistant|model|AI|LLM|agent)\s+(must|should|has\s+to|needs\s+to)\s+(always|never|first|also)\b/i,
  },
  {
    label: "imperative to the assistant",
    re: /\byou\s+(must|should|have\s+to|need\s+to)\s+(always|never|first|also)\b/i,
  },
  {
    label: "mandatory pre-step",
    re: /\bbefore\s+(using|calling|invoking|running)\s+(this|any\s+other|any)\s+tool\b[^.\n]{0,60}\b(must|always|first)\b/i,
  },
];

const SENSITIVE_PATH =
  /(~|\$HOME|%USERPROFILE%)?[\\/]?\.(ssh|aws|gnupg|kube|docker)\b[^\s"'`]*|\bid_(rsa|ed25519|ecdsa)\b|(^|[\s"'`/])\.env(\.[a-z]+)?\b|\.(npmrc|netrc|pgpass|git-credentials)\b|\/etc\/(passwd|shadow)\b|\bmcp\.json\b/i;

const SECRET_NOUN =
  "(api[\\s_-]?keys?|access\\s+tokens?|tokens?|passwords?|credentials?|secrets?|private\\s+keys?|session\\s+cookies?|conversation(\\s+history)?|chat\\s+history|previous\\s+messages|system\\s+prompt)";
const EXFIL_VERB =
  "(read|include|send|pass|attach|upload|forward|post|copy|append|embed|leak|exfiltrate|collect)";

/** Requests to move data the tool has no business touching. */
export const EXFILTRATION: readonly LabeledPattern[] = [
  { label: "reference to a credential file", re: SENSITIVE_PATH },
  {
    label: "request to move secrets or conversation data",
    re: new RegExp(`\\b${EXFIL_VERB}\\b[^.\\n]{0,60}\\b${SECRET_NOUN}\\b`, "i"),
  },
  {
    label: "request to send data to an external address",
    re: new RegExp(
      `\\b(send|forward|post|upload|bcc|cc)\\b[^.\\n]{0,80}\\b(to|at)\\s+(https?:\\/\\/\\S+|[\\w.+-]+@[\\w-]+\\.[\\w.]+)`,
      "i",
    ),
  },
];

/** Long HTML comments or whitespace walls that push text outside a reviewer's view. */
export const HIDDEN_CONTENT: readonly LabeledPattern[] = [
  { label: "HTML comment", re: /<!--[\s\S]*?-->/ },
  { label: "whitespace padding", re: /(\s*\n){12,}|[ \t]{120,}/ },
  { label: "encoded blob", re: /\b[A-Za-z0-9+/]{120,}={0,2}(?![A-Za-z0-9+/=])/ },
];
