import { redactSecrets, secretSpans } from "./secrets.js";
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
 * reach the model: zero-width, joiner and bidi controls (Trojan Source), line
 * and paragraph separators, Hangul fillers, Unicode tag characters (which
 * smuggle a full ASCII string), variation selectors used for the same purpose
 * (except U+FE0F after an emoji, where it is normal), and C0/C1 control codes
 * other than tab and newline.
 */
const INVISIBLE_SOURCE =
  "[\\u0000-\\u0008\\u000B\\u000C\\u000E-\\u001F\\u007F-\\u009F\\u00AD\\u034F\\u061C\\u115F\\u1160\\u17B4\\u17B5\\u180E\\u200B-\\u200F\\u2028-\\u202E\\u2060-\\u2064\\u2066-\\u2069\\u3164\\uFEFF\\uFFA0]" +
  "|[\\u{E0000}-\\u{E007F}]|[\\u{E0100}-\\u{E01EF}]" +
  "|(?<![\\p{Extended_Pictographic}#*0-9])[\\uFE00-\\uFE0F]";
// Matching control and combining characters one by one is the point of this class.
// eslint-disable-next-line no-misleading-character-class
const INVISIBLE = new RegExp(INVISIBLE_SOURCE, "gu");

export interface InvisibleHit {
  count: number;
  codepoints: string[];
  /** ASCII hidden with Unicode tag characters, if any. */
  smuggled?: string;
}

export function findInvisible(text: string): InvisibleHit | undefined {
  const matches = clamp(text).match(INVISIBLE);
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

const TAG_RUN = /[\u{E0000}-\u{E007F}]+/gu;

function decodeTags(run: string): string {
  return [...run].map((ch) => String.fromCharCode((ch.codePointAt(0) ?? 0) - 0xe0000)).join("");
}

/**
 * What the model effectively reads: tag-character runs decoded to ASCII and
 * other invisible characters removed, so "ig<U+200B>nore previous" or a
 * hidden tag sentence cannot slip past the text patterns.
 */
export function decodeHidden(text: string): string {
  return text.replace(TAG_RUN, decodeTags).replace(INVISIBLE, "");
}

/** Replaces invisible characters with their code point so evidence is reviewable. */
export function reveal(text: string): string {
  return text
    .replace(
      TAG_RUN,
      (run) => `<tags:${JSON.stringify(decodeTags(run).replace(/[^\x20-\x7e]/g, "?"))}>`,
    )
    .replace(INVISIBLE, (ch) => `<${codepoint(ch)}>`);
}

/**
 * For anything printed to a terminal or rendered as Markdown: every control,
 * escape, bidi and invisible character becomes a visible code (\x1b, <U+202E>),
 * and line breaks become spaces. ESC sequences (colours, cursor moves, OSC 8
 * links) from a server therefore cannot act on the reader's terminal.
 */
export function printable(text: string): string {
  return reveal(text)
    .replace(/[\t\n\r]/g, " ")
    .replace(/<U\+00([0-9A-F]{2})>/g, (_, hex: string) => `\\x${hex.toLowerCase()}`);
}

// ---------------------------------------------------------------- patterns

/**
 * Upper bound on the characters a text rule reads per field. Every pattern
 * below is linear, and this bound keeps even linear work small on hostile input.
 */
export const MAX_SCAN_CHARS = 256 * 1024;

function clamp(text: string): string {
  return text.length > MAX_SCAN_CHARS ? text.slice(0, MAX_SCAN_CHARS) : text;
}

export interface PatternHit {
  label: string;
  match: string;
  index: number;
}

/** A regular expression, or a hand-written scanner where a regex would backtrack. */
export type LabeledPattern =
  | { label: string; re: RegExp }
  | { label: string; scan: (text: string) => { index: number; length: number } | undefined };

export function firstHit(
  text: string,
  patterns: readonly LabeledPattern[],
): PatternHit | undefined {
  const t = clamp(text);
  for (const p of patterns) {
    if ("re" in p) {
      const m = p.re.exec(t);
      if (m) return { label: p.label, match: m[0], index: m.index };
    } else {
      const h = p.scan(t);
      if (h) return { label: p.label, match: t.slice(h.index, h.index + h.length), index: h.index };
    }
  }
  return undefined;
}

/**
 * A single-line window of text, for evidence. Secrets are found in the whole
 * text first and the window is widened so that none is cut in half, then
 * redacted: a partial credential never reaches a report.
 */
export function excerpt(text: string, index: number, length: number, radius = 60): string {
  let start = Math.max(0, index - radius);
  let end = Math.min(text.length, index + length + radius);
  // Widen to whole secrets and whole tag-character runs: a run may hide a secret
  // that only becomes visible (and redactable) once decoded.
  const spans = [
    ...secretSpans(text),
    ...[...text.matchAll(TAG_RUN)].map((m) => ({ start: m.index, end: m.index + m[0].length })),
  ];
  for (const s of spans) {
    if (s.start < start && s.end > start) start = s.start;
    if (s.start < end && s.end > end) end = s.end;
  }
  // Redact the raw text, then again after decoding hidden text.
  const body = redactSecrets(reveal(redactSecrets(text.slice(start, end))))
    .replace(/\s+/g, " ")
    .trim();
  return `${start > 0 ? "..." : ""}${body}${end < text.length ? "..." : ""}`;
}

/** The start of a text, for evidence, with the same secret handling as excerpt. */
export function head(text: string, max = 240): string {
  return excerpt(text, 0, 0, max);
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
  { label: "HTML comment", scan: scanHtmlComment },
  { label: "whitespace padding", scan: scanWhitespaceWall },
  { label: "encoded blob", scan: scanEncodedBlob },
];

/** `<!-- ... -->`, or an unclosed `<!--` (which hides everything after it). One pass. */
export function scanHtmlComment(text: string) {
  const open = text.indexOf("<!--");
  if (open === -1) return undefined;
  const close = text.indexOf("-->", open + 4);
  return { index: open, length: (close === -1 ? text.length : close + 3) - open };
}

/** A whitespace run with 12 or more line breaks, or 120 or more spaces and tabs. One pass. */
export function scanWhitespaceWall(text: string) {
  let runStart = -1;
  let newlines = 0;
  let blanks = 0;
  for (let i = 0; i <= text.length; i++) {
    const ch = text[i];
    const ws =
      ch === " " || ch === "\t" || ch === "\n" || ch === "\r" || ch === "\f" || ch === "\v";
    if (ws) {
      if (runStart === -1) runStart = i;
      if (ch === "\n") newlines++;
      blanks = ch === " " || ch === "\t" ? blanks + 1 : 0;
      if (newlines >= 12 || blanks >= 120) return { index: runStart, length: i + 1 - runStart };
    } else {
      runStart = -1;
      newlines = 0;
      blanks = 0;
    }
  }
  return undefined;
}

/** 120 or more consecutive base64 characters. One pass. */
export function scanEncodedBlob(text: string) {
  let runStart = -1;
  for (let i = 0; i <= text.length; i++) {
    const c = text.charCodeAt(i);
    const b64 =
      (c >= 48 && c <= 57) || (c >= 65 && c <= 90) || (c >= 97 && c <= 122) || c === 43 || c === 47;
    if (b64) {
      if (runStart === -1) runStart = i;
    } else {
      if (runStart !== -1 && i - runStart >= 120) return { index: runStart, length: i - runStart };
      runStart = -1;
    }
  }
  return undefined;
}
