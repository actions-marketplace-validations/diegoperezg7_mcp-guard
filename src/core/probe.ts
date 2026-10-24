import type { Client } from "@modelcontextprotocol/sdk/client/index.js";

import { logger } from "../shared/logger.js";
import { CANARY_ENV } from "./discover.js";
import { environmentLeak, injectionInOutput, secretInOutput } from "./rules/runtime.js";
import { findSecrets } from "./secrets.js";
import {
  decodeHidden,
  EXFILTRATION,
  excerpt,
  findInvisible,
  firstHit,
  HIDDEN_CONTENT,
  MODEL_DIRECTED,
  reveal,
} from "./text.js";
import type { Finding, FindingLocation, JsonSchema, ServerInventory, ToolInfo } from "./types.js";

export interface ProbeOptions {
  /** Also call tools that are not annotated read-only. Off by default. */
  allowUnsafe: boolean;
  timeoutMs: number;
}

export interface ProbeRecord {
  server: string;
  target: string;
  kind: "tool" | "resource";
  status: "called" | "skipped" | "error";
  reason?: string;
}

export interface ProbeResult {
  findings: Finding[];
  records: ProbeRecord[];
}

/** Marker placed in every argument the probe invents, so its traffic is recognisable in server logs. */
export const CANARY_ARG = "mcp-guard-canary";

/**
 * Which tools the probe may call. Only tools that declare readOnlyHint: true,
 * and are not also flagged destructive, are called by default. --allow-unsafe
 * widens that to unannotated tools; a tool that declares destructiveHint: true
 * and is not read-only is never called.
 */
export function probeDecision(
  tool: ToolInfo,
  allowUnsafe: boolean,
): { call: boolean; reason: string } {
  const a = tool.annotations ?? {};
  if (a.readOnlyHint === true && a.destructiveHint !== true)
    return { call: true, reason: "read-only" };
  if (a.destructiveHint === true) return { call: false, reason: "declares destructiveHint: true" };
  if (allowUnsafe) return { call: true, reason: "--allow-unsafe" };
  return {
    call: false,
    reason:
      a.readOnlyHint === false
        ? "not read-only (needs --allow-unsafe)"
        : "not annotated (needs --allow-unsafe)",
  };
}

export async function probeServer(
  client: Client,
  server: ServerInventory,
  opts: ProbeOptions & { canary?: string },
): Promise<ProbeResult> {
  const findings: Finding[] = [];
  const records: ProbeRecord[] = [];

  for (const r of server.resources) {
    const location: FindingLocation = {
      server: server.name,
      kind: "resource",
      name: r.uri,
      field: "contents",
    };
    try {
      const res = await client.readResource({ uri: r.uri }, { timeout: opts.timeoutMs });
      const text = res.contents
        .map((c) => ("text" in c && typeof c.text === "string" ? c.text : ""))
        .join("\n");
      findings.push(...inspectOutput(text, location, opts.canary));
      records.push({ server: server.name, target: r.uri, kind: "resource", status: "called" });
    } catch (err) {
      records.push({
        server: server.name,
        target: r.uri,
        kind: "resource",
        status: "error",
        reason: message(err),
      });
    }
  }

  for (const tool of server.tools) {
    const decision = probeDecision(tool, opts.allowUnsafe);
    if (!decision.call) {
      records.push({
        server: server.name,
        target: tool.name,
        kind: "tool",
        status: "skipped",
        reason: decision.reason,
      });
      continue;
    }
    const location: FindingLocation = {
      server: server.name,
      kind: "tool",
      name: tool.name,
      field: "result",
    };
    try {
      const args = sampleArguments(tool.inputSchema);
      logger.info({ tool: tool.name, args }, "probing tool");
      const res = await client.callTool({ name: tool.name, arguments: args }, undefined, {
        timeout: opts.timeoutMs,
      });
      findings.push(...inspectOutput(resultText(res), location, opts.canary));
      records.push({
        server: server.name,
        target: tool.name,
        kind: "tool",
        status: "called",
        reason: decision.reason,
      });
    } catch (err) {
      records.push({
        server: server.name,
        target: tool.name,
        kind: "tool",
        status: "error",
        reason: message(err),
      });
    }
  }
  return { findings, records };
}

function resultText(res: unknown): string {
  const r = res as { content?: unknown[]; structuredContent?: unknown };
  const parts: string[] = [];
  for (const c of r.content ?? []) {
    const item = c as { type?: string; text?: unknown; resource?: { text?: unknown } };
    if (typeof item.text === "string") parts.push(item.text);
    if (typeof item.resource?.text === "string") parts.push(item.resource.text);
  }
  if (r.structuredContent !== undefined) parts.push(JSON.stringify(r.structuredContent));
  return parts.join("\n");
}

/** The same detectors the static rules use, applied to what the server returned. */
export function inspectOutput(raw: string, location: FindingLocation, canary?: string): Finding[] {
  const out: Finding[] = [];
  const where = `${location.kind} "${location.name}"`;

  if (canary && raw.includes(canary)) {
    out.push({
      ruleId: environmentLeak.id,
      severity: environmentLeak.severity,
      message: `The environment canary came back in the output of ${where}: the server returns its own environment.`,
      location,
      // Only the fact, not the surrounding text: the rest of that output is the server's real environment.
      evidence: `value of ${CANARY_ENV} found in the result`,
    });
  }

  const text = canary ? raw.replaceAll(canary, "<canary>") : raw;
  const injection = firstHit(decodeHidden(text), [
    ...MODEL_DIRECTED,
    ...EXFILTRATION,
    ...HIDDEN_CONTENT,
  ]);
  const invisible = findInvisible(text);
  if (injection || invisible) {
    const what = injection
      ? injection.label
      : `${invisible!.count} invisible character(s)${invisible!.smuggled ? ` hiding "${invisible!.smuggled}"` : ""}`;
    out.push({
      ruleId: injectionInOutput.id,
      severity: injectionInOutput.severity,
      message: `Output of ${where} contains text aimed at the model: ${what}.`,
      location,
      evidence: injection
        ? excerpt(decodeHidden(text), injection.index, injection.match.length)
        : reveal(text).slice(0, 240),
    });
  }

  for (const hit of findSecrets(text)) {
    out.push({
      ruleId: secretInOutput.id,
      severity: secretInOutput.severity,
      message: `Output of ${where} contains a ${hit.kind}.`,
      location,
      evidence: hit.redacted,
    });
  }
  return out;
}

/**
 * Minimal valid arguments: required properties only, enums and consts
 * respected, strings set to the canary marker. Nothing in them is an exploit;
 * they exist to make a read-only tool return something to inspect.
 */
export function sampleArguments(schema: JsonSchema | undefined): Record<string, unknown> {
  const v = sampleValue(schema ?? { type: "object" }, 0);
  return v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : {};
}

function sampleValue(s: JsonSchema, depth: number): unknown {
  if (s.const !== undefined) return s.const;
  if (Array.isArray(s.enum) && s.enum.length) return s.enum[0];
  if (s.default !== undefined) return s.default;
  if (Array.isArray(s.examples) && s.examples.length) return s.examples[0];
  const variant = s.anyOf?.[0] ?? s.oneOf?.[0];
  if (variant) return sampleValue(variant, depth);
  const type = Array.isArray(s.type) ? s.type.find((t) => t !== "null") : s.type;
  switch (type ?? (s.properties ? "object" : "string")) {
    case "object": {
      const out: Record<string, unknown> = {};
      if (depth > 4) return out;
      for (const key of s.required ?? []) {
        const sub = s.properties?.[key];
        out[key] = sub ? sampleValue(sub, depth + 1) : CANARY_ARG;
      }
      return out;
    }
    case "array": {
      const item = Array.isArray(s.items) ? s.items[0] : s.items;
      const min = typeof s.minItems === "number" ? s.minItems : 0;
      return item && min > 0 ? [sampleValue(item, depth + 1)] : [];
    }
    case "integer":
    case "number":
      return typeof s.minimum === "number" ? s.minimum : 1;
    case "boolean":
      return false;
    case "null":
      return null;
    default:
      return sampleString(s);
  }
}

function sampleString(s: JsonSchema): string {
  if (s.format === "uri" || s.format === "url") return `https://example.invalid/${CANARY_ARG}`;
  if (s.format === "email") return `${CANARY_ARG}@example.invalid`;
  if (s.format === "date") return "2026-01-01";
  if (s.format === "date-time") return "2026-01-01T00:00:00Z";
  return CANARY_ARG;
}

function message(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
