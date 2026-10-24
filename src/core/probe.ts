import type { Client } from "@modelcontextprotocol/sdk/client/index.js";

import { logger } from "../shared/logger.js";
import { CANARY_ENV } from "./discover.js";
import { capText, DEFAULT_LIMITS } from "./limits.js";
import { scanTruncated, truncation } from "./rules/coverage.js";
import { destructiveVerb, writeVerb } from "./rules/permissions.js";
import { hiddenText } from "./rules/poisoning.js";
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
  head,
} from "./text.js";
import type { Finding, FindingLocation, JsonSchema, ServerInventory, ToolInfo } from "./types.js";

export interface ProbeOptions {
  /** Also call tools that are not annotated read-only, or whose name suggests a write. Off by default. */
  allowUnsafe: boolean;
  timeoutMs: number;
  /** Cap on the characters inspected per result or resource. */
  maxFieldChars?: number;
  /** Epoch ms after which no further call is made to this server. */
  deadline?: number;
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
 * Which tools the probe may call. By default only tools that declare
 * readOnlyHint: true, are not also flagged destructive, and whose name does
 * not contradict the claim (MCPG-020/021: delete_..., send_...).
 * --allow-unsafe widens that to unannotated tools and to suspicious names; a
 * tool that declares destructiveHint: true and is not read-only is never called.
 */
export function probeDecision(
  tool: ToolInfo,
  allowUnsafe: boolean,
): { call: boolean; reason: string } {
  const a = tool.annotations ?? {};
  if (a.destructiveHint === true && a.readOnlyHint !== true) {
    return { call: false, reason: "declares destructiveHint: true" };
  }
  if (a.destructiveHint === true) {
    return { call: false, reason: "declares both readOnlyHint and destructiveHint" };
  }
  const verb = destructiveVerb(tool) ?? writeVerb(tool);
  if (verb && !allowUnsafe) {
    return { call: false, reason: `name suggests side effects ("${verb}"), needs --allow-unsafe` };
  }
  if (a.readOnlyHint === true) return { call: true, reason: verb ? "--allow-unsafe" : "read-only" };
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
  const maxChars = opts.maxFieldChars ?? DEFAULT_LIMITS.maxFieldChars;
  const record = (
    kind: ProbeRecord["kind"],
    target: string,
    status: ProbeRecord["status"],
    reason?: string,
  ) => records.push({ server: server.name, target, kind, status, ...(reason ? { reason } : {}) });
  /** Per-call timeout within what is left of the server's budget; undefined when it is spent. */
  const budget = (): number | undefined => {
    if (opts.deadline === undefined) return opts.timeoutMs;
    const left = opts.deadline - Date.now();
    return left > 0 ? Math.min(opts.timeoutMs, left) : undefined;
  };
  const inspect = (raw: string, location: FindingLocation) => {
    const { text, truncated } = capText(raw, maxChars);
    if (truncated) {
      findings.push({
        ruleId: scanTruncated.id,
        severity: scanTruncated.severity,
        ...truncation(
          server.name,
          `${location.kind} "${location.name}" returned more than ${maxChars} characters; only the start was inspected`,
        ),
      });
    }
    findings.push(...inspectOutput(text, location, opts.canary));
  };

  for (const r of server.resources) {
    const timeout = budget();
    if (timeout === undefined) {
      record("resource", r.uri, "skipped", "server time budget exhausted");
      continue;
    }
    try {
      const res = await client.readResource({ uri: r.uri }, { timeout });
      const text = res.contents
        .map((c) => ("text" in c && typeof c.text === "string" ? c.text : ""))
        .join("\n");
      inspect(text, { server: server.name, kind: "resource", name: r.uri, field: "contents" });
      record("resource", r.uri, "called");
    } catch (err) {
      record("resource", r.uri, "error", message(err));
    }
  }

  for (const tool of server.tools) {
    const decision = probeDecision(tool, opts.allowUnsafe);
    if (!decision.call) {
      record("tool", tool.name, "skipped", decision.reason);
      continue;
    }
    const timeout = budget();
    if (timeout === undefined) {
      record("tool", tool.name, "skipped", "server time budget exhausted");
      continue;
    }
    try {
      const args = sampleArguments(tool.inputSchema);
      logger.info({ tool: tool.name, args }, "probing tool");
      const res = await client.callTool({ name: tool.name, arguments: args }, undefined, {
        timeout,
      });
      inspect(resultText(res), {
        server: server.name,
        kind: "tool",
        name: tool.name,
        field: "result",
      });
      record("tool", tool.name, "called", decision.reason);
    } catch (err) {
      record("tool", tool.name, "error", message(err));
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
      : `${invisible!.count} invisible character(s)${invisible!.smuggled ? ` hiding "${hiddenText(invisible!.smuggled)}"` : ""}`;
    out.push({
      ruleId: injectionInOutput.id,
      severity: injectionInOutput.severity,
      message: `Output of ${where} contains text aimed at the model: ${what}.`,
      location,
      evidence: injection
        ? excerpt(decodeHidden(text), injection.index, injection.match.length)
        : head(text),
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
 * Minimal valid arguments built only from types and bounds: required
 * properties, strings set to the canary marker. The server's own default and
 * examples values are never sent, and an enum or const value is used only
 * when it is a number, a boolean or a short plain identifier (a city, a unit);
 * otherwise the canary goes in and the call may simply be rejected.
 */
export function sampleArguments(schema: JsonSchema | undefined): Record<string, unknown> {
  const v = sampleValue(schema ?? { type: "object" }, 0);
  return v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : {};
}

function inertConstant(v: unknown): boolean {
  if (typeof v === "boolean") return true;
  if (typeof v === "number") return Number.isFinite(v) && Math.abs(v) <= 1e6;
  return typeof v === "string" && /^[A-Za-z0-9][A-Za-z0-9 _.-]{0,63}$/.test(v);
}

function sampleValue(s: JsonSchema, depth: number): unknown {
  if (s.const !== undefined) return inertConstant(s.const) ? s.const : CANARY_ARG;
  if (Array.isArray(s.enum) && s.enum.length) return s.enum.find(inertConstant) ?? CANARY_ARG;
  const variant = s.anyOf?.[0] ?? s.oneOf?.[0];
  if (variant) return sampleValue(variant, depth);
  const type = Array.isArray(s.type) ? s.type.find((t) => t !== "null") : s.type;
  switch (type ?? (s.properties ? "object" : "string")) {
    case "object": {
      const out: Record<string, unknown> = {};
      if (depth > 4) return out;
      for (const key of (s.required ?? []).slice(0, 50)) {
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
      return inertConstant(s.minimum) ? s.minimum : 1;
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
