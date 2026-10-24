import { readFile } from "node:fs/promises";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import {
  getDefaultEnvironment,
  StdioClientTransport,
} from "@modelcontextprotocol/sdk/client/stdio.js";
import {
  StreamableHTTPClientTransport,
  StreamableHTTPError,
} from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import { z } from "zod";

import { logger } from "../shared/logger.js";
import { VERSION } from "../shared/version.js";
import { checkHttpTransport } from "./httpChecks.js";
import type { ServerInventory, TargetSource, ToolInfo } from "./types.js";

export type Target =
  | { kind: "stdio"; command: string; args: string[]; env?: Record<string, string> }
  | { kind: "http"; url: string; headers?: Record<string, string> }
  | { kind: "json"; path: string };

/** A live connection kept open after discovery so --probe can reuse it. */
export interface Connection {
  inventory: ServerInventory;
  client?: Client;
  /** Canary injected into the server environment (stdio only). */
  canary?: string;
  close(): Promise<void>;
}

export class TargetError extends Error {}

export const CANARY_ENV = "MCP_GUARD_CANARY_TOKEN";

export function newClient(): Client {
  return new Client({ name: "mcp-guard", version: VERSION }, { capabilities: {} });
}

/** Reads every list the server advertises, following pagination cursors. */
export async function inventoryFromClient(
  client: Client,
  source: TargetSource,
  fallbackName: string,
): Promise<ServerInventory> {
  const caps = client.getServerCapabilities() ?? {};
  const info = client.getServerVersion();
  const inv: ServerInventory = {
    name: info?.name || fallbackName,
    source,
    ...(info ? { serverInfo: { name: info.name, version: info.version } } : {}),
    ...(client.getInstructions() ? { instructions: client.getInstructions() } : {}),
    tools: [],
    resources: [],
    resourceTemplates: [],
    prompts: [],
  };
  if (caps.tools) {
    // The SDK types schemas loosely; the rules read them as plain JSON Schema.
    inv.tools = (await paginate(
      (cursor) => client.listTools({ cursor }),
      (r) => r.tools,
    )) as ToolInfo[];
  }
  if (caps.resources) {
    inv.resources = await paginate(
      (cursor) => client.listResources({ cursor }),
      (r) => r.resources,
    );
    inv.resourceTemplates = await paginate(
      (cursor) => client.listResourceTemplates({ cursor }),
      (r) => r.resourceTemplates,
    ).catch(() => []); // optional method; some servers answer MethodNotFound
  }
  if (caps.prompts) {
    inv.prompts = await paginate(
      (cursor) => client.listPrompts({ cursor }),
      (r) => r.prompts,
    );
  }
  return inv;
}

const MAX_PAGES = 50;

async function paginate<R extends { nextCursor?: string }, T>(
  fetchPage: (cursor?: string) => Promise<R>,
  pick: (r: R) => T[],
): Promise<T[]> {
  const out: T[] = [];
  let cursor: string | undefined;
  for (let i = 0; i < MAX_PAGES; i++) {
    const page = await fetchPage(cursor);
    out.push(...pick(page));
    cursor = page.nextCursor;
    if (!cursor) break;
  }
  return out;
}

/** Opens a target. A JSON export can hold several servers, hence the array. */
export async function openTarget(
  target: Target,
  opts: { timeoutMs: number },
): Promise<Connection[]> {
  if (target.kind === "json") {
    return (await loadExports(target.path)).map((inventory) => ({
      inventory,
      close: async () => {},
    }));
  }
  return [await connect(target, opts)];
}

async function connect(
  target: Exclude<Target, { kind: "json" }>,
  opts: { timeoutMs: number },
): Promise<Connection> {
  const client = newClient();
  let transport: Transport;
  let source: TargetSource;
  let canary: string | undefined;
  let fallbackName: string;

  if (target.kind === "stdio") {
    canary = `mcpguard-canary-${crypto.randomUUID()}`;
    // The server gets the SDK's minimal environment (PATH, HOME...), not ours:
    // a scanned server should not see the CI runner's tokens.
    transport = new StdioClientTransport({
      command: target.command,
      args: target.args,
      env: { ...getDefaultEnvironment(), ...target.env, [CANARY_ENV]: canary },
      stderr: "pipe",
    });
    source = { kind: "stdio", command: target.command, args: target.args };
    fallbackName = [target.command, ...target.args].join(" ");
  } else {
    transport = new StreamableHTTPClientTransport(new URL(target.url), {
      requestInit: { headers: target.headers ?? {} },
    });
    source = { kind: "http", url: target.url };
    fallbackName = target.url;
  }

  try {
    await withTimeout(client.connect(transport), opts.timeoutMs, `connecting to ${fallbackName}`);
    const inventory = await withTimeout(
      inventoryFromClient(client, source, fallbackName),
      opts.timeoutMs,
      `listing ${fallbackName}`,
    );
    if (target.kind === "http") {
      inventory.transport = await checkHttpTransport(
        target.url,
        target.headers ?? {},
        opts.timeoutMs,
      );
    }
    logger.info({ server: inventory.name, tools: inventory.tools.length }, "inventory collected");
    return { inventory, client, ...(canary ? { canary } : {}), close: () => client.close() };
  } catch (err) {
    await client.close().catch(() => {});
    throw new TargetError(`Could not scan ${fallbackName}: ${explain(err)}`);
  }
}

function explain(err: unknown): string {
  if (err instanceof StreamableHTTPError && (err.code === 401 || err.code === 403)) {
    return `the server requires credentials (HTTP ${err.code}); pass them with -H "Authorization: Bearer <token>"`;
  }
  if (err instanceof StreamableHTTPError && err.code) return `HTTP ${err.code} ${err.message}`;
  return err instanceof Error ? err.message : String(err);
}

async function withTimeout<T>(p: Promise<T>, ms: number, what: string): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error(`timed out after ${ms} ms ${what}`)), ms);
  });
  try {
    return await Promise.race([p, timeout]);
  } finally {
    clearTimeout(timer);
  }
}

// ---------------------------------------------------------------- JSON export

const ToolSchema = z.looseObject({
  name: z.string(),
  title: z.string().optional(),
  description: z.string().optional(),
  inputSchema: z.record(z.string(), z.unknown()).optional(),
  outputSchema: z.record(z.string(), z.unknown()).optional(),
  annotations: z.record(z.string(), z.unknown()).optional(),
});

const ServerExport = z.object({
  name: z.string().optional(),
  instructions: z.string().optional(),
  tools: z.array(ToolSchema).default([]),
  resources: z
    .array(z.looseObject({ uri: z.string(), name: z.string(), description: z.string().optional() }))
    .default([]),
  resourceTemplates: z
    .array(
      z.looseObject({
        uriTemplate: z.string(),
        name: z.string(),
        description: z.string().optional(),
      }),
    )
    .default([]),
  prompts: z
    .array(
      z.looseObject({
        name: z.string(),
        description: z.string().optional(),
        arguments: z
          .array(
            z.object({
              name: z.string(),
              description: z.string().optional(),
              required: z.boolean().optional(),
            }),
          )
          .optional(),
      }),
    )
    .default([]),
});

/**
 * Accepts what people actually have on disk: a tools/list result
 * (`{ "tools": [...] }`), a bare array of tools, or several servers
 * (`{ "servers": [{ "name": ..., "tools": [...] }] }`) so cross-server rules
 * can run without starting anything.
 */
export async function loadExports(path: string): Promise<ServerInventory[]> {
  let raw: unknown;
  try {
    raw = JSON.parse(await readFile(path, "utf8"));
  } catch (err) {
    throw new TargetError(
      `Could not read ${path}: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  const fallback = path
    .split("/")
    .pop()!
    .replace(/\.json$/, "");
  const entries: unknown[] = Array.isArray(raw)
    ? [{ tools: raw }]
    : raw && typeof raw === "object" && Array.isArray((raw as { servers?: unknown }).servers)
      ? (raw as { servers: unknown[] }).servers
      : [raw];

  return entries.map((entry, i) => {
    const parsed = ServerExport.safeParse(entry);
    if (!parsed.success) {
      throw new TargetError(`${path}: not a tools/list export (${z.prettifyError(parsed.error)})`);
    }
    const s = parsed.data;
    return {
      name: s.name ?? (entries.length > 1 ? `${fallback}#${i + 1}` : fallback),
      source: { kind: "json", path },
      ...(s.instructions ? { instructions: s.instructions } : {}),
      tools: s.tools as ServerInventory["tools"],
      resources: s.resources as ServerInventory["resources"],
      resourceTemplates: s.resourceTemplates as ServerInventory["resourceTemplates"],
      prompts: s.prompts as ServerInventory["prompts"],
    };
  });
}

/** Splits a command line on whitespace, honouring single and double quotes. */
export function splitCommand(line: string): string[] {
  const out: string[] = [];
  let cur = "";
  let quote: '"' | "'" | null = null;
  let has = false;
  for (const ch of line) {
    if (quote) {
      if (ch === quote) quote = null;
      else cur += ch;
    } else if (ch === '"' || ch === "'") {
      quote = ch;
      has = true;
    } else if (/\s/.test(ch)) {
      if (has || cur) out.push(cur);
      cur = "";
      has = false;
    } else {
      cur += ch;
    }
  }
  if (quote) throw new TargetError(`Unterminated quote in command: ${line}`);
  if (has || cur) out.push(cur);
  return out;
}
