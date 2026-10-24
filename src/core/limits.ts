import type { ServerInventory } from "./types.js";

/**
 * Bounds on what one server can make the scanner hold and read. A hostile
 * server controls every list length and string size it returns, so nothing is
 * analysed unbounded; whatever is cut is reported (MCPG-090) rather than
 * silently dropped.
 */
export interface Limits {
  /** Items per list (tools, resources, resource templates, prompts). */
  maxItems: number;
  /** Characters per string field, tool result or resource body. */
  maxFieldChars: number;
  /** Serialised size of one server's inventory. */
  maxServerChars: number;
  /** Wall-clock budget per server: discovery, transport checks and probe. */
  serverTimeoutMs: number;
}

export const DEFAULT_LIMITS: Limits = {
  maxItems: 1000,
  maxFieldChars: 1024 * 1024,
  maxServerChars: 10 * 1024 * 1024,
  serverTimeoutMs: 120_000,
};

/** Cuts a string to the limit; returns the original when it fits. */
export function capText(text: string, max: number): { text: string; truncated: boolean } {
  return text.length > max
    ? { text: text.slice(0, max), truncated: true }
    : { text, truncated: false };
}

/**
 * Applies the field and server limits to an inventory in place and records
 * every cut in `inventory.truncated`.
 */
export function enforceLimits(inv: ServerInventory, limits: Limits): ServerInventory {
  const notes = (inv.truncated ??= []);
  let longFields = 0;
  const cap = (value: unknown): unknown => {
    if (typeof value === "string") {
      if (value.length <= limits.maxFieldChars) return value;
      longFields++;
      return value.slice(0, limits.maxFieldChars);
    }
    if (Array.isArray(value)) return value.map(cap);
    if (value && typeof value === "object") {
      return Object.fromEntries(Object.entries(value).map(([k, v]) => [cap(k) as string, cap(v)]));
    }
    return value;
  };
  inv.tools = inv.tools.map((t) => cap(t) as typeof t);
  inv.resources = inv.resources.map((r) => cap(r) as typeof r);
  inv.resourceTemplates = inv.resourceTemplates.map((r) => cap(r) as typeof r);
  inv.prompts = inv.prompts.map((p) => cap(p) as typeof p);
  if (inv.instructions) inv.instructions = cap(inv.instructions) as string;
  if (longFields)
    notes.push(`${longFields} string field(s) cut to ${limits.maxFieldChars} characters`);

  const lists = ["prompts", "resourceTemplates", "resources", "tools"] as const;
  // Leave room for the note added below.
  const budget = Math.max(0, limits.maxServerChars - 256);
  let size = JSON.stringify(inv).length;
  let dropped = 0;
  for (const key of lists) {
    while (size > budget && inv[key].length > 0) {
      const item = (inv[key] as unknown[]).pop();
      size -= JSON.stringify(item).length + 1;
      dropped++;
    }
  }
  if (dropped)
    notes.push(
      `${dropped} item(s) dropped to keep the inventory under ${limits.maxServerChars} characters`,
    );
  if (notes.length === 0) delete inv.truncated;
  return inv;
}
