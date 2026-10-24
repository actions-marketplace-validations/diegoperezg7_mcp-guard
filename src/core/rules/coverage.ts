import type { Finding } from "../types.js";
import { defineRule } from "./types.js";

export const scanTruncated = defineRule(
  {
    id: "MCPG-090",
    name: "ScanTruncated",
    title: "Part of the server was not analysed (input limit reached)",
    category: "coverage",
    severity: "info",
    mode: "static",
    description:
      "The server returned more than the scanner's input limits allow (items per list, characters per field or result, total inventory size, or the per-server time budget), so part of it was cut before analysis. Findings for the rest are still valid, but the cut part was not checked. Oversized metadata is unusual in itself and worth a look.",
    remediation:
      "Check why the server exposes that much. If it is legitimate, raise the limits with --max-items, --max-field-kb, --max-server-mb or --server-timeout and scan again.",
    bad: `tools/list -> 25,000 tools, or a 40 MB description`,
    good: `tools/list -> 12 tools with descriptions of a few hundred characters`,
    references: [
      {
        title: "OWASP Top 10 for LLM Applications 2025: LLM10 Unbounded Consumption",
        url: "https://genai.owasp.org/llmrisk/llm102025-unbounded-consumption/",
      },
    ],
  },
  (ctx, emit) => {
    for (const s of ctx.servers)
      for (const note of s.truncated ?? []) emit(truncation(s.name, note));
  },
);

export function truncation(server: string, note: string): Omit<Finding, "ruleId" | "severity"> {
  return {
    message: `Not fully analysed: ${note}.`,
    location: { server, kind: "server", name: server },
  };
}
