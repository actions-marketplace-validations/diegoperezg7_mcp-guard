import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { relative, resolve } from "node:path";

import { RULES } from "../rules/index.js";
import type { ScanReport } from "../scan.js";
import type { Finding, ServerInventory, Severity } from "../types.js";
import { ruleDocUrl } from "./links.js";

/** GitHub code scanning maps security-severity to its own labels: >= 9 critical, >= 7 high, >= 4 medium. */
const SECURITY_SEVERITY: Record<Severity, string> = {
  critical: "9.5",
  high: "8.0",
  medium: "5.5",
  low: "3.0",
  info: "0.0",
};

const LEVEL: Record<Severity, "error" | "warning" | "note"> = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "note",
  info: "note",
};

/**
 * SARIF 2.1.0 as GitHub code scanning reads it. Findings are not lines of
 * code, so each result points at the file that defines the target (the JSON
 * export, or the script a stdio command runs) and carries the tool or
 * resource as a logical location.
 */
export function toSarif(report: ScanReport, cwd = process.cwd()): object {
  const servers = new Map(report.servers.map((s) => [s.name, s]));
  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "mcp-guard",
            semanticVersion: report.scanner.version,
            informationUri: "https://github.com/diegoperezg7/mcp-guard",
            rules: RULES.map((r) => ({
              id: r.id,
              name: r.name,
              shortDescription: { text: r.title },
              fullDescription: { text: r.description },
              helpUri: ruleDocUrl(r.id),
              help: {
                text: `${r.description}\n\nRemediation: ${r.remediation}`,
                markdown: [
                  r.description,
                  `**Remediation.** ${r.remediation}`,
                  `Bad:\n\n\`\`\`\n${r.bad}\n\`\`\``,
                  `Good:\n\n\`\`\`\n${r.good}\n\`\`\``,
                  r.references.map((ref) => `- [${ref.title}](${ref.url})`).join("\n"),
                ].join("\n\n"),
              },
              defaultConfiguration: { level: LEVEL[r.severity] },
              properties: {
                "security-severity": SECURITY_SEVERITY[r.severity],
                precision: r.severity === "low" ? "medium" : "high",
                tags: ["security", "mcp", r.category],
              },
            })),
          },
        },
        automationDetails: { id: "mcp-guard/" },
        results: report.findings.map((f) => result(f, servers.get(f.location.server), cwd)),
      },
    ],
  };
}

function result(f: Finding, server: ServerInventory | undefined, cwd: string): object {
  const l = f.location;
  const where = `[${l.server}] ${l.kind} "${l.name}"${l.field ? ` (${l.field})` : ""}`;
  const text = [
    `${where}: ${f.message}`,
    f.evidence ? `Evidence: ${f.evidence}` : "",
    f.judge
      ? `LLM judge (${f.judge.model}, informational): ${f.judge.verdict}. ${f.judge.reason}`
      : "",
  ]
    .filter(Boolean)
    .join("\n");
  return {
    ruleId: f.ruleId,
    ruleIndex: RULES.findIndex((r) => r.id === f.ruleId),
    level: LEVEL[f.severity],
    message: { text },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: artifactFor(server, cwd) },
          region: { startLine: 1 },
        },
        logicalLocations: [
          {
            name: l.name,
            fullyQualifiedName: `${l.server}/${l.kind}/${l.name}${l.field ? `#${l.field}` : ""}`,
            kind:
              l.kind === "tool"
                ? "function"
                : l.kind === "server" || l.kind === "transport"
                  ? "module"
                  : "resource",
          },
        ],
      },
    ],
    partialFingerprints: {
      "mcpGuardFinding/v1": createHash("sha256")
        .update([f.ruleId, l.server, l.kind, l.name, l.field ?? ""].join("\u0000"))
        .digest("hex")
        .slice(0, 32),
    },
    properties: { severity: f.severity, server: l.server, ...(f.judge ? { judge: f.judge } : {}) },
  };
}

/** The repository file that best represents the target, so GitHub can attach the alert to something. */
function artifactFor(server: ServerInventory | undefined, cwd: string): string {
  const src = server?.source;
  if (src?.kind === "json") return toUri(src.path, cwd);
  if (src?.kind === "stdio") {
    const script = src.args.find(
      (a) => !a.startsWith("-") && /\.(m?[jt]s|py|cjs)$/.test(a) && existsSync(resolve(cwd, a)),
    );
    if (script) return toUri(script, cwd);
  }
  return "mcp-guard.targets";
}

function toUri(path: string, cwd: string): string {
  const rel = relative(cwd, resolve(cwd, path));
  return rel.startsWith("..") ? resolve(cwd, path) : rel.split("\\").join("/");
}
