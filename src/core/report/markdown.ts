import { getRule } from "../rules/index.js";
import type { ScanReport } from "../scan.js";
import { SEVERITIES, type Finding, type ServerInventory } from "../types.js";
import { ruleDocUrl } from "./links.js";

/** A report meant for a pull request comment or $GITHUB_STEP_SUMMARY. */
export function toMarkdown(report: ScanReport): string {
  const out: string[] = [];
  const total = report.findings.length;
  out.push(`## mcp-guard report`, "");
  out.push(
    `Scanned ${report.servers.length} server${report.servers.length === 1 ? "" : "s"} with mcp-guard ${report.scanner.version} in ${report.durationMs} ms. ` +
      (total === 0 ? "No findings." : `${total} finding${total === 1 ? "" : "s"}.`),
    "",
  );

  out.push("| Severity | Count |", "| --- | ---: |");
  for (const s of SEVERITIES) out.push(`| ${s} | ${report.summary[s]} |`);
  out.push("");

  out.push(
    "### Servers",
    "",
    "| Server | Source | Tools | Resources | Prompts |",
    "| --- | --- | ---: | ---: | ---: |",
  );
  for (const s of report.servers) {
    out.push(
      `| ${cell(s.name)} | ${cell(sourceLabel(s))} | ${s.tools.length} | ${s.resources.length + s.resourceTemplates.length} | ${s.prompts.length} |`,
    );
  }
  out.push("");

  if (total > 0) {
    out.push("### Findings", "");
    out.push(
      "| Severity | Rule | Server | Location | Finding |",
      "| --- | --- | --- | --- | --- |",
    );
    for (const f of report.findings) {
      out.push(
        `| ${f.severity} | [${f.ruleId}](${ruleDocUrl(f.ruleId)}) | ${cell(f.location.server)} | ${cell(locationLabel(f))} | ${cell(f.message)} |`,
      );
    }
    out.push("");
    out.push("### Details", "");
    for (const f of report.findings) out.push(...details(f));
  }

  if (report.probe) {
    out.push("### Probe", "", "| Server | Target | Status | Reason |", "| --- | --- | --- | --- |");
    for (const p of report.probe) {
      out.push(
        `| ${cell(p.server)} | ${p.kind} ${cell(p.target)} | ${p.status} | ${cell(p.reason ?? "")} |`,
      );
    }
    out.push("");
  }
  return `${out.join("\n").trimEnd()}\n`;
}

function details(f: Finding): string[] {
  const rule = getRule(f.ruleId);
  const lines = [
    `<details><summary><strong>${f.severity.toUpperCase()}</strong> ${f.ruleId} ${escapeHtml(rule?.title ?? "")}: <code>${escapeHtml(locationLabel(f))}</code></summary>`,
    "",
    f.message,
    "",
  ];
  if (f.evidence)
    lines.push("Evidence:", "", "```text", f.evidence.replaceAll("```", "`\u200B``"), "```", "");
  if (f.judge)
    lines.push(
      `LLM judge (${f.judge.model}, informational only): **${f.judge.verdict}**. ${f.judge.reason}`,
      "",
    );
  if (rule) lines.push(`**Remediation.** ${rule.remediation}`, "");
  lines.push("</details>", "");
  return lines;
}

export function locationLabel(f: Finding): string {
  const l = f.location;
  return `${l.kind} ${l.name}${l.field ? ` (${l.field})` : ""}`;
}

export function sourceLabel(s: ServerInventory): string {
  const src = s.source;
  if (src.kind === "stdio") return `stdio: ${[src.command, ...src.args].join(" ")}`;
  if (src.kind === "http") return `http: ${src.url}`;
  return `json: ${src.path}`;
}

function cell(s: string): string {
  return s.replace(/\|/g, "\\|").replace(/\r?\n/g, " ");
}

function escapeHtml(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}
