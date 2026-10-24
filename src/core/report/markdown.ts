import { getRule } from "../rules/index.js";
import type { ScanReport } from "../scan.js";
import { printable } from "../text.js";
import { SEVERITIES, type Finding, type ServerInventory } from "../types.js";
import { ruleDocUrl } from "./links.js";

/**
 * A report meant for a pull request comment or $GITHUB_STEP_SUMMARY.
 *
 * Every string that comes from a scanned server (names, URIs, messages that
 * quote them, evidence, the judge's reason) is untrusted: it goes through
 * mdText or mdCode, so it cannot add images, links, HTML or table cells to
 * the page that renders the report.
 */
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
      `| ${mdCode(s.name)} | ${mdCode(sourceLabel(s))} | ${s.tools.length} | ${s.resources.length + s.resourceTemplates.length} | ${s.prompts.length} |`,
    );
  }
  out.push("");

  if (total > 0) {
    out.push("### Findings", "");
    out.push("| Severity | Rule | Location | Finding |", "| --- | --- | --- | --- |");
    for (const f of report.findings) {
      out.push(
        `| ${f.severity} | [${f.ruleId}](${ruleDocUrl(f.ruleId)}) | ${mdCode(`${f.location.server} / ${locationLabel(f)}`)} | ${mdText(f.message)} |`,
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
        `| ${mdCode(p.server)} | ${p.kind} ${mdCode(p.target)} | ${p.status} | ${mdText(p.reason ?? "")} |`,
      );
    }
    out.push("");
  }
  return `${out.join("\n").trimEnd()}\n`;
}

function details(f: Finding): string[] {
  const rule = getRule(f.ruleId);
  const lines = [
    // Inside an HTML block Markdown is not parsed, so HTML escaping is the right defence here.
    `<details><summary><strong>${f.severity.toUpperCase()}</strong> ${f.ruleId} ${escapeHtml(rule?.title ?? "")}: <code>${escapeHtml(printable(locationLabel(f)))}</code></summary>`,
    "",
    mdText(f.message),
    "",
  ];
  if (f.evidence) lines.push("Evidence:", "", ...fenced(f.evidence), "");
  if (f.judge) {
    lines.push(
      `LLM judge (${mdCode(f.judge.model)}, informational only): **${f.judge.verdict}**. ${mdText(f.judge.reason)}`,
      "",
    );
  }
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

/**
 * Untrusted text as inert Markdown: control characters made visible, every
 * Markdown and HTML metacharacter backslash-escaped, and URLs, www. hosts and
 * email addresses defanged (hxxps://, www[.], user[@]host) so GitHub's
 * autolinker cannot turn them into links or tracking images.
 */
export function mdText(s: string): string {
  return defang(printable(s)).replace(/[\\`*_[\]()<>!#|~{}+=&]/g, (ch) =>
    ch === "&" ? "&amp;" : `\\${ch}`,
  );
}

/** Untrusted text as an inline code span, where Markdown, HTML and autolinks are not interpreted. */
export function mdCode(s: string): string {
  const text = defang(printable(s)).replace(/\|/g, "\\|");
  const longest = Math.max(0, ...(text.match(/`+/g) ?? []).map((run) => run.length));
  const fence = "`".repeat(longest + 1);
  const pad = text.startsWith("`") || text.endsWith("`") ? " " : "";
  return `${fence}${pad}${text}${pad}${fence}`;
}

/** A fenced block longer than any backtick run inside, so the content cannot close it. */
function fenced(s: string): string[] {
  const text = defang(printable(s));
  const longest = Math.max(2, ...(text.match(/`+/g) ?? []).map((run) => run.length));
  const fence = "`".repeat(longest + 1);
  return [`${fence}text`, text, fence];
}

/** HTML-escapes and also encodes Markdown punctuation and defangs URLs, for text inside raw HTML. */
function escapeHtml(s: string): string {
  return defang(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/[[\]()!*_`\\|]/g, (ch) => `&#${ch.charCodeAt(0)};`);
}

/** hxxps://, www[.], user[@]host: still readable, never a link. */
function defang(s: string): string {
  return s
    .replace(/\b(h)tt(ps?):\/\//gi, "$1xx$2://")
    .replace(/\b(ftp|file|data|javascript):/gi, "$1[:]")
    .replace(/\bwww\./gi, "www[.]")
    .replace(/@/g, "[@]");
}
