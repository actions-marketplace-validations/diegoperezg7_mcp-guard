import type { ScanReport } from "../scan.js";
import { breaches } from "../scan.js";
import { printable } from "../text.js";
import { SEVERITIES, severityRank, type Finding, type Severity } from "../types.js";

export interface TableOptions {
  /** ANSI colours. Off for NO_COLOR and when stdout is not a terminal. */
  color: boolean;
  width: number;
  /** Box-drawing and block characters; plain ASCII otherwise (logs, files, old terminals). */
  unicode?: boolean;
  /** Print the evidence line under each finding. */
  verbose?: boolean;
  failOn?: Severity | "none";
}

const SEVERITY_COLOR: Record<Severity, string> = {
  critical: "\x1b[1;30;41m",
  high: "\x1b[1;31m",
  medium: "\x1b[33m",
  low: "\x1b[34m",
  info: "\x1b[2m",
};

/** ASCII markers, readable with or without colour. */
const ICON: Record<Severity, string> = {
  critical: "[!!]",
  high: "[! ]",
  medium: "[~ ]",
  low: "[- ]",
  info: "[i ]",
};

/**
 * Terminal report: a boxed header with the verdict and severity counts, then
 * findings grouped by server and by tool or resource, then a summary.
 * Every server-supplied string goes through printable(), so escape sequences
 * and bidi controls from a server are shown, not executed.
 */
export function toTable(report: ScanReport, opts: TableOptions): string {
  const paint = (code: string, s: string) => (opts.color ? `${code}${s}\x1b[0m` : s);
  const dim = (s: string) => paint("\x1b[2m", s);
  const bold = (s: string) => paint("\x1b[1m", s);
  const sev = (s: Severity, text: string) => paint(SEVERITY_COLOR[s], text);
  const u = !!opts.unicode;
  const width = Math.max(60, Math.min(opts.width, 120));
  const failOn = opts.failOn ?? "high";
  const failed = breaches(report.findings, failOn);
  const out: string[] = [];

  // ---------------------------------------------------------------- header box
  const counts = report.servers.reduce(
    (a, s) => ({
      tools: a.tools + s.tools.length,
      resources: a.resources + s.resources.length + s.resourceTemplates.length,
      prompts: a.prompts + s.prompts.length,
    }),
    { tools: 0, resources: 0, prompts: 0 },
  );
  const verdict =
    failOn === "none"
      ? "REPORT ONLY"
      : failed
        ? `FAIL  (fail-on ${failOn})`
        : `PASS  (fail-on ${failOn})`;
  const verdictPainted =
    failOn === "none" ? bold(verdict) : paint(failed ? "\x1b[1;31m" : "\x1b[1;32m", verdict);
  const inner = width - 4;
  const box = u
    ? { tl: "\u256D", tr: "\u256E", bl: "\u2570", br: "\u256F", h: "\u2500", v: "\u2502" }
    : { tl: "+", tr: "+", bl: "+", br: "+", h: "-", v: "|" };
  const row = (left: string, leftLen: number, right = "", rightLen = 0) => {
    const gap = inner - leftLen - rightLen;
    return `${dim(box.v)} ${left}${" ".repeat(Math.max(right ? 1 : 0, gap))}${right} ${dim(box.v)}`;
  };

  const title = `mcp-guard ${report.scanner.version}`;
  const stats = `${report.servers.length} server(s)  ${counts.tools} tools  ${counts.resources} resources  ${counts.prompts} prompts  ${report.durationMs} ms`;
  const chipText = SEVERITIES.map((s) => ` ${report.summary[s]} ${s.toUpperCase()} `);
  const chips = SEVERITIES.map((s, i) =>
    report.summary[s] ? sev(s, chipText[i]!) : dim(chipText[i]!),
  ).join(" ");
  const chipsLen = chipText.join(" ").length;

  out.push(dim(`${box.tl}${box.h.repeat(width - 2)}${box.tr}`));
  out.push(row(bold(title), title.length, verdictPainted, verdict.length));
  out.push(row(dim(stats), stats.length));
  out.push(row("", 0));
  out.push(row(chips, chipsLen));
  const total = report.findings.length;
  if (total > 0) {
    const barWidth = inner;
    let bar = "";
    let used = 0;
    SEVERITIES.forEach((s, i) => {
      const n = report.summary[s];
      if (!n) return;
      const last = SEVERITIES.slice(i + 1).every((x) => !report.summary[x]);
      const len = last ? barWidth - used : Math.max(1, Math.round((barWidth * n) / total));
      used += len;
      bar += paint(SEVERITY_COLOR[s].replace("1;30;41", "31"), (u ? "\u2588" : "#").repeat(len));
    });
    out.push(row(bar, barWidth));
  }
  out.push(dim(`${box.bl}${box.h.repeat(width - 2)}${box.br}`));
  out.push("");

  // ---------------------------------------------------------------- findings by server and item
  if (total === 0) {
    out.push(paint("\x1b[32m", "  No findings. Every rule passed for every server."), "");
  }
  const indentWidth = 29;
  const textWidth = width - indentWidth;
  for (const server of report.servers) {
    const mine = report.findings.filter((f) => f.location.server === server.name);
    const sc = SEVERITIES.filter((s) => mine.some((f) => f.severity === s))
      .map((s) => sev(s, `${mine.filter((f) => f.severity === s).length} ${s}`))
      .join(dim(", "));
    const headLeft = `${u ? "\u25A0" : "=="} ${printable(server.name)}`;
    const meta = `${server.source.kind}, ${server.tools.length} tools`;
    out.push(`${bold(headLeft)}  ${dim(meta)}  ${mine.length ? sc : paint("\x1b[32m", "clean")}`);
    if (mine.length === 0) {
      out.push("");
      continue;
    }

    const items = new Map<string, Finding[]>();
    for (const f of mine) {
      const key = `${f.location.kind} ${printable(f.location.name)}`;
      items.set(key, [...(items.get(key) ?? []), f]);
    }
    const ordered = [...items.entries()].sort(
      (a, b) => worst(b[1]) - worst(a[1]) || a[0].localeCompare(b[0]),
    );
    for (const [item, findings] of ordered) {
      out.push(`  ${dim(u ? "\u2514" : "`-")} ${item}`);
      for (const f of findings) {
        const lines = wrap(
          printable(f.message) + (f.judge ? ` [judge: ${f.judge.verdict}]` : ""),
          textWidth,
        );
        const label = f.severity.toUpperCase().padEnd(8);
        out.push(
          `     ${sev(f.severity, ICON[f.severity])} ${sev(f.severity, label)} ${dim(f.ruleId)}  ${lines[0]}`,
        );
        const indent = " ".repeat(indentWidth);
        for (const line of lines.slice(1)) out.push(`${indent}${line}`);
        if (f.location.field) out.push(`${indent}${dim(`at ${printable(f.location.field)}`)}`);
        if (opts.verbose && f.evidence) {
          for (const line of wrap(`evidence: ${printable(f.evidence)}`, textWidth)) {
            out.push(`${indent}${dim(line)}`);
          }
        }
      }
    }
    out.push("");
  }

  // ---------------------------------------------------------------- summary
  const gating =
    failOn === "none"
      ? 0
      : report.findings.filter((f) => severityRank(f.severity) >= severityRank(failOn)).length;
  out.push(bold("Summary"));
  out.push(
    `  ${total} finding(s) in ${report.servers.length} server(s)` +
      (failOn === "none" ? ", gate disabled." : `, ${gating} at or above ${failOn}.`),
  );
  if (report.probe) {
    const called = report.probe.filter((p) => p.status === "called").length;
    const skipped = report.probe.filter((p) => p.status === "skipped").length;
    const errors = report.probe.filter((p) => p.status === "error").length;
    out.push(`  Probe: ${called} called, ${skipped} skipped, ${errors} errors.`);
  }
  out.push(
    `  Result: ${failOn === "none" ? bold("report only (exit 0)") : failed ? paint("\x1b[1;31m", "FAIL (exit 1)") : paint("\x1b[1;32m", "PASS (exit 0)")}`,
  );
  return `${out.join("\n")}\n`;
}

function worst(findings: Finding[]): number {
  return Math.max(...findings.map((f) => severityRank(f.severity)));
}

/** Greedy word wrap; words longer than the width are hard-split. */
export function wrap(text: string, width: number): string[] {
  const lines: string[] = [];
  let line = "";
  for (let word of text.split(/\s+/).filter(Boolean)) {
    while (word.length > width) {
      if (line) {
        lines.push(line);
        line = "";
      }
      lines.push(word.slice(0, width));
      word = word.slice(width);
    }
    if (!line) line = word;
    else if (line.length + 1 + word.length <= width) line += ` ${word}`;
    else {
      lines.push(line);
      line = word;
    }
  }
  if (line) lines.push(line);
  return lines.length ? lines : [""];
}
