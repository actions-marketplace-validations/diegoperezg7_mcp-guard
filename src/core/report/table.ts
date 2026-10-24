import type { ScanReport } from "../scan.js";
import { SEVERITIES, type Severity } from "../types.js";
import { locationLabel } from "./markdown.js";

export interface TableOptions {
  color: boolean;
  width: number;
  /** Print the evidence line under each finding. */
  verbose?: boolean;
}

const SEVERITY_COLOR: Record<Severity, string> = {
  critical: "\x1b[1;30;41m",
  high: "\x1b[1;31m",
  medium: "\x1b[33m",
  low: "\x1b[34m",
  info: "\x1b[2m",
};

/** Human-readable terminal output: one row per finding, wrapped to the terminal width. */
export function toTable(report: ScanReport, opts: TableOptions): string {
  const paint = (code: string, s: string) => (opts.color ? `${code}${s}\x1b[0m` : s);
  const dim = (s: string) => paint("\x1b[2m", s);
  const bold = (s: string) => paint("\x1b[1m", s);
  const out: string[] = [];

  const counts = report.servers.reduce(
    (a, s) => ({
      tools: a.tools + s.tools.length,
      resources: a.resources + s.resources.length,
      prompts: a.prompts + s.prompts.length,
    }),
    { tools: 0, resources: 0, prompts: 0 },
  );
  out.push(
    `${bold("mcp-guard")} ${report.scanner.version}  ${dim(
      `${report.servers.length} server(s), ${counts.tools} tools, ${counts.resources} resources, ${counts.prompts} prompts, ${report.durationMs} ms`,
    )}`,
    "",
  );

  if (report.findings.length === 0) {
    out.push(paint("\x1b[32m", "No findings."), "");
  } else {
    const rows = report.findings.map((f) => ({
      sev: f.severity,
      rule: f.ruleId,
      where: `${f.location.server} > ${locationLabel(f)}`,
      text: f.message + (f.judge ? ` [judge: ${f.judge.verdict}]` : ""),
      evidence: f.evidence,
    }));
    const sevW = 8;
    const ruleW = 8;
    const whereW = Math.min(44, Math.max(8, ...rows.map((r) => r.where.length)));
    const textW = Math.max(30, opts.width - sevW - ruleW - whereW - 6);
    const header = [
      pad("SEVERITY", sevW),
      pad("RULE", ruleW),
      pad("LOCATION", whereW),
      "FINDING",
    ].join("  ");
    out.push(dim(header));
    for (const r of rows) {
      const whereLines = wrap(r.where, whereW);
      const textLines = wrap(r.text, textW);
      const n = Math.max(whereLines.length, textLines.length);
      for (let i = 0; i < n; i++) {
        const sev =
          i === 0 ? paint(SEVERITY_COLOR[r.sev], pad(r.sev.toUpperCase(), sevW)) : pad("", sevW);
        const rule = i === 0 ? pad(r.rule, ruleW) : pad("", ruleW);
        out.push(
          [sev, rule, pad(whereLines[i] ?? "", whereW), textLines[i] ?? ""].join("  ").trimEnd(),
        );
      }
      if (opts.verbose && r.evidence) {
        for (const line of wrap(`evidence: ${r.evidence}`, textW)) {
          out.push(`${pad("", sevW + ruleW + whereW + 6)}${dim(line)}`);
        }
      }
    }
    out.push("");
  }

  const summary = SEVERITIES.filter((s) => report.summary[s] > 0)
    .map((s) => paint(SEVERITY_COLOR[s], `${report.summary[s]} ${s}`))
    .join(dim(", "));
  out.push(`${bold("Summary")}  ${summary || "clean"}`);

  if (report.probe) {
    const called = report.probe.filter((p) => p.status === "called").length;
    const skipped = report.probe.filter((p) => p.status === "skipped").length;
    const errors = report.probe.filter((p) => p.status === "error").length;
    out.push(`${bold("Probe")}    ${called} called, ${skipped} skipped, ${errors} errors`);
  }
  return `${out.join("\n")}\n`;
}

function pad(s: string, w: number): string {
  return s.length >= w ? s : s + " ".repeat(w - s.length);
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
