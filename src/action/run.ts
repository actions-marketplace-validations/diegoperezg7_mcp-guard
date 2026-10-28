import { randomUUID } from "node:crypto";
import { appendFile, mkdir, writeFile } from "node:fs/promises";
import { dirname } from "node:path";

import { executeScan, render, UsageError } from "../cli/commands/scan.js";
import { DEFAULT_LIMITS } from "../core/limits.js";
import { toMarkdown } from "../core/report/markdown.js";
import type { ScanReport } from "../core/scan.js";
import { printable } from "../core/text.js";
import { SEVERITIES, severityRank, type Severity } from "../core/types.js";

/**
 * The GitHub Action entry point, without the runner toolkit: inputs come from
 * INPUT_* variables, outputs and the job summary go to the files named by
 * GITHUB_OUTPUT and GITHUB_STEP_SUMMARY, exactly as the runner defines them.
 */

type Env = Record<string, string | undefined>;
type FailOn = Severity | "none";

export interface ActionIO {
  /** Plain log lines for the step log (stdout). */
  log: (line: string) => void;
}

export interface ActionResult {
  exitCode: 0 | 1;
  report?: ScanReport;
}

/** Same lookup as @actions/core: spaces become underscores, the name is upper-cased, hyphens stay. */
function input(env: Env, name: string): string {
  return (env[`INPUT_${name.replace(/ /g, "_").toUpperCase()}`] ?? "").trim();
}

/** One value per line; blank lines are ignored. */
function lines(env: Env, name: string): string[] {
  return input(env, name)
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l.length > 0);
}

function bool(env: Env, name: string, fallback: boolean): boolean {
  const v = input(env, name).toLowerCase();
  if (v === "") return fallback;
  if (v === "true") return true;
  if (v === "false") return false;
  throw new UsageError(`input ${name} must be true or false, got "${v}"`);
}

function positiveInt(env: Env, name: string, fallback: number): number {
  const v = input(env, name);
  if (v === "") return fallback;
  const n = Number(v);
  if (!Number.isInteger(n) || n <= 0)
    throw new UsageError(`input ${name} must be a positive integer, got "${v}"`);
  return n;
}

function failOn(env: Env): FailOn {
  const v = input(env, "fail-on").toLowerCase() || "high";
  if (v === "none" || (SEVERITIES as readonly string[]).includes(v)) return v as FailOn;
  throw new UsageError(`input fail-on must be one of ${[...SEVERITIES, "none"].join(", ")}`);
}

/** Escapes a message for a workflow command, so it cannot end the command or start another line. */
export function escapeCommandData(s: string): string {
  return s.replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");
}

async function writeOutputs(env: Env, values: Record<string, string>): Promise<void> {
  const file = env.GITHUB_OUTPUT;
  if (!file) return;
  let body = "";
  for (const [name, value] of Object.entries(values)) {
    const delimiter = `ghadelimiter_${randomUUID()}`;
    body += `${name}<<${delimiter}\n${value}\n${delimiter}\n`;
  }
  await appendFile(file, body, "utf8");
}

async function writeFileWithDirs(path: string, content: string): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, content, "utf8");
}

function countAtOrAbove(report: ScanReport, threshold: FailOn): number {
  if (threshold === "none") return 0;
  return report.findings.filter((f) => severityRank(f.severity) >= severityRank(threshold)).length;
}

export function verdictLine(report: ScanReport, threshold: FailOn): string {
  const failing = countAtOrAbove(report, threshold);
  if (threshold === "none") return "**Verdict: PASS** (`fail-on: none`, the scan never fails).";
  return failing > 0
    ? `**Verdict: FAIL**: ${failing} finding${failing === 1 ? "" : "s"} at or above \`${threshold}\` (\`fail-on\`).`
    : `**Verdict: PASS**: no finding at or above \`${threshold}\` (\`fail-on\`).`;
}

export async function runAction(env: Env, io: ActionIO): Promise<ActionResult> {
  try {
    return await scanAndReport(env, io);
  } catch (err) {
    // Messages can quote what a server sent: printable() makes control characters
    // visible and the command escaping keeps them inside this one annotation.
    const message = printable(err instanceof Error ? err.message : String(err));
    io.log(`::error title=mcp-guard::${escapeCommandData(message)}`);
    return { exitCode: 1 };
  }
}

async function scanAndReport(env: Env, io: ActionIO): Promise<ActionResult> {
  const threshold = failOn(env);
  const sarifFile = input(env, "sarif-file") || "mcp-guard.sarif";
  const htmlReport = input(env, "html-report");
  const probe = bool(env, "probe", false);
  const allowUnsafe = bool(env, "allow-unsafe", false);
  const uploadSummary = bool(env, "upload-summary", true);

  const stdio = lines(env, "stdio");
  const http = lines(env, "http");
  const json = lines(env, "json");
  if (stdio.length + http.length + json.length === 0)
    throw new UsageError("nothing to scan: set at least one of the stdio, http or json inputs");
  if (allowUnsafe && !probe)
    throw new UsageError("allow-unsafe only takes effect with probe: true");

  const report = await executeScan({
    stdio,
    http,
    json,
    header: [],
    env: [],
    failOn: threshold,
    probe,
    allowUnsafe,
    timeout: 15_000,
    serverTimeout: positiveInt(env, "server-timeout", DEFAULT_LIMITS.serverTimeoutMs),
    maxItems: positiveInt(env, "max-items", DEFAULT_LIMITS.maxItems),
    maxFieldKb: positiveInt(env, "max-field-kb", 1024),
    maxServerMb: 10,
  });

  await writeFileWithDirs(sarifFile, render(report, "sarif", { failOn: threshold, tty: false }));
  if (htmlReport)
    await writeFileWithDirs(htmlReport, render(report, "html", { failOn: threshold, tty: false }));

  const verdict = verdictLine(report, threshold);
  if (uploadSummary && env.GITHUB_STEP_SUMMARY) {
    const markdown = toMarkdown(report).replace(
      /^## mcp-guard report\n\n/,
      `## mcp-guard report\n\n${verdict}\n\n`,
    );
    await appendFile(env.GITHUB_STEP_SUMMARY, `${markdown}\n`, "utf8");
  }

  const failed = countAtOrAbove(report, threshold) > 0;
  await writeOutputs(env, {
    findings: String(report.findings.length),
    critical: String(report.summary.critical),
    high: String(report.summary.high),
    medium: String(report.summary.medium),
    low: String(report.summary.low),
    verdict: failed ? "fail" : "pass",
    "sarif-file": sarifFile,
    "html-report": htmlReport,
  });

  // The table quotes server-supplied names. The runner treats any stdout line
  // that starts with "::" as a workflow command, so command processing is
  // suspended with a one-time token while the table is printed.
  const token = randomUUID();
  io.log(`::stop-commands::${token}`);
  io.log(render(report, "table", { failOn: threshold, tty: false, verbose: false }).trimEnd());
  io.log(`::${token}::`);

  io.log(`SARIF written to ${sarifFile}${htmlReport ? `, HTML report to ${htmlReport}` : ""}.`);
  if (failed) {
    const count = countAtOrAbove(report, threshold);
    io.log(
      `::error title=mcp-guard::${count} finding${count === 1 ? "" : "s"} at or above "${threshold}" (fail-on). See the job summary or the SARIF file for details.`,
    );
    return { exitCode: 1, report };
  }
  io.log(`mcp-guard: no finding at or above "${threshold}" (fail-on).`);
  return { exitCode: 0, report };
}
