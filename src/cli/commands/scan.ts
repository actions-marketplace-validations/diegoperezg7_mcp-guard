import { writeFile } from "node:fs/promises";
import { Command, InvalidArgumentError, Option } from "commander";

import { splitCommand, TargetError, type Target } from "../../core/discover.js";
import { toHtml } from "../../core/report/html.js";
import { toJson } from "../../core/report/json.js";
import { toMarkdown } from "../../core/report/markdown.js";
import { toSarif } from "../../core/report/sarif.js";
import { toTable } from "../../core/report/table.js";
import { DEFAULT_LIMITS } from "../../core/limits.js";
import { breaches, scan, type ScanReport } from "../../core/scan.js";
import { SEVERITIES, type Severity } from "../../core/types.js";

export const EXIT = { pass: 0, findings: 1, error: 2 } as const;

const FORMATS = ["table", "json", "markdown", "sarif", "html"] as const;
type Format = (typeof FORMATS)[number];

export class UsageError extends Error {}

interface ScanFlags {
  stdio: string[];
  http: string[];
  json: string[];
  header: string[];
  env: string[];
  format: Format;
  output: string[];
  report?: string;
  failOn: Severity | "none";
  probe?: boolean;
  allowUnsafe?: boolean;
  judgeUrl?: string;
  judgeModel?: string;
  timeout: number;
  serverTimeout: number;
  maxItems: number;
  maxFieldKb: number;
  maxServerMb: number;
  verbose?: boolean;
}

const collect = (v: string, prev: string[]) => [...prev, v];

export function buildScanCommand(): Command {
  return new Command("scan")
    .description("Inventory one or more MCP servers and check them against every rule.")
    .option(
      "--stdio <command>",
      'start a server over stdio, e.g. "node server.js" (repeatable)',
      collect,
      [],
    )
    .option("--http <url>", "connect to a Streamable HTTP endpoint (repeatable)", collect, [])
    .option(
      "--json <file>",
      "read an exported tools/list result instead of connecting (repeatable)",
      collect,
      [],
    )
    .option(
      "-H, --header <name:value>",
      "HTTP header sent to --http targets, e.g. for auth (repeatable)",
      collect,
      [],
    )
    .option(
      "-e, --env <KEY=VALUE>",
      "environment variable for --stdio servers (repeatable)",
      collect,
      [],
    )
    .addOption(
      new Option("-f, --format <format>", "report printed to stdout")
        .choices(FORMATS)
        .default("table"),
    )
    .option(
      "-o, --output <format:file>",
      "also write a report to a file, e.g. sarif:mcp-guard.sarif (repeatable)",
      collect,
      [],
    )
    .option("-r, --report <file>", "also write the HTML report to a file (same as -o html:<file>)")
    .addOption(
      new Option("--fail-on <severity>", "exit 1 when a finding is at or above this severity")
        .choices([...SEVERITIES, "none"])
        .default("high"),
    )
    .option(
      "--probe",
      "call read-only tools and read resources with canary inputs (off by default)",
    )
    .option("--allow-unsafe", "with --probe, also call tools that are not annotated read-only")
    .option(
      "--judge-url <url>",
      "OpenAI-compatible base URL for the optional LLM judge, e.g. http://localhost:11434/v1",
    )
    .option("--judge-model <model>", "model name for the LLM judge")
    .option("--timeout <ms>", "per-request timeout", parsePositiveInt, 15_000)
    .option(
      "--server-timeout <ms>",
      "total time budget per server",
      parsePositiveInt,
      DEFAULT_LIMITS.serverTimeoutMs,
    )
    .option(
      "--max-items <n>",
      "items read per list (tools, resources, prompts)",
      parsePositiveInt,
      DEFAULT_LIMITS.maxItems,
    )
    .option(
      "--max-field-kb <kb>",
      "characters analysed per field, result or resource, in KiB",
      parsePositiveInt,
      1024,
    )
    .option(
      "--max-server-mb <mb>",
      "inventory size analysed per server, in MiB",
      parsePositiveInt,
      10,
    )
    .option("-v, --verbose", "show evidence in the table output")
    .addHelpText(
      "after",
      `
Exit codes: 0 no finding at or above --fail-on, 1 at least one, 2 usage or connection error.
The LLM judge API key, if needed, is read from MCP_GUARD_JUDGE_API_KEY.

Examples:
  mcp-guard scan --stdio "node dist/server.js"
  mcp-guard scan --http http://127.0.0.1:3000/mcp --format sarif > mcp-guard.sarif
  mcp-guard scan --json tools.json --stdio "npx -y some-mcp-server" --fail-on medium
  mcp-guard scan --stdio "python server.py" --probe -o markdown:report.md`,
    )
    .action(async (flags: ScanFlags) => {
      const code = await runScan(flags, (s) => process.stdout.write(s));
      process.exitCode = code;
    });
}

export async function runScan(flags: ScanFlags, print: (s: string) => void): Promise<number> {
  const targets = parseTargets(flags);
  const outputs = flags.output.map(parseOutput);
  if (flags.report) outputs.push({ format: "html", file: flags.report });
  if (flags.allowUnsafe && !flags.probe)
    throw new UsageError("--allow-unsafe only makes sense with --probe");
  if (!!flags.judgeUrl !== !!flags.judgeModel) {
    throw new UsageError("--judge-url and --judge-model must be given together");
  }

  let report: ScanReport;
  try {
    report = await scan({
      targets,
      timeoutMs: flags.timeout,
      limits: {
        maxItems: flags.maxItems,
        maxFieldChars: flags.maxFieldKb * 1024,
        maxServerChars: flags.maxServerMb * 1024 * 1024,
        serverTimeoutMs: flags.serverTimeout,
      },
      ...(flags.probe ? { probe: { allowUnsafe: !!flags.allowUnsafe } } : {}),
      ...(flags.judgeUrl && flags.judgeModel
        ? {
            judge: {
              baseUrl: flags.judgeUrl,
              model: flags.judgeModel,
              ...(process.env.MCP_GUARD_JUDGE_API_KEY
                ? { apiKey: process.env.MCP_GUARD_JUDGE_API_KEY }
                : {}),
            },
          }
        : {}),
    });
  } catch (err) {
    if (err instanceof TargetError) throw new UsageError(err.message);
    throw err;
  }

  print(render(report, flags.format, { verbose: !!flags.verbose, failOn: flags.failOn }));
  for (const { format, file } of outputs) {
    await writeFile(
      file,
      render(report, format, { verbose: true, tty: false, failOn: flags.failOn }),
      "utf8",
    );
  }
  return breaches(report.findings, flags.failOn) ? EXIT.findings : EXIT.pass;
}

export interface RenderOptions {
  failOn: Severity | "none";
  verbose?: boolean;
  /** Whether stdout is a terminal; decides colour for the table. */
  tty?: boolean;
}

export function render(report: ScanReport, format: Format, opts: RenderOptions): string {
  const tty = opts.tty ?? !!process.stdout.isTTY;
  switch (format) {
    case "json":
      return toJson(report);
    case "markdown":
      return toMarkdown(report);
    case "sarif":
      return `${JSON.stringify(toSarif(report), null, 2)}\n`;
    case "html":
      return toHtml(report, { failOn: opts.failOn });
    case "table":
      return toTable(report, {
        color: (tty && !process.env.NO_COLOR) || !!process.env.FORCE_COLOR,
        unicode: tty,
        width: process.stdout.columns || 120,
        verbose: !!opts.verbose,
        failOn: opts.failOn,
      });
  }
}

function parseTargets(flags: ScanFlags): Target[] {
  const headers = Object.fromEntries(flags.header.map((h) => splitPair(h, ":", "--header")));
  const env = Object.fromEntries(flags.env.map((e) => splitPair(e, "=", "--env")));
  const targets: Target[] = [];
  for (const line of flags.stdio) {
    const [command, ...args] = splitCommand(line);
    if (!command) throw new UsageError("--stdio needs a command");
    targets.push({ kind: "stdio", command, args, env });
  }
  for (const url of flags.http) {
    let u: URL;
    try {
      u = new URL(url);
    } catch {
      throw new UsageError(`--http: not a URL: ${url}`);
    }
    if (u.protocol !== "http:" && u.protocol !== "https:")
      throw new UsageError(`--http: unsupported scheme in ${url}`);
    targets.push({ kind: "http", url, headers });
  }
  for (const path of flags.json) targets.push({ kind: "json", path });
  if (targets.length === 0) throw new UsageError("Nothing to scan: pass --stdio, --http or --json");
  return targets;
}

function splitPair(s: string, sep: string, flag: string): [string, string] {
  const i = s.indexOf(sep);
  if (i <= 0) throw new UsageError(`${flag} expects name${sep}value, got "${s}"`);
  return [s.slice(0, i).trim(), s.slice(i + 1).trim()];
}

function parseOutput(s: string): { format: Format; file: string } {
  const i = s.indexOf(":");
  const format = s.slice(0, i) as Format;
  const file = s.slice(i + 1);
  if (i <= 0 || !FORMATS.includes(format) || !file) {
    throw new UsageError(`--output expects <${FORMATS.join("|")}>:<file>, got "${s}"`);
  }
  return { format, file };
}

function parsePositiveInt(v: string): number {
  const n = Number(v);
  if (!Number.isInteger(n) || n <= 0) throw new InvalidArgumentError("must be a positive integer");
  return n;
}
