import { logger } from "../shared/logger.js";
import { VERSION } from "../shared/version.js";
import { openTarget, type Connection, type Target } from "./discover.js";
import { judgeAmbiguous, type JudgeOptions } from "./judge.js";
import { probeServer, type ProbeRecord } from "./probe.js";
import { RULES } from "./rules/index.js";
import {
  SEVERITIES,
  severityRank,
  type Finding,
  type ServerInventory,
  type Severity,
} from "./types.js";

export interface ScanOptions {
  targets: Target[];
  timeoutMs: number;
  probe?: { allowUnsafe: boolean };
  judge?: Omit<JudgeOptions, "timeoutMs">;
}

export interface ScanReport {
  scanner: { name: "mcp-guard"; version: string };
  startedAt: string;
  durationMs: number;
  servers: ServerInventory[];
  findings: Finding[];
  summary: Record<Severity, number>;
  /** Present when --probe ran: every tool and resource, called or skipped, and why. */
  probe?: ProbeRecord[];
}

/** The deterministic part: every static rule over the inventories. */
export function analyze(servers: ServerInventory[]): Finding[] {
  const ctx = { servers };
  return sortFindings(RULES.flatMap((r) => r.check?.(ctx) ?? []));
}

export async function scan(opts: ScanOptions): Promise<ScanReport> {
  const started = Date.now();
  const connections: Connection[] = [];
  try {
    for (const target of opts.targets) connections.push(...(await openTarget(target, opts)));
    uniqueNames(connections.map((c) => c.inventory));
    const servers = connections.map((c) => c.inventory);

    const findings = analyze(servers);
    let probe: ProbeRecord[] | undefined;
    if (opts.probe) {
      probe = [];
      for (const c of connections) {
        if (!c.client) {
          probe.push({
            server: c.inventory.name,
            target: "*",
            kind: "tool",
            status: "skipped",
            reason: "JSON export, nothing to call",
          });
          continue;
        }
        const result = await probeServer(c.client, c.inventory, {
          allowUnsafe: opts.probe.allowUnsafe,
          timeoutMs: opts.timeoutMs,
          ...(c.canary ? { canary: c.canary } : {}),
        });
        findings.push(...result.findings);
        probe.push(...result.records);
      }
    }
    if (opts.judge)
      await judgeAmbiguous(findings, servers, { ...opts.judge, timeoutMs: opts.timeoutMs });

    const sorted = sortFindings(findings);
    return {
      scanner: { name: "mcp-guard", version: VERSION },
      startedAt: new Date(started).toISOString(),
      durationMs: Date.now() - started,
      servers,
      findings: sorted,
      summary: summarize(sorted),
      ...(probe ? { probe } : {}),
    };
  } finally {
    await Promise.all(
      connections.map((c) =>
        c.close().catch((err: unknown) => logger.debug({ err }, "close failed")),
      ),
    );
  }
}

function uniqueNames(servers: ServerInventory[]): void {
  const seen = new Map<string, number>();
  for (const s of servers) {
    const n = (seen.get(s.name) ?? 0) + 1;
    seen.set(s.name, n);
    if (n > 1) s.name = `${s.name}#${n}`;
  }
}

export function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort(
    (a, b) =>
      severityRank(b.severity) - severityRank(a.severity) ||
      a.ruleId.localeCompare(b.ruleId) ||
      a.location.server.localeCompare(b.location.server) ||
      a.location.name.localeCompare(b.location.name) ||
      (a.location.field ?? "").localeCompare(b.location.field ?? ""),
  );
}

export function summarize(findings: Finding[]): Record<Severity, number> {
  const out = Object.fromEntries(SEVERITIES.map((s) => [s, 0])) as Record<Severity, number>;
  for (const f of findings) out[f.severity]++;
  return out;
}

/** True when at least one finding is at or above the threshold. */
export function breaches(findings: Finding[], failOn: Severity | "none"): boolean {
  if (failOn === "none") return false;
  return findings.some((f) => severityRank(f.severity) >= severityRank(failOn));
}
