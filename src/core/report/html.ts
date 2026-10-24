import { createHash } from "node:crypto";

import { getRule } from "../rules/index.js";
import type { ScanReport } from "../scan.js";
import { breaches } from "../scan.js";
import { printable } from "../text.js";
import type { Severity } from "../types.js";
import { ruleDocUrl } from "./links.js";
import { sourceLabel } from "./markdown.js";
import { HTML_CLIENT, HTML_STYLE } from "./htmlAssets.js";

export interface HtmlOptions {
  failOn: Severity | "none";
}

/** What the page script receives. Every server-supplied string has been made printable. */
interface ReportData {
  meta: {
    version: string;
    startedAt: string;
    durationMs: number;
    failOn: Severity | "none";
    verdict: "pass" | "fail";
  };
  summary: Record<Severity, number>;
  servers: {
    name: string;
    kind: string;
    target: string;
    tools: number;
    resources: number;
    prompts: number;
    facts: string[];
  }[];
  findings: {
    ruleId: string;
    severity: Severity;
    server: string;
    kind: string;
    name: string;
    field: string;
    message: string;
    evidence: string;
    judge: string;
  }[];
  rules: Record<
    string,
    {
      title: string;
      category: string;
      remediation: string;
      doc: string;
      references: { title: string; url: string }[];
    }
  >;
  probe: { server: string; target: string; kind: string; status: string; reason: string }[] | null;
}

/**
 * A self-contained HTML report: one file, no network, CSS and JS inline.
 *
 * Server-supplied text never becomes markup. It travels as JSON inside a
 * non-executable <script type="application/json"> block, with <, >, & and
 * the JS line separators escaped so it cannot close the block, and the page
 * script renders it with textContent only. A Content-Security-Policy meta tag
 * allows no network access and only the one inline script, by hash.
 */
export function toHtml(report: ScanReport, opts: HtmlOptions): string {
  const data: ReportData = {
    meta: {
      version: report.scanner.version,
      startedAt: report.startedAt,
      durationMs: report.durationMs,
      failOn: opts.failOn,
      verdict: breaches(report.findings, opts.failOn) ? "fail" : "pass",
    },
    summary: report.summary,
    servers: report.servers.map((s) => ({
      name: printable(s.name),
      kind: s.source.kind,
      target: printable(sourceLabel(s)),
      tools: s.tools.length,
      resources: s.resources.length + s.resourceTemplates.length,
      prompts: s.prompts.length,
      facts: transportFacts(s.transport),
    })),
    findings: report.findings.map((f) => ({
      ruleId: f.ruleId,
      severity: f.severity,
      server: printable(f.location.server),
      kind: f.location.kind,
      name: printable(f.location.name),
      field: printable(f.location.field ?? ""),
      message: printable(f.message),
      evidence: f.evidence ? printable(f.evidence) : "",
      judge: f.judge ? printable(`${f.judge.verdict} (${f.judge.model}): ${f.judge.reason}`) : "",
    })),
    rules: {},
    probe: report.probe
      ? report.probe.map((p) => ({
          server: printable(p.server),
          target: printable(p.target),
          kind: p.kind,
          status: p.status,
          reason: printable(p.reason ?? ""),
        }))
      : null,
  };
  for (const id of new Set(report.findings.map((f) => f.ruleId))) {
    const r = getRule(id);
    if (!r) continue;
    data.rules[id] = {
      title: r.title,
      category: r.category,
      remediation: r.remediation,
      doc: ruleDocUrl(id),
      references: r.references.map((ref) => ({ title: ref.title, url: ref.url })),
    };
  }

  const json = embedJson(data);
  const scriptHash = createHash("sha256").update(HTML_CLIENT).digest("base64");
  const csp = [
    "default-src 'none'",
    "style-src 'unsafe-inline'",
    `script-src 'sha256-${scriptHash}'`,
    "img-src data:",
    "base-uri 'none'",
    "form-action 'none'",
  ].join("; ");

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="${csp}">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>mcp-guard report</title>
<style>${HTML_STYLE}</style>
</head>
<body>
<noscript><p class="noscript">This report renders with JavaScript. The raw results are in the JSON block of this file, or run mcp-guard with --format json.</p></noscript>
<div id="app"></div>
<script type="application/json" id="report-data">${json}</script>
<script>${HTML_CLIENT}</script>
</body>
</html>
`;
}

/** JSON that cannot end the surrounding <script> element or break out of it. */
export function embedJson(value: unknown): string {
  return JSON.stringify(value)
    .replace(/</g, "\\u003c")
    .replace(/>/g, "\\u003e")
    .replace(/&/g, "\\u0026")
    .replace(/\u2028/g, "\\u2028")
    .replace(/\u2029/g, "\\u2029");
}

function transportFacts(t: ScanReport["servers"][number]["transport"]): string[] {
  if (!t) return [];
  const facts = [t.tls ? "TLS" : "plain HTTP", t.loopback ? "loopback" : "remote"];
  facts.push(t.credentialsSupplied ? "credentials sent" : "no credentials");
  if (t.acceptsAnonymous) facts.push("accepts anonymous");
  if (t.acceptsForeignHost) facts.push("accepts foreign Host");
  if (t.reachableOn?.length) facts.push(`also on ${t.reachableOn.length} LAN address(es)`);
  return facts;
}
