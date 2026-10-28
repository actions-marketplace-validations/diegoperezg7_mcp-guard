import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { escapeCommandData, runAction } from "../src/action/run.js";

const notes = `${process.execPath} --import tsx examples/servers/poisoned-notes.ts`;
const weather = `${process.execPath} --import tsx examples/servers/weather-safe.ts`;

/** Runs the action as the runner would: INPUT_* variables and the two command files. */
async function act(inputs: Record<string, string>) {
  const dir = mkdtempSync(join(tmpdir(), "mcp-guard-action-"));
  const env: Record<string, string> = {
    GITHUB_OUTPUT: join(dir, "output"),
    GITHUB_STEP_SUMMARY: join(dir, "summary"),
  };
  writeFileSync(env.GITHUB_OUTPUT!, "");
  writeFileSync(env.GITHUB_STEP_SUMMARY!, "");
  for (const [k, v] of Object.entries(inputs)) env[`INPUT_${k.toUpperCase()}`] = v;
  const log: string[] = [];
  const result = await runAction(env, { log: (l) => log.push(l) });
  const outputs: Record<string, string> = {};
  const re = /^([\w-]+)<<(ghadelimiter_[\w-]+)\n([\s\S]*?)\n\2$/gm;
  for (const m of readFileSync(env.GITHUB_OUTPUT!, "utf8").matchAll(re)) outputs[m[1]!] = m[3]!;
  return {
    dir,
    result,
    outputs,
    log: log.join("\n"),
    summary: readFileSync(env.GITHUB_STEP_SUMMARY!, "utf8"),
  };
}

describe("GitHub Action", () => {
  it("fails on a vulnerable server and reports the counts as outputs", async () => {
    const dir = mkdtempSync(join(tmpdir(), "mcp-guard-action-"));
    const r = await act({
      stdio: notes,
      "sarif-file": join(dir, "out/mcp-guard.sarif"),
      "html-report": join(dir, "report.html"),
    });
    expect(r.result.exitCode).toBe(1);
    expect(r.outputs.verdict).toBe("fail");
    expect(Number(r.outputs.critical)).toBeGreaterThan(0);
    expect(Number(r.outputs.findings)).toBe(r.result.report!.findings.length);
    expect(r.outputs["sarif-file"]).toBe(join(dir, "out/mcp-guard.sarif"));
    expect(JSON.parse(readFileSync(join(dir, "out/mcp-guard.sarif"), "utf8")).version).toBe(
      "2.1.0",
    );
    expect(readFileSync(join(dir, "report.html"), "utf8")).toContain("<!doctype html>");
    expect(r.summary).toContain("**Verdict: FAIL**");
    expect(r.log).toMatch(/::error title=mcp-guard::\d+ findings at or above "high"/);
  });

  it("passes on the reference server", async () => {
    const r = await act({ stdio: weather, "sarif-file": join(tmpdir(), "mcp-guard-ok.sarif") });
    expect(r.result.exitCode).toBe(0);
    expect(r.outputs).toMatchObject({
      verdict: "pass",
      findings: "0",
      high: "0",
      "html-report": "",
    });
    expect(r.summary).toContain("**Verdict: PASS**");
  });

  it("honours fail-on and skips the summary when asked", async () => {
    const r = await act({
      stdio: notes,
      "fail-on": "none",
      "upload-summary": "false",
      "sarif-file": join(tmpdir(), "mcp-guard-none.sarif"),
    });
    expect(r.result.exitCode).toBe(0);
    expect(r.outputs.verdict).toBe("pass");
    expect(r.summary).toBe("");
  });

  it("rejects bad inputs with a clear error and no outputs", async () => {
    const cases: Record<string, string>[] = [
      {},
      { stdio: weather, "fail-on": "severe" },
      { stdio: weather, probe: "yes" },
      { stdio: weather, "max-items": "0" },
      { stdio: weather, "allow-unsafe": "true" },
    ];
    for (const inputs of cases) {
      const r = await act(inputs);
      expect(r.result.exitCode).toBe(1);
      expect(r.log).toMatch(/^::error title=mcp-guard::/);
      expect(r.outputs).toEqual({});
    }
  });

  it("keeps server text from opening a workflow command", async () => {
    expect(escapeCommandData("a\n::add-mask::x\r%")).toBe("a%0A::add-mask::x%0D%25");
    const r = await act({ stdio: notes, "sarif-file": join(tmpdir(), "mcp-guard-cmd.sarif") });
    const lines = r.log.split("\n");
    const start = lines.findIndex((l) => l.startsWith("::stop-commands::"));
    const token = lines[start]!.slice("::stop-commands::".length);
    expect(token).toMatch(/^[0-9a-f-]{36}$/);
    const end = lines.indexOf(`::${token}::`);
    expect(end).toBeGreaterThan(start);
    // Outside the suspended block, every command line is one the action wrote itself.
    const commands = lines.filter((l, i) => (i < start || i > end) && l.trim().startsWith("::"));
    expect(commands.every((l) => l.startsWith("::error title=mcp-guard::"))).toBe(true);
  });
});
