import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

function cli(...args: string[]) {
  const r = spawnSync(process.execPath, ["--import", "tsx", "src/cli/index.ts", ...args], {
    encoding: "utf8",
    env: { ...process.env, NO_COLOR: "1", LOG_LEVEL: "silent" },
  });
  return { code: r.status, stdout: r.stdout, stderr: r.stderr };
}

const notes = ["--stdio", `${process.execPath} --import tsx examples/servers/poisoned-notes.ts`];
const weather = ["--stdio", `${process.execPath} --import tsx examples/servers/weather-safe.ts`];

describe("mcp-guard CLI exit codes", () => {
  it("0 when nothing reaches --fail-on", () => {
    const r = cli("scan", ...weather);
    expect(r.stdout).toContain("No findings.");
    expect(r.code).toBe(0);
  });

  it("1 when a finding reaches --fail-on (default high)", () => {
    expect(cli("scan", ...notes).code).toBe(1);
  });

  it("--fail-on none never fails and --fail-on critical ignores lower severities", () => {
    expect(cli("scan", ...notes, "--fail-on", "none").code).toBe(0);
    expect(
      cli("scan", "--json", "examples/exports/mail-server.json", "--fail-on", "low").code,
    ).toBe(0);
  });

  it("2 on usage and connection errors", () => {
    expect(cli("scan").code).toBe(2);
    expect(cli("scan", "--json", "does-not-exist.json").code).toBe(2);
    expect(cli("scan", "--stdio", "definitely-not-a-command-xyz").code).toBe(2);
    expect(cli("scan", ...weather, "--allow-unsafe").code).toBe(2);
    expect(cli("scan", ...weather, "--fail-on", "severe").code).toBe(2);
    expect(cli("rules", "MCPG-999").code).toBe(2);
  });
});

describe("mcp-guard CLI output", () => {
  it("writes extra reports with --output while printing another format", () => {
    const dir = mkdtempSync(join(tmpdir(), "mcp-guard-"));
    const r = cli(
      "scan",
      ...notes,
      "--format",
      "json",
      "-o",
      `sarif:${dir}/r.sarif`,
      "-o",
      `markdown:${dir}/r.md`,
      "--fail-on",
      "none",
    );
    expect(r.code).toBe(0);
    expect(JSON.parse(r.stdout).findings.length).toBeGreaterThan(0);
    expect(JSON.parse(readFileSync(`${dir}/r.sarif`, "utf8")).version).toBe("2.1.0");
    expect(readFileSync(`${dir}/r.md`, "utf8")).toContain("## mcp-guard report");
  });

  it("keeps stdout clean JSON even while logging", () => {
    const r = spawnSync(
      process.execPath,
      ["--import", "tsx", "src/cli/index.ts", "scan", ...weather, "--format", "sarif"],
      {
        encoding: "utf8",
        env: { ...process.env, LOG_LEVEL: "debug" },
      },
    );
    expect(() => JSON.parse(r.stdout)).not.toThrow();
    expect(r.stderr).toContain("inventory collected");
  });

  it("rules lists and explains", () => {
    expect(cli("rules").stdout).toContain("MCPG-052");
    expect(cli("rules", "mcpg-022").stdout).toContain("Remediation:");
  });
});
