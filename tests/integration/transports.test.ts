import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { networkInterfaces } from "node:os";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { buildServer as opsToolbox } from "../../examples/servers/ops-toolbox.js";
import { buildServer as weatherSafe } from "../../examples/servers/weather-safe.js";
import { statelessHttp } from "../../examples/servers/shared.js";
import { toSarif } from "../../src/core/report/sarif.js";
import { scan } from "../../src/core/scan.js";

const hasLanAddress = Object.values(networkInterfaces())
  .flat()
  .some((i) => i && !i.internal && i.family === "IPv4");

function listen(server: Server, host: string): Promise<number> {
  return new Promise((resolve) =>
    server.listen(0, host, () => resolve((server.address() as AddressInfo).port)),
  );
}

describe("stdio subprocess", () => {
  it("injects the environment canary and catches the server echoing it", async () => {
    const report = await scan({
      targets: [
        {
          kind: "stdio",
          command: process.execPath,
          args: ["--import", "tsx", "examples/servers/poisoned-notes.ts"],
        },
      ],
      timeoutMs: 15_000,
      probe: { allowUnsafe: false },
    });
    expect(report.findings.filter((f) => f.ruleId === "MCPG-052")).toHaveLength(1);
    expect(JSON.stringify(report)).not.toMatch(/mcpguard-canary-[0-9a-f-]{36}/);

    const sarif = toSarif(report) as {
      runs: {
        results: { locations: { physicalLocation: { artifactLocation: { uri: string } } }[] }[];
      }[];
    };
    expect(sarif.runs[0]?.results[0]?.locations[0]?.physicalLocation.artifactLocation.uri).toBe(
      "examples/servers/poisoned-notes.ts",
    );
  });

  it("does not hand the scanner's own environment to the server", async () => {
    process.env.MCP_GUARD_TEST_SECRET = "should-not-leak";
    try {
      const report = await scan({
        targets: [
          {
            kind: "stdio",
            command: process.execPath,
            args: ["--import", "tsx", "examples/servers/poisoned-notes.ts"],
          },
        ],
        timeoutMs: 15_000,
        probe: { allowUnsafe: false },
      });
      expect(JSON.stringify(report)).not.toContain("should-not-leak");
    } finally {
      delete process.env.MCP_GUARD_TEST_SECRET;
    }
  });
});

describe("Streamable HTTP: vulnerable server bound to 0.0.0.0", () => {
  const app = statelessHttp(opsToolbox);
  let port = 0;
  beforeAll(async () => {
    port = await listen(app, "0.0.0.0");
  });
  afterAll(() => new Promise<void>((r) => app.close(() => r())));

  it("detects missing Host validation and the exposure on the LAN", async () => {
    const report = await scan({
      targets: [{ kind: "http", url: `http://127.0.0.1:${port}/mcp` }],
      timeoutMs: 10_000,
    });
    const ids = report.findings.map((f) => f.ruleId);
    expect(ids).toContain("MCPG-042");
    if (hasLanAddress) expect(ids).toContain("MCPG-041");
    expect(report.servers[0]?.transport).toMatchObject({
      loopback: true,
      acceptsAnonymous: true,
      acceptsForeignHost: true,
    });
  });
});

describe("Streamable HTTP: reference server on loopback with token and Host validation", () => {
  let app: Server;
  let port = 0;
  beforeAll(async () => {
    // allowedHosts needs the port, so bind first and rebuild the handler with it.
    const probe = statelessHttp(weatherSafe);
    port = await listen(probe, "127.0.0.1");
    await new Promise<void>((r) => probe.close(() => r()));
    app = statelessHttp(
      weatherSafe,
      { enableDnsRebindingProtection: true, allowedHosts: [`127.0.0.1:${port}`] },
      (req) => req.headers.authorization === "Bearer t0ken",
    );
    await new Promise<void>((r) => app.listen(port, "127.0.0.1", () => r()));
  });
  afterAll(() => new Promise<void>((r) => app.close(() => r())));

  it("is clean when the right token is supplied", async () => {
    const report = await scan({
      targets: [
        {
          kind: "http",
          url: `http://127.0.0.1:${port}/mcp`,
          headers: { authorization: "Bearer t0ken" },
        },
      ],
      timeoutMs: 10_000,
      probe: { allowUnsafe: false },
    });
    expect(report.findings).toEqual([]);
    expect(report.servers[0]?.transport).toMatchObject({
      credentialsSupplied: true,
      acceptsAnonymous: false,
      acceptsForeignHost: false,
      reachableOn: [],
    });
  });

  it("fails with an actionable message when credentials are missing", async () => {
    await expect(
      scan({ targets: [{ kind: "http", url: `http://127.0.0.1:${port}/mcp` }], timeoutMs: 10_000 }),
    ).rejects.toThrow(/requires credentials \(HTTP 401\)/);
  });
});
