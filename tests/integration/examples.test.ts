import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { afterEach, describe, expect, it } from "vitest";

import { buildServer as opsToolbox } from "../../examples/servers/ops-toolbox.js";
import { buildServer as poisonedNotes } from "../../examples/servers/poisoned-notes.js";
import { buildServer as weatherSafe } from "../../examples/servers/weather-safe.js";
import { inventoryFromClient, loadExports, newClient } from "../../src/core/discover.js";
import { probeServer } from "../../src/core/probe.js";
import { analyze } from "../../src/core/scan.js";

const open: Client[] = [];
afterEach(async () => {
  await Promise.all(open.splice(0).map((c) => c.close()));
});

async function connectInMemory(build: () => McpServer, name: string) {
  const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
  await build().connect(serverSide);
  const client = newClient();
  await client.connect(clientSide);
  open.push(client);
  return {
    client,
    inventory: await inventoryFromClient(client, { kind: "stdio", command: name, args: [] }, name),
  };
}

const ruleIds = (findings: { ruleId: string }[]) =>
  [...new Set(findings.map((f) => f.ruleId))].sort();

describe("example servers over InMemoryTransport", () => {
  it("inventories tools, annotations and resources", async () => {
    const { inventory } = await connectInMemory(poisonedNotes, "poisoned-notes");
    expect(inventory.name).toBe("poisoned-notes");
    expect(inventory.tools.map((t) => t.name)).toEqual([
      "add_note",
      "search_notes",
      "share_note",
      "server_info",
    ]);
    expect(inventory.tools[1]?.annotations).toMatchObject({ readOnlyHint: true });
    expect(inventory.resources.map((r) => r.uri)).toEqual(["notes://config/sync"]);
  });

  it("poisoned-notes raises the tool-poisoning rules", async () => {
    const { inventory } = await connectInMemory(poisonedNotes, "poisoned-notes");
    expect(ruleIds(analyze([inventory]))).toEqual([
      "MCPG-001",
      "MCPG-002",
      "MCPG-003",
      "MCPG-024",
      "MCPG-025",
      "MCPG-030",
    ]);
  });

  it("ops-toolbox raises the permission rules", async () => {
    const { inventory } = await connectInMemory(opsToolbox, "ops-toolbox");
    expect(ruleIds(analyze([inventory]))).toEqual([
      "MCPG-020",
      "MCPG-021",
      "MCPG-022",
      "MCPG-023",
      "MCPG-024",
      "MCPG-025",
    ]);
  });

  it("weather-safe is clean", async () => {
    const { inventory } = await connectInMemory(weatherSafe, "weather-safe");
    expect(analyze([inventory])).toEqual([]);
  });

  it("cross-server rules fire when the servers are scanned together", async () => {
    const notes = (await connectInMemory(poisonedNotes, "poisoned-notes")).inventory;
    const ops = (await connectInMemory(opsToolbox, "ops-toolbox")).inventory;
    const [mail] = await loadExports("examples/exports/mail-server.json");
    const findings = analyze([notes, ops, mail!]);
    expect(
      findings
        .filter((f) => f.ruleId === "MCPG-010")
        .map((f) => f.location.server)
        .sort(),
    ).toEqual(["mail", "ops-toolbox"]);
    expect(findings.find((f) => f.ruleId === "MCPG-012")?.location.name).toBe("share_note");
  });

  it("the probe finds the indirect injection and the leaked token, and skips write tools", async () => {
    const { client, inventory } = await connectInMemory(poisonedNotes, "poisoned-notes");
    const { findings, records } = await probeServer(client, inventory, {
      allowUnsafe: false,
      timeoutMs: 5000,
    });
    expect(ruleIds(findings)).toEqual(["MCPG-050", "MCPG-051"]);
    expect(records.filter((r) => r.status === "skipped").map((r) => r.target)).toEqual([
      "add_note",
      "share_note",
    ]);
  });

  it("the probe calls nothing on ops-toolbox that is not annotated read-only", async () => {
    const { client, inventory } = await connectInMemory(opsToolbox, "ops-toolbox");
    const { records } = await probeServer(client, inventory, {
      allowUnsafe: false,
      timeoutMs: 5000,
    });
    const called = records.filter((r) => r.status === "called").map((r) => r.target);
    // send_email claims readOnlyHint but its name says otherwise (MCPG-021): skipped without --allow-unsafe.
    expect(called.sort()).toEqual(["fetch_url", "read_file"]);
    expect(records.find((r) => r.target === "send_email")?.reason).toMatch(/needs --allow-unsafe/);
  });
});
