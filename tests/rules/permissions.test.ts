import { describe, expect, it } from "vitest";

import { words } from "../../src/core/rules/permissions.js";
import type { JsonSchema } from "../../src/core/types.js";
import { findingsFor, server, tool } from "../helpers.js";

const schema = (properties: Record<string, JsonSchema>): JsonSchema => ({
  type: "object",
  properties,
});

describe("tool name parsing", () => {
  it("splits snake, kebab and camel case", () => {
    expect(words("deleteProject")).toEqual(["delete", "project"]);
    expect(words("run-shell_command")).toEqual(["run", "shell", "command"]);
  });
});

describe("MCPG-020 destructive without hint", () => {
  it("flags a destructive name without destructiveHint: true", () => {
    const s = server("s", [
      tool("delete_project", { annotations: { readOnlyHint: false } }),
      tool("dropTable", { annotations: undefined }),
    ]);
    expect(findingsFor("MCPG-020", s).map((f) => f.location.name)).toEqual([
      "delete_project",
      "dropTable",
    ]);
  });

  it("accepts an explicit destructiveHint and ignores harmless names", () => {
    const s = server("s", [
      tool("delete_project", { annotations: { readOnlyHint: false, destructiveHint: true } }),
      tool("format_date"),
      tool("get_deleted_items"),
    ]);
    expect(findingsFor("MCPG-020", s)).toEqual([]);
  });
});

describe("MCPG-021 misleading readOnlyHint", () => {
  it("flags a read-only claim on a tool named for a write", () => {
    const s = server("s", [tool("send_invoice", { annotations: { readOnlyHint: true } })]);
    expect(findingsFor("MCPG-021", s)).toHaveLength(1);
  });

  it("accepts read-only lookups and honest write annotations", () => {
    const s = server("s", [
      tool("get_invoice"),
      tool("send_invoice", { annotations: { readOnlyHint: false, destructiveHint: false } }),
    ]);
    expect(findingsFor("MCPG-021", s)).toEqual([]);
  });
});

describe("MCPG-022 command argument", () => {
  it("flags a free-form command string", () => {
    const s = server("s", [tool("run", { inputSchema: schema({ command: { type: "string" } }) })]);
    expect(findingsFor("MCPG-022", s)[0]?.location.field).toBe("inputSchema.properties.command");
  });

  it("flags 'code' only on tools that execute it", () => {
    const s = server("s", [
      tool("eval_python", { inputSchema: schema({ code: { type: "string" } }) }),
      tool("lookup_country", { inputSchema: schema({ code: { type: "string" } }) }),
    ]);
    expect(findingsFor("MCPG-022", s).map((f) => f.location.name)).toEqual(["eval_python"]);
  });

  it("accepts an enum of allowed commands", () => {
    const s = server("s", [
      tool("run_check", {
        inputSchema: schema({ command: { type: "string", enum: ["lint", "test"] } }),
      }),
    ]);
    expect(findingsFor("MCPG-022", s)).toEqual([]);
  });
});

describe("MCPG-023 path argument", () => {
  it("flags unconstrained paths, nested ones included", () => {
    const s = server("s", [
      tool("read", { inputSchema: schema({ path: { type: "string" } }) }),
      tool("copy", {
        inputSchema: schema({
          files: {
            type: "array",
            items: { type: "object", properties: { dest_path: { type: "string" } } },
          },
        }),
      }),
    ]);
    expect(findingsFor("MCPG-023", s).map((f) => f.location.field)).toEqual([
      "inputSchema.properties.files.items.properties.dest_path",
      "inputSchema.properties.path",
    ]);
  });

  it("accepts a path restricted by pattern", () => {
    const s = server("s", [
      tool("read", { inputSchema: schema({ path: { type: "string", pattern: "^[\\w/-]+$" } }) }),
    ]);
    expect(findingsFor("MCPG-023", s)).toEqual([]);
  });
});

describe("MCPG-024 URL argument", () => {
  it("flags by name and by format", () => {
    const s = server("s", [
      tool("fetch", { inputSchema: schema({ url: { type: "string" } }) }),
      tool("ping", { inputSchema: schema({ target: { type: "string", format: "uri" } }) }),
    ]);
    expect(findingsFor("MCPG-024", s).map((f) => f.location.name)).toEqual(["fetch", "ping"]);
  });

  it("accepts an allowlisted host pattern", () => {
    const s = server("s", [
      tool("fetch", {
        inputSchema: schema({ url: { type: "string", pattern: "^https://api\\.example\\.com/" } }),
      }),
    ]);
    expect(findingsFor("MCPG-024", s)).toEqual([]);
  });
});

describe("MCPG-025 missing annotations", () => {
  it("flags a tool with neither hint", () => {
    const s = server("s", [
      tool("t", { annotations: undefined }),
      tool("u", { annotations: { title: "U" } }),
    ]);
    expect(findingsFor("MCPG-025", s)).toHaveLength(2);
  });

  it("accepts either hint", () => {
    const s = server("s", [tool("t"), tool("u", { annotations: { destructiveHint: false } })]);
    expect(findingsFor("MCPG-025", s)).toEqual([]);
  });
});
