/**
 * INTENTIONALLY VULNERABLE DEMO SERVER. Run it only on a machine and network you control.
 *
 * An "ops toolbox" over Streamable HTTP with the permission and transport
 * mistakes mcp-guard detects: a generic command runner, unconstrained path and
 * URL arguments, missing or misleading annotations, a bind to 0.0.0.0 with no
 * authentication and no Host/Origin validation.
 *
 * Every handler is a stub that only describes what it would have done: no
 * command runs, no file is read, no URL is fetched, nothing is deleted or sent.
 *
 *   PORT=3401 node dist/examples/ops-toolbox.js
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

import { isMain, statelessHttp } from "./shared.js";

const stub = (text: string) => ({
  content: [{ type: "text" as const, text: `[demo, nothing executed] ${text}` }],
});

export function buildServer(): McpServer {
  const server = new McpServer({ name: "ops-toolbox", version: "0.1.0" });

  server.registerTool(
    "run_command",
    {
      description: "Run a shell command on the build host and return its output.",
      inputSchema: { command: z.string() },
    },
    async ({ command }) => stub(`would run: ${command}`),
  );

  server.registerTool(
    "read_file",
    {
      description: "Read a text file from the build host.",
      inputSchema: { path: z.string() },
      annotations: { readOnlyHint: true },
    },
    async ({ path }) => stub(`would read ${path}`),
  );

  server.registerTool(
    "fetch_url",
    {
      description: "Fetch a URL from the build host and return the body.",
      inputSchema: { url: z.url() },
      annotations: { readOnlyHint: true, openWorldHint: true },
    },
    async ({ url }) => stub(`would fetch ${url}`),
  );

  server.registerTool(
    "delete_workspace",
    {
      description: "Delete a workspace and all its build artifacts.",
      inputSchema: { name: z.string().regex(/^[a-z0-9-]{1,40}$/) },
      annotations: { readOnlyHint: false },
    },
    async ({ name }) => stub(`would delete workspace ${name}`),
  );

  server.registerTool(
    "send_email",
    {
      description: "Send a build notification email.",
      inputSchema: { to: z.email(), subject: z.string().max(200), body: z.string().max(5000) },
      annotations: { readOnlyHint: true },
    },
    async ({ to }) => stub(`would email ${to}`),
  );

  return server;
}

if (isMain(import.meta.url)) {
  const port = Number(process.env.PORT ?? 3401);
  // The bug on purpose: every interface, no auth, no enableDnsRebindingProtection.
  statelessHttp(buildServer).listen(port, "0.0.0.0", () => {
    process.stderr.write(`ops-toolbox (INTENTIONALLY VULNERABLE) on http://0.0.0.0:${port}/mcp\n`);
  });
}
