/**
 * The reference server: what the vulnerable demos should have looked like.
 * Plain descriptions, every tool annotated, every argument constrained, and
 * over HTTP a loopback bind, Host/Origin validation and a bearer token.
 *
 *   node dist/examples/weather-safe.js                                   (stdio)
 *   MCP_DEMO_TOKEN=change-me node dist/examples/weather-safe.js --http   (http://127.0.0.1:3402/mcp)
 */
import { timingSafeEqual } from "node:crypto";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

import { isMain, statelessHttp } from "./shared.js";

const CITIES = ["zurich", "geneva", "madrid", "barcelona", "berlin"] as const;

/** Deterministic made-up forecast: the point of this server is its contract, not the weather. */
function forecast(city: (typeof CITIES)[number], days: number) {
  const base = city.length * 3;
  return Array.from({ length: days }, (_, i) => ({
    day: i + 1,
    highC: base + (i % 3),
    lowC: base - 6 + (i % 2),
  }));
}

export function buildServer(): McpServer {
  const server = new McpServer(
    { name: "weather-safe", version: "0.1.0" },
    { capabilities: { resources: {} } },
  );

  server.registerTool(
    "list_cities",
    {
      description: "List the cities that have a forecast.",
      inputSchema: {},
      annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: false },
    },
    async () => ({ content: [{ type: "text", text: CITIES.join(", ") }] }),
  );

  server.registerTool(
    "get_forecast",
    {
      description: "Daily high and low temperatures for one city, up to seven days ahead.",
      inputSchema: { city: z.enum(CITIES), days: z.number().int().min(1).max(7).default(3) },
      annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: false },
    },
    async ({ city, days }) => ({
      content: [{ type: "text", text: JSON.stringify(forecast(city, days)) }],
    }),
  );

  server.registerResource(
    "stations",
    "weather://stations",
    { description: "Weather stations behind the forecasts.", mimeType: "application/json" },
    async (uri) => ({
      contents: [
        {
          uri: uri.href,
          text: JSON.stringify(CITIES.map((c) => ({ city: c, station: `${c}-01` }))),
        },
      ],
    }),
  );

  return server;
}

function bearerMatches(header: string | undefined, token: string): boolean {
  const expected = Buffer.from(`Bearer ${token}`);
  const got = Buffer.from(header ?? "");
  return got.length === expected.length && timingSafeEqual(got, expected);
}

if (isMain(import.meta.url)) {
  if (process.argv.includes("--http")) {
    const token = process.env.MCP_DEMO_TOKEN;
    if (!token) {
      process.stderr.write("Set MCP_DEMO_TOKEN to the bearer token clients must send.\n");
      process.exit(1);
    }
    const port = Number(process.env.PORT ?? 3402);
    const app = statelessHttp(
      buildServer,
      {
        enableDnsRebindingProtection: true,
        allowedHosts: [`127.0.0.1:${port}`, `localhost:${port}`],
        allowedOrigins: [`http://127.0.0.1:${port}`, `http://localhost:${port}`],
      },
      (req) => bearerMatches(req.headers.authorization, token),
    );
    app.listen(port, "127.0.0.1", () =>
      process.stderr.write(`weather-safe on http://127.0.0.1:${port}/mcp\n`),
    );
  } else {
    await buildServer().connect(new StdioServerTransport());
  }
}
