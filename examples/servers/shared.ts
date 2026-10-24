import { realpathSync } from "node:fs";
import { createServer, type IncomingMessage, type Server } from "node:http";
import { fileURLToPath } from "node:url";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import {
  StreamableHTTPServerTransport,
  type StreamableHTTPServerTransportOptions,
} from "@modelcontextprotocol/sdk/server/streamableHttp.js";

export function isMain(moduleUrl: string): boolean {
  if (!process.argv[1]) return false;
  try {
    return realpathSync(process.argv[1]) === realpathSync(fileURLToPath(moduleUrl));
  } catch {
    return false;
  }
}

async function readJson(req: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > 1_000_000) throw new Error("body too large");
    chunks.push(chunk as Buffer);
  }
  const raw = Buffer.concat(chunks).toString("utf8");
  return raw.trim() ? JSON.parse(raw) : undefined;
}

/**
 * Stateless Streamable HTTP: one McpServer and transport per POST at /mcp.
 * `authorize` runs before anything else; return false to answer 401.
 */
export function statelessHttp(
  build: () => McpServer,
  transportOptions: Omit<StreamableHTTPServerTransportOptions, "sessionIdGenerator"> = {},
  authorize: (req: IncomingMessage) => boolean = () => true,
): Server {
  return createServer(async (req, res) => {
    if ((req.url ?? "").split("?")[0] !== "/mcp") {
      res.writeHead(404).end();
      return;
    }
    if (!authorize(req)) {
      res.writeHead(401, { "www-authenticate": 'Bearer realm="mcp"' }).end();
      return;
    }
    if (req.method !== "POST") {
      res.writeHead(405, { allow: "POST" }).end();
      return;
    }
    const server = build();
    const transport = new StreamableHTTPServerTransport({
      ...transportOptions,
      sessionIdGenerator: undefined,
    });
    res.on("close", () => {
      void transport.close();
      void server.close();
    });
    try {
      const body = await readJson(req);
      await server.connect(transport);
      await transport.handleRequest(req, res, body);
    } catch {
      if (!res.headersSent) res.writeHead(400).end();
    }
  });
}
