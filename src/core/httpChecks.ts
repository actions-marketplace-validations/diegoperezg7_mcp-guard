import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { networkInterfaces } from "node:os";

import { logger } from "../shared/logger.js";
import { VERSION } from "../shared/version.js";
import type { TransportFacts } from "./types.js";

/** A domain under the reserved .invalid TLD: it can never resolve to anything real. */
export const FOREIGN_HOST = "rebind-check.mcp-guard.invalid";

export function isLoopbackHost(hostname: string): boolean {
  const h = hostname.replace(/^\[|\]$/g, "").toLowerCase();
  return (
    h === "localhost" || h.endsWith(".localhost") || h === "::1" || /^127(\.\d{1,3}){3}$/.test(h)
  );
}

/**
 * Transport facts for an HTTP target, from plain initialize requests. None of
 * them calls a tool: the worst a check can do is open a session, which is
 * deleted straight away.
 */
export async function checkHttpTransport(
  url: string,
  headers: Record<string, string>,
  timeoutMs: number,
): Promise<TransportFacts> {
  const u = new URL(url);
  const loopback = isLoopbackHost(u.hostname);
  const credentialsSupplied = Object.keys(headers).length > 0;
  const facts: TransportFacts = {
    url,
    loopback,
    tls: u.protocol === "https:",
    credentialsSupplied,
  };

  facts.acceptsAnonymous = credentialsSupplied ? await initializeAccepted(u, {}, timeoutMs) : true;

  if (loopback) {
    const port = u.port || (u.protocol === "https:" ? "443" : "80");
    facts.acceptsForeignHost = await initializeAccepted(
      u,
      { ...headers, host: `${FOREIGN_HOST}:${port}`, origin: `http://${FOREIGN_HOST}` },
      timeoutMs,
    );
    const reachable: string[] = [];
    for (const address of lanAddresses()) {
      const alt = new URL(u);
      alt.hostname = address.includes(":") ? `[${address}]` : address;
      if (await initializeAccepted(alt, {}, Math.min(timeoutMs, 2000))) reachable.push(alt.host);
    }
    facts.reachableOn = reachable;
  }
  return facts;
}

function lanAddresses(): string[] {
  return Object.values(networkInterfaces())
    .flat()
    .filter((i): i is NonNullable<typeof i> => !!i && !i.internal && i.family === "IPv4")
    .map((i) => i.address);
}

const INITIALIZE = JSON.stringify({
  jsonrpc: "2.0",
  id: 1,
  method: "initialize",
  params: {
    protocolVersion: "2025-06-18",
    capabilities: {},
    clientInfo: { name: "mcp-guard-transport-check", version: VERSION },
  },
});

/** True when the endpoint answered initialize with a JSON-RPC result. */
export async function initializeAccepted(
  url: URL,
  headers: Record<string, string>,
  timeoutMs: number,
): Promise<boolean> {
  try {
    const res = await post(url, INITIALIZE, headers, timeoutMs);
    const ok =
      res.status === 200 && /"result"\s*:/.test(res.body) && /protocolVersion/.test(res.body);
    const session = res.headers["mcp-session-id"];
    if (ok && typeof session === "string") {
      await post(url, "", { ...headers, "mcp-session-id": session }, timeoutMs, "DELETE").catch(
        () => {},
      );
    }
    return ok;
  } catch (err) {
    logger.debug({ url: url.href, err }, "transport check request failed");
    return false;
  }
}

interface RawResponse {
  status: number;
  headers: Record<string, string | string[] | undefined>;
  body: string;
}

/** node:http rather than fetch: fetch does not allow overriding the Host header. */
function post(
  url: URL,
  body: string,
  headers: Record<string, string>,
  timeoutMs: number,
  method = "POST",
): Promise<RawResponse> {
  const send = url.protocol === "https:" ? httpsRequest : httpRequest;
  return new Promise((resolve, reject) => {
    const req = send(
      url,
      {
        method,
        timeout: timeoutMs,
        headers: {
          "content-type": "application/json",
          accept: "application/json, text/event-stream",
          "mcp-protocol-version": "2025-06-18",
          ...headers,
        },
      },
      (res) => {
        let data = "";
        res.setEncoding("utf8");
        res.on("data", (chunk: string) => {
          // An initialize result is small; stop reading anything that is not.
          if (data.length < 64_000) data += chunk;
          else res.destroy();
        });
        res.on("end", () =>
          resolve({ status: res.statusCode ?? 0, headers: res.headers, body: data }),
        );
        res.on("error", reject);
      },
    );
    req.on("timeout", () => req.destroy(new Error("timeout")));
    req.on("error", reject);
    req.end(body);
  });
}
