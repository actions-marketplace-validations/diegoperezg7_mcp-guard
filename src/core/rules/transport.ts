import type { ServerInventory, TransportFacts } from "../types.js";
import { defineRule, REF, type Emit } from "./types.js";

function forEachHttp(
  servers: ServerInventory[],
  fn: (s: ServerInventory, t: TransportFacts) => void,
) {
  for (const s of servers) if (s.transport) fn(s, s.transport);
}

const at = (server: string, field: string) =>
  ({ server, kind: "transport", name: server, field }) as const;

export const plaintextHttp = defineRule(
  {
    id: "MCPG-040",
    name: "PlaintextRemoteTransport",
    title: "Remote MCP endpoint over plain HTTP",
    category: "transport",
    severity: "high",
    mode: "static",
    description:
      "The server is reached over http:// on a host that is not loopback. Tool calls, results and any bearer token travel in clear text and can be read or rewritten by anyone on the path, including tool descriptions, which makes it a poisoning vector of its own.",
    remediation:
      "Serve the endpoint over HTTPS (a reverse proxy such as Caddy or a tunnel is enough) and refuse plain HTTP outside localhost.",
    bad: `http://10.0.0.12:8080/mcp`,
    good: `https://mcp.example.com/mcp`,
    references: [
      REF.cwe(319, "Cleartext Transmission of Sensitive Information"),
      REF.mcpTransports,
    ],
  },
  (ctx, emit) =>
    forEachHttp(ctx.servers, (s, t) => {
      if (t.tls || t.loopback) return;
      emit({
        message: `${t.url} is plain HTTP on a non-loopback host.`,
        location: at(s.name, "url"),
      });
    }),
);

export const exposedWithoutAuth = defineRule(
  {
    id: "MCPG-041",
    name: "ExposedOnNetworkWithoutAuth",
    title: "Local server reachable from the network without authentication",
    category: "transport",
    severity: "high",
    mode: "static",
    description:
      "The endpoint was given as localhost, but the same port also answered an anonymous initialize on one of this machine's network addresses: the server is bound to 0.0.0.0 (or ::). Anyone on the same network, cafe Wi-Fi included, can list and call its tools.",
    remediation:
      "Bind to 127.0.0.1 for local use. If the server must be reachable from other hosts, require authentication (OAuth per the MCP authorization spec, or at least a bearer token) and TLS.",
    bad: `app.listen(3000, "0.0.0.0")   // no auth`,
    good: `app.listen(3000, "127.0.0.1")`,
    references: [
      REF.cwe(306, "Missing Authentication for Critical Function"),
      REF.mcpTransports,
      REF.mcpAuth,
    ],
  },
  (ctx, emit) =>
    forEachHttp(ctx.servers, (s, t) => {
      if (!t.reachableOn?.length) return;
      emit({
        message: `${t.url} also answers without credentials on ${t.reachableOn.join(", ")}.`,
        location: at(s.name, "bind"),
      });
    }),
);

export const missingRebindingProtection = defineRule(
  {
    id: "MCPG-042",
    name: "MissingDnsRebindingProtection",
    title: "Local server accepts requests for a foreign Host",
    category: "transport",
    severity: "medium",
    mode: "static",
    description:
      "mcp-guard sent initialize with Host and Origin set to an unrelated domain and the server accepted it. A web page the user visits can then use DNS rebinding to reach the local server from the browser and call its tools. The MCP transport spec requires servers to validate Origin for this reason.",
    remediation:
      "Validate the Host and Origin headers against an allowlist. With the TypeScript SDK: enableDnsRebindingProtection: true with allowedHosts: ['127.0.0.1:3000', 'localhost:3000'].",
    bad: `new StreamableHTTPServerTransport({ sessionIdGenerator: undefined })`,
    good: `new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableDnsRebindingProtection: true, allowedHosts: ["127.0.0.1:3000"] })`,
    references: [
      REF.mcpTransports,
      REF.cwe(350, "Reliance on Reverse DNS Resolution for a Security-Critical Action"),
    ],
  },
  (ctx, emit) =>
    forEachHttp(ctx.servers, (s, t) => {
      if (!t.loopback || !t.acceptsForeignHost) return;
      emit({
        message: `${t.url} accepted initialize with Host and Origin set to a foreign domain.`,
        location: at(s.name, "host-validation"),
      });
    }),
);

export const remoteWithoutAuth = defineRule(
  {
    id: "MCPG-043",
    name: "RemoteWithoutAuth",
    title: "Remote server accepts anonymous clients",
    category: "transport",
    severity: "medium",
    mode: "static",
    description:
      "A non-loopback endpoint completed initialize and listed its tools without any credentials. That can be intended for a public, read-only server; for anything that reaches private data or has side effects it means anyone who finds the URL has the same access as the user.",
    remediation:
      "Require authorization (OAuth 2.1 as described in the MCP authorization spec, or a bearer token behind TLS). If the server is deliberately public, make every tool read-only and rate-limit it.",
    bad: `POST https://mcp.example.com/mcp (no Authorization header) -> 200`,
    good: `POST https://mcp.example.com/mcp (no Authorization header) -> 401 with WWW-Authenticate`,
    references: [REF.mcpAuth, REF.cwe(306, "Missing Authentication for Critical Function")],
  },
  (ctx, emit: Emit) =>
    forEachHttp(ctx.servers, (s, t) => {
      if (t.loopback || !t.acceptsAnonymous) return;
      emit({ message: `${t.url} lists tools without credentials.`, location: at(s.name, "auth") });
    }),
);
