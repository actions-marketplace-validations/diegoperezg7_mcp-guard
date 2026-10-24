import { analyze } from "../src/core/scan.js";
import type { Finding, ServerInventory, ToolInfo, TransportFacts } from "../src/core/types.js";

export function server(
  name: string,
  tools: ToolInfo[],
  extra: Partial<ServerInventory> = {},
): ServerInventory {
  return {
    name,
    source: { kind: "json", path: `${name}.json` },
    tools,
    resources: [],
    resourceTemplates: [],
    prompts: [],
    ...extra,
  };
}

/** A tool that passes every static rule; tests override one property at a time. */
export function tool(name: string, overrides: Partial<ToolInfo> = {}): ToolInfo {
  return {
    name,
    description: "Returns the current status of the build.",
    inputSchema: { type: "object", properties: {} },
    annotations: { readOnlyHint: true },
    ...overrides,
  };
}

export function httpServer(
  facts: Omit<TransportFacts, "credentialsSupplied"> & { credentialsSupplied?: boolean },
) {
  return server("remote", [tool("status")], {
    source: { kind: "http", url: facts.url },
    transport: { credentialsSupplied: false, ...facts },
  });
}

export function findingsFor(ruleId: string, ...servers: ServerInventory[]): Finding[] {
  return analyze(servers).filter((f) => f.ruleId === ruleId);
}

/** Builds strings shaped like credentials at runtime so secret scanners do not flag the test sources. */
export const fake = {
  awsKeyId: () => ["AK", "IA", "Z7Q4M2X9P1L8K3J6"].join(""),
  githubToken: () => ["gh", "p_", "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"].join(""),
  privateKeyHeader: () => ["-----BEGIN ", "OPENSSH PRIVATE", " KEY-----"].join(""),
  dbUrl: () => ["postgres://app:", "Xk9#mQ2vLp7w", "@db.internal:5432/app"].join(""),
  highEntropy: () => ["Zk3pQ9vX", "2mL7tR4wB8nY"].join(""),
};
