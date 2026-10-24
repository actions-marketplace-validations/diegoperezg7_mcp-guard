import { describe, expect, it } from "vitest";

import { findSecrets, redactSecrets, shannonEntropy } from "../../src/core/secrets.js";
import { fake, findingsFor, server, tool } from "../helpers.js";

describe("secret detectors", () => {
  it.each([
    ["AWS access key id", fake.awsKeyId()],
    ["GitHub token", fake.githubToken()],
    ["private key", fake.privateKeyHeader()],
    ["password in a URL", fake.dbUrl()],
  ])("detects a %s", (kind, value) => {
    expect(findSecrets(`config: ${value}`).map((h) => h.kind)).toContain(kind);
  });

  it("requires entropy for generic assignments", () => {
    expect(findSecrets("password: correcthorsebatterystaple")).toEqual([]);
    expect(findSecrets(`api_key=${fake.highEntropy()}`)).toHaveLength(1);
  });

  it("never returns the raw secret", () => {
    const token = fake.githubToken();
    const [hit] = findSecrets(token);
    expect(hit?.redacted).not.toContain(token.slice(8));
    expect(redactSecrets(`token=${token}`)).not.toContain(token.slice(8));
  });

  it("measures entropy in bits per character", () => {
    expect(shannonEntropy("aaaa")).toBe(0);
    expect(shannonEntropy("abcd")).toBe(2);
  });
});

describe("MCPG-030 secret in metadata", () => {
  it("flags credentials in schema defaults and resource descriptions", () => {
    const s = server(
      "s",
      [
        tool("connect", {
          inputSchema: {
            type: "object",
            properties: { dsn: { type: "string", default: fake.dbUrl() } },
          },
        }),
      ],
      { resources: [{ uri: "cfg://x", name: "x", description: `deploy key ${fake.awsKeyId()}` }] },
    );
    const found = findingsFor("MCPG-030", s);
    expect(found.map((f) => f.location.kind).sort()).toEqual(["resource", "tool"]);
    expect(JSON.stringify(found)).not.toContain(fake.awsKeyId());
  });

  it("does not flag placeholders", () => {
    const s = server("s", [
      tool("connect", { description: "Set API_KEY=<your key> on the server. password: changeme" }),
    ]);
    expect(findingsFor("MCPG-030", s)).toEqual([]);
  });
});
