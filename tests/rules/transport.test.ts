import { describe, expect, it } from "vitest";

import { isLoopbackHost } from "../../src/core/httpChecks.js";
import { findingsFor, httpServer, server, tool } from "../helpers.js";

describe("loopback detection", () => {
  it.each(["localhost", "127.0.0.1", "127.1.2.3", "[::1]", "api.localhost"])(
    "%s is loopback",
    (h) => {
      expect(isLoopbackHost(h)).toBe(true);
    },
  );
  it.each(["10.0.0.5", "0.0.0.0", "example.com", "127.example.com"])("%s is not", (h) => {
    expect(isLoopbackHost(h)).toBe(false);
  });
});

describe("MCPG-040 plaintext remote", () => {
  it("flags http:// on a remote host", () => {
    expect(
      findingsFor(
        "MCPG-040",
        httpServer({ url: "http://10.0.0.5/mcp", loopback: false, tls: false }),
      ),
    ).toHaveLength(1);
  });
  it("accepts https and plain http on loopback", () => {
    expect(
      findingsFor(
        "MCPG-040",
        httpServer({ url: "https://mcp.example.com/mcp", loopback: false, tls: true }),
      ),
    ).toEqual([]);
    expect(
      findingsFor(
        "MCPG-040",
        httpServer({ url: "http://127.0.0.1/mcp", loopback: true, tls: false }),
      ),
    ).toEqual([]);
  });
  it("does not apply to stdio or exported servers", () => {
    expect(findingsFor("MCPG-040", server("s", [tool("t")]))).toEqual([]);
  });
});

describe("MCPG-041 exposed on the network", () => {
  it("flags a loopback URL that also answers on a LAN address", () => {
    const s = httpServer({
      url: "http://127.0.0.1:3000/mcp",
      loopback: true,
      tls: false,
      reachableOn: ["192.168.1.20:3000"],
    });
    expect(findingsFor("MCPG-041", s)[0]?.message).toContain("192.168.1.20:3000");
  });
  it("is quiet when nothing else answered", () => {
    expect(
      findingsFor(
        "MCPG-041",
        httpServer({
          url: "http://127.0.0.1:3000/mcp",
          loopback: true,
          tls: false,
          reachableOn: [],
        }),
      ),
    ).toEqual([]);
  });
});

describe("MCPG-042 DNS rebinding", () => {
  it("flags a loopback server that accepts a foreign Host", () => {
    const s = httpServer({
      url: "http://127.0.0.1:3000/mcp",
      loopback: true,
      tls: false,
      acceptsForeignHost: true,
    });
    expect(findingsFor("MCPG-042", s)).toHaveLength(1);
  });
  it("is quiet when the Host is validated", () => {
    const s = httpServer({
      url: "http://127.0.0.1:3000/mcp",
      loopback: true,
      tls: false,
      acceptsForeignHost: false,
    });
    expect(findingsFor("MCPG-042", s)).toEqual([]);
  });
});

describe("MCPG-043 remote without auth", () => {
  it("flags a remote server that lists tools anonymously", () => {
    const s = httpServer({
      url: "https://mcp.example.com/mcp",
      loopback: false,
      tls: true,
      acceptsAnonymous: true,
    });
    expect(findingsFor("MCPG-043", s)).toHaveLength(1);
  });
  it("is quiet when credentials were required", () => {
    const s = httpServer({
      url: "https://mcp.example.com/mcp",
      loopback: false,
      tls: true,
      acceptsAnonymous: false,
      credentialsSupplied: true,
    });
    expect(findingsFor("MCPG-043", s)).toEqual([]);
  });
});
