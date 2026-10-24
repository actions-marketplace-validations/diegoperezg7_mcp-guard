import type { Finding, ServerInventory, Severity } from "../types.js";

export type RuleCategory =
  | "tool-poisoning"
  | "shadowing"
  | "excessive-permissions"
  | "secrets"
  | "transport"
  | "runtime"
  | "coverage";

export interface RuleReference {
  title: string;
  url: string;
}

/** Everything a reviewer needs to understand and fix a finding. Rendered into docs/rules.md and SARIF. */
export interface RuleMeta {
  id: string;
  /** PascalCase identifier, used as the SARIF rule name. */
  name: string;
  title: string;
  category: RuleCategory;
  severity: Severity;
  /** Static rules read the inventory; probe rules need `--probe` and live calls. */
  mode: "static" | "probe";
  description: string;
  remediation: string;
  bad: string;
  good: string;
  references: RuleReference[];
}

export interface ScanContext {
  servers: ServerInventory[];
}

export interface Rule extends RuleMeta {
  /** Probe rules have no static check; the probe raises their findings. */
  check?: (ctx: ScanContext) => Finding[];
}

export type Emit = (finding: Omit<Finding, "ruleId" | "severity">) => void;

export function defineRule(meta: RuleMeta, check?: (ctx: ScanContext, emit: Emit) => void): Rule {
  if (!check) return { ...meta };
  return {
    ...meta,
    check(ctx) {
      const out: Finding[] = [];
      check(ctx, (f) => out.push({ ruleId: meta.id, severity: meta.severity, ...f }));
      return out;
    },
  };
}

export const REF = {
  mcpSecurity: {
    title: "MCP specification: Security Best Practices",
    url: "https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices",
  },
  mcpTools: {
    title: "MCP specification: Tools (annotations and security considerations)",
    url: "https://modelcontextprotocol.io/specification/2025-06-18/server/tools",
  },
  mcpTransports: {
    title: "MCP specification: Transports (Streamable HTTP security warning)",
    url: "https://modelcontextprotocol.io/specification/2025-06-18/basic/transports",
  },
  mcpAuth: {
    title: "MCP specification: Authorization",
    url: "https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization",
  },
  owaspLlm01: {
    title: "OWASP Top 10 for LLM Applications 2025: LLM01 Prompt Injection",
    url: "https://genai.owasp.org/llmrisk/llm01-prompt-injection/",
  },
  owaspLlm02: {
    title: "OWASP Top 10 for LLM Applications 2025: LLM02 Sensitive Information Disclosure",
    url: "https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/",
  },
  owaspLlm06: {
    title: "OWASP Top 10 for LLM Applications 2025: LLM06 Excessive Agency",
    url: "https://genai.owasp.org/llmrisk/llm062025-excessive-agency/",
  },
  trojanSource: {
    title: "Trojan Source: Invisible Vulnerabilities (CVE-2021-42574)",
    url: "https://trojansource.codes/",
  },
  unicodeTags: {
    title: "Unicode Tags block (U+E0000 to U+E007F)",
    url: "https://www.unicode.org/charts/PDF/UE0000.pdf",
  },
  cwe: (id: number, name: string): RuleReference => ({
    title: `CWE-${id}: ${name}`,
    url: `https://cwe.mitre.org/data/definitions/${id}.html`,
  }),
} as const;
