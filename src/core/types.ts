/** What the scanner knows about one MCP server, however it was obtained. */
export interface ServerInventory {
  /** Label used in findings; unique within a scan. */
  name: string;
  source: TargetSource;
  /** serverInfo reported in the initialize handshake, when connected live. */
  serverInfo?: { name: string; version: string };
  instructions?: string;
  tools: ToolInfo[];
  resources: ResourceInfo[];
  resourceTemplates: ResourceTemplateInfo[];
  prompts: PromptInfo[];
  /** Facts gathered by the HTTP transport checks; absent for stdio and JSON. */
  transport?: TransportFacts;
}

export type TargetSource =
  | { kind: "stdio"; command: string; args: string[] }
  | { kind: "http"; url: string }
  | { kind: "json"; path: string };

export interface ToolAnnotations {
  title?: string;
  readOnlyHint?: boolean;
  destructiveHint?: boolean;
  idempotentHint?: boolean;
  openWorldHint?: boolean;
}

export interface ToolInfo {
  name: string;
  title?: string;
  description?: string;
  inputSchema?: JsonSchema;
  outputSchema?: JsonSchema;
  annotations?: ToolAnnotations;
}

export interface ResourceInfo {
  uri: string;
  name: string;
  title?: string;
  description?: string;
  mimeType?: string;
}

export interface ResourceTemplateInfo {
  uriTemplate: string;
  name: string;
  title?: string;
  description?: string;
  mimeType?: string;
}

export interface PromptInfo {
  name: string;
  title?: string;
  description?: string;
  arguments?: { name: string; description?: string; required?: boolean }[];
}

/** A JSON Schema object as servers send it. Only the keywords the rules read are typed. */
export interface JsonSchema {
  type?: string | string[];
  description?: string;
  title?: string;
  properties?: Record<string, JsonSchema>;
  items?: JsonSchema | JsonSchema[];
  required?: string[];
  enum?: unknown[];
  const?: unknown;
  pattern?: string;
  format?: string;
  maxLength?: number;
  default?: unknown;
  examples?: unknown[];
  anyOf?: JsonSchema[];
  oneOf?: JsonSchema[];
  allOf?: JsonSchema[];
  [keyword: string]: unknown;
}

export interface TransportFacts {
  url: string;
  /** True when the URL host is localhost, 127.0.0.0/8 or ::1. */
  loopback: boolean;
  tls: boolean;
  /** The client sent credentials (--header) to get in. */
  credentialsSupplied: boolean;
  /** initialize succeeded with no credentials at all. */
  acceptsAnonymous?: boolean;
  /** initialize succeeded with a Host and Origin of an attacker-controlled site. */
  acceptsForeignHost?: boolean;
  /** Non-loopback addresses of this machine where the same port answered initialize. */
  reachableOn?: string[];
}

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export const SEVERITIES: readonly Severity[] = ["critical", "high", "medium", "low", "info"];

export function severityRank(s: Severity): number {
  return SEVERITIES.length - SEVERITIES.indexOf(s);
}

/** Where in the inventory a finding points. */
export interface FindingLocation {
  server: string;
  kind: "tool" | "resource" | "resource-template" | "prompt" | "server" | "transport";
  /** Tool, resource or prompt name; server name for server-level findings. */
  name: string;
  /** Dotted path inside the item, e.g. "description" or "inputSchema.properties.path". */
  field?: string;
}

export interface Finding {
  ruleId: string;
  severity: Severity;
  message: string;
  location: FindingLocation;
  /** The offending text, trimmed and with invisible characters made visible. */
  evidence?: string;
  /** Optional LLM classification. Informational only; it never changes severity. */
  judge?: { verdict: "benign" | "suspicious" | "malicious"; reason: string; model: string };
}
