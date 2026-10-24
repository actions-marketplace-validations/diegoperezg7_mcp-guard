import type { JsonSchema, ToolInfo } from "../types.js";
import { defineRule, REF, type Emit, type ScanContext } from "./types.js";

/** Splits snake_case, kebab-case and camelCase names into lowercase words. */
export function words(name: string): string[] {
  return name
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(Boolean);
}

const DESTRUCTIVE = new Set([
  "delete",
  "remove",
  "rm",
  "drop",
  "destroy",
  "purge",
  "truncate",
  "wipe",
  "erase",
  "kill",
  "terminate",
  "overwrite",
  "reset",
  "uninstall",
  "revoke",
  "unlink",
  "rmdir",
  "exec",
  "execute",
  "run",
  "shell",
  "eval",
]);

const WRITES = new Set([
  ...DESTRUCTIVE,
  "write",
  "create",
  "update",
  "set",
  "put",
  "post",
  "send",
  "upload",
  "move",
  "rename",
  "insert",
  "modify",
  "edit",
  "patch",
  "deploy",
  "publish",
  "transfer",
  "pay",
  "push",
  "merge",
  "install",
  "save",
  "append",
  "commit",
  "approve",
  "invite",
]);

function nameVerbs(tool: ToolInfo, vocabulary: Set<string>): string[] {
  return words(tool.name).filter((w) => vocabulary.has(w));
}

export const destructiveWithoutHint = defineRule(
  {
    id: "MCPG-020",
    name: "DestructiveWithoutHint",
    title: "Destructive tool without destructiveHint",
    category: "excessive-permissions",
    severity: "medium",
    mode: "static",
    description:
      "The tool name says it deletes, overwrites or executes, but the tool does not declare destructiveHint: true. Clients use the annotation to decide when to ask the user for confirmation; the spec's default is permissive and many clients only gate on an explicit true, so the call can run unattended.",
    remediation:
      "Declare the annotations explicitly: readOnlyHint: false, destructiveHint: true, and idempotentHint where it applies. Annotations are hints, so also enforce the dangerous part on the server.",
    bad: `{ "name": "delete_project", "annotations": {} }`,
    good: `{ "name": "delete_project", "annotations": { "readOnlyHint": false, "destructiveHint": true } }`,
    references: [REF.mcpTools, REF.owaspLlm06],
  },
  (ctx, emit) => {
    forEachTool(ctx, (server, tool) => {
      const verbs = nameVerbs(tool, DESTRUCTIVE);
      if (verbs.length === 0 || tool.annotations?.destructiveHint === true) return;
      if (tool.annotations?.readOnlyHint === true) return; // MCPG-021 reports the contradiction.
      emit({
        message: `Tool "${tool.name}" looks destructive ("${verbs.join('", "')}") but does not set destructiveHint: true.`,
        location: { server, kind: "tool", name: tool.name, field: "annotations" },
      });
    });
  },
);

export const misleadingReadOnly = defineRule(
  {
    id: "MCPG-021",
    name: "MisleadingReadOnlyHint",
    title: "Tool marked read-only but named for a write",
    category: "excessive-permissions",
    severity: "high",
    mode: "static",
    description:
      "readOnlyHint: true tells clients the tool cannot change anything, so they may auto-approve it, and mcp-guard --probe would call it. A name such as delete_, send_ or write_ contradicts the hint: either the name or the annotation is wrong, and a wrong read-only claim removes the user's last confirmation step.",
    remediation:
      "Set readOnlyHint: false (and destructiveHint as appropriate) for any tool with side effects, or rename the tool if it really only reads.",
    bad: `{ "name": "send_invoice", "annotations": { "readOnlyHint": true } }`,
    good: `{ "name": "send_invoice", "annotations": { "readOnlyHint": false, "destructiveHint": false, "openWorldHint": true } }`,
    references: [REF.mcpTools, REF.owaspLlm06],
  },
  (ctx, emit) => {
    forEachTool(ctx, (server, tool) => {
      if (tool.annotations?.readOnlyHint !== true) return;
      const verbs = nameVerbs(tool, WRITES);
      if (verbs.length === 0) return;
      emit({
        message: `Tool "${tool.name}" declares readOnlyHint: true but its name suggests a write ("${verbs.join('", "')}").`,
        location: { server, kind: "tool", name: tool.name, field: "annotations.readOnlyHint" },
      });
    });
  },
);

interface ArgClass {
  names: RegExp;
  /** Matches tool names that make an otherwise ambiguous argument dangerous. */
  toolNames?: RegExp;
  formats?: string[];
}

const COMMAND_ARG: ArgClass = {
  names:
    /^(command|cmd|commands|shell|script|bash|sh|exec|code|expression|expr|eval|sql|raw_sql|args?)$/i,
  toolNames: /(exec|shell|command|run|eval|script|sql|terminal|bash)/i,
};
const PATH_ARG: ArgClass = {
  names:
    /^(path|paths|file|files|filename|filepath|file_?path|dir|dirname|directory|folder|src|source|dest|destination|target|location|.*_path|.*Path|.*_dir|.*_file)$/,
};
const URL_ARG: ArgClass = {
  names:
    /^(url|uri|urls|endpoint|host|hostname|address|webhook|callback|link|href|.*_url|.*Url|.*_uri|.*_endpoint|.*_host)$/,
  formats: ["uri", "url", "iri", "hostname", "uri-reference"],
};

/** A string argument whose value the server accepts without any declared restriction. */
function unconstrainedStrings(
  schema: JsonSchema | undefined,
  cls: ArgClass,
  toolName: string,
): string[] {
  const out: string[] = [];
  const visit = (s: JsonSchema | undefined, path: string, name: string) => {
    if (!s || typeof s !== "object") return;
    if (s.properties) {
      for (const [k, sub] of Object.entries(s.properties)) visit(sub, `${path}.properties.${k}`, k);
    }
    const items = Array.isArray(s.items) ? s.items : s.items ? [s.items] : [];
    for (const [i, sub] of items.entries())
      visit(sub, `${path}.items${items.length > 1 ? `[${i}]` : ""}`, name);
    if (!name || !isString(s)) return;
    const matches =
      cls.names.test(name) ||
      (cls.formats !== undefined && typeof s.format === "string" && cls.formats.includes(s.format));
    if (!matches) return;
    // "code" and "args" are only command-like on a tool that runs things.
    if (cls.toolNames && /^(args?|code)$/i.test(name) && !cls.toolNames.test(toolName)) return;
    if (constrained(s)) return;
    out.push(path);
  };
  visit(schema, "inputSchema", "");
  return out;
}

function isString(s: JsonSchema): boolean {
  if (s.type === "string" || (Array.isArray(s.type) && s.type.includes("string"))) return true;
  return s.type === undefined && !s.properties && !s.items && !s.enum && s.const === undefined;
}

function constrained(s: JsonSchema): boolean {
  return s.enum !== undefined || s.const !== undefined || typeof s.pattern === "string";
}

function argRule(cls: ArgClass, label: string) {
  return (ctx: ScanContext, emit: Emit) => {
    forEachTool(ctx, (server, tool) => {
      for (const path of unconstrainedStrings(tool.inputSchema, cls, tool.name)) {
        const arg = path.split(".properties.").pop()!;
        emit({
          message: `Tool "${tool.name}" accepts ${label} "${arg}" with no enum, const or pattern.`,
          location: { server, kind: "tool", name: tool.name, field: path },
        });
      }
    });
  };
}

export const commandArgument = defineRule(
  {
    id: "MCPG-022",
    name: "UnconstrainedCommandArgument",
    title: "Free-form command or code argument",
    category: "excessive-permissions",
    severity: "high",
    mode: "static",
    description:
      "A string argument named like a shell command, script, SQL statement or expression, with no enum, const or pattern. Whatever text reaches the model (a web page, an email, another tool's output) can become a command on the host. Prompt injection turns into remote code execution.",
    remediation:
      "Expose specific operations instead of a generic runner (git_status rather than run_command), or restrict the argument with an enum of allowed commands. Run whatever executes in a sandbox with no credentials.",
    bad: `{ "name": "run_command", "inputSchema": { "properties": { "command": { "type": "string" } } } }`,
    good: `{ "name": "run_check", "inputSchema": { "properties": { "check": { "type": "string", "enum": ["lint", "test", "typecheck"] } } } }`,
    references: [REF.cwe(78, "OS Command Injection"), REF.owaspLlm06, REF.mcpSecurity],
  },
  argRule(COMMAND_ARG, "a command-like argument"),
);

export const pathArgument = defineRule(
  {
    id: "MCPG-023",
    name: "UnconstrainedPathArgument",
    title: "Filesystem path argument without a declared restriction",
    category: "excessive-permissions",
    severity: "medium",
    mode: "static",
    description:
      "A path argument with no pattern or enum. Nothing in the contract tells the client (or the reviewer) that the server limits it to a workspace, so ../../.ssh/id_rsa is as valid an input as notes/today.md. The server may well validate it; the scanner cannot see that, and neither can the user approving the tool.",
    remediation:
      "Resolve paths against an allowlisted root on the server and reject anything outside it after resolving symlinks. Declare the restriction in the schema, e.g. a pattern that forbids '..' and absolute paths.",
    bad: `"path": { "type": "string" }`,
    good: `"path": { "type": "string", "pattern": "^(?!/)(?!.*\\\\.\\\\.)[\\\\w./-]+$", "description": "Relative to the workspace root" }`,
    references: [REF.cwe(22, "Path Traversal"), REF.owaspLlm06],
  },
  argRule(PATH_ARG, "a path argument"),
);

export const urlArgument = defineRule(
  {
    id: "MCPG-024",
    name: "UnconstrainedUrlArgument",
    title: "URL or host argument without a declared restriction",
    category: "excessive-permissions",
    severity: "medium",
    mode: "static",
    description:
      "A URL or host argument the server will connect to, with no pattern or enum. Injected text can point it at cloud metadata endpoints (169.254.169.254), internal services or an attacker's collector. This is server-side request forgery driven by the model.",
    remediation:
      "Allowlist the hosts the tool may reach (enum or pattern in the schema, and the same check on the server). Block private, loopback and link-local ranges after DNS resolution.",
    bad: `"url": { "type": "string", "format": "uri" }`,
    good: `"url": { "type": "string", "pattern": "^https://api\\\\.example\\\\.com/" }`,
    references: [REF.cwe(918, "Server-Side Request Forgery (SSRF)"), REF.owaspLlm06],
  },
  argRule(URL_ARG, "a URL argument"),
);

export const missingAnnotations = defineRule(
  {
    id: "MCPG-025",
    name: "MissingToolAnnotations",
    title: "Tool declares no behaviour annotations",
    category: "excessive-permissions",
    severity: "low",
    mode: "static",
    description:
      "The tool has no readOnlyHint or destructiveHint. Clients then fall back to their own defaults, which differ between clients, and cannot tell a lookup from a deletion. mcp-guard --probe also skips it unless --allow-unsafe is given.",
    remediation:
      "Annotate every tool. A read-only lookup: readOnlyHint: true. Anything with side effects: readOnlyHint: false plus destructiveHint and idempotentHint.",
    bad: `{ "name": "get_forecast" }`,
    good: `{ "name": "get_forecast", "annotations": { "readOnlyHint": true, "openWorldHint": true } }`,
    references: [REF.mcpTools],
  },
  (ctx, emit) => {
    forEachTool(ctx, (server, tool) => {
      const a = tool.annotations;
      if (a?.readOnlyHint !== undefined || a?.destructiveHint !== undefined) return;
      emit({
        message: `Tool "${tool.name}" has no readOnlyHint or destructiveHint.`,
        location: { server, kind: "tool", name: tool.name, field: "annotations" },
      });
    });
  },
);

function forEachTool(ctx: ScanContext, fn: (server: string, tool: ToolInfo) => void): void {
  for (const s of ctx.servers) for (const t of s.tools) fn(s.name, t);
}
