import { Command, Option } from "commander";

import { getRule, RULES } from "../../core/rules/index.js";
import { rulesMarkdown } from "../../core/report/rulesDoc.js";
import { UsageError } from "./scan.js";

export function buildRulesCommand(): Command {
  return new Command("rules")
    .description("List the rules, or explain one: mcp-guard rules MCPG-002")
    .argument("[id]", "rule id")
    .addOption(
      new Option("-f, --format <format>", "output format")
        .choices(["table", "json", "markdown"])
        .default("table"),
    )
    .action((id: string | undefined, flags: { format: "table" | "json" | "markdown" }) => {
      process.stdout.write(renderRules(id, flags.format));
    });
}

export function renderRules(id: string | undefined, format: "table" | "json" | "markdown"): string {
  if (id) {
    const rule = getRule(id.toUpperCase());
    if (!rule) throw new UsageError(`Unknown rule ${id}. Run "mcp-guard rules" for the list.`);
    const { check: _check, ...meta } = rule;
    if (format === "json") return `${JSON.stringify(meta, null, 2)}\n`;
    return [
      `${rule.id} ${rule.title}`,
      `severity: ${rule.severity}   category: ${rule.category}   mode: ${rule.mode}`,
      "",
      rule.description,
      "",
      `Bad:   ${rule.bad}`,
      `Good:  ${rule.good}`,
      "",
      `Remediation: ${rule.remediation}`,
      "",
      ...rule.references.map((r) => `- ${r.title}: ${r.url}`),
      "",
    ].join("\n");
  }
  if (format === "json")
    return `${JSON.stringify(
      RULES.map(({ check: _check, ...meta }) => meta),
      null,
      2,
    )}\n`;
  if (format === "markdown") return rulesMarkdown();
  const rows = RULES.map((r) => [r.id, r.severity, r.category, r.mode, r.title]);
  const widths = [8, 8, 21, 6];
  const line = (cols: string[]) =>
    cols.map((c, i) => (i < widths.length ? c.padEnd(widths[i]!) : c)).join("  ");
  return `${[line(["ID", "SEVERITY", "CATEGORY", "MODE", "TITLE"]), ...rows.map(line)].join("\n")}\n`;
}
