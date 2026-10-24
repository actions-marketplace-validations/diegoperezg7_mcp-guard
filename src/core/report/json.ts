import type { ScanReport } from "../scan.js";

/** The full report, inventory included, for scripts and dashboards. */
export function toJson(report: ScanReport): string {
  return `${JSON.stringify(report, null, 2)}\n`;
}
