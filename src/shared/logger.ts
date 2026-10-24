import pino from "pino";

/**
 * Every log line goes to stderr (fd 2), so stdout carries only the report and
 * `mcp-guard scan --format sarif > results.sarif` stays valid JSON.
 */
export const logger = pino(
  {
    level: process.env.LOG_LEVEL ?? "warn",
    base: { service: "mcp-guard" },
    timestamp: pino.stdTimeFunctions.isoTime,
  },
  pino.destination(2),
);
