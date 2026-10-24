/* global process, console */
// Regenerates the HTML report screenshots in docs/assets. Run after `npm run build`:
//   node docs/screenshots.mjs
// Scans the bundled demo servers, opens the HTML report in Chromium at
// 1440x900 @2x and fails if the page logs an error or a CSP violation.
import { execFileSync, spawn } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";
import { pathToFileURL } from "node:url";
import { chromium } from "playwright";

const out = "docs/assets";
const html = join(mkdtempSync(join(tmpdir(), "mcp-guard-shots-")), "report.html");

const ops = spawn(process.execPath, ["dist/examples/ops-toolbox.js"], { stdio: "ignore" });
await sleep(800);
try {
  try {
    execFileSync(
      process.execPath,
      [
        "dist/cli/index.js",
        "scan",
        "--stdio",
        "node dist/examples/poisoned-notes.js",
        "--http",
        "http://127.0.0.1:3401/mcp",
        "--json",
        "examples/exports/mail-server.json",
        "--probe",
        "--format",
        "json",
        "-r",
        html,
      ],
      { stdio: ["ignore", "ignore", "inherit"] },
    );
  } catch (err) {
    if (err.status !== 1) throw err; // 1 = findings, expected for the demos
  }
} finally {
  ops.kill();
}

const browser = await chromium.launch();
const problems = [];
async function page(colorScheme) {
  const context = await browser.newContext({
    viewport: { width: 1440, height: 900 },
    deviceScaleFactor: 2,
    colorScheme,
  });
  const p = await context.newPage();
  p.on("console", (m) => m.type() === "error" && problems.push(m.text()));
  p.on("pageerror", (e) => problems.push(e.message));
  await p.goto(pathToFileURL(html).href);
  await p.waitForSelector("details.finding");
  return p;
}

const light = await page("light");
await light.screenshot({ path: `${out}/report.png` });

const dark = await page("dark");
await dark.screenshot({ path: `${out}/report-dark.png` });

// A finding opened: hidden tag-character text revealed in the evidence.
const finding = light.locator("details.finding", { hasText: "MCPG-001" }).first();
await finding.locator("summary").click();
const item = light.locator(".item", { has: finding });
await item.scrollIntoViewIfNeeded();
await light.mouse.move(0, 0); // no cursor or hover state in the picture
await item.screenshot({ path: `${out}/report-finding.png` });

await browser.close();
if (problems.length) {
  console.error(problems.join("\n"));
  process.exit(1);
}
console.log(`screenshots written to ${out}`);
