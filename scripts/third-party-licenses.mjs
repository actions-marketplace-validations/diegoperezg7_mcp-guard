// Writes dist/action/licenses.txt with the license text of every production dependency bundled into the action.
/* global process */
import { execSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
const dirs = [
  ...new Set(
    execSync("npm ls --omit=dev --all --parseable", { encoding: "utf8" })
      .trim()
      .split("\n")
      .slice(1),
  ),
];
let out = "Third-party software bundled in dist/action/index.js\n\n";
for (const d of dirs.sort()) {
  const pj = JSON.parse(fs.readFileSync(path.join(d, "package.json"), "utf8"));
  const lf = fs.readdirSync(d).find((f) => /^(licen[cs]e|copying)/i.test(f));
  out +=
    "=".repeat(72) +
    `\n${pj.name}@${pj.version} (${pj.license || "see file"})\n` +
    "=".repeat(72) +
    "\n" +
    (lf ? fs.readFileSync(path.join(d, lf), "utf8").trim() : "(no license file shipped)") +
    "\n\n";
}
fs.writeFileSync("dist/action/licenses.txt", out);
process.stdout.write(dirs.length + " packages\n");
