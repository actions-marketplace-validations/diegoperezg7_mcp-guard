import { defineConfig } from "tsup";

export default defineConfig({
  entry: {
    "cli/index": "src/cli/index.ts",
    "core/index": "src/core/index.ts",
    "examples/poisoned-notes": "examples/servers/poisoned-notes.ts",
    "examples/ops-toolbox": "examples/servers/ops-toolbox.ts",
    "examples/weather-safe": "examples/servers/weather-safe.ts",
  },
  format: ["esm"],
  target: "node22",
  outDir: "dist",
  splitting: false,
  sourcemap: true,
  clean: true,
  dts: { entry: { "core/index": "src/core/index.ts" } },
  banner: { js: "#!/usr/bin/env node" },
});
