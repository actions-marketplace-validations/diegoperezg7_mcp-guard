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
  // dist/action is the committed GitHub Action bundle, built by tsup.action.config.ts.
  clean: ["!action/**"],
  dts: { entry: { "core/index": "src/core/index.ts" } },
  banner: { js: "#!/usr/bin/env node" },
});
