import { defineConfig } from "tsup";

// The GitHub Action bundle: one self-contained file, committed to the repository,
// that the runner executes with no node_modules. `npm run build:action` regenerates
// it and CI fails if the committed copy is stale.
export default defineConfig({
  entry: { index: "src/action/index.ts" },
  format: ["esm"],
  platform: "node",
  target: "node22",
  outDir: "dist/action",
  noExternal: [/.*/],
  splitting: false,
  sourcemap: false,
  minify: false,
  clean: ["!licenses.txt"],
  dts: false,
  // Bundled CommonJS dependencies call require() for Node built-ins.
  banner: {
    js: 'import { createRequire as __mcpGuardCreateRequire } from "node:module";\nconst require = __mcpGuardCreateRequire(import.meta.url);',
  },
});
