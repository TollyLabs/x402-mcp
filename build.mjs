// Bundles src/ into dist/index.js: one ESM file with a node shebang. The runtime dependencies
// stay external (npm installs them from package.json); the server reports the package version.
//   npm run build
import { readFileSync, rmSync } from "node:fs";
import { build } from "esbuild";

const pkg = JSON.parse(readFileSync(new URL("./package.json", import.meta.url), "utf8"));
const deps = Object.keys(pkg.dependencies ?? {});

rmSync(new URL("./dist", import.meta.url), { recursive: true, force: true });
await build({
  entryPoints: ["src/index.ts"],
  outfile: "dist/index.js",
  bundle: true,
  platform: "node",
  format: "esm",
  target: "node20",
  external: deps.flatMap((d) => [d, `${d}/*`]),
  banner: { js: "#!/usr/bin/env node" },
  define: { __TOLLY_MCP_VERSION__: JSON.stringify(pkg.version) },
  legalComments: "none",
});
console.log(`built dist/index.js (${pkg.version})`);
