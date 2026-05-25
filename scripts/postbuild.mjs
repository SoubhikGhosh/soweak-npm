/**
 * Post-build: writes `dist/cjs/package.json` and `dist/esm/package.json` so
 * Node treats the two trees correctly under hybrid resolution.
 */
import { writeFileSync, mkdirSync, existsSync } from "node:fs";

const stamps = [
  ["dist/cjs/package.json", { type: "commonjs" }],
  ["dist/esm/package.json", { type: "module" }],
];

for (const [path, content] of stamps) {
  const dir = path.split("/").slice(0, -1).join("/");
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true });
  }
  writeFileSync(path, JSON.stringify(content));
}

console.log("postbuild: stamped CJS / ESM package.json");
