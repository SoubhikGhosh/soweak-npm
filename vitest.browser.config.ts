import { defineConfig } from "vitest/config";

/**
 * Runs the same tests under a browser-like environment (`happy-dom`) to
 * verify the main entrypoint never touches Node-only globals.
 *
 * The `soweak/node` subpath is excluded — those tests live in
 * `tests/node/` and only run under the default Node config.
 */
export default defineConfig({
  test: {
    include: ["tests/**/*.test.ts"],
    exclude: ["tests/node/**", "tests/**/*.node.test.ts"],
    environment: "happy-dom",
  },
});
