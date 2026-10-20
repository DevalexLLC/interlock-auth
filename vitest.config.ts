import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    projects: [
      {
        test: {
          // The root entry's core runs on the server: Node's environment, and a timeout that
          // covers the refresher's lease waits and the transport's local TLS servers.
          name: "core",
          environment: "node",
          include: ["src/core/**/*.test.ts"],
          testTimeout: 30_000,
        },
      },
      {
        plugins: [react()],
        test: {
          name: "dom",
          environment: "jsdom",
          include: [
            "src/__tests__/**/*.test.ts",
            "src/react/**/*.test.{ts,tsx}",
            "src/next/**/*.test.{ts,tsx}",
          ],
        },
      },
    ],
    coverage: {
      provider: "v8",
      // `lcov` is what the SonarQube scanner reads; `text` keeps the numbers
      // visible in the CI log without opening an artifact.
      reporter: ["text", "lcov"],
      // Default `include` is only files touched by a test, which would hide an
      // entirely untested module from the coverage figure Sonar records.
      include: ["src/**/*.{ts,tsx}"],
      // The specs and their helpers under `__tests__` are test code. The entry
      // barrels re-export and nothing else, so their coverage is noise; they
      // are named one by one, because `src/core/database/migrations/index.ts`
      // is code.
      exclude: [
        "src/**/*.test.ts",
        "src/**/*.test.tsx",
        "src/**/__tests__/**",
        "src/index.ts",
        "src/next/index.ts",
        "src/react/index.ts",
      ],
    },
  },
});
