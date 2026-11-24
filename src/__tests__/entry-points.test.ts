import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

// Pins the entry points' contract. The root entry carries the core; the entries not yet filled
// load and export nothing, and the item that fills one replaces its case here with real tests.
describe("entry points", () => {
  it(". exports the core", async () => {
    const mod = await import("../index.js");

    expect(mod.createKeycloakAuthOptions).toBeInstanceOf(Function);
    expect(mod.normalizeClaims).toBeInstanceOf(Function);
    expect(mod.MalformedClaimError).toBeInstanceOf(Function);
  });

  it("./claims exports claim normalization, the same code the root entry re-exports", async () => {
    const claims = await import("../claims/index.js");
    const root = await import("../index.js");

    expect(Object.keys(claims).toSorted()).toEqual(["MalformedClaimError", "normalizeClaims"]);
    expect(root.normalizeClaims).toBe(claims.normalizeClaims);
    expect(root.MalformedClaimError).toBe(claims.MalformedClaimError);
  });

  // A backend installs `./claims` without Better Auth, Kysely, or React, which are optional peers.
  // Every module the entry reaches must therefore import only other package files.
  it("./claims reaches no package outside its own files", () => {
    const src = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
    const seen = new Set<string>();
    const bare: string[] = [];
    const visit = (file: string): void => {
      if (seen.has(file)) return;
      seen.add(file);
      const text = readFileSync(file, "utf8");
      for (const [, specifier] of text.matchAll(/(?:from|import)\s*\(?\s*["']([^"']+)["']/g)) {
        if (specifier === undefined) continue;
        if (specifier.startsWith("."))
          visit(path.resolve(path.dirname(file), specifier.replace(/\.js$/, ".ts")));
        else bare.push(`${file.slice(src.length)}: ${specifier}`);
      }
    };
    visit(path.resolve(src, "claims/index.ts"));

    expect(seen.size).toBeGreaterThan(1);
    expect(bare).toEqual([]);
  });

  it.each([["./next", async () => import("../next/index.js")]])(
    "%s is empty",
    async (_entry, load) => {
      const mod: object = await load();
      expect(Object.keys(mod)).toEqual([]);
    },
  );
});

it("./react exports the provider, hooks, and framework-free factories", async () => {
  const mod = await import("../react/index.js");
  for (const name of [
    "InterlockProvider",
    "useInterlockSession",
    "useInterlockFetch",
    "useCatalogClient",
    "useNotificationSocket",
    "useSocketEvent",
    "createSessionController",
    "createSocketConnector",
    "classifyResponse",
  ] as const)
    expect(mod[name]).toBeInstanceOf(Function);
});
