import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

// Comments, removed before the scan so that one inside a multi-line import cannot hide it. String
// literals are matched first and kept, so a `/*` or `//` inside one ("sites/*", a URL) is not read
// as a comment and cannot erase the code after it.
const COMMENTS_OR_STRINGS =
  /("(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*'|`(?:\\.|[^`\\])*`)|\/\*[\s\S]*?\*\/|\/\/[^\n]*/g;
const withoutComments = (text: string): string =>
  text.replaceAll(COMMENTS_OR_STRINGS, (_match, literal?: string) => literal ?? "");

// The specifier of an `import`/`export … from` clause, a side-effect `import "x"`, a dynamic
// `import(…)`, or a `require(…)` (`import x = require(…)` included), with a string or template
// literal. A `from` must be followed by the literal, so `Array.from("x")` is not read as an import.
// A string that merely contains `from "x"` is read as one, which fails the test rather than
// passing it.
const IMPORT_SPECIFIER =
  /\bfrom\s*["'`]([^"'`]+)["'`]|\bimport\s*["'`]([^"'`]+)["'`]|\b(?:import|require)\s*\(\s*["'`]([^"'`]+)["'`]/g;

// A relative specifier names the emitted `.js`; its source is `.ts` or `.tsx`, or a folder's
// `index`. One that resolves to none of them is reported, not thrown on.
const sourceOf = (from: string, specifier: string): string | undefined => {
  const target = path.resolve(path.dirname(from), specifier.replace(/\.js$/, ""));
  return [".ts", ".tsx", "/index.ts", "/index.tsx"]
    .map((suffix) => target + suffix)
    .find((candidate) => existsSync(candidate));
};

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

    expect(Object.keys(claims).toSorted()).toEqual([
      "MalformedClaimError",
      "isMalformedClaimError",
      "normalizeClaims",
    ]);
    expect(root.normalizeClaims).toBe(claims.normalizeClaims);
    expect(root.MalformedClaimError).toBe(claims.MalformedClaimError);
  });

  // A backend installs `./claims` without Better Auth, Kysely, or React, which are optional peers.
  // Every module the entry reaches must therefore import only other package files.
  it("./claims reaches no package outside its own files", () => {
    const src = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
    const seen = new Set<string>();
    const bare: string[] = [];
    const unresolved: string[] = [];
    const visit = (file: string): void => {
      if (seen.has(file)) return;
      seen.add(file);
      const text = withoutComments(readFileSync(file, "utf8"));
      for (const [, fromClause, sideEffect, dynamic] of text.matchAll(IMPORT_SPECIFIER)) {
        const specifier = fromClause ?? sideEffect ?? dynamic;
        if (specifier === undefined) continue;
        if (!specifier.startsWith(".")) {
          bare.push(`${file.slice(src.length)}: ${specifier}`);
          continue;
        }
        const source = sourceOf(file, specifier);
        if (source === undefined) unresolved.push(`${file.slice(src.length)}: ${specifier}`);
        else visit(source);
      }
    };
    visit(path.resolve(src, "claims/index.ts"));

    expect(seen.size).toBeGreaterThan(1);
    expect(bare).toEqual([]);
    expect(unresolved).toEqual([]);
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
