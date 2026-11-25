import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { parseAst } from "vite";
import { describe, expect, it } from "vitest";

// A string literal, or a template literal with no substitutions; `null` for anything else.
const literal = (node: unknown): string | null => {
  const value = node as {
    type?: string;
    value?: unknown;
    expressions?: unknown[];
    quasis?: { value: { cooked?: string } }[];
  };
  if (value?.type === "Literal" && typeof value.value === "string") return value.value;
  if (value?.type === "TemplateLiteral" && value.expressions?.length === 0)
    return value.quasis?.[0]?.value.cooked ?? null;
  return null;
};

// Every module specifier in a TypeScript file, read from its syntax tree rather than its text, so
// comments, strings and regular expressions cannot hide or fake one. A specifier that is not a
// literal is returned as `null`: the scan cannot follow it, so the test refuses it.
const specifiersOf = (file: string): (string | null)[] => {
  const found: (string | null)[] = [];
  const walk = (node: unknown): void => {
    if (Array.isArray(node)) {
      for (const item of node) walk(item);
      return;
    }
    if (typeof node !== "object" || node === null) return;
    const n = node as Record<string, unknown> & { type?: string };
    switch (n.type) {
      case "ImportDeclaration":
      case "ExportAllDeclaration":
      case "ExportNamedDeclaration":
        if (n.source) found.push(literal(n.source));
        break;
      case "ImportExpression":
      case "TSImportType":
        found.push(literal(n.source));
        break;
      case "TSExternalModuleReference":
        found.push(literal(n.expression));
        break;
      case "CallExpression": {
        const callee = n.callee as { type?: string; name?: string };
        if (callee?.type === "Identifier" && callee.name === "require")
          found.push(literal((n.arguments as unknown[])[0]));
        break;
      }
      default:
        break;
    }
    for (const [key, value] of Object.entries(n)) if (key !== "type") walk(value);
  };
  walk(parseAst(readFileSync(file, "utf8"), { lang: file.endsWith(".tsx") ? "tsx" : "ts" }));
  return found;
};

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
      for (const specifier of specifiersOf(file)) {
        if (specifier === null) {
          unresolved.push(`${file.slice(src.length)}: a specifier that is not a literal`);
          continue;
        }
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
