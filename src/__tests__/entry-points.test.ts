import { describe, expect, it } from "vitest";

// Pins the entry points' contract. The root entry carries the core; the entries not yet filled
// load and export nothing, and the item that fills one replaces its case here with real tests.
describe("entry points", () => {
  it(". exports the core", async () => {
    const mod = await import("../index.js");

    expect(mod.createKeycloakAuthOptions).toBeInstanceOf(Function);
    expect(mod.normalizeClaims).toBeInstanceOf(Function);
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
