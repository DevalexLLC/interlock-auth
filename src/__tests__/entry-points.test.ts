import { describe, expect, it } from "vitest";

// Pins the scaffold's contract: every published entry point loads and exports nothing. The item
// that fills an entry replaces its case here with real tests.
describe("entry points", () => {
  it.each([
    [".", async () => import("../index.js")],
    ["./next", async () => import("../next/index.js")],
    ["./react", async () => import("../react/index.js")],
  ])("%s is empty", async (_entry, load) => {
    const mod: object = await load();
    expect(Object.keys(mod)).toEqual([]);
  });
});
