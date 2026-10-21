import { expect, it } from "vitest";

import { backoffDelay } from "./backoff.js";

it.each([
  [0, 500],
  [1, 1000],
  [2, 2000],
  [20, 15000],
])("backoff attempt %i yields %i at half jitter", (attempt, expected) => {
  expect(backoffDelay(attempt, {}, () => 0.5)).toBe(expected);
});
it("jitter ranges from zero to its capped ceiling", () => {
  expect(backoffDelay(100, {}, () => 0)).toBe(0);
  expect(backoffDelay(100, {}, () => 1)).toBe(30000);
  expect(backoffDelay(2, { baseMs: 100, capMs: 300 }, () => 1)).toBe(300);
});
