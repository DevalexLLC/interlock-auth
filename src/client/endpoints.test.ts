import { expect, it } from "vitest";

import { resolveEndpoints } from "./endpoints.js";

it.each([undefined, "", "/", "/relative"])("%s selects the page origin", (uri) => {
  expect(resolveEndpoints(uri, { origin: "https://demo.test" })).toEqual({
    origin: "https://demo.test",
    authBaseURL: "https://demo.test/api/auth",
    socketURL: "wss://demo.test/ws/irongate",
  });
});
it.each([
  ["http", "ws"],
  ["https", "wss"],
])("absolute %s selects Interlock", (http, ws) => {
  expect(resolveEndpoints(`${http}://interlock.test/path`).socketURL).toBe(
    `${ws}://interlock.test/ws/irongate`,
  );
});
it("rejects unsupported schemes", () => {
  expect(() => resolveEndpoints("ftp://interlock.test")).toThrow(TypeError);
});
