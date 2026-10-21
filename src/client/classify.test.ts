import { describe, expect, it } from "vitest";

import { rejected, unauthorized, unavailable } from "./__tests__/helpers/responses.js";
import { classifyResponse } from "./classify.js";

describe("response contract", () => {
  it.each([undefined, "refresh_indeterminate"] as const)(
    "401 %s ends the session",
    async (reason) => {
      expect(await classifyResponse(unauthorized(reason))).toEqual({
        kind: "session_ended",
        ...(reason ? { reason } : {}),
      });
    },
  );
  it("an unreadable 401 still ends the session", async () => {
    expect(await classifyResponse(new Response("not json", { status: 401 }))).toEqual({
      kind: "session_ended",
    });
  });
  it.each([
    "refresh_in_progress",
    "keycloak_unreachable",
    "database",
    "upstream_unreachable",
    "upstream_timeout",
    "upstream_busy",
    "upstream_unavailable",
  ])("503 dependency_failure %s", async (reason) => {
    expect(await classifyResponse(unavailable(reason), () => 42)).toMatchObject({
      kind: "dependency_failure",
      failure: { reason, source: "bff", status: 503, at: 42 },
    });
  });
  it.each(["upstream_rejected_token", "upstream_redirect", "upstream_handshake_failed"])(
    "502 %s preserves the session",
    async (code) => {
      expect(await classifyResponse(rejected(code))).toMatchObject({
        kind: "dependency_failure",
        failure: { reason: code, source: "upstream" },
      });
    },
  );
  it.each([403, 404, 409, 500, 502, 503])("upstream %i passes through", async (status) => {
    const response = Response.json({ statusCode: status }, { status });
    expect(await classifyResponse(response)).toEqual({ kind: "pass_through" });
    expect(await response.json()).toEqual({ statusCode: status });
  });
  it.each([200, 204])("%i is ok", async (status) => {
    expect(await classifyResponse(new Response(null, { status }))).toEqual({ kind: "ok" });
  });
});
