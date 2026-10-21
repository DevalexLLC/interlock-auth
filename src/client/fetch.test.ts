import { describe, expect, it, vi } from "vitest";

import { deferred, signedIn } from "./__tests__/helpers/fake-ports.js";
import { rejected, unauthorized, unavailable } from "./__tests__/helpers/responses.js";
import { resolveEndpoints } from "./endpoints.js";
import { DependencyFailureError, SessionEndedError } from "./errors.js";
import { createInterlockFetch } from "./fetch.js";

const endpoints = resolveEndpoints("https://interlock.test");
describe("Interlock fetch", () => {
  it("sends credentials, query parameters and JSON without application identity", async () => {
    const { controller } = signedIn();
    const fetch = vi.fn<typeof globalThis.fetch>().mockResolvedValue(Response.json({}));
    await createInterlockFetch(
      endpoints,
      controller,
      fetch,
    )("/api/irongate/user-requests", {
      credentials: "omit",
      method: "POST",
      query: { user: "a b", absent: undefined },
      json: { group: "/Apps" },
    });
    const [url, init] = fetch.mock.calls[0] ?? [];
    expect((url as URL).href).toBe("https://interlock.test/api/irongate/user-requests?user=a+b");
    expect(init).toMatchObject({
      credentials: "include",
      body: '{"group":"/Apps"}',
      method: "POST",
    });
    expect(new Headers(init?.headers).get("content-type")).toBe("application/json");
    expect(new Headers(init?.headers).has("x-application-id")).toBe(false);
  });
  it.each([undefined, "refresh_indeterminate"] as const)(
    "401 %s applies one transition",
    async (reason) => {
      const { controller, ports } = signedIn();
      const fetch = createInterlockFetch(
        endpoints,
        controller,
        vi.fn().mockResolvedValue(unauthorized(reason)),
      );
      await expect(fetch("/api/irongate/applications")).rejects.toBeInstanceOf(SessionEndedError);
      expect(controller.getState().phase.kind).toBe(reason ? "re_entering_login" : "signed_out");
      expect(ports.signIn).toHaveBeenCalledTimes(reason ? 1 : 0);
    },
  );
  it("captures generation before send: logout then delayed indeterminate never redirects", async () => {
    const { controller, ports } = signedIn();
    const pending = deferred<Response>();
    const request = createInterlockFetch(
      endpoints,
      controller,
      vi.fn().mockReturnValue(pending.promise),
    )("/api/irongate/applications");
    // The assertion is attached before resolving the deliberately delayed response.
    // oxlint-disable-next-line vitest/valid-expect
    const assertion = expect(request).rejects.toMatchObject({ generation: 0 });
    await controller.signOut();
    pending.resolve(unauthorized("refresh_indeterminate"));
    await assertion;
    expect(ports.signIn).not.toHaveBeenCalled();
    expect(controller.getState().phase.kind).toBe("signed_out");
  });
  it.each([unavailable, rejected])(
    "contract dependency failure preserves session and success clears it",
    async (response) => {
      const { controller } = signedIn();
      const fetch = createInterlockFetch(
        endpoints,
        controller,
        vi.fn().mockResolvedValueOnce(response()).mockResolvedValueOnce(Response.json({})),
      );
      await expect(fetch("/read")).rejects.toBeInstanceOf(DependencyFailureError);
      expect(controller.getState().phase.kind).toBe("signed_in");
      expect(controller.getState().dependency).not.toBeNull();
      await fetch("/read");
      expect(controller.getState().dependency).toBeNull();
    },
  );
  it("TypeError is network dependency failure; abort is not", async () => {
    const { controller } = signedIn();
    const fetch = createInterlockFetch(
      endpoints,
      controller,
      vi
        .fn()
        .mockRejectedValueOnce(new TypeError("offline"))
        .mockRejectedValueOnce(new DOMException("aborted", "AbortError")),
    );
    await expect(fetch("/read")).rejects.toMatchObject({ failure: { source: "network" } });
    await expect(fetch("/read")).rejects.toMatchObject({ name: "AbortError" });
  });
  it("403 passes through intact", async () => {
    const { controller } = signedIn();
    const response = Response.json({ message: "no" }, { status: 403 });
    expect(
      await createInterlockFetch(
        endpoints,
        controller,
        vi.fn().mockResolvedValue(response),
      )("/read"),
    ).toBe(response);
  });
});
