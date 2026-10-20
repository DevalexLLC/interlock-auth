import { betterAuth, type BetterAuthOptions } from "better-auth";
import { createAuthMiddleware } from "better-auth/api";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  CALLBACK_ENDPOINT,
  callbackStartOf,
  composeBeforeHooks,
  recordCallbackStart,
} from "../../grants/callback-start.js";
import { defined, TEST_CONFIG } from "../helpers/config.js";
import { FakeKeycloak, loginThrough } from "../helpers/fake-keycloak.js";
import { createMemoryAuthSetup } from "../helpers/memory-store.js";

type Hook = NonNullable<NonNullable<BetterAuthOptions["hooks"]>["before"]>;

/** Runs a before hook the way Better Auth's dispatcher does. */
const run = async (hook: Hook, path: string, context: object = {}) =>
  hook({ path, context, headers: new Headers(), returnHeaders: true } as never) as Promise<{
    headers: Headers;
    response: unknown;
  }>;

describe("recordCallbackStart", () => {
  afterEach(() => vi.restoreAllMocks());

  it("should record a start on the callback and answer nothing", async () => {
    const context = {};
    const before = performance.now();
    const { headers, response } = await run(recordCallbackStart(), CALLBACK_ENDPOINT, context);

    expect(response).toBeUndefined();
    expect([...headers.keys()]).toEqual([]);
    expect(callbackStartOf(context)).toBeGreaterThanOrEqual(before);
    expect(callbackStartOf(context)).toBeLessThanOrEqual(performance.now());
  });

  // Every route Better Auth serves goes through the hook; only the callback
  // is touched, and none is answered.
  it("should pass every other route through unchanged", async () => {
    vi.spyOn(globalThis, "fetch").mockRejectedValue(new TypeError("fetch failed"));
    const auth = betterAuth(createMemoryAuthSetup(TEST_CONFIG).options);
    const paths = Object.values(auth.api)
      .map((endpoint) => Reflect.get(endpoint, "path") as unknown)
      .filter((path): path is string => typeof path === "string");

    expect(paths).toEqual(expect.arrayContaining(["/get-session", "/sign-out", CALLBACK_ENDPOINT]));
    for (const path of paths) {
      const context = {};
      const { headers, response } = await run(recordCallbackStart(), path, context);
      expect(response).toBeUndefined();
      expect([...headers.keys()]).toEqual([]);
      expect(callbackStartOf(context) !== undefined).toBe(path === CALLBACK_ENDPOINT);
    }
  });

  // The anchor works only because the before hook and the database hooks of
  // one request share the auth context object (Better Auth 1.7.7).
  it("should be found by the same callback's database hooks", async () => {
    const keycloak = new FakeKeycloak();
    vi.spyOn(globalThis, "fetch").mockImplementation(keycloak.fetch);
    const { options } = createMemoryAuthSetup(TEST_CONFIG);
    const seen: (number | undefined)[] = [];
    const databaseHooks = defined(options.databaseHooks, "the database hooks");
    const sessionHooks = defined(databaseHooks.session, "the session hooks");
    const create = defined(sessionHooks.create, "the session create hooks");
    const after = defined(create.after, "the session create after hook");
    const auth = betterAuth({
      ...options,
      databaseHooks: {
        ...databaseHooks,
        session: {
          ...sessionHooks,
          create: {
            ...create,
            after: async (session, context) => {
              seen.push(callbackStartOf(context?.context));
              return after(session, context);
            },
          },
        },
      },
    });

    const before = performance.now();
    const res = await loginThrough(auth.handler, keycloak);

    expect(res.location).toBe("/");
    expect(seen).toHaveLength(1);
    expect(seen[0]).toBeGreaterThanOrEqual(before);
  });
});

const answering = (body: unknown, cookie?: string) =>
  createAuthMiddleware(async (ctx) => {
    if (cookie) {
      ctx.setCookie(cookie, "v");
    }
    ctx.setHeader("x-hook", cookie ?? "none");
    return Promise.resolve(body);
  });

describe("composeBeforeHooks", () => {
  it("should run every hook in order and answer with nothing when none answers", async () => {
    const calls: string[] = [];
    const quiet = (name: string) =>
      createAuthMiddleware(async () => {
        calls.push(name);
        return Promise.resolve();
      });
    const { response } = await run(composeBeforeHooks([quiet("a"), quiet("b")]), "/x");

    expect(calls).toEqual(["a", "b"]);
    expect(response).toBeUndefined();
  });

  it("should answer with the first answer and keep the headers set so far", async () => {
    const later = vi.fn<() => Promise<string>>(async () => "never");
    const { headers, response } = await run(
      composeBeforeHooks([
        answering(undefined, "first"),
        answering({ ok: 1 }, "second"),
        createAuthMiddleware(later),
      ]),
      "/x",
    );

    expect(response).toEqual({ ok: 1 });
    expect(later).not.toHaveBeenCalled();
    expect(headers.getSetCookie().map((c) => c.split("=")[0])).toEqual(["first", "second"]);
    expect(headers.get("x-hook")).toBe("second");
  });
});
