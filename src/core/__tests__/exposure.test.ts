import { runInNewContext } from "node:vm";

import { APIError } from "better-auth/api";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";

import {
  EXPOSED_ROUTES,
  ID_TOKEN_FORBIDDEN,
  ROUTE_NOT_EXPOSED,
  scrubProviderTokens,
  stripProviderTokens,
} from "../exposure.js";
import { GRANT_UNSUPPORTED_LOGIN } from "../grants/grant-errors.js";
import { TOKEN_FIELDS } from "../grants/grant-hooks.js";
import {
  BASE,
  buildAuth,
  sessionCookieName,
  setsSession,
  type AuthInstance,
} from "./helpers/auth-instance.js";
import { AUTH_ROUTES, concretePath } from "./helpers/auth-routes.js";

/** Every key of a parsed JSON value, at any depth. */
const keysOf = (value: unknown): string[] => {
  if (value === null || typeof value !== "object") {
    return [];
  }
  return Object.entries(value).flatMap(([key, item]) => [key, ...keysOf(item)]);
};

/** A route's request through the handler, as a logged-in browser on its own origin. */
const send = async (setup: AuthInstance, path: string, method: string, cookie: string) =>
  setup.auth.handler(
    new Request(`${BASE}${concretePath(path)}`, {
      method,
      headers: {
        origin: BASE,
        cookie,
        ...(method === "POST" ? { "content-type": "application/json" } : {}),
      },
      ...(method === "POST" ? { body: "{}" } : {}),
    }),
  );

const signIn = async (setup: AuthInstance) =>
  setup.post("sign-in/social", "", {
    provider: "keycloak",
    idToken: { token: setup.keycloak.idToken(99), accessToken: "client-access" },
  });

describe("route exposure", () => {
  afterEach(() => vi.restoreAllMocks());

  // Risk R6: a Better Auth bump that adds or renames a route fails here until
  // the route is reviewed against EXPOSED_ROUTES and helpers/auth-routes.ts.
  it("should pin Better Auth's route table", () => {
    const { auth } = buildAuth();
    const table = Object.values(auth.api as Record<string, { path?: unknown; options?: unknown }>)
      .filter((endpoint) => typeof endpoint.path === "string")
      .map((endpoint) => {
        const { method } = endpoint.options as { method: string | string[] };
        return { path: endpoint.path as string, methods: [method].flat() };
      })
      .toSorted((a, b) => a.path.localeCompare(b.path));

    expect(table).toEqual(AUTH_ROUTES);
    const paths = AUTH_ROUTES.map((route) => route.path);
    for (const path of EXPOSED_ROUTES) {
      expect(paths).toContain(path);
    }
  });

  describe("as a logged-in browser", () => {
    let setup: AuthInstance;
    let cookie: string;

    beforeAll(async () => {
      setup = buildAuth();
      ({ cookie } = await setup.login());
    });

    afterAll(() => vi.restoreAllMocks());

    it.each(
      AUTH_ROUTES.filter((route) => !EXPOSED_ROUTES.has(route.path)).flatMap((route) =>
        route.methods.map((method) => [method, route.path] as const),
      ),
    )("should answer %s %s with a 404", async (method, path) => {
      const res = await send(setup, path, method, cookie);

      expect(res.status).toBe(404);
      expect(await res.json()).toMatchObject({ code: ROUTE_NOT_EXPOSED });
    });

    it.each(
      AUTH_ROUTES.filter(
        (route) => EXPOSED_ROUTES.has(route.path) && route.path !== "/sign-out",
      ).flatMap((route) => route.methods.map((method) => [method, route.path] as const)),
    )("should let %s %s through", async (method, path) => {
      const res = await send(setup, path, method, cookie);

      expect(res.status).not.toBe(404);
    });

    it("should let sign-out through", async () => {
      const res = await send(setup, "/sign-out", "POST", cookie);

      expect(res.status).toBe(200);
    });
  });

  it("should answer get-session with no provider token at any depth", async () => {
    const setup = buildAuth();
    const { cookie } = await setup.login();
    const res = await setup.auth.handler(
      new Request(`${BASE}/api/auth/get-session`, { headers: { cookie } }),
    );
    const body = (await res.json()) as { session: { token: string } };

    expect(res.status).toBe(200);
    expect(body.session.token).toEqual(expect.any(String));
    const keys = keysOf(body);
    for (const field of TOKEN_FIELDS) {
      expect(keys).not.toContain(field);
    }
  });

  describe("an idToken sign-in body, with discovery on", () => {
    it("should be a 400 before any Keycloak or JWKS contact", async () => {
      const setup = buildAuth({ discovery: true });
      // Discovery runs as the instance initializes; only later calls count.
      await setup.auth.$context;
      setup.fetch.mockClear();
      const res = await signIn(setup);

      expect(res.status).toBe(400);
      expect(await res.json()).toMatchObject({ code: ID_TOKEN_FORBIDDEN });
      expect(setsSession(res.headers.getSetCookie(), await sessionCookieName(setup.auth))).toBe(
        false,
      );
      expect(setup.tables.session).toEqual([]);
      expect(setup.grants.rows).toEqual([]);
      expect(setup.keycloak.codeExchanges).toBe(0);
      expect(setup.fetch).not.toHaveBeenCalled();
    });

    it("should still meet the session hook without the exposure hook (control)", async () => {
      const setup = buildAuth({ discovery: true, exposure: false });
      const res = await signIn(setup);

      expect(res.status).toBe(401);
      expect(await res.json()).toMatchObject({ code: GRANT_UNSUPPORTED_LOGIN });
      expect(setup.tables.session).toEqual([]);
    });

    it("should let a sign-in body without idToken through", async () => {
      const setup = buildAuth({ discovery: true });
      const res = await setup.post("sign-in/social", "", { provider: "keycloak" });

      expect(res.status).toBe(200);
    });
  });
});

const tokens = () => ({
  accessToken: "a",
  refreshToken: "r",
  idToken: "i",
  accessTokenExpiresAt: new Date(0),
  refreshTokenExpiresAt: new Date(0),
});

describe("scrubProviderTokens", () => {
  it("should delete every token field at any depth and keep everything else", () => {
    const when = new Date(1_000);
    const value = {
      ...tokens(),
      session: { token: "session-token", expiresAt: when, ...tokens() },
      accounts: [{ id: "x", ...tokens() }, [{ ...tokens() }]],
      bare: Object.assign(Object.create(null) as object, tokens()),
    };
    scrubProviderTokens(value);

    expect(value).toEqual({
      session: { token: "session-token", expiresAt: when },
      accounts: [{ id: "x" }, [{}]],
      bare: {},
    });
    expect(value.session.expiresAt).toBe(when);
  });

  // A request body or a result can come from another realm's JSON.parse.
  it("should scrub an object from another realm", () => {
    const value = runInNewContext('({ user: { id: "u", idToken: "i" }, accessToken: "a" })') as {
      user: object;
    };
    scrubProviderTokens(value);

    expect(JSON.stringify(value)).toBe('{"user":{"id":"u"}}');
  });

  it("should leave null, primitives, dates, errors and responses untouched", () => {
    const error = Object.assign(new APIError("FOUND"), { accessToken: "a" });
    const response = Object.assign(new Response("{}"), { accessToken: "a" });
    const date = Object.assign(new Date(0), { accessToken: "a" });
    for (const value of [null, undefined, "accessToken", 1, error, response, date]) {
      scrubProviderTokens(value);
    }

    expect(error.accessToken).toBe("a");
    expect(response.accessToken).toBe("a");
    expect(date.accessToken).toBe("a");
  });

  // A strict-mode `delete` would throw here too; `Reflect.deleteProperty`
  // returns false instead, so an unchecked call would serialize the token.
  it.each([
    ["frozen", () => Object.freeze({ id: "u", accessToken: "a" })],
    [
      "non-configurable",
      () => Object.defineProperty({ id: "u" }, "idToken", { value: "i", enumerable: true }),
    ],
  ])("should throw on a %s token field rather than leave it", (_case, make) => {
    const value = { user: make() };

    expect(() => scrubProviderTokens(value)).toThrow(/Could not strip the provider token field/);
    expect(JSON.stringify(value)).toMatch(/"(accessToken|idToken)"/);
  });

  it("should stop at a cycle", () => {
    const value: Record<string, unknown> = { idToken: "i" };
    value.self = value;
    value.list = [value];
    scrubProviderTokens(value);

    expect(value).not.toHaveProperty("idToken");
    expect(value.self).toBe(value);
  });

  it("should strip the returned value in place as an after hook", async () => {
    const returned = { session: { token: "t" }, user: { id: "u", ...tokens() } };
    const { response } = (await stripProviderTokens()({
      path: "/get-session",
      context: { returned },
      headers: new Headers(),
      returnHeaders: true,
    } as never)) as unknown as { response: unknown };

    expect(returned).toEqual({ session: { token: "t" }, user: { id: "u" } });
    expect(response).toBeUndefined();
  });
});
