import { decryptOAuthToken } from "better-auth/oauth2";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ID_TOKEN_FORBIDDEN, ROUTE_NOT_EXPOSED } from "../../exposure.js";
import {
  GRANT_ID_TOKEN_MISSING,
  GRANT_NOT_CREATED,
  GRANT_REFRESH_EXPIRY_MISSING,
  GRANT_SID_MISSING,
  GRANT_UNSUPPORTED_LOGIN,
} from "../../grants/grant-errors.js";
import { idTokenClaims, TOKEN_FIELDS } from "../../grants/grant-hooks.js";
import type { LifetimeAnchor, NewGrant } from "../../grants/grant-store.js";
import {
  BASE,
  buildAuth,
  sessionCookieName,
  setsSession,
  type AuthInstance,
  type BuildOptions,
} from "../helpers/auth-instance.js";
import { defined, records, testLogger, type TestLogger } from "../helpers/config.js";
import { ISSUER, SUBJECT, type LoginResult } from "../helpers/fake-keycloak.js";
import { MemoryGrantStore, type MemoryTables } from "../helpers/memory-store.js";

/** Better Auth's versioned envelope under secret version 1, the newest test secret. */
const ENVELOPE = /^\$ba\$1\$[0-9a-f]+$/;

const errorOf = ({ location }: LoginResult) => {
  const url = new URL(location ?? "", BASE);
  return { path: url.pathname, error: url.searchParams.get("error") };
};

const expectStripped = (tables: MemoryTables) => {
  expect(tables.account.length).toBeGreaterThan(0);
  for (const account of tables.account) {
    for (const field of TOKEN_FIELDS) {
      expect(account[field] ?? null).toBeNull();
    }
  }
};

const signIn = async (setup: AuthInstance) =>
  setup.post("sign-in/social", "", {
    provider: "keycloak",
    idToken: {
      token: setup.keycloak.idToken(99),
      accessToken: "client-access",
      refreshToken: "client-refresh",
    },
  });

const callEndpoints = async (setup: AuthInstance) => {
  const { cookie } = await setup.login();
  const body = { accountId: defined(setup.tables.account[0]).id };
  const access = await setup.post("get-access-token", cookie, body);
  const refresh = await setup.post("refresh-token", cookie, body);
  return {
    access: { status: access.status, text: await access.text() },
    refresh: { status: refresh.status, text: await refresh.text() },
  };
};

const jwt = (payload: unknown) =>
  `e30.${Buffer.from(JSON.stringify(payload)).toString("base64url")}.sig`;

/**
 * The grant hooks through a real instance's handler on the memory store,
 * with Keycloak faked at `fetch`. The memory adapter has no foreign keys, so
 * the cascade on sign-out is proved by Interlock's Postgres grant suite.
 */
describe("session grant hooks", () => {
  let logger: TestLogger;
  let error: TestLogger["error"];

  beforeEach(() => {
    logger = testLogger();
    ({ error } = logger);
  });

  afterEach(() => vi.restoreAllMocks());

  const build = (options: BuildOptions = {}) => buildAuth({ logger, ...options });

  describe.each([
    ["without discovery", false],
    ["with discovery, verifying the ID token", true],
  ])("a callback login %s", (_mode, discovery) => {
    it("should write one grant with the encrypted tokens and strip the account row", async () => {
      const { auth, keycloak, tables, grants, login } = build({ discovery });
      const res = await login();
      const ctx = await auth.$context;

      // The mode really is what it says: discovery set the provider's issuer.
      expect(ctx.socialProviders.find((p) => p.id === "keycloak")?.issuer).toBe(
        discovery ? ISSUER : undefined,
      );
      expect(res.status).toBe(302);
      expect(res.location).toBe("/");
      expect(setsSession(res.setCookies, await sessionCookieName(auth))).toBe(true);
      expect(tables.session).toHaveLength(1);
      expect(grants.rows).toHaveLength(1);

      const grant = defined(grants.rows[0], "the grant");
      const idToken = defined(keycloak.idTokens[0], "the ID token");
      expect(grant).toMatchObject({
        sessionId: defined(tables.session[0]).id,
        keycloakSid: "sid-1",
        keycloakSubject: SUBJECT,
        leaseHolder: null,
        dispatched: false,
        version: 1,
      });
      expect(grant.accessTokenExpiresAt).toBeInstanceOf(Date);
      expect(grant.refreshTokenExpiresAt).toBeInstanceOf(Date);
      // One deadline on both rows, the grant's, in the store's time.
      expect(defined(tables.session[0]).expiresAt).toEqual(grant.refreshTokenExpiresAt);
      // Prefix and inequality first: decryptOAuthToken returns a string that
      // is not encrypted unchanged, so decrypting alone would pass on plaintext.
      for (const [stored, plain] of [
        [grant.accessToken, "access-1"],
        [grant.refreshToken, "refresh-1"],
        [grant.idToken, idToken],
      ] as const) {
        expect(stored).toMatch(ENVELOPE);
        expect(stored).not.toBe(plain);
        await expect(decryptOAuthToken(stored, ctx)).resolves.toBe(plain);
      }

      expectStripped(tables);
      expect(tables.account).toHaveLength(1);
      expect(tables.account[0]).toMatchObject({
        providerId: "keycloak",
        accountId: SUBJECT,
        scope: expect.any(String) as string,
      });
    });
  });

  it("should write a second grant with its own tokens when the same user logs in again", async () => {
    const { auth, tables, grants, login } = build();
    const first = await login();
    const second = await login();
    const ctx = await auth.$context;

    expect([first.status, second.status]).toEqual([302, 302]);
    expect(first.cookie).not.toBe(second.cookie);
    expect(tables.session).toHaveLength(2);
    expect(grants.rows.map((g) => g.sessionId).toSorted()).toEqual(
      tables.session.map((s) => String(s.id)).toSorted(),
    );
    expect(grants.rows.map((g) => g.keycloakSid)).toEqual(["sid-1", "sid-2"]);
    await expect(
      Promise.all(grants.rows.map(async (g) => decryptOAuthToken(g.refreshToken, ctx))),
    ).resolves.toEqual(["refresh-1", "refresh-2"]);
    // The repeat login went through the account update path.
    expect(tables.account).toHaveLength(1);
    expectStripped(tables);
  });

  it.each([
    ["an ID token without sid", { omitSid: true }, GRANT_SID_MISSING],
    ["a token response without an ID token", { omitIdToken: true }, GRANT_ID_TOKEN_MISSING],
  ])("should refuse the login on %s", async (_case, next, code) => {
    const { auth, keycloak, tables, grants, login } = build();
    keycloak.next = next;
    const res = await login();

    expect(res.status).toBe(302);
    expect(errorOf(res)).toEqual({ path: "/api/auth/error", error: code });
    expect(setsSession(res.setCookies, await sessionCookieName(auth))).toBe(false);
    expect(tables.session).toEqual([]);
    expect(grants.rows).toEqual([]);
    expectStripped(tables);
  });

  it("should refuse the login, delete the session and log no token when the grant insert fails", async () => {
    const attempted: NewGrant[] = [];
    const failing = new MemoryGrantStore();
    failing.insert = async (grant: NewGrant, _anchor: LifetimeAnchor) => {
      attempted.push(grant);
      // A database error's detail can quote the failing row.
      throw Object.assign(new Error("insert failed"), {
        code: "23502",
        detail: `Failing row contains (${grant.accessToken}, ${grant.refreshToken}, access-1)`,
      });
    };
    const { auth, keycloak, tables, login } = build({ grants: failing });
    const res = await login();

    expect(errorOf(res)).toEqual({ path: "/api/auth/error", error: GRANT_NOT_CREATED });
    expect(setsSession(res.setCookies, await sessionCookieName(auth))).toBe(false);
    expect(tables.session).toEqual([]);
    expect(attempted).toHaveLength(1);
    expect(error).toHaveBeenCalledWith(
      expect.objectContaining({
        message: expect.stringContaining("Could not store the session grant") as string,
      }),
    );
    const logged = JSON.stringify(records(error));
    const tried = defined(attempted[0], "the attempted grant");
    for (const value of [
      "access-1",
      "refresh-1",
      defined(keycloak.idTokens[0], "the ID token"),
      tried.accessToken,
      tried.refreshToken,
      tried.idToken,
    ]) {
      expect(logged).not.toContain(value);
    }
  });

  // The deadlines start before the code exchange leaves the process, so a
  // slow exchange or userinfo response can only shorten them, never extend
  // them; the store writes them in its own (database) time.
  describe("the login deadlines", () => {
    it.each([
      ["a slow code exchange", "exchangeDelayMs"],
      ["a slow userinfo response", "userinfoDelayMs"],
    ] as const)(
      "should be anchored at the callback start despite %s",
      async (_case, delay) => {
        const { keycloak, tables, grants, login } = build();
        keycloak[delay] = 2000;
        const before = grants.now().getTime();
        const res = await login();
        const grant = defined(grants.rows[0], "the grant");

        expect(res.status).toBe(302);
        expect(res.location).toBe("/");
        const accessFrom = defined(grant.accessTokenExpiresAt).getTime() - 300_000 - before;
        const refreshFrom = defined(grant.refreshTokenExpiresAt).getTime() - 1_800_000 - before;
        for (const offset of [accessFrom, refreshFrom]) {
          expect(offset).toBeGreaterThanOrEqual(-1);
          expect(offset).toBeLessThan(1000);
        }
        expect(defined(tables.session[0]).expiresAt).toEqual(grant.refreshTokenExpiresAt);
      },
      10000,
    );

    it.each([
      ["no refresh_expires_in", { refresh_expires_in: undefined }],
      ["a refresh_expires_in of 0 (an offline token or unlimited SSO)", { refresh_expires_in: 0 }],
      ["no expires_in", { expires_in: undefined }],
    ])("should refuse a login whose token response has %s", async (_case, fields) => {
      const { auth, keycloak, tables, grants, login } = build();
      keycloak.next = { fields };
      const res = await login();

      expect(res.status).toBe(302);
      expect(errorOf(res)).toEqual({
        path: "/api/auth/error",
        error: GRANT_REFRESH_EXPIRY_MISSING,
      });
      expect(setsSession(res.setCookies, await sessionCookieName(auth))).toBe(false);
      expect(tables.session).toEqual([]);
      expect(grants.rows).toEqual([]);
      expectStripped(tables);
      const refusals = records(error).filter((record) =>
        record.message.includes("refresh_expires_in"),
      );
      expect(refusals).toHaveLength(1);
      const logged = JSON.stringify(records(error));
      for (const value of ["access-1", "refresh-1", defined(keycloak.idTokens[0])]) {
        expect(logged).not.toContain(value);
      }
    });

    it("should issue a session for such a response without the hooks (control)", async () => {
      const { auth, keycloak, tables, login } = build({ hooks: false });
      keycloak.next = { fields: { refresh_expires_in: undefined } };
      const res = await login();

      expect(res.location).toBe("/");
      expect(setsSession(res.setCookies, await sessionCookieName(auth))).toBe(true);
      expect(tables.session).toHaveLength(1);
    });

    // The slide is off in Interlock; turned back on, the update hook still
    // keeps the session inside the realm's deadline.
    it("should clamp Better Auth's slide to the grant's refresh deadline", async () => {
      const { auth, tables, grants, login } = build({ slide: true });
      const { cookie } = await login();
      const grant = defined(grants.rows[0], "the grant");
      const res = await auth.handler(
        new Request(`${BASE}/api/auth/get-session`, { headers: { cookie } }),
      );

      // The slide ran: Better Auth reissued the cookie for seven days.
      expect(res.status).toBe(200);
      expect(setsSession(res.headers.getSetCookie(), await sessionCookieName(auth))).toBe(true);
      expect(defined(tables.session[0]).expiresAt).toEqual(grant.refreshTokenExpiresAt);
    });
  });

  it("should strip tokens from an account update outside the callback and write no grant", async () => {
    const { auth, tables, grants, login } = build();
    await login();
    const ctx = await auth.$context;

    await ctx.internalAdapter.updateAccount(String(defined(tables.account[0]).id), {
      accessToken: "outside-access",
      refreshToken: "outside-refresh",
      idToken: "outside-id",
    });

    expectStripped(tables);
    expect(grants.rows).toHaveLength(1);
  });

  // The ID-token sign-in path exists once discovery has succeeded. Its tokens
  // are the client's, so they never become a grant, and a session without a
  // grant is never issued. The exposure hook refuses the body first; the
  // session hook is the inner layer behind it.
  describe("an ID-token sign-in", () => {
    it("should be refused by the exposure hook before the session hook", async () => {
      const setup = build({ discovery: true });
      const res = await signIn(setup);

      expect(res.status).toBe(400);
      expect(await res.json()).toMatchObject({ code: ID_TOKEN_FORBIDDEN });
      expect(setup.tables.session).toEqual([]);
      expect(setup.grants.rows).toEqual([]);
    });

    it("should meet the session hook without the exposure hook, leaving no session or grant", async () => {
      const setup = build({ discovery: true, exposure: false });
      const res = await signIn(setup);

      expect(res.status).toBe(401);
      expect(await res.json()).toMatchObject({ code: GRANT_UNSUPPORTED_LOGIN });
      expect(setsSession(res.headers.getSetCookie(), await sessionCookieName(setup.auth))).toBe(
        false,
      );
      expect(setup.tables.session).toEqual([]);
      expect(setup.grants.rows).toEqual([]);
      for (const account of setup.tables.account) {
        for (const field of TOKEN_FIELDS) {
          expect(account[field] ?? null).toBeNull();
        }
      }
    });

    it("should issue a session without the hooks (control)", async () => {
      const setup = build({ discovery: true, hooks: false });
      const res = await signIn(setup);

      expect(res.status).toBe(200);
      expect(setsSession(res.headers.getSetCookie(), await sessionCookieName(setup.auth))).toBe(
        true,
      );
      expect(setup.tables.session).toHaveLength(1);
    });
  });

  it("should return no provider token from get-session", async () => {
    const { auth, login } = build();
    const { cookie } = await login();
    const res = await auth.handler(
      new Request(`${BASE}/api/auth/get-session`, { headers: { cookie } }),
    );
    const text = await res.text();
    const body = JSON.parse(text) as { session: { token: string }; user: { id: string } };

    expect(res.status).toBe(200);
    expect(body.session.token).toEqual(expect.any(String));
    expect(body.user.id).toEqual(expect.any(String));
    for (const key of ["accessToken", "refreshToken", "idToken"]) {
      expect(text).not.toContain(`"${key}"`);
    }
  });

  // Better Auth's own token endpoints read the account row. The exposure hook
  // blocks them; behind it, the stripped row leaves them nothing to return
  // or refresh with.
  describe("Better Auth's token endpoints", () => {
    it("should be blocked by the exposure hook", async () => {
      const setup = build();
      const { access, refresh } = await callEndpoints(setup);

      for (const res of [access, refresh]) {
        expect(res.status).toBe(404);
        expect(JSON.parse(res.text)).toMatchObject({ code: ROUTE_NOT_EXPOSED });
      }
      expect(setup.keycloak.refreshes).toBe(0);
    });

    it("should have no token to return or refresh without the exposure hook", async () => {
      const setup = build({ exposure: false });
      const { access, refresh } = await callEndpoints(setup);

      expect(refresh.status).toBe(400);
      expect(JSON.parse(refresh.text)).toMatchObject({ code: "REFRESH_TOKEN_NOT_FOUND" });
      expect(access.status).toBe(200);
      expect(JSON.parse(access.text)).toMatchObject({ accessToken: "" });
      for (const value of ["access-1", "refresh-1", setup.keycloak.idTokens[0]]) {
        expect(access.text).not.toContain(value);
        expect(refresh.text).not.toContain(value);
      }
      expect(setup.keycloak.codeExchanges).toBe(1);
      expect(setup.keycloak.refreshes).toBe(0);
    });

    it("should return and refresh the tokens without the hooks (control)", async () => {
      const setup = build({ hooks: false });
      const { access, refresh } = await callEndpoints(setup);

      expect(access.status).toBe(200);
      expect(JSON.parse(access.text)).toMatchObject({ accessToken: "access-1" });
      expect(refresh.status).toBe(200);
      expect(JSON.parse(refresh.text)).toMatchObject({ accessToken: "access-refreshed-1" });
      expect(setup.keycloak.refreshedWith).toEqual(["refresh-1"]);
    });
  });

  // Better Auth would build a browser end-session URL from the account row;
  // its provider logout is off, and sign-out ends the Keycloak session from
  // the server (logout/sign-out.spec.ts), with or without the hooks.
  describe("sign-out", () => {
    it.each([true, false])(
      "should hand the browser no end-session URL (hooks: %s)",
      async (hooks) => {
        const setup = build({ discovery: true, hooks });
        const { cookie } = await setup.login();
        const res = await setup.post("sign-out", cookie, {});

        expect(res.status).toBe(200);
        expect(res.headers.get("location")).toBeNull();
        expect(await res.json()).not.toHaveProperty("url");
      },
    );
  });

  describe("idTokenClaims", () => {
    it("should read sid and sub", () => {
      expect(idTokenClaims(jwt({ sid: "s", sub: "u", exp: 1 }))).toEqual({ sid: "s", sub: "u" });
    });

    it.each([
      ["a blank claim", jwt({ sid: " ", sub: "u" }), { sid: undefined, sub: "u" }],
      ["a non-string claim", jwt({ sid: 1, sub: "u" }), { sid: undefined, sub: "u" }],
      ["a payload that is not an object", jwt("x"), {}],
      ["a token that is not a JWT", "opaque", {}],
    ])("should drop %s", (_case, token, claims) => {
      expect(idTokenClaims(token)).toEqual(claims);
    });
  });
});
