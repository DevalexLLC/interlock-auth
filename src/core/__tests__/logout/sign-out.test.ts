import { betterAuth } from "better-auth";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { createGrantRefresher } from "../../grants/refresh.js";
import {
  KEYCLOAK_LOGOUT_DEADLINE_MS,
  type UnconfirmedReason,
} from "../../logout/keycloak-logout.js";
import { SIGN_OUT_INCOMPLETE } from "../../logout/sign-out.js";
import { BASE, buildAuth, type AuthInstance, type BuildOptions } from "../helpers/auth-instance.js";
import { defined, records, TEST_CONFIG, testLogger, type TestLogger } from "../helpers/config.js";
import {
  FakeKeycloak,
  fakeTransport,
  loginThrough,
  type NextLogout,
} from "../helpers/fake-keycloak.js";
import { createMemoryAuthSetup } from "../helpers/memory-store.js";

const signOut = async (setup: AuthInstance, cookie: string, body: object = {}) => {
  const res = await setup.post("sign-out", cookie, body);
  return { res, body: (await res.json()) as Record<string, unknown> };
};

const getSession = async (setup: AuthInstance, cookie: string) =>
  (
    await setup.auth.handler(new Request(`${BASE}/api/auth/get-session`, { headers: { cookie } }))
  ).json() as Promise<unknown>;

const login = async (setup: AuthInstance) => {
  const { cookie } = await setup.login();
  const { sessionId } = defined(setup.grants.rows.at(-1), "the newest grant");
  return { cookie, sessionId };
};

/** Nothing a browser receives names a Keycloak URL or carries a token. */
const expectNothingForTheBrowser = (res: Response, body: Record<string, unknown>) => {
  expect(res.headers.get("location")).toBeNull();
  expect(Object.keys(body)).not.toContain("url");
  expect(Object.keys(body)).not.toContain("redirect");
  const text = JSON.stringify(body);
  expect(text).not.toContain("protocol/openid-connect");
  expect(text).not.toContain(".ey");
};

const clearedCookies = (res: Response) =>
  res.headers.getSetCookie().filter((line) => /max-age=0/i.test(line));

/**
 * Sign-out ends the local session, proves the deletion with a statement
 * of its own, and ends the Keycloak session from the server with the grant's
 * ID token. The browser gets `{ success, keycloakLogout }`, never a token, a
 * Keycloak URL or a `Location`. The fake answers the logout POST as Keycloak
 * 26.7 does (`FakeKeycloak.logout`).
 */
describe("sign-out", () => {
  let logger: TestLogger;
  let log: TestLogger["log"];
  let warn: TestLogger["warn"];
  let error: TestLogger["error"];

  beforeEach(() => {
    logger = testLogger();
    ({ log, warn, error } = logger);
  });

  afterEach(() => vi.restoreAllMocks());

  const build = (options: BuildOptions = {}) => buildAuth({ logger, ...options });

  /** No log record names or holds an ID token. */
  const expectNoTokenLogged = (setup: AuthInstance) => {
    for (const record of [log, warn, error].flatMap(records)) {
      expect(Object.keys(record).filter((key) => /token/i.test(key))).toEqual([]);
      for (const token of setup.keycloak.idTokens) {
        expect(JSON.stringify(record)).not.toContain(token);
      }
    }
  };

  it("should end the Keycloak session from the server and hand the browser nothing", async () => {
    const setup = build();
    const { cookie, sessionId } = await login(setup);

    const { res, body } = await signOut(setup, cookie);

    expect(res.status).toBe(200);
    expect(body).toEqual({ success: true, keycloakLogout: "ended" });
    expectNothingForTheBrowser(res, body);
    expect(clearedCookies(res)).toHaveLength(3);
    expect(setup.keycloak.logouts).toEqual([
      {
        hint: setup.keycloak.idTokens[0],
        sid: "sid-1",
        clientId: "interlock",
        redirect: `${BASE}/`,
        state: expect.stringMatching(/^[\w-]{22}$/),
        cookie: false,
      },
    ]);
    expect(setup.keycloak.endedSids).toEqual(new Set(["sid-1"]));
    expect(setup.tables.session).toEqual([]);
    await expect(setup.grants.findBySessionId(sessionId)).resolves.toBeUndefined();
    expect(await getSession(setup, cookie)).toBeNull();
    expect(records(log)).toContainEqual({
      message: "Sign-out ended the Keycloak session",
      sessionId,
      keycloakSid: "sid-1",
    });
    expectNoTokenLogged(setup);
  });

  // A trailing slash passes configuration; the redirect URI is still the root.
  it("should send the root as the redirect URI when BETTER_AUTH_URL ends in a slash", async () => {
    const keycloak = new FakeKeycloak();
    vi.spyOn(globalThis, "fetch").mockImplementation(keycloak.fetch);
    const auth = betterAuth(
      createMemoryAuthSetup(
        { ...TEST_CONFIG, betterAuth: { ...TEST_CONFIG.betterAuth, url: `${BASE}/` } },
        undefined,
        logger,
      ).options,
    );
    const { cookie } = await loginThrough(auth.handler, keycloak);

    const res = await auth.handler(
      new Request(`${BASE}/api/auth/sign-out`, {
        method: "POST",
        headers: { "content-type": "application/json", origin: BASE, cookie },
        body: "{}",
      }),
    );

    expect(await res.json()).toEqual({ success: true, keycloakLogout: "ended" });
    expect(keycloak.logouts.map((l) => l.redirect)).toEqual([`${BASE}/`]);
  });

  it("should send the latest ID token after a refresh", async () => {
    const setup = build();
    const { cookie, sessionId } = await login(setup);
    const refresher = createGrantRefresher(setup.grants, TEST_CONFIG, {
      logger,
      transport: fakeTransport(setup.keycloak),
    });
    setup.grants.advance(250_000);
    expect(await refresher.refreshIfDue(sessionId, await setup.auth.$context)).toMatchObject({
      kind: "ok",
      refreshed: true,
    });

    const { body } = await signOut(setup, cookie);

    expect(body.keycloakLogout).toBe("ended");
    expect(defined(setup.keycloak.logouts[0]).hint).toBe(setup.keycloak.idTokens[1]);
  });

  // The other Keycloak session of the same user is not touched; local
  // sessions sharing the ended one's sid end through the back-channel
  // delivery Keycloak makes before it answers.
  it("should leave the user's other Keycloak session alone and end only this sid's", async () => {
    const setup = build({ discovery: true });
    const a = await login(setup);
    setup.keycloak.next = { sid: "sid-1" };
    const sameSid = await login(setup);
    const other = await login(setup);
    const delivered: number[] = [];
    setup.keycloak.onLogout = async (sid) => {
      const res = await setup.postForm("backchannel-logout", {
        logout_token: setup.keycloak.logoutToken({ sid }),
      });
      delivered.push(res.status);
    };

    const { body } = await signOut(setup, a.cookie);

    expect(body).toEqual({ success: true, keycloakLogout: "ended" });
    expect(delivered).toEqual([200]);
    expect(setup.keycloak.endedSids).toEqual(new Set(["sid-1"]));
    expect(await getSession(setup, sameSid.cookie)).toBeNull();
    expect(await getSession(setup, other.cookie)).toMatchObject({
      session: { id: other.sessionId },
    });
  });

  describe("an unconfirmed Keycloak logout", () => {
    const cases: [string, NextLogout, UnconfirmedReason, number | undefined][] = [
      ["the confirmation page", { status: 200 }, "unexpected_status", 200],
      [
        "the logged-out page",
        { status: 200, text: "You are logged out" },
        "unexpected_status",
        200,
      ],
      [
        "an error page",
        { status: 400, text: "Invalid parameter: id_token_hint" },
        "unexpected_status",
        400,
      ],
      ["a server error", { status: 502 }, "unexpected_status", 502],
      [
        "a redirect elsewhere",
        { status: 302, location: "https://elsewhere.test/" },
        "unexpected_redirect",
        302,
      ],
      ["a redirect with another state", { wrongState: true }, "unexpected_redirect", 302],
      ["a refused connection", { refuse: true }, "unreachable", undefined],
    ];

    it.each(cases)(
      "should report %s as unconfirmed and still sign out locally",
      async (_case, next, reason, status) => {
        const setup = build();
        const { cookie, sessionId } = await login(setup);
        setup.keycloak.nextLogout = next;

        const { res, body } = await signOut(setup, cookie);

        expect(res.status).toBe(200);
        expect(body).toEqual({ success: true, keycloakLogout: "unconfirmed" });
        expectNothingForTheBrowser(res, body);
        expect(clearedCookies(res)).toHaveLength(3);
        expect(setup.tables.session).toEqual([]);
        expect(records(warn)).toContainEqual({
          message: "Sign-out could not confirm that the Keycloak session ended",
          sessionId,
          keycloakSid: "sid-1",
          reason,
          status,
        });
        expectNoTokenLogged(setup);
      },
    );

    it("should give up at the deadline", async () => {
      const setup = build();
      const { cookie } = await login(setup);
      setup.keycloak.nextLogout = { hang: true };
      const started = Date.now();

      const { res, body } = await signOut(setup, cookie);

      const took = Date.now() - started;
      expect(took).toBeGreaterThanOrEqual(KEYCLOAK_LOGOUT_DEADLINE_MS - 50);
      expect(took).toBeLessThan(KEYCLOAK_LOGOUT_DEADLINE_MS + 2_000);
      expect(res.status).toBe(200);
      expect(body).toEqual({ success: true, keycloakLogout: "unconfirmed" });
      expect(records(warn)).toContainEqual(expect.objectContaining({ reason: "timeout" }));
      expect(setup.tables.session).toEqual([]);
    });

    it("should not attempt it for a session whose grant is gone", async () => {
      const setup = build();
      const { cookie, sessionId } = await login(setup);
      await setup.grants.deleteBySessionId(sessionId);

      const { body } = await signOut(setup, cookie);

      expect(body).toEqual({ success: true, keycloakLogout: "unconfirmed" });
      expect(setup.keycloak.logouts).toEqual([]);
      expect(records(warn)).toContainEqual(expect.objectContaining({ reason: "no_hint" }));
      expect(setup.tables.session).toEqual([]);
    });

    it("should not attempt it when the grant cannot be read", async () => {
      const setup = build();
      const { cookie, sessionId } = await login(setup);
      vi.spyOn(setup.grants, "findBySessionId").mockRejectedValue(new Error("connection lost"));

      const { body } = await signOut(setup, cookie);

      expect(body).toEqual({ success: true, keycloakLogout: "unconfirmed" });
      expect(setup.keycloak.logouts).toEqual([]);
      expect(warn).toHaveBeenCalledWith({
        message:
          "Sign-out could not read the session grant; the Keycloak logout will be unconfirmed",
        sessionId,
      });
      expect(setup.tables.session).toEqual([]);
    });
  });

  describe("no session", () => {
    it("should answer no_session without a session cookie and call nothing", async () => {
      const setup = build();
      await login(setup);

      const { res, body } = await signOut(setup, "");

      expect(res.status).toBe(200);
      expect(body).toEqual({ success: true, keycloakLogout: "no_session" });
      expectNothingForTheBrowser(res, body);
      expect(setup.keycloak.logouts).toEqual([]);
      expect(setup.tables.session).toHaveLength(1);
    });

    // A replayed cookie after an unconfirmed sign-out must not read as a
    // global logout: no_session asserts nothing about Keycloak.
    it("should answer no_session, not ended, when the cookie is replayed after sign-out", async () => {
      const setup = build();
      const { cookie } = await login(setup);
      setup.keycloak.nextLogout = { status: 502 };
      expect((await signOut(setup, cookie)).body.keycloakLogout).toBe("unconfirmed");

      const { body } = await signOut(setup, cookie);

      expect(body).toEqual({ success: true, keycloakLogout: "no_session" });
      expect(setup.keycloak.logouts).toHaveLength(1);
    });
  });

  describe("the local deletion", () => {
    // Better Auth's own delete swallows a failed lookup and still answers
    // success, so its answer proves nothing; the grant store's statement does.
    it("should establish the deletion itself when Better Auth's did nothing", async () => {
      const setup = build();
      const { cookie, sessionId } = await login(setup);
      const ctx = await setup.auth.$context;
      vi.spyOn(ctx.internalAdapter, "deleteSession").mockResolvedValue(undefined);

      const { res, body } = await signOut(setup, cookie);

      expect(res.status).toBe(200);
      expect(body).toEqual({ success: true, keycloakLogout: "ended" });
      expect(setup.tables.session).toEqual([]);
      await expect(setup.grants.findBySessionId(sessionId)).resolves.toBeUndefined();
    });

    it("should answer 503 sign_out_incomplete, cookies cleared, when the session cannot be deleted", async () => {
      const setup = build();
      const { cookie, sessionId } = await login(setup);
      const ctx = await setup.auth.$context;
      vi.spyOn(ctx.internalAdapter, "deleteSession").mockResolvedValue(undefined);
      vi.spyOn(setup.grants, "endSessionByToken").mockRejectedValue(new Error("connection lost"));

      const { res, body } = await signOut(setup, cookie);

      expect(res.status).toBe(503);
      expect(body).toMatchObject({ code: SIGN_OUT_INCOMPLETE, keycloakLogout: "ended" });
      expect(body).not.toHaveProperty("success");
      expectNothingForTheBrowser(res, body);
      expect(clearedCookies(res)).toHaveLength(3);
      expect(setup.tables.session).toHaveLength(1);
      expect(records(error)).toContainEqual({
        message: "Sign-out could not end the session in the database",
        sessionId,
      });
      expectNoTokenLogged(setup);
    });
  });

  it("should leave a sign-out Better Auth refused alone", async () => {
    const setup = build();
    const { cookie } = await login(setup);

    const res = await setup.auth.handler(
      new Request(`${BASE}/api/auth/sign-out`, {
        method: "POST",
        headers: { "content-type": "application/json", origin: "https://evil.test", cookie },
        body: "{}",
      }),
    );

    expect(res.status).toBe(403);
    expect(setup.keycloak.logouts).toEqual([]);
    expect(setup.tables.session).toHaveLength(1);
  });
});
