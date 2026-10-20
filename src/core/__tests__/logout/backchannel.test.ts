import { setTimeout as sleep } from "node:timers/promises";

import { createRemoteJWKSet } from "jose";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { createGrantRefresher } from "../../grants/refresh.js";
import {
  KEY_FETCH_BACKOFF_MS,
  KEY_REFETCH_COOLDOWN_MS,
  LOGOUT_TOKEN_INVALID,
  LOGOUT_TOKEN_UNVERIFIABLE,
  realmKeys,
  type KeyResolutionReason,
  type LogoutTokenRejection,
} from "../../logout/backchannel.js";
import { BASE, buildAuth, type AuthInstance, type BuildOptions } from "../helpers/auth-instance.js";
import {
  allRecords,
  defined,
  records,
  TEST_CONFIG,
  testLogger,
  type TestLogger,
} from "../helpers/config.js";
import { fakeTransport, type LogoutTokenSpec } from "../helpers/fake-keycloak.js";

/** Past the cooldown and the backoff, which are equal. */
const PAST_COOLDOWN_MS = Math.max(KEY_REFETCH_COOLDOWN_MS, KEY_FETCH_BACKOFF_MS) + 150;

const deliver = async (setup: AuthInstance, token: string) =>
  setup.postForm("backchannel-logout", { logout_token: token });

const token = (setup: AuthInstance, spec: LogoutTokenSpec = {}) => setup.keycloak.logoutToken(spec);

const sessionIds = (setup: AuthInstance) =>
  setup.tables.session.map((row) => row.id as string).sort();

const getSession = async (setup: AuthInstance, cookie: string) =>
  (
    await setup.auth.handler(new Request(`${BASE}/api/auth/get-session`, { headers: { cookie } }))
  ).json() as Promise<unknown>;

const now = () => Math.floor(Date.now() / 1000);

const post = async (setup: AuthInstance, init: RequestInit) =>
  setup.auth.handler(
    new Request(`${BASE}/api/auth/backchannel-logout`, { method: "POST", ...init }),
  );

describe("the back-channel logout receiver", () => {
  let logger: TestLogger;
  let log: TestLogger["log"];
  let warn: TestLogger["warn"];
  let error: TestLogger["error"];
  let debug: TestLogger["debug"];

  beforeEach(() => {
    logger = testLogger();
    ({ log, warn, error, debug } = logger);
  });

  afterEach(() => vi.restoreAllMocks());

  const build = (options: BuildOptions = {}) => buildAuth({ logger, ...options });

  /** An instance with the fake serving its key set, and two logins: sid-1 and sid-2. */
  const twoLogins = async (options: BuildOptions = {}) => {
    const setup = build({ discovery: true, ...options });
    const a = await setup.login();
    const b = await setup.login();
    const [rowA, rowB] = setup.grants.rows;
    return {
      setup,
      a: { ...a, id: defined(rowA, "the first grant").sessionId },
      b: { ...b, id: defined(rowB, "the second grant").sessionId },
    };
  };

  /** No log record names or carries a logout token. */
  const expectNoTokenLogged = (...tokens: string[]) => {
    for (const record of allRecords(logger)) {
      expect(Object.keys(record).filter((key) => /token/i.test(key))).toEqual([]);
      for (const value of tokens) {
        expect(JSON.stringify(record)).not.toContain(value);
      }
    }
  };

  const expectRefused = async (res: Response, reason: LogoutTokenRejection) => {
    expect(res.status).toBe(400);
    expect(res.headers.get("cache-control")).toBe("no-store");
    expect(await res.json()).toMatchObject({ code: LOGOUT_TOKEN_INVALID });
    expect(records(warn)).toContainEqual({
      message: "Refused a back-channel logout token",
      reason,
    });
  };

  const expectUnverifiable = async (res: Response, reason: KeyResolutionReason) => {
    expect(res.status).toBe(503);
    expect(res.headers.get("cache-control")).toBe("no-store");
    expect(await res.json()).toMatchObject({ code: LOGOUT_TOKEN_UNVERIFIABLE });
    expect(records(error)).toContainEqual(expect.objectContaining({ reason }));
  };

  describe("a valid token", () => {
    it("should end the sessions of its sid only", async () => {
      const { setup, a, b } = await twoLogins();
      const logout = token(setup, { sid: "sid-1" });

      const res = await deliver(setup, logout);

      expect(res.status).toBe(200);
      expect(res.headers.get("cache-control")).toBe("no-store");
      expect(await res.json()).toEqual({ ended: 1 });
      expect(sessionIds(setup)).toEqual([b.id]);
      expect(setup.grants.rows.map((row) => row.sessionId)).toEqual([b.id]);
      expect(await getSession(setup, a.cookie)).toBeNull();
      expect(await getSession(setup, b.cookie)).not.toBeNull();
      expect(records(log)).toContainEqual({
        message: "Back-channel logout ended the sessions of a Keycloak session",
        keycloakSid: "sid-1",
        subject: setup.keycloak.subject,
        endedSessions: [a.id],
        logoutJti: expect.any(String),
      });
      expect(records(debug)).toContainEqual({
        message: "Back-channel logout token header",
        alg: "RS256",
        typ: "logout+jwt",
        kid: "fake-keycloak",
      });
      expectNoTokenLogged(logout);
    });

    it("should end every session of the subject when only sub is present, as a deviation", async () => {
      const { setup, a, b } = await twoLogins();
      const logout = token(setup, { sid: null });

      const res = await deliver(setup, logout);

      expect(res.status).toBe(200);
      expect(await res.json()).toEqual({ ended: 2 });
      expect(setup.tables.session).toEqual([]);
      expect(setup.grants.rows).toEqual([]);
      expect(records(warn)).toContainEqual({
        message: expect.stringContaining("contract deviation"),
        subject: setup.keycloak.subject,
        endedSessions: expect.arrayContaining([a.id, b.id]),
        logoutJti: expect.any(String),
      });
      expectNoTokenLogged(logout);
    });

    it("should end the survivor with a sub-only token after a sid logout", async () => {
      const { setup, b } = await twoLogins();

      expect(await (await deliver(setup, token(setup, { sid: "sid-1" }))).json()).toEqual({
        ended: 1,
      });
      const res = await deliver(setup, token(setup, { sid: null }));

      expect(await res.json()).toEqual({ ended: 1 });
      expect(records(warn)).toContainEqual(expect.objectContaining({ endedSessions: [b.id] }));
      expect(setup.tables.session).toEqual([]);
    });

    it("should match a sid-only token by sid and log no subject", async () => {
      const { setup, a, b } = await twoLogins();

      const res = await deliver(setup, token(setup, { sid: "sid-2", sub: null }));

      expect(await res.json()).toEqual({ ended: 1 });
      expect(sessionIds(setup)).toEqual([a.id]);
      const record = defined(
        records(log).find((r) => r.endedSessions !== undefined),
        "the record of the ended sessions",
      );
      expect(record).toMatchObject({ endedSessions: [b.id] });
      expect(record.subject).toBeUndefined();
    });

    it("should answer an unknown sid and a replay with ended 0", async () => {
      const { setup } = await twoLogins();
      const logout = token(setup, { sid: "sid-1" });

      expect(await (await deliver(setup, token(setup, { sid: "sid-9" }))).json()).toEqual({
        ended: 0,
      });
      expect(await (await deliver(setup, logout)).json()).toEqual({ ended: 1 });
      const replay = await deliver(setup, logout);

      expect(replay.status).toBe(200);
      expect(await replay.json()).toEqual({ ended: 0 });
      expect(setup.tables.session).toHaveLength(1);
    });

    // Without a jti cache, a sub-only token replayed inside its lifetime ends
    // a session created after its first delivery (the gate record's residual).
    it("should end a later session when a sub-only token is replayed", async () => {
      const { setup } = await twoLogins();
      const logout = token(setup, { sid: null });
      expect(await (await deliver(setup, logout)).json()).toEqual({ ended: 2 });
      await setup.login();

      const res = await deliver(setup, logout);

      expect(await res.json()).toEqual({ ended: 1 });
      expect(setup.tables.session).toEqual([]);
    });

    it("should leave nothing behind when it lands during an in-flight refresh", async () => {
      const { setup, a } = await twoLogins();
      const ctx = await setup.auth.$context;
      const refresher = createGrantRefresher(setup.grants, TEST_CONFIG, {
        logger,
        transport: fakeTransport(setup.keycloak),
      });
      // Due: past the access token's lifetime less the leeway, on the store's clock.
      setup.grants.advance(250_000);
      let delivered: Response | undefined;
      setup.keycloak.onRefresh = async () => {
        delivered = await deliver(setup, token(setup, { sid: "sid-1" }));
      };

      const outcome = await refresher.refreshIfDue(a.id, ctx);

      expect(setup.keycloak.refreshes).toBe(1);
      expect(delivered?.status).toBe(200);
      expect(outcome).toMatchObject({ kind: "ended" });
      expect(setup.grants.rows.map((row) => row.sessionId)).not.toContain(a.id);
      expect(sessionIds(setup)).not.toContain(a.id);
      expect(await getSession(setup, a.cookie)).toBeNull();
    });
  });

  describe("a refused token", () => {
    const cases: [string, LogoutTokenSpec | string, LogoutTokenRejection][] = [
      ["a wrong issuer", { claims: { iss: "https://127.0.0.1:1/realms/other" } }, "issuer"],
      ["a wrong audience", { claims: { aud: "other-client" } }, "audience"],
      ["an iat seven minutes old", { claims: { iat: now() - 420, exp: now() + 60 } }, "iat_stale"],
      [
        "an iat two minutes ahead",
        { claims: { iat: now() + 120, exp: now() + 240 } },
        "iat_future",
      ],
      ["a passed exp", { claims: { iat: now() - 200, exp: now() - 80 } }, "expired"],
      ["no iat", { claims: { iat: undefined } }, "iat_missing"],
      ["no exp", { claims: { exp: undefined } }, "exp_missing"],
      ["no jti", { claims: { jti: undefined } }, "jti_missing"],
      ["a blank jti", { claims: { jti: " " } }, "jti_missing"],
      ["no events", { claims: { events: undefined } }, "events_missing"],
      ["events without the logout member", { claims: { events: { other: {} } } }, "events_missing"],
      ["a nonce", { claims: { nonce: "n" } }, "nonce_present"],
      ["neither sid nor sub", { sid: null, sub: null }, "subject_missing"],
      ["a blank sid", { sid: " " }, "malformed"],
      ["alg none", { header: { alg: "none" } }, "alg_not_allowed"],
      ["alg HS256", { header: { alg: "HS256" } }, "alg_not_allowed"],
      ["a signature that does not verify", { unsigned: true }, "signature"],
      ["a string that is not a JWT", "not-a-jwt", "malformed"],
    ];

    it.each(cases)("should refuse %s with a 400 and end nothing", async (_case, spec, reason) => {
      const { setup } = await twoLogins();
      const logout = typeof spec === "string" ? spec : token(setup, spec);

      await expectRefused(await deliver(setup, logout), reason);
      expect(setup.tables.session).toHaveLength(2);
      expect(setup.grants.rows).toHaveLength(2);
      expectNoTokenLogged(logout);
    });

    it("should refuse an unknown kid outside the cooldown after exactly one fetch", async () => {
      const { setup } = await twoLogins();
      expect((await deliver(setup, token(setup, { sid: "sid-9" }))).status).toBe(200);
      await sleep(PAST_COOLDOWN_MS);
      const before = setup.keycloak.certsFetches;

      await expectRefused(
        await deliver(setup, token(setup, { header: { kid: "unknown" } })),
        "unknown_key",
      );
      expect(setup.keycloak.certsFetches - before).toBe(1);
      expect(setup.tables.session).toHaveLength(2);
    });

    it("should refuse a missing or empty logout_token", async () => {
      const { setup } = await twoLogins();

      await expectRefused(await setup.postForm("backchannel-logout", {}), "token_missing");
      await expectRefused(
        await setup.auth.handler(
          new Request(`${BASE}/api/auth/backchannel-logout`, { method: "POST" }),
        ),
        "token_missing",
      );
      await expectRefused(
        await setup.postForm("backchannel-logout", { logout_token: "" }),
        "token_missing",
      );
      expect(setup.tables.session).toHaveLength(2);
    });

    // better-call keeps the last of repeated fields, so the duplicate itself
    // is not detectable; the value kept is judged like any other.
    it("should judge the last of repeated logout_token fields", async () => {
      const { setup } = await twoLogins();

      await expectRefused(
        await setup.postForm("backchannel-logout", "logout_token=a&logout_token=b"),
        "malformed",
      );
      expect(setup.tables.session).toHaveLength(2);
    });
  });

  describe("key rotation", () => {
    it("should answer 503 inside the cooldown and verify the new key after it", async () => {
      const { setup, b } = await twoLogins();
      expect((await deliver(setup, token(setup, { sid: "sid-9" }))).status).toBe(200);
      setup.keycloak.rotateKey();
      const rotated = token(setup, { sid: "sid-1" });
      const before = setup.keycloak.certsFetches;

      await expectUnverifiable(await deliver(setup, rotated), "key_refresh_cooling");
      expect(setup.keycloak.certsFetches).toBe(before);
      expect(setup.tables.session).toHaveLength(2);

      await sleep(PAST_COOLDOWN_MS);
      const res = await deliver(setup, rotated);
      expect(res.status).toBe(200);
      expect(await res.json()).toEqual({ ended: 1 });
      expect(setup.keycloak.certsFetches - before).toBe(1);

      // The old key stays in the set, passive, and keeps verifying.
      const old = await deliver(setup, token(setup, { sid: "sid-2", keyIndex: 0 }));
      expect(old.status).toBe(200);
      expect(await old.json()).toEqual({ ended: 1 });
      expect(sessionIds(setup)).not.toContain(b.id);
      expect(setup.keycloak.certsFetches - before).toBe(1);
    });
  });

  describe("an unavailable key set", () => {
    it.each([
      ["a 503", { status: 503, body: { error: "unavailable" } }, "jwks_status"],
      ["a body that is not JSON", { text: "<html>" }, "jwks_malformed"],
      ["keys that are not an array", { body: { keys: "x" } }, "jwks_malformed"],
    ] as const)("should answer %s from the JWKS with a 503", async (_case, response, reason) => {
      const { setup } = await twoLogins();
      setup.keycloak.certsResponse = response;
      const logout = token(setup, { sid: "sid-1" });

      await expectUnverifiable(await deliver(setup, logout), reason);
      expect(setup.tables.session).toHaveLength(2);
      expectNoTokenLogged(logout);
    });

    it("should answer a refused connection with a 503", async () => {
      const { setup } = await twoLogins({
        logoutKeys: realmKeys("https://127.0.0.1:1/realms/gone"),
      });

      await expectUnverifiable(
        await deliver(setup, token(setup, { sid: "sid-1" })),
        "jwks_unreachable",
      );
      expect(setup.tables.session).toHaveLength(2);
    });

    it("should answer a JWKS timeout with a 503", async () => {
      const certs = "https://127.0.0.1:1/realms/test/protocol/openid-connect/certs";
      const { setup } = await twoLogins({
        logoutKeys: createRemoteJWKSet(new URL(certs), { timeoutDuration: 50 }),
      });
      const serve = setup.keycloak.fetch;
      // jose asks with a string URL and a timeout signal; the rest is the fake.
      setup.fetch.mockImplementation(async (input, init) => {
        if (input !== certs) {
          return serve(input, init);
        }
        const signal = defined(init?.signal, "the timeout signal");
        return new Promise<Response>((_resolve, reject) => {
          signal.addEventListener("abort", () => reject(signal.reason));
        });
      });

      await expectUnverifiable(
        await deliver(setup, token(setup, { sid: "sid-1" })),
        "jwks_timeout",
      );
      expect(setup.tables.session).toHaveLength(2);
    });

    it("should fetch once per backoff during an outage and keep verifying cached keys", async () => {
      const { setup } = await twoLogins();
      expect((await deliver(setup, token(setup, { sid: "sid-9" }))).status).toBe(200);
      await sleep(PAST_COOLDOWN_MS);
      setup.keycloak.certsResponse = { status: 503, body: {} };
      const before = setup.keycloak.certsFetches;

      const answers: number[] = [];
      for (let i = 0; i < 5; i += 1) {
        answers.push(
          (await deliver(setup, token(setup, { header: { kid: `unknown-${i}` } }))).status,
        );
      }

      expect(answers).toEqual([503, 503, 503, 503, 503]);
      expect(setup.keycloak.certsFetches - before).toBe(1);
      expect(
        records(error)
          .map((r) => r.reason)
          .filter((reason) => reason !== undefined),
      ).toEqual(["jwks_status", "jwks_backoff", "jwks_backoff", "jwks_backoff", "jwks_backoff"]);
      const cached = await deliver(setup, token(setup, { sid: "sid-1" }));
      expect(cached.status).toBe(200);
      expect(await cached.json()).toEqual({ ended: 1 });
      expect(setup.keycloak.certsFetches - before).toBe(1);

      await sleep(PAST_COOLDOWN_MS);
      await expectUnverifiable(
        await deliver(setup, token(setup, { header: { kid: "unknown-5" } })),
        "jwks_status",
      );
      expect(setup.keycloak.certsFetches - before).toBe(2);
    });

    it("should keep verifying an expired cache through an outage", async () => {
      const certs = `${TEST_CONFIG.keycloak.issuer}/protocol/openid-connect/certs`;
      const { setup } = await twoLogins({
        logoutKeys: createRemoteJWKSet(new URL(certs), {
          cooldownDuration: KEY_REFETCH_COOLDOWN_MS,
          cacheMaxAge: 1_500,
        }),
      });
      const unknown = async () => deliver(setup, token(setup, { header: { kid: "unknown" } }));
      expect((await deliver(setup, token(setup, { sid: "sid-9" }))).status).toBe(200);
      await sleep(1_650);
      setup.keycloak.certsResponse = { status: 503, body: {} };
      const before = setup.keycloak.certsFetches;

      // The request that triggers the failed fetch still verifies.
      expect((await deliver(setup, token(setup, { sid: "sid-9" }))).status).toBe(200);
      expect(setup.keycloak.certsFetches - before).toBe(1);
      // During the backoff: no fetch, cached keys verify, unknown ones are 503s.
      expect((await deliver(setup, token(setup, { sid: "sid-1" }))).status).toBe(200);
      await expectUnverifiable(await unknown(), "jwks_backoff");
      expect(setup.keycloak.certsFetches - before).toBe(1);

      // After the backoff the next request fetches again, fails, and still verifies.
      await sleep(PAST_COOLDOWN_MS);
      const res = await deliver(setup, token(setup, { sid: "sid-2" }));
      expect(res.status).toBe(200);
      expect(await res.json()).toEqual({ ended: 1 });
      expect(setup.keycloak.certsFetches - before).toBe(2);
      await expectUnverifiable(await unknown(), "jwks_backoff");
    });
  });

  describe("requests the framework answers", () => {
    it.each([
      ["a JSON body", { "content-type": "application/json" }, '{"logout_token":"x"}'],
      ["malformed JSON", { "content-type": "application/json" }, '{"logout_token":'],
      ["a text/plain body", { "content-type": "text/plain" }, "logout_token=x"],
      ["no content type", {}, new TextEncoder().encode("logout_token=x")],
    ] as const)("should answer %s with a 415 before the handler", async (_case, headers, body) => {
      const { setup } = await twoLogins();

      const res = await post(setup, { headers, body });

      expect(res.status).toBe(415);
      expect(await res.json()).toMatchObject({ code: "UNSUPPORTED_MEDIA_TYPE" });
      // A recorded exception: framework answers carry no no-store, and no session data.
      expect(res.headers.get("cache-control")).toBeNull();
      expect(warn).not.toHaveBeenCalledWith(
        expect.objectContaining({ message: "Refused a back-channel logout token" }),
      );
      expect(setup.tables.session).toHaveLength(2);
    });

    it("should answer GET with a 404", async () => {
      const { setup } = await twoLogins();

      const res = await setup.auth.handler(new Request(`${BASE}/api/auth/backchannel-logout`));

      expect(res.status).toBe(404);
    });
  });

  // Keycloak sends every logout from one address and never retries a 429.
  it("should be exempt from the rate limiter that governs sign-out", async () => {
    const setup = build({ discovery: true, rateLimit: true });
    await setup.auth.$context;

    const receiver: number[] = [];
    for (let i = 0; i < 150; i += 1) {
      receiver.push((await deliver(setup, token(setup, { sid: `sid-${i + 100}` }))).status);
    }
    const signOut: number[] = [];
    for (let i = 0; i < 150; i += 1) {
      signOut.push((await setup.post("sign-out", "", {})).status);
    }

    expect(new Set(receiver)).toEqual(new Set([200]));
    expect(signOut).toContain(429);
  });
});
