import { betterAuth, type BetterAuthOptions } from "better-auth";
import { makeSignature } from "better-auth/crypto";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

import { COOKIE_NAME_POLICIES, type CookieNamePolicy } from "../config.js";
import { TEST_CONFIG } from "./helpers/config.js";
import { createMemoryAuthOptions } from "./helpers/memory-store.js";
import { checkSetCookies, namesOf } from "./helpers/set-cookie.js";

const BASE = "https://interlock.test";
const PREFIXES: Record<CookieNamePolicy, string> = {
  host: "__Host-interlock.",
  secure: "__Secure-interlock.",
};

const emitted = (res: Response) => checkSetCookies(res.headers.getSetCookie());

/**
 * Every cookie a login, a session refresh, and a logout emit, through a real
 * instance's handler on the memory store, under each cookie-name policy.
 * Each step asserts the exact set of names it emits: the cookie getter takes
 * any kind string, so only the endpoints can show that Better Auth still uses
 * the kinds the policy was checked against. Interlock's own cookie suite
 * repeats this through its HTTP server and Postgres.
 *
 * The options turn Better Auth's session slide off (the refresher owns
 * `expiresAt`), so this instance turns it back on: the slide is still the
 * path on which Better Auth reissues the session cookie, and its name must
 * still follow the policy if the slide is ever re-enabled. The e2e suite
 * checks that the running server reissues nothing.
 */
describe.each(COOKIE_NAME_POLICIES)("cookie-name policy %s", (policy: CookieNamePolicy) => {
  const prefix = PREFIXES[policy];
  let auth: ReturnType<typeof betterAuth>;

  // Discovery runs while the instance initializes, so the stubs go first.
  beforeAll(async () => {
    vi.spyOn(globalThis, "fetch").mockRejectedValue(new TypeError("fetch failed"));
    const options = createMemoryAuthOptions({ ...TEST_CONFIG, cookieNamePolicy: policy });
    const slide: BetterAuthOptions = {
      ...options,
      session: { ...options.session, disableSessionRefresh: false },
    };
    auth = betterAuth(slide);
    await auth.$context;
  });

  afterAll(() => vi.restoreAllMocks());

  /** A user with a session; `due` makes the session ready for its refresh. */
  const signedIn = async (due: boolean) => {
    const ctx = await auth.$context;
    // Seed the fixture directly: OAuth user writes now require an endpoint context.
    const user = await ctx.adapter.create<{ id: string }>({
      model: "user",
      data: {
        email: `ann-${crypto.randomUUID()}@example.com`,
        name: "ann",
        emailVerified: true,
        createdAt: new Date(),
        updatedAt: new Date(),
      },
    });
    const { expiresIn, updateAge } = ctx.sessionConfig;
    // get-session refreshes once `expiresAt - expiresIn + updateAge <= now`.
    // `createSession` spreads the override before its own `expiresAt`, so
    // the last argument (`overrideAll`) is what makes the override stick.
    const session = due
      ? await ctx.internalAdapter.createSession(
          user.id,
          false,
          { expiresAt: new Date(Date.now() + (expiresIn - updateAge) * 1000 - 1000) },
          true,
        )
      : await ctx.internalAdapter.createSession(user.id, false);
    const signature = await makeSignature(session.token, ctx.secret);
    return {
      session,
      cookie: `${ctx.authCookies.sessionToken.name}=${encodeURIComponent(`${session.token}.${signature}`)}`,
    };
  };

  const getSession = async (cookie: string) =>
    auth.handler(new Request(`${BASE}/api/auth/get-session`, { headers: { cookie } }));

  it("should set only the state cookie when a login starts", async () => {
    const res = await auth.handler(
      new Request(`${BASE}/api/auth/sign-in/social`, {
        method: "POST",
        headers: { "content-type": "application/json", origin: BASE },
        body: JSON.stringify({ provider: "keycloak", callbackURL: "/" }),
      }),
    );

    expect(res.status).toBe(200);
    expect(emitted(res)).toEqual([{ name: `${prefix}state`, maxAge: 300 }]);
  });

  // The control: without it the refresh assertion below would also pass if
  // get-session set the cookie on every call.
  it("should set no cookie on get-session while the session is fresh", async () => {
    const { session, cookie } = await signedIn(false);
    const res = await getSession(cookie);

    expect(res.status).toBe(200);
    expect(res.headers.getSetCookie()).toEqual([]);
    expect(await res.json()).toMatchObject({ session: { token: session.token } });
  });

  it("should reissue only the session cookie on get-session once a refresh is due", async () => {
    const { session, cookie } = await signedIn(true);
    const { sessionConfig } = await auth.$context;
    const res = await getSession(cookie);

    expect(res.status).toBe(200);
    expect(emitted(res)).toEqual([
      { name: `${prefix}session_token`, maxAge: sessionConfig.expiresIn },
    ]);
    expect(sessionConfig.expiresIn).toBe(604800);
    expect(await res.json()).toMatchObject({ session: { token: session.token } });
  });

  it("should expire the session cookies on sign-out", async () => {
    const { cookie } = await signedIn(false);
    const res = await auth.handler(
      new Request(`${BASE}/api/auth/sign-out`, {
        method: "POST",
        headers: { "content-type": "application/json", origin: BASE, cookie },
        body: "{}",
      }),
    );
    const cookies = emitted(res);

    expect(res.status).toBe(200);
    expect(namesOf(cookies)).toEqual(
      ["dont_remember", "session_data", "session_token"].map((kind) => `${prefix}${kind}`),
    );
    expect(cookies.map((c) => c.maxAge)).toEqual([0, 0, 0]);
    await expect(getSession(cookie).then(async (r) => r.json())).resolves.toBeNull();
  });
});
