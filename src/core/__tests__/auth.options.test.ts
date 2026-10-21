import { betterAuth, type BetterAuthOptions } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { createCookieGetter } from "better-auth/cookies";
import type { GenericOAuthConfig, GenericOAuthOptions } from "better-auth/plugins/generic-oauth";
import { Kysely } from "kysely";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  cookieSettings,
  createKeycloakAuthOptions,
  createPostgresStore,
  type KeycloakAuthOptions,
} from "../auth.options.js";
import { StartupError } from "../callback-path.js";
import { COOKIE_NAME_POLICIES, type CookieNamePolicy } from "../config.js";
import type { GrantStore } from "../grants/grant-store.js";
import type { AuthLogger } from "../logger.js";
import { assertReceiverRoute } from "../logout/backchannel.js";
import {
  defined,
  testLogger,
  withKeycloak,
  type TestConfig,
  type TestLogger,
} from "./helpers/config.js";
import { TEST_SCHEMA, unreachableKysely } from "./helpers/kysely.js";
import {
  createMemoryAuthOptions,
  createMemoryAuthSetup,
  MemoryGrantStore,
} from "./helpers/memory-store.js";

const config = (issuer = "https://auth.example.com/realms/main") => withKeycloak({ issuer });

const store = memoryAdapter({});
const grants = new MemoryGrantStore();

/** The options over the shared memory store, with `overrides` in place. */
const build = (overrides: Partial<KeycloakAuthOptions> = {}, cfg: TestConfig = config()) =>
  createKeycloakAuthOptions(cfg, { database: store, grants, logger: testLogger(), ...overrides });

const providerOf = (options: BetterAuthOptions): GenericOAuthConfig => {
  const plugin = defined(
    options.plugins?.find((p) => p.id === "generic-oauth"),
    "the generic OAuth plugin",
  );
  return defined((plugin.options as GenericOAuthOptions).config[0], "the Keycloak provider");
};

const receiverPathOf = (options: BetterAuthOptions) =>
  defined(
    options.plugins?.find((p) => p.id === "backchannel-logout")?.endpoints?.backchannelLogout,
    "the receiver endpoint",
  ).path;

describe("createKeycloakAuthOptions", () => {
  afterEach(() => vi.restoreAllMocks());

  it.each(["https://auth.example.com/realms/main", "https://auth.example.com/realms/main/"])(
    "should register keycloak with explicit endpoints derived from %s",
    (issuer) => {
      const provider = providerOf(build({}, config(issuer)));
      const base = "https://auth.example.com/realms/main";

      expect(provider).toMatchObject({
        providerId: "keycloak",
        clientId: "interlock",
        clientSecret: "test-client-secret",
        discoveryUrl: `${base}/.well-known/openid-configuration`,
        authorizationUrl: `${base}/protocol/openid-connect/auth`,
        tokenUrl: `${base}/protocol/openid-connect/token`,
        userInfoUrl: `${base}/protocol/openid-connect/userinfo`,
        disableProviderLogout: true,
        overrideUserInfo: true,
      });
      expect(provider.scopes).toEqual(["openid", "profile", "email"]);
      expect(provider.redirectURI).toBeUndefined();
      expect(provider.accountSubject).toBeInstanceOf(Function);
      expect(provider.mapProfileToUser).toBeInstanceOf(Function);
    },
  );

  it("should keep sessions and tokens on the server, in the store it is given", () => {
    const options = build();

    expect(options.user?.additionalFields).toEqual({
      username: { type: "string", required: false, input: false },
    });
    expect(options.database).toBe(store);
    expect(options.session?.cookieCache?.enabled).toBe(false);
    expect(options.account).toEqual({ encryptOAuthTokens: true, storeAccountCookie: false });
  });

  // Without a database Better Auth 1.7 silently keeps sessions in cookies.
  it.each([undefined, null])("should refuse to build options with no store (%s)", (database) => {
    expect(() => build({ database })).toThrow("Better Auth needs a database");
  });

  // Without the hooks the account row keeps the tokens and no session has a grant.
  it.each([undefined, null])(
    "should refuse to build options with no grant store (%s)",
    (missing) => {
      expect(() => build({ grants: missing as unknown as GrantStore })).toThrow(
        "Better Auth needs a grant store",
      );
    },
  );

  // Without a logger the first hook to log would throw mid-request.
  it.each([undefined, null])("should refuse to build options with no logger (%s)", (missing) => {
    expect(() => build({ logger: missing as unknown as AuthLogger })).toThrow(
      "Better Auth needs a logger",
    );
  });

  it("should carry the grant hooks", () => {
    const { databaseHooks } = build();

    expect(databaseHooks?.account?.create?.before).toBeInstanceOf(Function);
    expect(databaseHooks?.account?.update?.before).toBeInstanceOf(Function);
    expect(databaseHooks?.session?.create?.before).toBeInstanceOf(Function);
    expect(databaseHooks?.session?.create?.after).toBeInstanceOf(Function);
    expect(databaseHooks?.session?.update?.before).toBeInstanceOf(Function);
  });

  // The refresher owns `expiresAt`; the callback's start anchors the login;
  // the after hook strips provider tokens from every result.
  it("should turn the session slide off and install the request hooks", () => {
    const options = build();

    expect(options.session?.disableSessionRefresh).toBe(true);
    expect(options.hooks?.before).toBeInstanceOf(Function);
    expect(options.hooks?.after).toBeInstanceOf(Function);
  });

  it("should pass the validated configuration through", () => {
    const options = build();

    expect(options).toMatchObject({
      baseURL: "https://interlock.test",
      basePath: "/api/auth",
      secrets: [
        { version: 1, value: "test-secret-current" },
        { version: 0, value: "test-secret-previous" },
      ],
      trustedOrigins: ["https://interlock.test"],
      telemetry: { enabled: false },
      advanced: {
        useSecureCookies: false,
        cookiePrefix: "__Host-interlock",
        defaultCookieAttributes: { secure: true },
        disableOriginCheck: false,
        disableCSRFCheck: false,
      },
    });
    expect(options.secret).toBeUndefined();
  });

  describe("the back-channel logout receiver", () => {
    it("should mount the receiver at its route and exempt it from the rate limiter", () => {
      const options = build();

      expect(receiverPathOf(options)).toBe("/backchannel-logout");
      expect(options.rateLimit).toEqual({ customRules: { "/backchannel-logout": false } });
    });

    it("should serve and expose a receiver configured at another path, and only there", async () => {
      vi.spyOn(globalThis, "fetch").mockRejectedValue(new TypeError("fetch failed"));
      const custom = withKeycloak({ backchannelLogoutPath: "/api/auth/other" });
      const { options } = createMemoryAuthSetup(custom);
      const auth = betterAuth(options);
      const post = async (path: string) =>
        auth.handler(
          new Request(`https://interlock.test/api/auth${path}`, {
            method: "POST",
            headers: { "content-type": "application/x-www-form-urlencoded" },
            body: "logout_token=not-a-jwt",
          }),
        );

      expect(receiverPathOf(options)).toBe("/other");
      expect(options.rateLimit).toEqual({ customRules: { "/other": false } });
      const served = await post("/other");
      expect(served.status).toBe(400);
      expect(await served.json()).toMatchObject({ code: "logout_token_invalid" });
      expect((await post("/backchannel-logout")).status).toBe(404);
      expect(() => assertReceiverRoute(auth, "/other")).not.toThrow();
    });

    // The exposure hook allows a path whatever serves it, so a receiver path
    // that Better Auth also serves would expose, or shadow, that route.
    it.each([
      ["/list-sessions", "/list-sessions"],
      ["/callback/keycloak", "/callback/:id"],
      ["/reset-password/x", "/reset-password/:token"],
    ])("should refuse to start with the receiver at %s", (route, other) => {
      vi.spyOn(globalThis, "fetch").mockRejectedValue(new TypeError("fetch failed"));
      const custom = withKeycloak({ backchannelLogoutPath: `/api/auth${route}` });
      const auth = betterAuth(createMemoryAuthSetup(custom).options);

      expect(() => assertReceiverRoute(auth, route)).toThrow(StartupError);
      expect(() => assertReceiverRoute(auth, route)).toThrow(
        `which Better Auth also serves (${other})`,
      );
    });

    it("should accept the receiver at its usual route, and only where it is served", () => {
      vi.spyOn(globalThis, "fetch").mockRejectedValue(new TypeError("fetch failed"));
      const auth = betterAuth(build());

      expect(() => assertReceiverRoute(auth, "/backchannel-logout")).not.toThrow();
      expect(() => assertReceiverRoute(auth, "/other")).toThrow(
        "The back-channel logout receiver is not served at /other",
      );
    });
  });

  it("should give the memory store used by unit specs a fresh store on every call", () => {
    expect(createMemoryAuthOptions(config()).database).not.toBe(
      createMemoryAuthOptions(config()).database,
    );
  });

  describe("Better Auth's own logs", () => {
    const logOf = (logger: TestLogger) => {
      const options = build({ logger });
      expect(options.logger?.level).toBe("info");
      return defined(options.logger?.log, "Better Auth's log function");
    };

    // A host logger that redacts works on record keys, so Better Auth's
    // arguments must arrive as a record rather than as a formatted string.
    it.each([
      ["error", "error"],
      ["warn", "warn"],
      ["info", "log"],
      ["debug", "debug"],
    ] as const)(
      "should send Better Auth %s logs to the logger's %s as a record",
      (level, method) => {
        const logger = testLogger();

        logOf(logger)(level, "something happened", { accessToken: "x" });

        expect(logger[method]).toHaveBeenCalledWith({
          message: "[better-auth] something happened",
          args: [{ accessToken: "x" }],
        });
      },
    );

    it("should not repeat the tag when Better Auth already wrote it", () => {
      const logger = testLogger();

      logOf(logger)("warn", "[better-auth] Warning: short secret");

      expect(logger.warn).toHaveBeenCalledWith({
        message: "[better-auth] Warning: short secret",
        args: [],
      });
    });
  });

  // R1's re-check on every Better Auth bump: a release that prefixes names
  // regardless of `useSecureCookies`, or drops an attribute, fails here.
  // cookie-policy.test.ts checks which kinds the endpoints really emit.
  describe("cookie names", () => {
    const KINDS = [
      "session_token",
      "session_data",
      "account_data",
      "dont_remember",
      "state",
      "oauth_state",
    ];
    const PREFIXES: Record<CookieNamePolicy, string> = {
      host: "__Host-interlock.",
      secure: "__Secure-interlock.",
    };

    const cookiesOf = (
      overrides: Partial<TestConfig>,
      options: Partial<KeycloakAuthOptions> = {},
    ) => {
      const createCookie = createCookieGetter(build(options, { ...config(), ...overrides }));
      return KINDS.map((kind) => ({ kind, ...createCookie(kind) }));
    };

    it.each(COOKIE_NAME_POLICIES)("should name every %s cookie with one prefix", (policy) => {
      for (const { kind, name, attributes } of cookiesOf({ cookieNamePolicy: policy })) {
        expect(name).toBe(`${PREFIXES[policy]}${kind}`);
        expect(attributes).toMatchObject({
          secure: true,
          httpOnly: true,
          sameSite: "lax",
          path: "/",
        });
        expect(attributes).not.toHaveProperty("domain");
      }
    });

    // Pinned, not inferred from the base URL: on http the browser drops the
    // cookies instead of receiving an insecure, unprefixed session cookie.
    it.each(COOKIE_NAME_POLICIES)("should keep %s cookies Secure on an http base URL", (policy) => {
      const base = config();
      const cookies = cookiesOf({
        cookieNamePolicy: policy,
        betterAuth: { ...base.betterAuth, url: "http://interlock.test" },
      });

      for (const { kind, name, attributes } of cookies) {
        expect(name).toBe(`${PREFIXES[policy]}${kind}`);
        expect(attributes.secure).toBe(true);
      }
    });

    // Another application names its own cookies under the same policy.
    it.each([
      ["host", "__Host-portal."],
      ["secure", "__Secure-portal."],
    ] as const)("should put a host's own prefix under the %s policy", (policy, prefix) => {
      for (const { kind, name } of cookiesOf(
        { cookieNamePolicy: policy },
        { cookiePrefix: "portal" },
      )) {
        expect(name).toBe(`${prefix}${kind}`);
      }
    });

    it("should derive the advanced cookie options from the policy and the prefix", () => {
      expect(cookieSettings("host")).toEqual({
        useSecureCookies: false,
        cookiePrefix: "__Host-interlock",
        defaultCookieAttributes: { secure: true },
      });
      expect(cookieSettings("secure")).toEqual({
        useSecureCookies: true,
        cookiePrefix: "interlock",
        defaultCookieAttributes: { secure: true },
      });
      expect(cookieSettings("host", "portal")).toMatchObject({ cookiePrefix: "__Host-portal" });
      expect(cookieSettings("secure", "portal")).toMatchObject({ cookiePrefix: "portal" });
    });
  });

  describe("createPostgresStore", () => {
    // `transaction` is the one that matters: the `{ db }` shape treats unset as
    // false, and then `createOAuthUser` commits the user before a failing
    // account insert (Interlock's Postgres session-store suite proves both
    // ways).
    it("should qualify statements with the schema and run multi-step writes in a transaction", async () => {
      const db = unreachableKysely();
      try {
        expect(createPostgresStore(db, TEST_SCHEMA)).toEqual({
          db,
          type: "postgres",
          schemaName: TEST_SCHEMA,
          transaction: true,
        });
        expect(db).toBeInstanceOf(Kysely);
      } finally {
        await db.destroy();
      }
    });
  });
});
