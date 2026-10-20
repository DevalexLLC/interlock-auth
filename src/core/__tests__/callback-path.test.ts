import { betterAuth } from "better-auth";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { createKeycloakAuthOptions, createPostgresStore } from "../auth.options.js";
import {
  assertCallbackPath,
  resolveCallbackPath,
  StartupError,
  type CallbackPathSource,
} from "../callback-path.js";
import { KEYCLOAK_CALLBACK_PATH } from "../constants.js";
import { KyselyGrantStore } from "../grants/grant-store.js";
import { TEST_CONFIG, testLogger, type TestLogger } from "./helpers/config.js";
import { TEST_SCHEMA, unreachableKysely } from "./helpers/kysely.js";
import { createMemoryAuthOptions } from "./helpers/memory-store.js";

const issuer = "https://127.0.0.1:1/realms/test";

const discovery = {
  issuer,
  authorization_endpoint: `${issuer}/protocol/openid-connect/auth`,
  token_endpoint: `${issuer}/protocol/openid-connect/token`,
  userinfo_endpoint: `${issuer}/protocol/openid-connect/userinfo`,
  end_session_endpoint: `${issuer}/protocol/openid-connect/logout`,
  jwks_uri: `${issuer}/protocol/openid-connect/certs`,
  id_token_signing_alg_values_supported: ["RS256"],
};

/** A real instance built from the test configuration, with discovery stubbed. */
const createAuth = (logger: TestLogger, url?: string) =>
  betterAuth(
    createMemoryAuthOptions(
      url === undefined
        ? TEST_CONFIG
        : { ...TEST_CONFIG, betterAuth: { ...TEST_CONFIG.betterAuth, url } },
      logger,
    ),
  );

/** A stand-in instance, for the cases a real one cannot produce. */
const fakeAuth = (
  providers: { id: string; callbackPath?: string; issuer?: string }[],
  endpointPath = "/callback/:id",
): CallbackPathSource => ({
  $context: Promise.resolve({
    baseURL: "https://interlock.test/api/auth",
    socialProviders: providers,
  }),
  api: { callbackOAuth: Object.assign(() => undefined, { path: endpointPath }) },
});

describe("callback path", () => {
  let logger: TestLogger;

  beforeEach(() => {
    logger = testLogger();
  });

  afterEach(() => vi.restoreAllMocks());

  // The R6 guard: a Better Auth release that moves the route fails here.
  describe("with a real Better Auth instance", () => {
    it("should resolve the contract path when discovery succeeds", async () => {
      vi.spyOn(globalThis, "fetch").mockResolvedValue(Response.json(discovery));
      const auth = createAuth(logger);

      await expect(assertCallbackPath(auth, { logger })).resolves.toBe(KEYCLOAK_CALLBACK_PATH);
      expect(KEYCLOAK_CALLBACK_PATH).toBe("/api/auth/callback/keycloak");
      expect(logger.log).toHaveBeenCalledWith({
        message: "Keycloak callback path is /api/auth/callback/keycloak",
      });
      expect(logger.warn).not.toHaveBeenCalledWith({
        message: expect.stringContaining("discovery failed") as string,
      });
    });

    it("should keep the provider, and warn, when discovery fails", async () => {
      vi.spyOn(globalThis, "fetch").mockRejectedValue(new TypeError("fetch failed"));
      const auth = createAuth(logger);

      await expect(assertCallbackPath(auth, { logger })).resolves.toBe(KEYCLOAK_CALLBACK_PATH);
      expect(logger.warn).toHaveBeenCalledWith({
        message: expect.stringContaining("discovery failed") as string,
      });
    });

    // The runtime wiring. The pool points at a refused port, so this also
    // shows that building the instance never touches Postgres: a database
    // that is down does not stop the host from booting.
    it("should store sessions in Postgres through Kysely, not in cookies", async () => {
      vi.spyOn(globalThis, "fetch").mockRejectedValue(new TypeError("fetch failed"));
      const db = unreachableKysely();
      try {
        const ctx = await betterAuth(
          createKeycloakAuthOptions(TEST_CONFIG, {
            database: createPostgresStore(db, TEST_SCHEMA),
            grants: new KyselyGrantStore(db, TEST_SCHEMA),
            logger,
          }),
        ).$context;

        expect(ctx.adapter.id).toBe("kysely");
        expect(ctx.options.session?.cookieCache?.enabled).toBe(false);
        expect(ctx.options.account?.storeAccountCookie).toBe(false);
      } finally {
        await db.destroy();
      }
    });

    // Better Auth keeps a base URL that already has a path and ignores
    // `basePath`, so the callback silently loses `/api/auth`.
    it("should refuse a BETTER_AUTH_URL with a path", async () => {
      vi.spyOn(globalThis, "fetch").mockRejectedValue(new TypeError("fetch failed"));
      const auth = createAuth(logger, "https://interlock.test/prefix");

      await expect(assertCallbackPath(auth, { logger })).rejects.toThrow(
        "Better Auth serves the keycloak callback at /prefix/callback/keycloak, " +
          "but the realm's redirect URI is /api/auth/callback/keycloak",
      );
    });
  });

  describe("resolveCallbackPath", () => {
    it("should honor a provider's own callbackPath", async () => {
      const auth = fakeAuth([{ id: "keycloak", callbackPath: "/oauth2/callback/keycloak" }]);

      await expect(resolveCallbackPath(auth, "keycloak")).resolves.toMatchObject({
        path: "/api/auth/oauth2/callback/keycloak",
      });
      await expect(assertCallbackPath(auth, { logger })).rejects.toBeInstanceOf(StartupError);
    });

    it("should fail when the provider is not registered", async () => {
      await expect(resolveCallbackPath(fakeAuth([]), "keycloak")).rejects.toThrow(
        "OAuth provider keycloak is not registered",
      );
    });

    it("should fail when the core callback endpoint moves", async () => {
      const auth = fakeAuth([{ id: "keycloak" }], "/oauth2/callback/:id");

      await expect(resolveCallbackPath(auth, "keycloak")).rejects.toThrow(
        'no longer serves OAuth callbacks at /callback/:id (found "/oauth2/callback/:id")',
      );
    });
  });

  it("should fail when the expected path differs", async () => {
    const auth = fakeAuth([{ id: "keycloak", issuer }]);

    await expect(
      assertCallbackPath(auth, { logger, expected: "/auth/callback/keycloak" }),
    ).rejects.toThrow(StartupError);
  });
});
