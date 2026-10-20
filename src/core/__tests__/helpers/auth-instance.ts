import { betterAuth, type BetterAuthOptions } from "better-auth";
import type { RemoteJWKSet } from "jose";
import { vi } from "vitest";

import {
  composeAfterHooks,
  composeBeforeHooks,
  recordCallbackStart,
} from "../../grants/callback-start.js";
import { BACKCHANNEL_LOGOUT_ROUTE, backchannelLogout } from "../../logout/backchannel.js";
import { captureSignOut, finishSignOut } from "../../logout/sign-out.js";
import { TEST_CONFIG, testLogger, type TestLogger } from "./config.js";
import { FakeKeycloak, loginThrough } from "./fake-keycloak.js";
import { createMemoryAuthSetup, MemoryGrantStore } from "./memory-store.js";

export const BASE = "https://interlock.test";

export interface BuildOptions {
  /** Whether the fake serves discovery, which turns the ID-token sign-in path on. */
  discovery?: boolean;
  grants?: MemoryGrantStore;
  /** False removes the grant hooks and every request hook, for the controls. */
  hooks?: boolean;
  /**
   * False removes the exposure hooks alone (the allow-list and the token
   * strip), keeping the callback start, the sign-out hooks and the grant
   * hooks, to reach the inner layers the allow-list stands in front of.
   */
  exposure?: boolean;
  /** True turns Better Auth's session slide back on. */
  slide?: boolean;
  /** True turns Better Auth's rate limiter on, as `NODE_ENV=production` does. */
  rateLimit?: boolean;
  /** The key set the back-channel logout receiver verifies with, in place of the realm's. */
  logoutKeys?: RemoteJWKSet;
  /** Where everything logs; a fresh `testLogger()` unless given. */
  logger?: TestLogger;
}

/**
 * A real instance on a fresh memory store, with Keycloak faked at `fetch`.
 * The caller restores the `fetch` spy (`vi.restoreAllMocks`).
 *
 * Interlock's own test helper of the same name, whose only users were the
 * specs that moved here.
 */
export function buildAuth({
  discovery = false,
  grants = new MemoryGrantStore(),
  hooks = true,
  exposure = true,
  slide = false,
  rateLimit = false,
  logoutKeys,
  logger = testLogger(),
}: BuildOptions = {}) {
  const keycloak = new FakeKeycloak(discovery);
  const fetch = vi.spyOn(globalThis, "fetch").mockImplementation(keycloak.fetch);
  const config = TEST_CONFIG;
  const setup = createMemoryAuthSetup(config, grants, logger);
  let options: BetterAuthOptions = setup.options;
  if (slide) {
    options = { ...options, session: { ...options.session, disableSessionRefresh: false } };
  }
  if (rateLimit) {
    options = { ...options, rateLimit: { ...options.rateLimit, enabled: true } };
  }
  if (logoutKeys) {
    const receiver = backchannelLogout(grants, {
      route: BACKCHANNEL_LOGOUT_ROUTE,
      issuer: keycloak.issuer,
      clientId: config.keycloak.clientId,
      getKey: logoutKeys,
      logger,
    });
    options = {
      ...options,
      plugins: (options.plugins ?? []).map((plugin) =>
        plugin.id === receiver.id ? receiver : plugin,
      ),
    };
  }
  if (!exposure) {
    options = {
      ...options,
      hooks: {
        before: composeBeforeHooks([recordCallbackStart(), captureSignOut(grants, logger)]),
        after: composeAfterHooks([
          finishSignOut(grants, {
            issuer: keycloak.issuer,
            clientId: config.keycloak.clientId,
            postLogoutRedirectUri: `${BASE}/`,
            logger,
          }),
        ]),
      },
    };
  }
  if (!hooks) {
    options = { ...options, databaseHooks: undefined, hooks: undefined };
  }
  const auth = betterAuth(options);
  return {
    auth,
    keycloak,
    fetch,
    logger,
    tables: setup.tables,
    grants,
    login: async () => loginThrough(auth.handler, keycloak),
    post: async (path: string, cookie: string, body: object) =>
      auth.handler(
        new Request(`${BASE}/api/auth/${path}`, {
          method: "POST",
          headers: { "content-type": "application/json", origin: BASE, cookie },
          body: JSON.stringify(body),
        }),
      ),
    /** A form POST as Keycloak's back-channel delivery sends one: no cookie, no `Origin`. */
    postForm: async (path: string, body: Record<string, string> | string) =>
      auth.handler(
        new Request(`${BASE}/api/auth/${path}`, {
          method: "POST",
          headers: { "content-type": "application/x-www-form-urlencoded" },
          body: typeof body === "string" ? body : new URLSearchParams(body).toString(),
        }),
      ),
  };
}

export type AuthInstance = ReturnType<typeof buildAuth>;

export const sessionCookieName = async (auth: AuthInstance["auth"]) =>
  (await auth.$context).authCookies.sessionToken.name;

/** Whether a response set a session cookie with a value. */
export const setsSession = (setCookies: readonly string[], name: string) =>
  setCookies.some((line) => line.startsWith(`${name}=`) && !line.startsWith(`${name}=;`));
