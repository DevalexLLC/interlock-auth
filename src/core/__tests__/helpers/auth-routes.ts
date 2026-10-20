/** One Better Auth route as its endpoint declares it. */
export interface AuthRoute {
  path: string;
  methods: readonly string[];
}

/**
 * Every pathed route Better Auth 1.7.7 serves with the package's options,
 * sorted by path: the core routes (`genericOAuth` adds none) and the
 * back-channel logout receiver (`logout/backchannel.ts`).
 * `setPassword` has no path and is not here.
 *
 * `exposure.test.ts` proves this equals the instance's own table and walks
 * it; Interlock keeps a copy for its end-to-end sweep. A Better Auth bump
 * that adds or renames a route fails that pin until the route is reviewed
 * against `EXPOSED_ROUTES` (risk R6) and this list is updated.
 */
export const AUTH_ROUTES: readonly AuthRoute[] = [
  { path: "/account-info", methods: ["GET"] },
  // The receiver's plugin route, at its usual path.
  { path: "/backchannel-logout", methods: ["POST"] },
  { path: "/callback/:id", methods: ["GET", "POST"] },
  { path: "/change-email", methods: ["POST"] },
  { path: "/change-password", methods: ["POST"] },
  { path: "/delete-user", methods: ["POST"] },
  { path: "/delete-user/callback", methods: ["GET"] },
  { path: "/error", methods: ["GET"] },
  { path: "/get-access-token", methods: ["POST"] },
  { path: "/get-session", methods: ["GET", "POST"] },
  { path: "/link-social", methods: ["POST"] },
  { path: "/list-accounts", methods: ["GET"] },
  { path: "/list-sessions", methods: ["GET"] },
  { path: "/ok", methods: ["GET"] },
  { path: "/refresh-token", methods: ["POST"] },
  { path: "/request-password-reset", methods: ["POST"] },
  { path: "/reset-password", methods: ["POST"] },
  { path: "/reset-password/:token", methods: ["GET"] },
  { path: "/revoke-other-sessions", methods: ["POST"] },
  { path: "/revoke-session", methods: ["POST"] },
  { path: "/revoke-sessions", methods: ["POST"] },
  { path: "/send-verification-email", methods: ["POST"] },
  { path: "/sign-in/email", methods: ["POST"] },
  { path: "/sign-in/social", methods: ["POST"] },
  { path: "/sign-out", methods: ["POST"] },
  { path: "/sign-up/email", methods: ["POST"] },
  { path: "/unlink-account", methods: ["POST"] },
  { path: "/update-session", methods: ["POST"] },
  { path: "/update-user", methods: ["POST"] },
  { path: "/verify-email", methods: ["GET"] },
  { path: "/verify-password", methods: ["POST"] },
];

/** A route's path with concrete parameters, under `/api/auth`. */
export const concretePath = (path: string) =>
  `/api/auth${path.replace(":id", "keycloak").replace(":token", "x")}`;
