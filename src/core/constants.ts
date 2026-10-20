/** Where Better Auth's handler is mounted; its `basePath`. */
export const AUTH_BASE_PATH = "/api/auth";

/** The `genericOAuth` provider id, and the last segment of the callback path. */
export const KEYCLOAK_PROVIDER_ID = "keycloak";

/**
 * The callback path the realm contract registers as the client's only redirect URI (the
 * `interlock` README, "Client"). `assertCallbackPath` checks at startup that Better Auth really
 * serves this path, because it has moved between releases.
 */
export const KEYCLOAK_CALLBACK_PATH = `${AUTH_BASE_PATH}/callback/${KEYCLOAK_PROVIDER_ID}`;

/**
 * The base of every cookie name, `<prefix>.<kind>`. The cookie-name policy decides what precedes
 * it: a literal `__Host-` under `host`, Better Auth's `__Secure-` under `secure` (see
 * `cookieSettings` in `auth.options.ts`).
 */
export const COOKIE_PREFIX = "interlock";

/**
 * How long the host's runtime pool waits for a free connection (`connectionTimeoutMillis`). The
 * refresher's read race and the lease bound assume exactly this value, so the host must configure
 * its pool with it (the README's database host contract).
 */
export const POOL_CONNECTION_TIMEOUT_MS = 2000;

/**
 * The server-side `statement_timeout` of every runtime connection. Like
 * `POOL_CONNECTION_TIMEOUT_MS`, the host must set exactly this value.
 */
export const STATEMENT_TIMEOUT_MS = 2000;

/**
 * The budget of a refresh's `complete` transaction, checked before each of its statements; a
 * completion that runs out rolls back instead of committing late.
 */
export const COMPLETE_BUDGET_MS = 3000;

/** What the refresh lease keeps beyond the request, the pool wait and the write. */
export const LEASE_MARGIN_MS = 1000;
