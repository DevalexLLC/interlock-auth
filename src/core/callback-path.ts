import { getOAuthCallbackPath } from "better-auth/oauth2";

import { KEYCLOAK_CALLBACK_PATH, KEYCLOAK_PROVIDER_ID } from "./constants.js";
import type { AuthLogger } from "./logger.js";

/** A startup check failed. Messages carry paths and ids, never configuration values. */
export class StartupError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "StartupError";
  }
}

interface CallbackProvider {
  id: string;
  callbackPath?: string;
  issuer?: string;
}

/** The part of a Better Auth instance the check reads. */
export interface CallbackPathSource {
  $context: Promise<{ baseURL: string; socialProviders: CallbackProvider[] }>;
  api: object;
}

/** The core endpoint every social provider's callback is served by. */
const CALLBACK_ENDPOINT = "/callback/:id";

/**
 * The callback path Better Auth actually serves for a provider, worked out the
 * way its sign-in endpoint builds the `redirect_uri`: the resolved base URL's
 * path (which already includes `basePath`) plus the provider's callback path.
 */
export async function resolveCallbackPath(auth: CallbackPathSource, providerId: string) {
  const endpoint: unknown = Reflect.get(auth.api, "callbackOAuth");
  const endpointPath: unknown =
    endpoint && typeof endpoint === "function" ? Reflect.get(endpoint, "path") : undefined;
  if (endpointPath !== CALLBACK_ENDPOINT) {
    throw new StartupError(
      `Better Auth no longer serves OAuth callbacks at ${CALLBACK_ENDPOINT} ` +
        `(found ${JSON.stringify(endpointPath) ?? "nothing"}); the realm's redirect URI would not match`,
    );
  }

  const ctx = await auth.$context;
  const provider = ctx.socialProviders.find((p) => p.id === providerId);
  if (!provider) {
    throw new StartupError(`OAuth provider ${providerId} is not registered`);
  }

  return { path: new URL(ctx.baseURL).pathname + getOAuthCallbackPath(provider), provider };
}

export interface CallbackPathOptions {
  /** Where the resolved path, and a failed discovery, are reported. */
  logger: AuthLogger;
  /** The realm's redirect URI path; `KEYCLOAK_CALLBACK_PATH` unless the host registers another. */
  expected?: string;
}

/**
 * Fails startup unless the Keycloak callback Better Auth serves is the one
 * path the realm registers as a redirect URI. A dependency bump that moves
 * the route, or a `BETTER_AUTH_URL` with a path, stops the app here instead
 * of failing every login at Keycloak.
 */
export async function assertCallbackPath(
  auth: CallbackPathSource,
  { logger, expected = KEYCLOAK_CALLBACK_PATH }: CallbackPathOptions,
) {
  const { path, provider } = await resolveCallbackPath(auth, KEYCLOAK_PROVIDER_ID);
  if (path !== expected) {
    throw new StartupError(
      `Better Auth serves the ${KEYCLOAK_PROVIDER_ID} callback at ${path}, ` +
        `but the realm's redirect URI is ${expected}`,
    );
  }

  logger.log({ message: `Keycloak callback path is ${path}` });
  if (!provider.issuer) {
    logger.warn({
      message:
        "Keycloak discovery failed at startup; logins use the configured endpoints " +
        "without ID-token verification until the next restart",
    });
  }
  return path;
}
