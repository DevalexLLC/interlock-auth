import type { BetterAuthOptions } from "better-auth";

import { mapKeycloakProfile } from "./keycloak-profile.js";

type UserOptions = NonNullable<BetterAuthOptions["user"]>;
type UserHooks = NonNullable<NonNullable<BetterAuthOptions["databaseHooks"]>["user"]>;

/**
 * Better Auth 1.7.7 strips input:false fields even from mapped OAuth profiles.
 * Carry the verified provider profile across its validation/write seam instead.
 * The weak key is the request context, never a user or a process-wide last profile.
 */
export function keycloakUserFields() {
  const usernames = new WeakMap<object, string | null>();
  const validateUserInfo: NonNullable<UserOptions["validateUserInfo"]> = ({ source }, ctx) => {
    if (source.method === "oauth" && source.oauth?.providerId === "keycloak") {
      usernames.set(ctx.context, mapKeycloakProfile(source.oauth.profile ?? {}).username ?? null);
    }
  };
  const before: NonNullable<NonNullable<UserHooks["update"]>["before"]> = async (user, ctx) => {
    if (ctx && usernames.has(ctx.context)) {
      return { data: { ...user, username: usernames.get(ctx.context) } };
    }
    return undefined;
  };
  return {
    user: {
      additionalFields: { username: { type: "string", required: false, input: false } },
      validateUserInfo,
    } satisfies UserOptions,
    hooks: { create: { before }, update: { before } } satisfies UserHooks,
  };
}
