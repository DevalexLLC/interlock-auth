/**
 * Maps a Keycloak profile onto Better Auth's user, with two fallbacks:
 *
 *  - **No `name` claim.** Keycloak emits `name` only when the user has both a
 *    given and a family name; `preferred_username` is always present.
 *  - **No `email` claim.** Better Auth would fail the callback with
 *    `email_not_found` and create no session. Email identifies nobody here:
 *    the account is keyed by `sub` and authorization comes from Keycloak
 *    groups, so the user gets a stable placeholder instead of being locked out.
 *    `.invalid` is reserved by RFC 2606 and never resolves or receives mail.
 */

import { registerLoginLifetimes, tokenLifetimes } from "./keycloak-token.js";

/** The claims read here; Better Auth hands over the whole profile. */
interface KeycloakProfile {
  sub?: unknown;
  name?: unknown;
  preferred_username?: unknown;
  email?: unknown;
  email_verified?: unknown;
  [claim: string]: unknown;
}

/** Domain of the placeholder address. Reserved by RFC 2606. */
const PLACEHOLDER_EMAIL_DOMAIN = "keycloak.invalid";

/** A claim is usable only if it is a non-blank string. */
const claim = (value: unknown) =>
  typeof value === "string" && value.trim() !== "" ? value : undefined;

/** Keycloak's `sub`, or undefined when it is missing or blank. */
const subject = (profile: KeycloakProfile) => {
  const { sub } = profile;
  return typeof sub === "number" ? String(sub) : claim(sub);
};

export function mapKeycloakProfile(profile: KeycloakProfile) {
  const email = claim(profile.email);
  return {
    name: claim(profile.name) ?? claim(profile.preferred_username),
    email: email ?? `${subject(profile) ?? "unknown"}@${PLACEHOLDER_EMAIL_DOMAIN}`,
    // Set every time: Better Auth spreads this over its own mapping, and a
    // placeholder address must never count as verified.
    emailVerified: email !== undefined && profile.email_verified === true,
  };
}

/** The part of Better Auth's token object `keycloakAccountSubject` reads and marks. */
interface LoginTokens {
  refreshTokenExpiresAt?: Date;
  raw?: unknown;
}

/**
 * The account key. Keycloak always identifies a user by `sub`; without a
 * discovery document the generic provider would fall back to `id`, which
 * Keycloak never sends. Throwing makes the callback log the failure and
 * redirect with `unable_to_get_user_info` instead of keying an account on nothing.
 *
 * It also carries the token response's lifetimes to the grant. Better Auth
 * reads `refresh_token_expires_in`, which Keycloak never sends (it sends
 * `refresh_expires_in`), and copies only named fields into the account write,
 * but it hands this function and the account hooks the same token object. So
 * `tokens.refreshTokenExpiresAt` gets a Date of its own, and the raw lifetimes
 * are registered under that Date, which the account hook receives as it is.
 * A response without a usable `refresh_expires_in` gets no Date, and the
 * session hook refuses the login.
 */
export function keycloakAccountSubject({
  tokens,
  profile,
}: {
  tokens?: LoginTokens;
  profile: KeycloakProfile;
}) {
  const sub = subject(profile);
  if (sub === undefined) {
    throw new Error("Keycloak profile has no sub claim");
  }
  if (tokens) {
    const lifetimes = tokenLifetimes(tokens.raw);
    if (lifetimes.refreshExpiresIn === null) {
      delete tokens.refreshTokenExpiresAt;
    } else {
      const marker = new Date(Date.now() + lifetimes.refreshExpiresIn * 1000);
      registerLoginLifetimes(marker, lifetimes);
      tokens.refreshTokenExpiresAt = marker;
    }
  }
  return sub;
}

/**
 * Whether an address is the placeholder `mapKeycloakProfile` made up, so a UI
 * can say "not provided" rather than show it. Nothing should authorize on it.
 */
export function isPlaceholderEmail(email: string | null | undefined): boolean {
  return typeof email === "string" && email.endsWith(`@${PLACEHOLDER_EMAIL_DOMAIN}`);
}
