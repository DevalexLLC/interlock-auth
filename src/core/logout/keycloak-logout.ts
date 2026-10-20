import { randomBytes } from "node:crypto";

/**
 * The deadline on the whole outbound logout: connecting, sending, and
 * Keycloak's answer, which includes its own back-channel deliveries to the
 * realm's clients (its socket timeout for each is also 5 s). An answer that
 * misses it is `unconfirmed`, never `ended`.
 */
export const KEYCLOAK_LOGOUT_DEADLINE_MS = 5_000;

/**
 * What sign-out reports about the Keycloak session, as `keycloakLogout`:
 *
 * - `ended`: Keycloak confirmed the targeted Keycloak session is gone (ended
 *   now, or already). It says nothing about whether every other client of
 *   that session received its back-channel logout.
 * - `unconfirmed`: the outcome is unknown. The session may already be gone;
 *   if it survives, activity elsewhere can keep extending its idle lifetime.
 * - `no_session`: there was no Interlock session to end, so nothing is
 *   asserted about Keycloak; a repeated sign-out never upgrades an earlier
 *   `unconfirmed`.
 */
export type KeycloakLogout = "ended" | "unconfirmed" | "no_session";

/** Why a logout was not confirmed, as logged. */
export type UnconfirmedReason =
  | "no_hint"
  | "timeout"
  | "unreachable"
  | "unexpected_status"
  | "unexpected_redirect";

export type KeycloakLogoutResult =
  | { outcome: "ended" }
  | { outcome: "unconfirmed"; reason: UnconfirmedReason; status?: number };

export interface KeycloakLogoutRequest {
  /** The realm's issuer, without a trailing slash. */
  issuer: string;
  clientId: string;
  /**
   * A URI the client's `post.logout.redirect.uris` accepts. Keycloak's
   * redirect to it, carrying this request's `state`, is the only proof of a
   * logout: its pages (the confirmation, "You are logged out", an error) all
   * answer 200 or 400 with HTML.
   */
  postLogoutRedirectUri: string;
  /** The grant's ID token, decrypted. Sent in the form body only. */
  idTokenHint: string;
  deadlineMs?: number;
}

/** A 302 to the redirect URI with this request's `state` is a confirmed logout. */
function classify(
  status: number,
  location: string | null,
  expected: URL,
  state: string,
): KeycloakLogoutResult {
  if (status !== 302) {
    return { outcome: "unconfirmed", reason: "unexpected_status", status };
  }
  let url: URL;
  try {
    url = new URL(location ?? "");
  } catch {
    return { outcome: "unconfirmed", reason: "unexpected_redirect", status };
  }
  return url.origin === expected.origin &&
    url.pathname === expected.pathname &&
    url.searchParams.get("state") === state
    ? { outcome: "ended" }
    : { outcome: "unconfirmed", reason: "unexpected_redirect", status };
}

/**
 * Ends a Keycloak session from the server: OIDC RP-initiated logout posted to
 * the realm's end-session endpoint with the session's ID token as
 * `id_token_hint`, and no browser cookies. Keycloak 26.7 then ends exactly the
 * session the hint names (its `sid`), delivers back-channel logout to that
 * session's clients, and redirects to `post_logout_redirect_uri` with the
 * `state` it was given. It checks the hint's signature and type, not its
 * `exp`, so the hint of a session idle past its ID token's lifetime still
 * works. Redirects are never followed and the answer's body is never read.
 * Never throws.
 */
export async function endKeycloakSession({
  issuer,
  clientId,
  postLogoutRedirectUri,
  idTokenHint,
  deadlineMs = KEYCLOAK_LOGOUT_DEADLINE_MS,
}: KeycloakLogoutRequest): Promise<KeycloakLogoutResult> {
  const state = randomBytes(16).toString("base64url");
  const expected = new URL(postLogoutRedirectUri);
  const controller = new AbortController();
  let timer: NodeJS.Timeout | undefined;
  const deadline = new Promise<KeycloakLogoutResult>((resolve) => {
    timer = setTimeout(() => {
      controller.abort();
      resolve({ outcome: "unconfirmed", reason: "timeout" });
    }, deadlineMs);
  });
  const attempt = (async (): Promise<KeycloakLogoutResult> => {
    const response = await fetch(`${issuer}/protocol/openid-connect/logout`, {
      method: "POST",
      body: new URLSearchParams({
        id_token_hint: idTokenHint,
        client_id: clientId,
        post_logout_redirect_uri: postLogoutRedirectUri,
        state,
      }),
      redirect: "manual",
      signal: controller.signal,
    });
    await response.body?.cancel().catch(() => undefined);
    return classify(response.status, response.headers.get("location"), expected, state);
  })().catch((): KeycloakLogoutResult => ({ outcome: "unconfirmed", reason: "unreachable" }));
  try {
    return await Promise.race([attempt, deadline]);
  } finally {
    clearTimeout(timer);
  }
}
