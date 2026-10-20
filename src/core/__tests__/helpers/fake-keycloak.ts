import { generateKeyPairSync, randomUUID, sign, type KeyObject } from "node:crypto";
import { performance } from "node:perf_hooks";
import { setTimeout as sleep } from "node:timers/promises";

import type { TokenTransport } from "../../keycloak-token.js";
import { defined } from "./config.js";

/** `TEST_CONFIG`'s issuer; nothing listens there. */
export const ISSUER = "https://127.0.0.1:1/realms/test";

/** The one user every fake login is for. */
export const SUBJECT = "sub-ann";

const BASE = "https://interlock.test";
const KID = "fake-keycloak";
const b64 = (value: object) => Buffer.from(JSON.stringify(value)).toString("base64url");

/** `header.payload.signature`, signed by `signer` when there is one, else `unsigned`. */
const jws = (header: object, payload: object, signer: { key: KeyObject } | undefined) => {
  const input = `${b64(header)}.${b64(payload)}`;
  const signature = signer
    ? sign("RSA-SHA256", Buffer.from(input), signer.key).toString("base64url")
    : "unsigned";
  return `${input}.${signature}`;
};

/** The `events` member of a logout token (OIDC Back-Channel Logout 1.0). */
const LOGOUT_EVENT = "http://schemas.openid.net/event/backchannel-logout";

/** What a logout token from `FakeKeycloak.logoutToken` should carry. */
export interface LogoutTokenSpec {
  /** The Keycloak session; the first login's by default, null leaves the claim out. */
  sid?: string | null;
  /** The subject; the fake's own by default, null leaves the claim out. */
  sub?: string | null;
  /** Overrides of the JWS header, e.g. `alg: 'none'` or an unknown `kid`. */
  header?: Record<string, unknown>;
  /** Overrides of the claims; `undefined` removes one. */
  claims?: Record<string, unknown>;
  /** A signature that does not verify. */
  unsigned?: boolean;
  /** Sign with this key, by index (0 is the first); the newest by default. */
  keyIndex?: number;
}

/** A JWKS answer other than the key set, for the receiver's failure specs. */
export interface CertsResponse {
  status?: number;
  /** A JSON body. */
  body?: unknown;
  /** A raw body, e.g. text that is not JSON. */
  text?: string;
}

/** What the next code exchange should get wrong, for the failure specs. */
export interface NextLogin {
  omitIdToken?: boolean;
  omitSid?: boolean;
  /** Put this Keycloak session's `sid` on the ID token, as a second login in one SSO session would. */
  sid?: string;
  /** Overrides of the token response's fields; `undefined` removes one. */
  fields?: Record<string, unknown>;
}

/**
 * What the next refresh-token grant should do, consumed by it. The
 * transport-level failures are acted out by `fakeTransport` (connecting:
 * Keycloak never sees the request) or by the listening server
 * (test/fake-keycloak-server.ts), which reads the body and then closes the
 * socket for `sentFail`.
 */
export interface NextRefresh {
  /** Answer 400 `invalid_grant`, as for a reused or revoked refresh token. */
  invalidGrant?: boolean;
  /** Process the refresh (the token rotates) and never answer. */
  hang?: boolean;
  /** Answer this status with an `error` body instead. */
  status?: number;
  /** Keycloak's `error` code for `status`. */
  error?: string;
  /** Wait this long before answering. */
  delayMs?: number;
  /** Overrides of the response's fields; `undefined` removes one. */
  fields?: Record<string, unknown>;
  /** Fail before anything is written, with this code. */
  connectFail?: string;
  /** Spend this long connecting first. */
  connectDelayMs?: number;
  /** Process the refresh, then lose the answer with this code. */
  sentFail?: string;
}

/** A response of the fake: status and JSON body (or raw `text`), or never. */
export interface FakeResponse {
  status: number;
  body: unknown;
  text?: string;
  headers?: Record<string, string>;
}

/** What the next RP-initiated logout should do instead of Keycloak's normal answer. */
export interface NextLogout {
  /** Answer this status with an HTML page (and `location`, if given) and end nothing. */
  status?: number;
  /** The page's text, e.g. Keycloak's confirmation page. */
  text?: string;
  location?: string;
  /** End the session, then redirect with a `state` other than the one sent. */
  wrongState?: boolean;
  /** Never answer. */
  hang?: boolean;
  /** Refuse the connection. */
  refuse?: boolean;
}

/** One RP-initiated logout the fake received. */
export interface ReceivedLogout {
  /** The hint as sent, so specs can compare it with the issued ID tokens. */
  hint: string | null;
  sid: string | undefined;
  clientId: string | null;
  redirect: string | null;
  state: string | null;
  /** Whether a cookie came with it; Interlock never sends one. */
  cookie: boolean;
}

const html = (text: string) => `<!DOCTYPE html><html><body><p>${text}</p></body></html>`;

/** Spreads overrides, dropping the keys set to undefined. */
const withFields = (body: Record<string, unknown>, fields: Record<string, unknown> = {}) =>
  Object.fromEntries(
    Object.entries({ ...body, ...fields }).filter(([, value]) => value !== undefined),
  );

/**
 * Keycloak's token, userinfo and (in discovery mode) discovery and JWKS
 * endpoints, as a `fetch` replacement and as a request handler for the
 * listening server. Login `n` gets `access-<n>`, `refresh-<n>` and an ID
 * token with `sid-<n>`, in the shape a real Keycloak token response has,
 * `refresh_expires_in` included; refresh `n` gets `access-refreshed-<n>`,
 * `refresh-refreshed-<n>` and a new ID token. Without discovery the ID token
 * is unsigned, as the provider then never verifies it; with discovery it is
 * signed RS256 with a key generated here, so Better Auth verifies it against
 * the served JWKS. Any other URL is refused, as an unreachable host would be.
 *
 * The issuer defaults to `TEST_CONFIG`'s; the listening
 * server passes its own origin. Calls arrive with a `URL` object as well as
 * strings, so the URL is read with `String(input)`.
 */
export class FakeKeycloak {
  /** Code exchanges so far; also the number of the last login. */
  codeExchanges = 0;
  /** Refresh-token grants so far, and the refresh token each one presented. */
  refreshes = 0;
  readonly refreshedWith: string[] = [];
  /** Every ID token issued, in order. */
  readonly idTokens: string[] = [];
  next: NextLogin = {};
  nextRefresh: NextRefresh = {};
  /** Delays of the login's own requests, for the login-anchor specs. */
  exchangeDelayMs = 0;
  userinfoDelayMs = 0;
  /** Awaited when a refresh arrives, before it is processed. */
  onRefresh: (() => unknown) | undefined;
  /** The nonce the next ID token carries; the login helper sets it. */
  nonce: string | undefined;
  /**
   * The user every login is for. Suites that share the e2e schema and run in
   * parallel each use their own, so one suite's cleanup never removes
   * another's user.
   */
  subject = SUBJECT;
  /** The user's address; Better Auth links accounts by it, so it changes with `subject`. */
  email = "ann@example.com";
  /**
   * Login `n`'s Keycloak session is `<sidPrefix>-<n>`. An e2e suite that
   * sends sid-bound logout tokens sets its own, because the schema is shared
   * and a `sid-1` logout would end every parallel suite's first session.
   */
  sidPrefix = "sid";

  /** JWKS fetches so far (discovery mode). */
  certsFetches = 0;
  /** Answer the JWKS endpoint with this instead of the keys, until cleared. */
  certsResponse: CertsResponse | undefined;
  /** Every RP-initiated logout, in order, and the sids they ended. */
  readonly logouts: ReceivedLogout[] = [];
  readonly endedSids = new Set<string>();
  nextLogout: NextLogout = {};
  /**
   * Awaited for each session a logout ends, before the answer: Keycloak
   * delivers its back-channel logout to the session's clients first.
   */
  onLogout: ((sid: string) => unknown) | undefined;

  /** The signing keys, oldest first; the newest signs. Discovery mode only. */
  private readonly keys: { key: KeyObject; jwk: object; kid: string }[] = [];

  constructor(
    readonly discovery = false,
    readonly issuer = ISSUER,
  ) {
    if (discovery) {
      this.addKey(KID);
    }
  }

  private addKey(kid: string) {
    const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    this.keys.push({
      key: privateKey,
      jwk: { ...publicKey.export({ format: "jwk" }), kid, alg: "RS256", use: "sig" },
      kid,
    });
  }

  /**
   * Rotates the realm key as Keycloak does: a new key with a new `kid` signs
   * from now on, and the old one stays in the key set, passive.
   */
  rotateKey() {
    if (!this.discovery) {
      throw new Error("the fake has keys only in discovery mode");
    }
    this.addKey(`${KID}-${this.keys.length + 1}`);
  }

  private get signer() {
    return this.keys[this.keys.length - 1];
  }

  endpoint(name: string) {
    return `${this.issuer}/protocol/openid-connect/${name}`;
  }

  /**
   * A back-channel logout token as Keycloak 26 sends one: header
   * `typ: logout+jwt`, `exp` 120 s after `iat`, the client as audience, the
   * subject, the session's `sid` and the logout event. Discovery mode only,
   * since only then does the fake have a key and serve the key set.
   */
  logoutToken({
    sid = `${this.sidPrefix}-1`,
    sub = this.subject,
    header = {},
    claims = {},
    unsigned = false,
    keyIndex,
  }: LogoutTokenSpec = {}) {
    if (!this.discovery) {
      throw new Error("logout tokens need the fake in discovery mode");
    }
    const signer = defined(
      keyIndex === undefined ? this.signer : this.keys[keyIndex],
      "a signing key",
    );
    const now = Math.floor(Date.now() / 1000);
    const token = jws(
      { alg: "RS256", typ: "logout+jwt", kid: signer.kid, ...header },
      withFields(
        {
          jti: randomUUID(),
          iat: now,
          exp: now + 120,
          iss: this.issuer,
          aud: "interlock",
          typ: "Logout",
          sub: sub ?? undefined,
          sid: sid ?? undefined,
          events: { [LOGOUT_EVENT]: {} },
        },
        claims,
      ),
      signer,
    );
    return unsigned ? `${token.slice(0, token.lastIndexOf("."))}.unsigned` : token;
  }

  /** An ID token for `n`, signed in discovery mode. */
  idToken(n: number, claims: Record<string, unknown> = {}) {
    const now = Math.floor(Date.now() / 1000);
    return jws(
      { alg: "RS256", typ: "JWT", kid: this.signer?.kid ?? KID },
      {
        iss: this.issuer,
        aud: "interlock",
        sub: this.subject,
        sid: `${this.sidPrefix}-${n}`,
        iat: now,
        exp: now + 300,
        n,
        ...(this.nonce ? { nonce: this.nonce } : {}),
        ...claims,
      },
      this.signer,
    );
  }

  /**
   * One request. Resolves to the response, or never (`hang`); undefined
   * means an unknown URL, which `fetch` turns into a refused connection.
   */
  async handle(
    url: string,
    body: string,
    headers: { cookie?: boolean } = {},
  ): Promise<FakeResponse | undefined> {
    if (url === this.endpoint("logout")) {
      return this.logout(new URLSearchParams(body), headers.cookie === true);
    }
    if (url === this.endpoint("token")) {
      const params = new URLSearchParams(body);
      return params.get("grant_type") === "refresh_token"
        ? this.refresh(params.get("refresh_token"))
        : { status: 200, body: await this.exchange() };
    }
    if (url === this.endpoint("userinfo")) {
      await sleep(this.userinfoDelayMs);
      return {
        status: 200,
        body: {
          sub: this.subject,
          preferred_username: "ann",
          email: this.email,
          email_verified: true,
        },
      };
    }
    if (this.discovery && url === `${this.issuer}/.well-known/openid-configuration`) {
      return {
        status: 200,
        body: {
          issuer: this.issuer,
          authorization_endpoint: this.endpoint("auth"),
          token_endpoint: this.endpoint("token"),
          userinfo_endpoint: this.endpoint("userinfo"),
          end_session_endpoint: this.endpoint("logout"),
          jwks_uri: this.endpoint("certs"),
          id_token_signing_alg_values_supported: ["RS256"],
        },
      };
    }
    if (this.discovery && url === this.endpoint("certs")) {
      this.certsFetches += 1;
      if (this.certsResponse !== undefined) {
        const { status = 200, body: answer, text } = this.certsResponse;
        return { status, body: answer, text };
      }
      return { status: 200, body: { keys: this.keys.map(({ jwk }) => jwk) } };
    }
    return undefined;
  }

  readonly fetch = async (input: string | URL | Request, init?: RequestInit) => {
    const url = String(input instanceof Request ? input.url : input);
    const body = init?.body;
    const response = await this.handle(
      url,
      body instanceof URLSearchParams ? body.toString() : typeof body === "string" ? body : "",
      { cookie: new Headers(init?.headers).has("cookie") },
    );
    if (response === undefined) {
      throw new TypeError(`fetch failed: ${url}`);
    }
    return response.text === undefined
      ? Response.json(response.body, { status: response.status, headers: response.headers })
      : new Response(response.text, { status: response.status, headers: response.headers });
  };

  /**
   * RP-initiated logout as Keycloak 26.7 answers a POST with `id_token_hint`
   * and no browser cookies: an unknown hint or another client's `client_id`
   * is a 400 page, an unregistered redirect a 400 page; otherwise the hint's
   * session ends (`onLogout` runs first, as Keycloak's back-channel delivery
   * does), and the answer is a 302 to `post_logout_redirect_uri` with the
   * `state`, or without a redirect URI the 200 "You are logged out" page. A
   * session already gone answers the same, as Keycloak does.
   */
  private async logout(
    params: URLSearchParams,
    cookie: boolean,
  ): Promise<FakeResponse | undefined> {
    const next = this.nextLogout;
    this.nextLogout = {};
    if (next.refuse) {
      return undefined;
    }
    if (next.hang) {
      return new Promise<never>(() => undefined);
    }
    const hint = params.get("id_token_hint");
    const known = hint !== null && this.idTokens.includes(hint);
    const sid = known
      ? (
          JSON.parse(Buffer.from(hint.split(".")[1] ?? "", "base64url").toString("utf8")) as {
            sid?: string;
          }
        ).sid
      : undefined;
    const clientId = params.get("client_id");
    const redirect = params.get("post_logout_redirect_uri");
    const state = params.get("state");
    this.logouts.push({ hint, sid, clientId, redirect, state, cookie });
    const page = (status: number, text: string, location?: string): FakeResponse => ({
      status,
      body: undefined,
      text: html(text),
      headers: { "content-type": "text/html", ...(location ? { location } : {}) },
    });
    if (next.status !== undefined) {
      return page(next.status, next.text ?? "Do you want to log out?", next.location);
    }
    if (!known || (clientId !== null && clientId !== "interlock")) {
      return page(400, "Invalid parameter: id_token_hint");
    }
    if (redirect !== null && !redirect.startsWith(`${BASE}/`)) {
      return page(400, "Invalid redirect uri");
    }
    if (sid !== undefined) {
      await this.onLogout?.(sid);
      this.endedSids.add(sid);
    }
    if (redirect === null) {
      return page(200, "You are logged out");
    }
    const location = new URL(redirect);
    if (state !== null) {
      location.searchParams.set("state", next.wrongState ? `${state}-other` : state);
    }
    return { status: 302, body: undefined, text: "", headers: { location: location.href } };
  }

  private async exchange() {
    await sleep(this.exchangeDelayMs);
    this.codeExchanges += 1;
    const n = this.codeExchanges;
    const { omitIdToken, omitSid, sid, fields } = this.next;
    this.next = {};
    const idToken = omitIdToken
      ? undefined
      : this.idToken(n, omitSid ? { sid: undefined } : sid ? { sid } : {});
    if (idToken) {
      this.idTokens.push(idToken);
    }
    return withFields(
      {
        access_token: `access-${n}`,
        refresh_token: `refresh-${n}`,
        id_token: idToken,
        token_type: "Bearer",
        expires_in: 300,
        refresh_expires_in: 1800,
        "not-before-policy": 0,
        session_state: sid ?? `${this.sidPrefix}-${n}`,
        scope: "openid profile email",
      },
      fields,
    );
  }

  private async refresh(presented: string | null): Promise<FakeResponse> {
    const next = this.nextRefresh;
    this.nextRefresh = {};
    await this.onRefresh?.();
    this.refreshes += 1;
    this.refreshedWith.push(presented ?? "");
    const n = this.refreshes;
    if (next.hang) {
      return new Promise<never>(() => undefined);
    }
    await sleep(next.delayMs ?? 0);
    if (next.invalidGrant) {
      return {
        status: 400,
        body: { error: "invalid_grant", error_description: "Token is not active" },
      };
    }
    if (next.status !== undefined) {
      return { status: next.status, body: { error: next.error ?? "server_error" } };
    }
    const idToken = this.idToken(1000 + n);
    this.idTokens.push(idToken);
    return {
      status: 200,
      body: withFields(
        {
          access_token: `access-refreshed-${n}`,
          refresh_token: `refresh-refreshed-${n}`,
          id_token: idToken,
          token_type: "Bearer",
          expires_in: 300,
          refresh_expires_in: 1800,
          scope: "openid profile email",
        },
        next.fields,
      ),
    };
  }
}

/**
 * The refresher's two-phase transport over a `FakeKeycloak`, for unit specs.
 * A `connectFail` (or a `connectDelayMs` past the deadline) fails in the
 * connecting phase, before Keycloak sees anything; everything after that is
 * the sent phase, where Keycloak processes the refresh before a `sentFail`,
 * a `hang` or the deadline loses its answer.
 */
export const fakeTransport =
  (keycloak: FakeKeycloak): TokenTransport =>
  async ({ url, body, timeoutMs, onSent }) => {
    const start = performance.now();
    const { connectFail, connectDelayMs = 0, sentFail } = keycloak.nextRefresh;
    if (connectDelayMs > 0) {
      await sleep(Math.min(connectDelayMs, timeoutMs));
      if (connectDelayMs >= timeoutMs) {
        keycloak.nextRefresh = {};
        return { phase: "connecting", cause: "timeout" };
      }
    }
    if (connectFail !== undefined) {
      keycloak.nextRefresh = {};
      return { phase: "connecting", cause: connectFail };
    }
    const sentAt = performance.now();
    onSent?.();
    const left = Math.max(0, timeoutMs - (sentAt - start));
    let timer: NodeJS.Timeout | undefined;
    const deadline = new Promise<"timeout">((resolve) => {
      timer = setTimeout(() => resolve("timeout"), left);
    });
    const response = await Promise.race([keycloak.handle(url, body), deadline]);
    clearTimeout(timer);
    if (response === "timeout") {
      return { phase: "sent", sentAt, cause: "timeout" };
    }
    if (response === undefined || sentFail !== undefined) {
      return { phase: "sent", sentAt, cause: sentFail ?? "ECONNRESET" };
    }
    return { phase: "sent", sentAt, status: response.status, body: JSON.stringify(response.body) };
  };

/** The `name=value` pairs a response sets, skipping cookies it clears. */
export const cookiesSetBy = (setCookies: readonly string[]) =>
  setCookies
    .map((line) => line.split(";")[0] ?? "")
    .filter((pair) => !pair.endsWith("="))
    .join("; ");

export interface LoginResult {
  status: number;
  location: string | null;
  /** The cookies the callback set, as a `Cookie` header. */
  cookie: string;
  setCookies: string[];
}

/**
 * One browser login through a Better Auth handler: sign-in, then the
 * callback with the state cookie and a code, as Keycloak's redirect would
 * arrive. The nonce from the authorization URL goes into the next ID token.
 */
export async function loginThrough(
  handler: (request: Request) => Promise<Response>,
  keycloak: FakeKeycloak,
): Promise<LoginResult> {
  const start = await handler(
    new Request(`${BASE}/api/auth/sign-in/social`, {
      method: "POST",
      headers: { "content-type": "application/json", origin: BASE },
      body: JSON.stringify({ provider: "keycloak", callbackURL: "/" }),
    }),
  );
  const authorize = new URL(((await start.json()) as { url: string }).url);
  keycloak.nonce = authorize.searchParams.get("nonce") ?? undefined;
  const state = authorize.searchParams.get("state");
  const callback = await handler(
    new Request(`${BASE}/api/auth/callback/keycloak?code=fake-code&state=${state}`, {
      headers: { cookie: cookiesSetBy(start.headers.getSetCookie()) },
    }),
  );
  const setCookies = callback.headers.getSetCookie();
  return {
    status: callback.status,
    location: callback.headers.get("location"),
    cookie: cookiesSetBy(setCookies),
    setCookies,
  };
}
