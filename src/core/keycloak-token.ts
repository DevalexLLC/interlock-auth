import http from "node:http";
import https from "node:https";
import { performance } from "node:perf_hooks";

import type { AuthLogger } from "./logger.js";

/** A token response's two lifetimes, in seconds. */
export interface Lifetimes {
  accessExpiresIn: number;
  refreshExpiresIn: number;
}

/** A lifetime is usable only as a positive finite number of seconds. */
const lifetime = (value: unknown) =>
  typeof value === "number" && Number.isFinite(value) && value > 0 ? value : null;

/**
 * `expires_in` and `refresh_expires_in` from a Keycloak token response, or
 * null for one that is missing or not positive. Keycloak sends `0` for an
 * offline token or an unlimited SSO session, neither of which the realm
 * contract allows, so a zero is as unusable as a missing value.
 */
export function tokenLifetimes(raw: unknown): {
  accessExpiresIn: number | null;
  refreshExpiresIn: number | null;
} {
  const body = typeof raw === "object" && raw !== null ? (raw as Record<string, unknown>) : {};
  return {
    accessExpiresIn: lifetime(body.expires_in),
    refreshExpiresIn: lifetime(body.refresh_expires_in),
  };
}

/**
 * The lifetimes of a login's token response, keyed by the `Date` that
 * `keycloakAccountSubject` assigns to `tokens.refreshTokenExpiresAt`. Better
 * Auth copies that same object into the account write, so the account hook
 * finds the raw lifetimes by it (the raw response itself never reaches a hook).
 */
const loginLifetimes = new WeakMap<Date, ReturnType<typeof tokenLifetimes>>();

export const registerLoginLifetimes = (
  marker: Date,
  lifetimes: ReturnType<typeof tokenLifetimes>,
) => loginLifetimes.set(marker, lifetimes);

/** The lifetimes registered for an account write's `refreshTokenExpiresAt`, if any. */
export const loginLifetimesOf = (marker: unknown) =>
  marker instanceof Date ? loginLifetimes.get(marker) : undefined;

/** One token request, as the transport sends it. */
export interface TokenRequest {
  url: string;
  headers: Record<string, string>;
  body: string;
  /** One deadline over both phases. */
  timeoutMs: number;
  /** Called once, immediately before the first byte of the request is written. */
  onSent?: () => void;
}

/**
 * What a transport observed, by phase. `connecting` (DNS, TCP, TLS) ends
 * before anything is written, so a failure there proves Keycloak never saw
 * the request. Anything that goes wrong in `sent` may have reached it.
 * `sentAt` is `performance.now()` immediately before the first write.
 */
export type TransportResult =
  | { phase: "connecting"; cause: string }
  | { phase: "sent"; sentAt: number; cause: string }
  | { phase: "sent"; sentAt: number; status: number; body: string };

export type TokenTransport = (request: TokenRequest) => Promise<TransportResult>;

/** More than any token response; a larger body is a failure, not a buffer. */
const MAX_RESPONSE_BYTES = 256 * 1024;

const causeOf = (err: unknown) => {
  const code = (err as { code?: unknown } | undefined)?.code;
  return typeof code === "string" ? code : "error";
};

/**
 * The token request over Node's `https.request` (`http.request` for a plain
 * `http:` URL, which only tests use). Not `fetch`: it reports every failure
 * as one rejection, and no error code proves the request never left, because
 * an established socket reports `EHOSTUNREACH` or `ECONNRESET` after the body
 * was written just as a failed connect does.
 *
 * Nothing is written until the socket's `secureConnect` (`connect`), so the
 * phase boundary is an event, not an inference. `agent: false` makes every
 * request a fresh connection: a reused keep-alive socket never emits those
 * events again. Redirects are never followed; a 3xx is just a status.
 */
export const httpTransport: TokenTransport = async (request) =>
  new Promise((resolve) => {
    const url = new URL(request.url);
    const secure = url.protocol === "https:";
    let phase: "connecting" | "sent" = "connecting";
    let sentAt = 0;
    let settled = false;
    let timer: NodeJS.Timeout | undefined;

    const finish = (result: TransportResult) => {
      if (!settled) {
        settled = true;
        clearTimeout(timer);
        resolve(result);
      }
    };
    const fail = (cause: string) =>
      finish(phase === "connecting" ? { phase, cause } : { phase, sentAt, cause });

    const req = (secure ? https : http).request(url, {
      method: "POST",
      agent: false,
      headers: { ...request.headers, "content-length": Buffer.byteLength(request.body) },
    });
    timer = setTimeout(() => {
      fail("timeout");
      req.destroy();
    }, request.timeoutMs);

    req.on("error", (err) => fail(causeOf(err)));
    req.on("socket", (socket) => {
      socket.once(secure ? "secureConnect" : "connect", () => {
        if (settled) {
          return;
        }
        sentAt = performance.now();
        phase = "sent";
        request.onSent?.();
        req.end(request.body);
      });
    });
    req.on("response", (res) => {
      const chunks: Buffer[] = [];
      let size = 0;
      res.on("data", (chunk: Buffer) => {
        size += chunk.length;
        if (size > MAX_RESPONSE_BYTES) {
          fail("response_too_large");
          req.destroy();
          return;
        }
        chunks.push(chunk);
      });
      res.on("end", () =>
        finish({
          phase: "sent",
          sentAt,
          status: res.statusCode ?? 0,
          body: Buffer.concat(chunks).toString("utf8"),
        }),
      );
      res.on("error", (err) => fail(causeOf(err)));
      res.on("close", () => {
        if (!res.complete) {
          fail("response_aborted");
        }
      });
    });
  });

/** A refresh's tokens, in plaintext; the refresher encrypts them before they are stored. */
export interface RefreshedTokens {
  accessToken: string;
  refreshToken: string;
  idToken?: string;
}

/**
 * How a refresh ended, by what it proves:
 *
 * - `ok`: Keycloak rotated the tokens.
 * - `invalid_grant`: Keycloak refused the refresh token, so its session is gone.
 * - `unsent`: the request provably never left (the connecting phase), so the
 *   stored refresh token is unused.
 * - `indeterminate`: everything else. Keycloak may have rotated the token, so
 *   the stored one must never be replayed.
 */
export type RefreshResult =
  | { kind: "ok"; tokens: RefreshedTokens; lifetimes: Lifetimes; sentAt: number }
  | { kind: "invalid_grant" }
  | { kind: "unsent"; cause: string }
  | { kind: "indeterminate"; cause: string };

export interface RefreshRequest {
  tokenUrl: string;
  clientId: string;
  clientSecret: string;
  /** Plaintext, decrypted just before the call; never logged. */
  refreshToken: string;
  timeoutMs: number;
  transport?: TokenTransport;
  onSent?: () => void;
  /** Where a client-configuration error or a contract breach is reported. */
  logger: AuthLogger;
}

const parseJson = (body: string): Record<string, unknown> | undefined => {
  try {
    const value: unknown = JSON.parse(body);
    return typeof value === "object" && value !== null && !Array.isArray(value)
      ? (value as Record<string, unknown>)
      : undefined;
  } catch {
    return undefined;
  }
};

const nonBlank = (value: unknown) =>
  typeof value === "string" && value.trim() !== "" ? value : undefined;

/**
 * One `refresh_token` grant at Keycloak's token endpoint, authenticated as
 * `client_secret_post` (what Better Auth's own exchange uses with a client
 * secret), classified by what it proves (`RefreshResult`). The phase, not an
 * error code, decides `unsent`: anything that cannot be shown to have
 * happened before the first byte was written is indeterminate.
 *
 * A client-configuration error (`invalid_client` and friends) and a 200 that
 * breaks the contract are logged at error level with Keycloak's `error` code
 * only (`error_description` can quote the request), and still count as
 * indeterminate.
 */
export async function refreshTokens({
  tokenUrl,
  clientId,
  clientSecret,
  refreshToken,
  timeoutMs,
  transport = httpTransport,
  onSent,
  logger,
}: RefreshRequest): Promise<RefreshResult> {
  const result = await transport({
    url: tokenUrl,
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      accept: "application/json",
    },
    body: new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: refreshToken,
      client_id: clientId,
      client_secret: clientSecret,
    }).toString(),
    timeoutMs,
    onSent,
  });

  if (result.phase === "connecting") {
    return { kind: "unsent", cause: result.cause };
  }
  if (!("status" in result)) {
    return { kind: "indeterminate", cause: result.cause };
  }

  const body = parseJson(result.body);
  if (result.status === 200 && body !== undefined) {
    const accessToken = nonBlank(body.access_token);
    const refreshed = nonBlank(body.refresh_token);
    const { accessExpiresIn, refreshExpiresIn } = tokenLifetimes(body);
    if (accessToken && refreshed && accessExpiresIn !== null && refreshExpiresIn !== null) {
      return {
        kind: "ok",
        tokens: { accessToken, refreshToken: refreshed, idToken: nonBlank(body.id_token) },
        lifetimes: { accessExpiresIn, refreshExpiresIn },
        sentAt: result.sentAt,
      };
    }
    const missing = Object.entries({
      access_token: accessToken,
      refresh_token: refreshed,
      expires_in: accessExpiresIn,
      refresh_expires_in: refreshExpiresIn,
    })
      .filter(([, present]) => present === null || present === undefined)
      .map(([field]) => field);
    logger.error({
      message: `Keycloak answered a token refresh without ${missing.join(", ")}; the realm contract requires them`,
      missing,
    });
    return { kind: "indeterminate", cause: "malformed_response" };
  }

  const error = typeof body?.error === "string" ? body.error : undefined;
  if (result.status === 400 && error === "invalid_grant") {
    return { kind: "invalid_grant" };
  }
  if (result.status >= 400 && result.status < 500) {
    logger.error({
      message: `Keycloak refused a token refresh with ${result.status} ${error ?? "(no error code)"}; check the client configuration`,
      status: result.status,
      error,
    });
  }
  return {
    kind: "indeterminate",
    cause: result.status === 200 ? "malformed_response" : String(result.status),
  };
}
