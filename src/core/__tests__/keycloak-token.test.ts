import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createServer as createHttpServer, type IncomingMessage, type Server } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import { createServer as createNetServer, type AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import path from "node:path";
import tls from "node:tls";

import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

import {
  httpTransport,
  refreshTokens,
  tokenLifetimes,
  type RefreshRequest,
  type TokenRequest,
  type TransportResult,
} from "../keycloak-token.js";
import { allRecords, defined, testLogger, type TestLogger } from "./helpers/config.js";

const REFRESH = "refresh-canary-123";

/** The logger of the current `refreshTokens` case; `request` hands it over. */
let logger: TestLogger = testLogger();

const request = (overrides: Partial<RefreshRequest> = {}): RefreshRequest => ({
  tokenUrl: "https://keycloak.test/realms/test/protocol/openid-connect/token",
  clientId: "interlock",
  clientSecret: "client-secret-canary",
  refreshToken: REFRESH,
  timeoutMs: 1000,
  logger,
  ...overrides,
});

const OK_BODY = {
  access_token: "a2",
  refresh_token: "r2",
  id_token: "i2",
  expires_in: 300,
  refresh_expires_in: 1800,
};

/** A transport that records what it was asked to send and answers `result`. */
const answering = (result: TransportResult) => {
  const sent: TokenRequest[] = [];
  const transport = async (req: TokenRequest) => {
    sent.push(req);
    if (result.phase === "sent") {
      req.onSent?.();
    }
    return result;
  };
  return { sent, transport };
};

const respond = (status: number, body: unknown): TransportResult => ({
  phase: "sent",
  sentAt: 1,
  status,
  body: typeof body === "string" ? body : JSON.stringify(body),
});

describe("tokenLifetimes", () => {
  it.each([
    ["both present", { expires_in: 300, refresh_expires_in: 1800 }, [300, 1800]],
    ["both missing", {}, [null, null]],
    [
      "zero (an offline token or unlimited SSO)",
      { expires_in: 0, refresh_expires_in: 0 },
      [null, null],
    ],
    ["negative", { expires_in: -1, refresh_expires_in: 1800 }, [null, 1800]],
    ["non-numeric", { expires_in: "300", refresh_expires_in: null }, [null, null]],
    ["not finite", { expires_in: Infinity, refresh_expires_in: Number.NaN }, [null, null]],
    ["not an object", "nope", [null, null]],
  ])("should read %s", (_case, raw, [accessExpiresIn, refreshExpiresIn]) => {
    expect(tokenLifetimes(raw)).toEqual({ accessExpiresIn, refreshExpiresIn });
  });
});

/** No path logs the refresh token, the client secret, or a description. */
const expectNoSecretLogged = () => {
  const logged = JSON.stringify(allRecords(logger));
  expect(logged).not.toContain(REFRESH);
  expect(logged).not.toContain("client-secret-canary");
  expect(logged).not.toContain("description-canary");
};

describe("refreshTokens", () => {
  let error: TestLogger["error"];

  beforeEach(() => {
    logger = testLogger();
    ({ error } = logger);
  });

  afterEach(() => expectNoSecretLogged());

  it("should post a client_secret_post refresh grant as a form", async () => {
    const { sent, transport } = answering(respond(200, OK_BODY));
    await refreshTokens(request({ transport }));

    expect(sent).toHaveLength(1);
    expect(sent[0]).toMatchObject({
      url: "https://keycloak.test/realms/test/protocol/openid-connect/token",
      headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
      timeoutMs: 1000,
    });
    expect(Object.fromEntries(new URLSearchParams(defined(sent[0]).body))).toEqual({
      grant_type: "refresh_token",
      refresh_token: REFRESH,
      client_id: "interlock",
      client_secret: "client-secret-canary",
    });
  });

  it("should classify a complete 200 as ok, with the lifetimes and the send time", async () => {
    const { transport } = answering(respond(200, OK_BODY));

    await expect(refreshTokens(request({ transport }))).resolves.toEqual({
      kind: "ok",
      tokens: { accessToken: "a2", refreshToken: "r2", idToken: "i2" },
      lifetimes: { accessExpiresIn: 300, refreshExpiresIn: 1800 },
      sentAt: 1,
    });
  });

  it("should keep the ID token optional", async () => {
    const { transport } = answering(respond(200, { ...OK_BODY, id_token: undefined }));
    const result = await refreshTokens(request({ transport }));

    expect(result).toMatchObject({ kind: "ok", tokens: { idToken: undefined } });
  });

  it.each(["access_token", "refresh_token", "expires_in", "refresh_expires_in"])(
    "should classify a 200 without %s as indeterminate and log the deviation",
    async (field) => {
      const { transport } = answering(respond(200, { ...OK_BODY, [field]: undefined }));

      await expect(refreshTokens(request({ transport }))).resolves.toEqual({
        kind: "indeterminate",
        cause: "malformed_response",
      });
      expect(error).toHaveBeenCalledWith(expect.objectContaining({ missing: [field] }));
    },
  );

  it("should classify a refresh_expires_in of 0 as indeterminate", async () => {
    const { transport } = answering(respond(200, { ...OK_BODY, refresh_expires_in: 0 }));

    await expect(refreshTokens(request({ transport }))).resolves.toMatchObject({
      kind: "indeterminate",
    });
  });

  it("should classify a body that is not JSON as indeterminate", async () => {
    const { transport } = answering(respond(200, "<html>proxy error</html>"));

    await expect(refreshTokens(request({ transport }))).resolves.toEqual({
      kind: "indeterminate",
      cause: "malformed_response",
    });
  });

  it("should classify invalid_grant as the end of the Keycloak session", async () => {
    const { transport } = answering(
      respond(400, { error: "invalid_grant", error_description: "description-canary" }),
    );

    await expect(refreshTokens(request({ transport }))).resolves.toEqual({ kind: "invalid_grant" });
    expect(error).not.toHaveBeenCalled();
  });

  it.each([
    [400, "invalid_request"],
    [401, "invalid_client"],
    [400, "unauthorized_client"],
  ])(
    "should classify %s %s as indeterminate and log the code, not the description",
    async (status, code) => {
      const { transport } = answering(
        respond(status, { error: code, error_description: "description-canary" }),
      );

      await expect(refreshTokens(request({ transport }))).resolves.toEqual({
        kind: "indeterminate",
        cause: String(status),
      });
      expect(error).toHaveBeenCalledWith(expect.objectContaining({ status, error: code }));
    },
  );

  it.each([
    [302, ""],
    [500, '{"error":"unknown_error"}'],
    [503, "unavailable"],
  ])("should classify a %s as indeterminate", async (status, body) => {
    const { transport } = answering(respond(status, body));

    await expect(refreshTokens(request({ transport }))).resolves.toEqual({
      kind: "indeterminate",
      cause: String(status),
    });
  });

  // The phase, not the code, is the evidence.
  it("should classify the same error code by the phase it happened in", async () => {
    const connecting = answering({ phase: "connecting", cause: "EHOSTUNREACH" });
    const sent = answering({ phase: "sent", sentAt: 1, cause: "EHOSTUNREACH" });

    await expect(refreshTokens(request({ transport: connecting.transport }))).resolves.toEqual({
      kind: "unsent",
      cause: "EHOSTUNREACH",
    });
    await expect(refreshTokens(request({ transport: sent.transport }))).resolves.toEqual({
      kind: "indeterminate",
      cause: "EHOSTUNREACH",
    });
  });
});

/** What a server received, and a handler that answers with `answer`. */
const recording = (
  answer: (req: IncomingMessage, body: string) => (res: import("node:http").ServerResponse) => void,
) => {
  const received: {
    headers: IncomingMessage["headers"];
    method: string | undefined;
    url: string | undefined;
    body: string;
  }[] = [];
  const handler = (req: IncomingMessage, res: import("node:http").ServerResponse) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => {
      const body = Buffer.concat(chunks).toString("utf8");
      received.push({ headers: req.headers, method: req.method, url: req.url, body });
      answer(req, body)(res);
    });
  };
  return { received, handler };
};

const send = (url: string, timeoutMs = 2000) => {
  const sent = vi.fn<() => void>();
  return {
    sent,
    result: httpTransport({
      url,
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        accept: "application/json",
      },
      body: "grant_type=refresh_token&refresh_token=x",
      timeoutMs,
      onSent: sent,
    }),
  };
};

/**
 * The real transport against local servers. HTTPS needs a certificate:
 * openssl makes a self-signed one, which the default CA bundle does not
 * trust until a case adds it.
 */
describe("httpTransport", () => {
  let dir: string;
  let cert: string;
  let key: string;
  const servers: { close: () => void }[] = [];

  beforeAll(() => {
    dir = mkdtempSync(path.join(tmpdir(), "interlock-tls-"));
    execFileSync(
      "openssl",
      [
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-days",
        "1",
        "-subj",
        "/CN=127.0.0.1",
        "-addext",
        "subjectAltName=IP:127.0.0.1",
        "-keyout",
        path.join(dir, "key.pem"),
        "-out",
        path.join(dir, "cert.pem"),
      ],
      { stdio: "ignore" },
    );
    cert = readFileSync(path.join(dir, "cert.pem"), "utf8");
    key = readFileSync(path.join(dir, "key.pem"), "utf8");
  });

  afterAll(() => rmSync(dir, { recursive: true, force: true }));

  afterEach(() => {
    for (const server of servers.splice(0)) {
      server.close();
    }
  });

  const listen = async (server: Server | ReturnType<typeof createNetServer>) => {
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    servers.push({
      close: () => {
        (server as Server).closeAllConnections?.();
        server.close();
      },
    });
    return (server.address() as AddressInfo).port;
  };

  const json = () => (res: import("node:http").ServerResponse) =>
    res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify(OK_BODY));

  it("should send the form as specified and read the answer", async () => {
    const { received, handler } = recording(json);
    const port = await listen(createHttpServer(handler));
    const { sent, result } = send(
      `http://127.0.0.1:${port}/realms/test/protocol/openid-connect/token`,
    );

    await expect(result).resolves.toMatchObject({ phase: "sent", status: 200 });
    expect(sent).toHaveBeenCalledTimes(1);
    expect(received).toEqual([
      expect.objectContaining({
        method: "POST",
        url: "/realms/test/protocol/openid-connect/token",
        body: "grant_type=refresh_token&refresh_token=x",
      }),
    ]);
    expect(defined(received[0]).headers).toMatchObject({
      "content-type": "application/x-www-form-urlencoded",
      accept: "application/json",
      "content-length": "40",
    });
  });

  it("should be unsent when the port refuses the connection", async () => {
    const port = await listen(createNetServer());
    defined(servers.pop()).close();
    const { sent, result } = send(`https://127.0.0.1:${port}/token`);

    await expect(result).resolves.toEqual({ phase: "connecting", cause: "ECONNREFUSED" });
    expect(sent).not.toHaveBeenCalled();
  });

  it("should be unsent when the certificate is not trusted", async () => {
    const { received, handler } = recording(json);
    const port = await listen(createHttpsServer({ cert, key }, handler));
    const { sent, result } = send(`https://127.0.0.1:${port}/token`);

    await expect(result).resolves.toMatchObject({ phase: "connecting" });
    expect(sent).not.toHaveBeenCalled();
    expect(received).toEqual([]);
  });

  it("should be unsent when the deadline passes during the TLS handshake", async () => {
    // Accepts the TCP connection and never answers the ClientHello.
    const port = await listen(createNetServer(() => undefined));
    const { sent, result } = send(`https://127.0.0.1:${port}/token`, 100);

    await expect(result).resolves.toEqual({ phase: "connecting", cause: "timeout" });
    expect(sent).not.toHaveBeenCalled();
  });

  it("should be sent and failed when the deadline passes after the body was written", async () => {
    const port = await listen(createHttpServer(() => undefined));
    const { sent, result } = send(`http://127.0.0.1:${port}/token`, 100);

    await expect(result).resolves.toMatchObject({ phase: "sent", cause: "timeout" });
    expect(sent).toHaveBeenCalledTimes(1);
  });

  it("should be sent and failed when the server reads the body and closes the socket", async () => {
    const { received, handler } = recording((req) => () => req.socket.destroy());
    const port = await listen(createHttpServer(handler));
    const { result } = send(`http://127.0.0.1:${port}/token`);

    const outcome = await result;
    expect(outcome).toMatchObject({ phase: "sent" });
    expect("status" in outcome).toBe(false);
    expect(received).toHaveLength(1);
  });

  it("should not follow a redirect", async () => {
    const { received, handler } = recording(
      () => (res) => res.writeHead(307, { location: "/elsewhere" }).end(),
    );
    const port = await listen(createHttpServer(handler));
    const { result } = send(`http://127.0.0.1:${port}/token`);

    await expect(result).resolves.toMatchObject({ phase: "sent", status: 307 });
    expect(received).toHaveLength(1);
  });

  // A reused keep-alive socket would never emit `secureConnect` again, and a
  // transport waiting for it would call a request that never started unsent.
  // Trusting the certificate needs `tls.setDefaultCACertificates`, which
  // Node 22.18 (the `engines` floor) lacks; the case runs on 22.19 and 24.5 up.
  it.skipIf(typeof tls.setDefaultCACertificates !== "function")(
    "should answer two consecutive requests over trusted TLS",
    async () => {
      const defaults = tls.getCACertificates("default");
      tls.setDefaultCACertificates([...defaults, cert]);
      try {
        const { received, handler } = recording(json);
        const port = await listen(createHttpsServer({ cert, key }, handler));
        const url = `https://127.0.0.1:${port}/token`;

        for (let i = 0; i < 2; i++) {
          const { sent, result } = send(url);
          await expect(result).resolves.toMatchObject({ phase: "sent", status: 200 });
          expect(sent).toHaveBeenCalledTimes(1);
        }
        expect(received).toHaveLength(2);
      } finally {
        tls.setDefaultCACertificates(defaults);
      }
    },
  );
});
