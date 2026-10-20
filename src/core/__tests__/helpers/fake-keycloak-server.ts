import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";

import { FakeKeycloak } from "./fake-keycloak.js";

/**
 * `FakeKeycloak` listening on plain HTTP on 127.0.0.1, so the refresher's
 * real transport (`http.request` for an `http:` issuer) reaches it. A
 * refresh with `sentFail` is processed (the token rotates) and the socket is
 * then destroyed without an answer. A connecting-phase failure cannot be
 * acted out by a listening server; a refused port is one.
 *
 * With `discovery` the fake also serves discovery and its key set, so
 * Better Auth verifies the login's ID token and the back-channel logout
 * receiver can verify the fake's logout tokens.
 */
export async function startFakeKeycloakServer({ discovery = false } = {}) {
  const server: Server = createServer();
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  const issuerOrigin = `http://127.0.0.1:${port}`;
  const issuer = `${issuerOrigin}/realms/test`;
  const keycloak = new FakeKeycloak(discovery, issuer);
  server.on("request", (req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => {
      void (async () => {
        const url = `${issuerOrigin}${req.url ?? ""}`;
        const { sentFail } = keycloak.nextRefresh;
        const response = await keycloak.handle(url, Buffer.concat(chunks).toString("utf8"), {
          cookie: req.headers.cookie !== undefined,
        });
        if (response === undefined) {
          res.writeHead(404).end();
          return;
        }
        if (sentFail !== undefined) {
          req.socket.destroy();
          return;
        }
        res
          .writeHead(response.status, {
            "content-type": response.text === undefined ? "application/json" : "text/plain",
            ...response.headers,
          })
          .end(response.text ?? JSON.stringify(response.body));
      })();
    });
  });
  return {
    keycloak,
    issuer,
    close: async () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  };
}
