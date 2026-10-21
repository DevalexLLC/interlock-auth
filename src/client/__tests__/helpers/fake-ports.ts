import { vi } from "vitest";

import { createSessionController, type SessionPorts } from "../../session-controller.js";
import type { InterlockSession } from "../../types.js";

export const session = (id = "s1"): InterlockSession => ({
  user: {
    id: "u1",
    name: "Ann",
    username: "ann",
    email: "ann@example.com",
    emailVerified: true,
    createdAt: new Date(0),
    updatedAt: new Date(0),
  },
  session: { id, userId: "u1", token: "opaque", expiresAt: new Date(9999999999999) },
});
export const fakePorts = () => ({
  signIn: vi.fn<SessionPorts["signIn"]>().mockResolvedValue(undefined),
  signOut: vi
    .fn<SessionPorts["signOut"]>()
    .mockResolvedValue({ keycloakLogout: "ended", incomplete: false }),
  refetchSession: vi.fn<SessionPorts["refetchSession"]>().mockResolvedValue(undefined),
  onSessionEnded: vi.fn<NonNullable<SessionPorts["onSessionEnded"]>>(),
  callbackURL: "https://demo.test/",
});
export function signedIn() {
  const ports = fakePorts();
  const controller = createSessionController(ports);
  controller.dispatch({ type: "session_resolved", session: session() });
  return { ports, controller };
}
export function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((yes, no) => {
    resolve = yes;
    reject = no;
  });
  return { promise, resolve, reject };
}
