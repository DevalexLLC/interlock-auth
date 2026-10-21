import { describe, expect, it, vi } from "vitest";

import { fakePorts, session, signedIn } from "./__tests__/helpers/fake-ports.js";
import { dependencyFailure } from "./dependency-failure.js";
import { createSessionController } from "./session-controller.js";

describe("session effect ordering", () => {
  it("notifies before publish and queues re-entrant dispatch until after publish", () => {
    const ports = fakePorts();
    const controller = createSessionController(ports);
    controller.dispatch({ type: "session_resolved", session: session() });
    const events: string[] = [];
    ports.onSessionEnded.mockImplementation(() => {
      events.push("clear");
      expect(controller.generation()).toBe(1);
      controller.dispatch({
        type: "dependency_failed",
        failure: dependencyFailure("network", "unreachable"),
      });
    });
    controller.subscribe(() => events.push(controller.getState().dependency ? "failure" : "ended"));
    controller.dispatch({ type: "unauthorized", generation: 0 });
    expect(events).toEqual(["clear", "ended", "failure"]);
  });
  it("automatic login passes callbackURL", () => {
    const { ports, controller } = signedIn();
    controller.dispatch({ type: "unauthorized", generation: 0, reason: "refresh_indeterminate" });
    expect(ports.signIn).toHaveBeenCalledWith({ callbackURL: ports.callbackURL });
  });
  it.each([false, true])("signOut orchestrates completion, incomplete=%s", async (incomplete) => {
    const ports = {
      ...fakePorts(),
      signOut: vi.fn<() => Promise<{ keycloakLogout: "unconfirmed"; incomplete: boolean }>>(
        async () => ({ keycloakLogout: "unconfirmed" as const, incomplete }),
      ),
    };
    const controller = createSessionController(ports);
    await controller.signOut();
    expect(controller.getState().phase).toMatchObject({
      kind: "signed_out",
      keycloakLogout: "unconfirmed",
      signOutIncomplete: incomplete,
    });
    expect(ports.signOut).toHaveBeenCalledTimes(1);
  });
  it("signOut failure refetches and never retries signOut", async () => {
    const { ports, controller } = signedIn();
    ports.signOut.mockRejectedValue(new TypeError("offline"));
    await controller.signOut();
    expect(controller.getState().phase.kind).toBe("signed_in");
    expect(ports.signOut).toHaveBeenCalledTimes(1);
    expect(ports.refetchSession).toHaveBeenCalledTimes(1);
  });
});

it("re-entrant signOut shares the in-flight operation", async () => {
  const { controller, ports } = signedIn();
  controller.subscribe(() => {
    if (controller.getState().phase.kind === "signing_out") void controller.signOut();
  });
  await controller.signOut();
  expect(ports.signOut).toHaveBeenCalledTimes(1);
});
