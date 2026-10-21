import { beforeEach, describe, expect, it, vi } from "vitest";

import { deferred, signedIn } from "./__tests__/helpers/fake-ports.js";
import { FakeWebSocket } from "./__tests__/helpers/fake-web-socket.js";
import { ManualTimers } from "./__tests__/helpers/manual-timers.js";
import { unauthorized, unavailable } from "./__tests__/helpers/responses.js";
import { resolveEndpoints } from "./endpoints.js";
import { createInterlockFetch } from "./fetch.js";
import { createSocketConnector } from "./socket-connector.js";

const latest = () => {
  const socket = FakeWebSocket.instances.at(-1);
  if (!socket) throw new Error("No socket");
  return socket;
};
function setup(revalidate = vi.fn<() => Promise<unknown>>().mockResolvedValue(undefined)) {
  const { ports, controller } = signedIn();
  const timers = new ManualTimers();
  const connector = createSocketConnector({
    url: "wss://interlock.test/ws/irongate",
    controller,
    WebSocket: FakeWebSocket,
    revalidate,
    timers,
    random: () => 0.5,
  });
  connector.start();
  return { ports, controller, connector, timers, revalidate };
}
beforeEach(() => {
  FakeWebSocket.instances = [];
});
describe("notification socket lifecycle", () => {
  it("starts once, parses envelopes, sends only while open, and stops with 1000", () => {
    const { connector } = setup();
    connector.start();
    expect(FakeWebSocket.instances).toHaveLength(1);
    expect(connector.send({ event: "read", data: 1 })).toBe(false);
    const message = vi.fn<(message: unknown) => void>();
    const unsubscribe = connector.subscribeMessages(message);
    latest().simulateOpen();
    expect(connector.send({ event: "read", data: 1 })).toBe(true);
    expect(latest().sent).toEqual(['{"event":"read","data":1}']);
    latest().simulateMessage('{"event":"notifications","data":{"count":2}}');
    latest().simulateMessage("invalid");
    latest().simulateMessage('{"event":"missing-data"}');
    latest().simulateMessage("null");
    expect(message).toHaveBeenCalledExactlyOnceWith({ event: "notifications", data: { count: 2 } });
    unsubscribe();
    connector.stop();
    expect(latest().closeCalls).toEqual([1000]);
    expect(connector.getState().phase).toBe("idle");
  });
  it("4401 ends session without redirect", () => {
    const { controller, connector, ports } = setup();
    latest().simulateOpen();
    latest().simulateClose(4401, "session_invalid");
    expect(controller.getState().phase.kind).toBe("signed_out");
    expect(connector.getState().phase).toBe("idle");
    expect(ports.signIn).not.toHaveBeenCalled();
  });
  it.each(["database", "upstream_unavailable"])(
    "4503 %s preserves session and schedules reconnect",
    (reason) => {
      const { controller, connector, timers } = setup();
      latest().simulateOpen();
      latest().simulateClose(4503, reason);
      expect(controller.getState().phase.kind).toBe("signed_in");
      expect(controller.getState().dependency).toMatchObject({ source: "socket", reason });
      expect(connector.getState().phase).toBe("waiting");
      timers.advance(500);
      expect(FakeWebSocket.instances).toHaveLength(2);
      latest().simulateOpen();
      expect(controller.getState().dependency).toBeNull();
      connector.stop();
    },
  );
  it.each([1000, 1001, 1011])("close %i reconnects and opening resets attempts", (code) => {
    const { connector, timers } = setup();
    latest().simulateOpen();
    latest().simulateClose(code);
    expect(connector.getState().attempt).toBe(1);
    timers.advance(500);
    latest().simulateOpen();
    expect(connector.getState().attempt).toBe(0);
    connector.stop();
  });
  it.each([false, true])("failed open / abnormal close revalidates (opened=%s)", async (opened) => {
    const { connector, revalidate, timers } = setup();
    if (opened) latest().simulateOpen();
    latest().simulateClose(1006);
    expect(revalidate).toHaveBeenCalledTimes(1);
    await vi.waitFor(() => expect(connector.getState().phase).toBe("waiting"));
    timers.advance(500);
    expect(FakeWebSocket.instances).toHaveLength(2);
    connector.stop();
  });
  it.each(["ok", "ended", "dependency", "network"])(
    "BFF revalidation handles %s",
    async (outcome) => {
      const { controller } = signedIn();
      const timers = new ManualTimers();
      const fetchImpl = vi.fn<typeof globalThis.fetch>();
      if (outcome === "network") fetchImpl.mockRejectedValue(new TypeError("offline"));
      else
        fetchImpl.mockResolvedValue(
          outcome === "ended"
            ? unauthorized()
            : outcome === "dependency"
              ? unavailable()
              : Response.json({ count: 0 }),
        );
      const fetch = createInterlockFetch(
        resolveEndpoints("https://interlock.test"),
        controller,
        fetchImpl,
      );
      const connector = createSocketConnector({
        url: "wss://interlock.test/ws/irongate",
        controller,
        WebSocket: FakeWebSocket,
        timers,
        revalidate: async () => fetch("/api/irongate/notifications/count"),
      });
      connector.start();
      latest().simulateClose(1006);
      await vi.waitFor(() =>
        expect(connector.getState().phase).toBe(outcome === "ended" ? "idle" : "waiting"),
      );
      expect((fetchImpl.mock.calls[0]?.[0] as URL | undefined)?.href).toBe(
        "https://interlock.test/api/irongate/notifications/count",
      );
      expect(controller.getState().phase.kind).toBe(
        outcome === "ended" ? "signed_out" : "signed_in",
      );
      connector.stop();
      expect(timers.pending()).toBe(0);
    },
  );
  it("sign-out closes immediately, cancels reconnect, and ignores late revalidation", async () => {
    const pending = deferred<undefined>();
    const { controller, connector, timers } = setup(vi.fn(async () => pending.promise));
    const socket = latest();
    const signOut = controller.signOut();
    expect(socket.closeCalls).toEqual([1000]);
    expect(timers.pending()).toBe(0);
    await signOut;
    pending.resolve(undefined);
    expect(connector.getState().phase).toBe("idle");
  });
  it("stop while revalidating prevents a late success from scheduling", async () => {
    const pending = deferred<undefined>();
    const { connector, timers } = setup(vi.fn(async () => pending.promise));
    latest().simulateClose(1006);
    connector.stop();
    pending.resolve(undefined);
    await pending.promise;
    await Promise.resolve();
    expect(connector.getState().phase).toBe("idle");
    expect(timers.pending()).toBe(0);
  });
});

it("a subscriber stopping during reconnect prevents a new connection", () => {
  const { connector, timers } = setup();
  latest().simulateOpen();
  latest().simulateClose(1001);
  connector.subscribe(() => {
    if (connector.getState().phase === "connecting") connector.stop();
  });
  timers.advance(500);
  expect(FakeWebSocket.instances).toHaveLength(1);
  expect(connector.getState().phase).toBe("idle");
});
