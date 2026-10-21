import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { StrictMode, useLayoutEffect } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { deferred, session } from "../client/__tests__/helpers/fake-ports.js";
import { FakeWebSocket } from "../client/__tests__/helpers/fake-web-socket.js";
import { ManualTimers } from "../client/__tests__/helpers/manual-timers.js";
import { unauthorized } from "../client/__tests__/helpers/responses.js";
import { InterlockProvider, type InterlockProviderProps } from "./provider.js";
import { useInterlockFetch, useCatalogClient } from "./use-fetch.js";
import { useInterlockSession } from "./use-session.js";
import { useNotificationSocket, useSocketEvent } from "./use-socket.js";

const ignore = () => {
  /* The provider renders the failure. */
};
function Consumer({
  onCommit,
  onEvent,
}: {
  onCommit?: (phase: string) => void;
  onEvent?: (data: unknown) => void;
}) {
  const state = useInterlockSession();
  const fetch = useInterlockFetch();
  const socket = useNotificationSocket();
  useSocketEvent("notifications", onEvent ?? ignore);
  useLayoutEffect(() => {
    onCommit?.(state.phase.kind);
  }, [state.phase.kind, onCommit]);
  return (
    <>
      <output data-testid="phase">{state.phase.kind}</output>
      <output data-testid="socket">{socket.phase}</output>
      <output data-testid="user">{state.user?.username}</output>
      <output data-testid="outcome">
        {state.phase.kind === "signed_out"
          ? `${state.phase.keycloakLogout ?? ""}:${String(state.phase.signOutIncomplete ?? false)}`
          : ""}
      </output>
      <button
        type="button"
        onClick={() => {
          void state.signIn();
        }}
      >
        Sign in
      </button>
      <button
        type="button"
        onClick={() => {
          void state.signOut();
        }}
      >
        Sign out
      </button>
      <button
        type="button"
        onClick={() => {
          void state.retry();
        }}
      >
        Retry
      </button>
      <button
        type="button"
        onClick={() => {
          void fetch("/api/irongate/applications").catch(ignore);
        }}
      >
        Read
      </button>
    </>
  );
}
function mount(
  fetch: typeof globalThis.fetch,
  props: Partial<InterlockProviderProps> = {},
  child = <Consumer />,
) {
  return render(
    <InterlockProvider
      uri="https://interlock.test"
      fetch={fetch}
      WebSocket={FakeWebSocket}
      refetchIntervalSeconds={0}
      {...props}
    >
      {child}
    </InterlockProvider>,
  );
}
const phase = async (value: string) =>
  waitFor(() => expect(screen.getByTestId("phase").textContent).toBe(value));
const requestPath = (input: Parameters<typeof fetch>[0]) =>
  new URL(input instanceof Request ? input.url : input).pathname;
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});
beforeEach(() => {
  FakeWebSocket.instances = [];
});

describe("InterlockProvider with real Better Auth client", () => {
  it("mount resolves a session and exposes username", async () => {
    const fetch = vi
      .fn<typeof globalThis.fetch>()
      .mockImplementation(async () => Response.json(session()));
    mount(fetch);
    await phase("signed_in");
    expect(screen.getByTestId("user").textContent).toBe("ann");
    expect(fetch).toHaveBeenCalledTimes(1);
  });
  it("mount null is signed out without navigation", async () => {
    const navigate = vi.fn<(url: string) => void>();
    mount(
      vi.fn<typeof fetch>().mockImplementation(async () => Response.json(null)),
      { navigate },
    );
    await phase("signed_out");
    expect(navigate).not.toHaveBeenCalled();
  });
  it("mount 500 is unavailable and retries through its timer", async () => {
    const timers = new ManualTimers();
    const fetch = vi
      .fn<typeof globalThis.fetch>()
      .mockResolvedValueOnce(Response.json({ message: "database" }, { status: 500 }))
      .mockResolvedValueOnce(Response.json(session()));
    mount(fetch, { timers });
    await phase("unavailable");
    expect(timers.pending()).toBe(1);
    act(() => timers.advance(5000));
    await phase("signed_in");
  });
  it("provider refetch null ends without navigation", async () => {
    const navigate = vi.fn<(url: string) => void>();
    const fetch = vi
      .fn<typeof globalThis.fetch>()
      .mockResolvedValueOnce(Response.json(session()))
      .mockImplementation(async () => Response.json(null));
    mount(fetch, { navigate });
    await phase("signed_in");
    fireEvent.click(screen.getByText("Retry"));
    await phase("signed_out");
    expect(navigate).not.toHaveBeenCalled();
  });
  it("storage events refetch and discover an ended session", async () => {
    const fetch = vi
      .fn<typeof globalThis.fetch>()
      .mockResolvedValueOnce(Response.json(session()))
      .mockImplementation(async () => Response.json(null));
    mount(fetch);
    await phase("signed_in");
    act(() => {
      window.dispatchEvent(
        new StorageEvent("storage", {
          key: "better-auth.message",
          newValue: JSON.stringify({ event: "session", data: { trigger: "signout" } }),
        }),
      );
    });
    await phase("signed_out");
    expect(fetch.mock.calls.length).toBeGreaterThanOrEqual(2);
  });
  it("401 clears consumer caches before the signed-out commit", async () => {
    const order: string[] = [];
    const fetch = vi
      .fn<typeof globalThis.fetch>()
      .mockImplementation(async (input) =>
        requestPath(input).endsWith("get-session") ? Response.json(session()) : unauthorized(),
      );
    mount(
      fetch,
      { onSessionEnded: () => order.push("clear") },
      <Consumer onCommit={(value) => order.push(value)} />,
    );
    await phase("signed_in");
    fireEvent.click(screen.getByText("Read"));
    await phase("signed_out");
    expect(order.indexOf("clear")).toBeLessThan(order.indexOf("signed_out"));
    // The refetch returned the stale session object, but cannot revive it.
    await waitFor(() => expect(fetch).toHaveBeenCalledTimes(3));
    expect(screen.getByTestId("phase").textContent).toBe("signed_out");
  });
  it.each([false, true])(
    "explicit/automatic login uses disableRedirect and navigates once (automatic=%s)",
    async (automatic) => {
      const navigate = vi.fn<(url: string) => void>();
      const fetch = vi.fn<typeof globalThis.fetch>().mockImplementation(async (input) => {
        const path = requestPath(input);
        if (path.endsWith("get-session")) return Response.json(session());
        if (path.endsWith("sign-in/social"))
          return Response.json({ url: "https://keycloak.test/login", redirect: true });
        return unauthorized("refresh_indeterminate");
      });
      mount(fetch, { navigate, callbackURL: "https://demo.test/" });
      await phase("signed_in");
      fireEvent.click(screen.getByText(automatic ? "Read" : "Sign in"));
      await waitFor(() =>
        expect(navigate).toHaveBeenCalledExactlyOnceWith("https://keycloak.test/login"),
      );
      const call = fetch.mock.calls.find(([input]) =>
        requestPath(input).endsWith("sign-in/social"),
      );
      expect(JSON.parse(call?.[1]?.body as string)).toMatchObject({
        provider: "keycloak",
        disableRedirect: true,
        callbackURL: "https://demo.test/",
      });
    },
  );
  it.each([200, 503])(
    "logout %i records outcome and closes the socket immediately",
    async (status) => {
      const pending = deferred<Response>();
      const fetch = vi
        .fn<typeof globalThis.fetch>()
        .mockImplementation(async (input) =>
          requestPath(input).endsWith("sign-out") ? pending.promise : Response.json(session()),
        );
      mount(fetch);
      await phase("signed_in");
      const socket = FakeWebSocket.instances[0];
      act(() => socket?.simulateOpen());
      fireEvent.click(screen.getByText("Sign out"));
      await phase("signing_out");
      expect(socket?.closeCalls).toEqual([1000]);
      pending.resolve(
        Response.json(
          status === 200
            ? { success: true, keycloakLogout: "ended" }
            : { code: "sign_out_incomplete", keycloakLogout: "unconfirmed" },
          { status },
        ),
      );
      await phase("signed_out");
      expect(screen.getByTestId("outcome").textContent).toBe(
        status === 200 ? "ended:false" : "unconfirmed:true",
      );
    },
  );
  it("StrictMode opens one socket and one get-session; socket hook receives events", async () => {
    const onEvent = vi.fn<(data: unknown) => void>();
    const fetch = vi
      .fn<typeof globalThis.fetch>()
      .mockImplementation(async () => Response.json(session()));
    render(
      <StrictMode>
        <InterlockProvider
          uri="https://interlock.test"
          fetch={fetch}
          WebSocket={FakeWebSocket}
          refetchIntervalSeconds={0}
        >
          <Consumer onEvent={onEvent} />
        </InterlockProvider>
      </StrictMode>,
    );
    await phase("signed_in");
    expect(fetch).toHaveBeenCalledTimes(1);
    expect(FakeWebSocket.instances).toHaveLength(1);
    act(() => {
      FakeWebSocket.instances[0]?.simulateOpen();
      FakeWebSocket.instances[0]?.simulateMessage('{"event":"notifications","data":2}');
    });
    expect(screen.getByTestId("socket").textContent).toBe("open");
    expect(onEvent).toHaveBeenCalledWith(2);
  });
  it.each([useInterlockSession, useInterlockFetch, useCatalogClient, useNotificationSocket])(
    "hooks reject use outside the provider (%s)",
    (hook) => {
      function Outside() {
        hook();
        return null;
      }
      expect(() => render(<Outside />)).toThrow("InterlockProvider");
    },
  );
});
