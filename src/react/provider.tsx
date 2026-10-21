import { useEffect, useState, useSyncExternalStore, type ReactNode } from "react";

import type { BackoffOptions } from "../client/backoff.js";
import { createCatalogClient } from "../client/catalog.js";
import { dependencyFailure } from "../client/dependency-failure.js";
import { resolveEndpoints } from "../client/endpoints.js";
import { UpstreamError } from "../client/errors.js";
import { createInterlockFetch } from "../client/fetch.js";
import { createSessionController } from "../client/session-controller.js";
import { createSocketConnector } from "../client/socket-connector.js";
import {
  defaultTimers,
  type InterlockSession,
  type SessionEndedInfo,
  type Timers,
  type WebSocketConstructor,
} from "../client/types.js";
import { createInterlockAuthClient } from "./auth-client.js";
import { InterlockContext } from "./context.js";

export interface InterlockProviderProps {
  uri?: string;
  children: ReactNode;
  onSessionEnded?: (info: SessionEndedInfo) => void;
  callbackURL?: string;
  refetchIntervalSeconds?: number;
  unavailableRetryMs?: number;
  socket?: { enabled?: boolean; backoff?: BackoffOptions };
  fetch?: typeof fetch;
  WebSocket?: WebSocketConstructor;
  navigate?: (url: string) => void;
  timers?: Timers;
}
/** Configuration is fixed for the provider's lifetime; remount to change origins. */
export function InterlockProvider(props: InterlockProviderProps) {
  const [runtime] = useState(() => {
    const timers = props.timers ?? defaultTimers;
    const endpoints = resolveEndpoints(
      props.uri,
      typeof window === "undefined" ? undefined : window.location,
    );
    const auth = createInterlockAuthClient(endpoints, props);
    const controller = createSessionController({
      ...auth,
      callbackURL:
        props.callbackURL ?? (typeof window === "undefined" ? undefined : window.location.href),
      onSessionEnded: props.onSessionEnded,
      now: timers.now,
    });
    const fetch = createInterlockFetch(endpoints, controller, props.fetch);
    const socket = createSocketConnector({
      url: endpoints.socketURL,
      controller,
      timers,
      backoff: props.socket?.backoff,
      WebSocket: props.WebSocket,
      revalidate: async () => {
        const response = await fetch("/api/irongate/notifications/count");
        if (!response.ok) throw new UpstreamError(response.status, null);
      },
    });
    return {
      auth,
      controller,
      fetch,
      catalog: createCatalogClient(fetch),
      socket,
      timers,
      enabled: props.socket?.enabled !== false,
      unavailableRetryMs: props.unavailableRetryMs ?? 5000,
    };
  });
  const { data, error, isPending, isRefetching } = runtime.auth.useSession();
  const state = useSyncExternalStore(
    runtime.controller.subscribe,
    runtime.controller.getState,
    runtime.controller.getState,
  );
  useEffect(() => {
    if (isPending || isRefetching) return;
    if (error)
      runtime.controller.dispatch({
        type: "session_unavailable",
        failure: dependencyFailure(
          "session",
          "get_session_failed",
          { status: error.status, message: error.message },
          runtime.timers.now,
        ),
      });
    else
      runtime.controller.dispatch({
        type: "session_resolved",
        session: data as InterlockSession | null,
      });
  }, [runtime, data, error, isPending, isRefetching]);
  useEffect(() => {
    if (state.phase.kind !== "unavailable" || runtime.unavailableRetryMs <= 0) return undefined;
    const id = runtime.timers.setTimeout(() => {
      void runtime.controller.retry();
    }, runtime.unavailableRetryMs);
    return () => runtime.timers.clearTimeout(id);
  }, [runtime, state.phase]);
  useEffect(() => {
    if (runtime.enabled) runtime.socket.start();
    return runtime.socket.stop;
  }, [runtime]);
  return <InterlockContext.Provider value={runtime}>{props.children}</InterlockContext.Provider>;
}
