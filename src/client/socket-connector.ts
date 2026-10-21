/* The connector exclusively owns each socket and clears its handlers on stop. */
/* oxlint-disable unicorn/prefer-add-event-listener */
import { backoffDelay, type BackoffOptions } from "./backoff.js";
import { dependencyFailure } from "./dependency-failure.js";
import { DependencyFailureError, SessionEndedError } from "./errors.js";
import type { SessionController } from "./session-controller.js";
import { initialSocketState, reduceSocket, type SocketEvent } from "./socket-machine.js";
import {
  defaultTimers,
  type SocketMessage,
  type Timers,
  type WebSocketConstructor,
  type WebSocketPort,
} from "./types.js";

export interface SocketOptions {
  url: string;
  controller: SessionController;
  WebSocket?: WebSocketConstructor;
  revalidate: () => Promise<unknown>;
  timers?: Timers;
  random?: () => number;
  backoff?: BackoffOptions;
}
export function createSocketConnector({
  url,
  controller,
  WebSocket,
  revalidate,
  timers = defaultTimers,
  random,
  backoff,
}: SocketOptions) {
  let state = initialSocketState();
  let socket: WebSocketPort | undefined;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let unsubscribe: (() => void) | undefined;
  let revision = 0;
  let generation = 0;
  const listeners = new Set<() => void>();
  const messages = new Set<(message: SocketMessage) => void>();
  const dispatch = (event: SocketEvent) => {
    const result = reduceSocket(state, event);
    state = result.state;
    for (const listener of listeners) listener();
    for (const effect of result.effects) {
      // A subscriber may stop the connector while observing this transition.
      if (state !== result.state) break;
      if (effect === "cancel_timer" && timer !== undefined) {
        timers.clearTimeout(timer);
        timer = undefined;
      }
      if (effect === "close") {
        revision += 1;
        const closing = socket;
        socket = undefined;
        if (closing) {
          closing.onopen = null;
          closing.onclose = null;
          closing.onmessage = null;
          closing.onerror = null;
          closing.close(1000);
        }
      }
      if (effect === "open") open();
      if (effect === "schedule")
        timer = timers.setTimeout(
          () => {
            timer = undefined;
            dispatch({ type: "timer" });
          },
          backoffDelay(state.attempt - 1, backoff, random),
        );
      if (effect === "report_unauthorized")
        controller.dispatch({ type: "unauthorized", generation });
      if (effect === "report_dependency" && state.failure)
        controller.dispatch({ type: "dependency_failed", failure: state.failure });
      if (effect === "revalidate") void check(revision);
    }
  };
  async function check(at: number) {
    try {
      await revalidate();
      if (at === revision) dispatch({ type: "revalidated", result: "alive" });
    } catch (error) {
      if (at !== revision) return;
      if (error instanceof SessionEndedError) dispatch({ type: "revalidated", result: "ended" });
      else
        dispatch({
          type: "revalidated",
          result: "dependency",
          failure:
            error instanceof DependencyFailureError
              ? error.failure
              : dependencyFailure("socket", "revalidation_failed", {}, timers.now),
        });
    }
  }
  function open() {
    generation = controller.generation();
    revision += 1;
    const at = revision;
    try {
      const current = new (WebSocket ?? globalThis.WebSocket)(url);
      socket = current;
      current.onopen = () => {
        if (at === revision) {
          dispatch({ type: "opened" });
          controller.dispatch({ type: "dependency_recovered" });
        }
      };
      current.onclose = (event) => {
        if (at !== revision) return;
        socket = undefined;
        dispatch({
          type: "closed",
          code: event.code,
          ...(event.code === 4503
            ? {
                failure: dependencyFailure(
                  "socket",
                  event.reason === "database" ? "database" : "upstream_unavailable",
                  {},
                  timers.now,
                ),
              }
            : {}),
        });
      };
      // Browsers report the actionable result in close, including refused handshakes.
      current.onerror = () => {
        /* close carries the actionable error. */
      };
      current.onmessage = (event) => {
        if (at !== revision || typeof event.data !== "string") return;
        let parsed: unknown;
        try {
          parsed = JSON.parse(event.data);
        } catch {
          return;
        }
        if (
          !parsed ||
          typeof parsed !== "object" ||
          !("event" in parsed) ||
          typeof parsed.event !== "string" ||
          !("data" in parsed)
        )
          return;
        const message = { event: parsed.event, data: parsed.data };
        for (const listener of messages) listener(message);
      };
    } catch {
      dispatch({ type: "closed", code: 1006 });
    }
  }
  const sync = () => {
    if (controller.getState().phase.kind === "signed_in") {
      if (state.phase === "idle") dispatch({ type: "start" });
    } else dispatch({ type: "stop" });
  };
  const start = () => {
    if (unsubscribe) return;
    unsubscribe = controller.subscribe(sync);
    sync();
  };
  const stop = () => {
    unsubscribe?.();
    unsubscribe = undefined;
    dispatch({ type: "stop" });
  };
  return {
    start,
    stop,
    getState: () => state,
    subscribe: (listener: () => void) => {
      listeners.add(listener);
      return () => {
        listeners.delete(listener);
      };
    },
    subscribeMessages: (listener: (message: SocketMessage) => void) => {
      messages.add(listener);
      return () => {
        messages.delete(listener);
      };
    },
    send: (message: SocketMessage) => {
      if (!socket || socket.readyState !== 1) return false;
      socket.send(JSON.stringify(message));
      return true;
    },
    reconnectNow: () => {
      if (controller.getState().phase.kind === "signed_in") {
        if (state.phase === "idle") dispatch({ type: "start" });
        else dispatch({ type: "reconnect_now" });
      }
    },
  };
}
export type SocketConnector = ReturnType<typeof createSocketConnector>;
