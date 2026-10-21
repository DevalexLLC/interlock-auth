import { dependencyFailure } from "./dependency-failure.js";
import { DependencyFailureError, UpstreamError } from "./errors.js";
import {
  initialSessionState,
  reduceSession,
  type SessionEvent,
  type SessionState,
} from "./session-machine.js";
import type { SessionEndedInfo, SignOutResponse } from "./types.js";

export interface SignInOptions {
  callbackURL?: string;
}
export interface SessionPorts {
  signIn(options: SignInOptions): Promise<void>;
  signOut(): Promise<SignOutResponse>;
  refetchSession(): Promise<unknown>;
  onSessionEnded?(info: SessionEndedInfo): void;
  /** A function is read at each sign-in, so an automatic re-login returns to the current route. */
  callbackURL?: string | (() => string | undefined);
  now?: () => number;
}
export function createSessionController(ports: SessionPorts, initial = initialSessionState()) {
  let state = initial;
  let dispatching = false;
  let signingOut: Promise<void> | undefined;
  const listeners = new Set<() => void>();
  const queue: SessionEvent[] = [];
  const failureOf = (error: unknown) =>
    error instanceof DependencyFailureError
      ? error.failure
      : error instanceof UpstreamError
        ? dependencyFailure("bff", "request_failed", { status: error.status }, ports.now)
        : dependencyFailure("network", "unreachable", {}, ports.now);
  const callbackURL = () =>
    typeof ports.callbackURL === "function" ? ports.callbackURL() : ports.callbackURL;
  const retry = async () => {
    try {
      await ports.refetchSession();
    } catch (error) {
      dispatch({ type: "session_unavailable", failure: failureOf(error) });
    }
  };
  const signIn = async (options: SignInOptions = {}) => {
    try {
      await ports.signIn({ callbackURL: callbackURL(), ...options });
    } catch (error) {
      dispatch({ type: "login_failed", failure: failureOf(error) });
    }
  };
  function dispatch(event: SessionEvent) {
    queue.push(event);
    if (dispatching) return;
    dispatching = true;
    try {
      while (queue.length) {
        const pending = queue.shift();
        if (!pending) break;
        const result = reduceSession(state, pending);
        // Install before the callback so generation() is synchronous, but publish after it.
        const changed = result.state !== state;
        state = result.state;
        for (const effect of result.effects) {
          if (effect.type === "notify_ended") {
            try {
              ports.onSessionEnded?.(effect.info);
            } catch (error) {
              console.error("Interlock onSessionEnded failed", error);
            }
          }
        }
        if (changed) for (const listener of listeners) listener();
        for (const effect of result.effects) {
          if (effect.type === "re_enter_login") void signIn();
          if (effect.type === "refetch_session") void retry();
        }
      }
    } finally {
      dispatching = false;
    }
  }
  const signOut = async () => {
    if (signingOut) return signingOut;
    signingOut = Promise.resolve()
      .then(async () => {
        try {
          dispatch({ type: "sign_out_completed", result: await ports.signOut() });
        } catch (error) {
          dispatch({ type: "sign_out_failed", failure: failureOf(error) });
        }
      })
      .finally(() => {
        signingOut = undefined;
      });
    dispatch({ type: "sign_out_requested" });
    return signingOut;
  };
  return {
    getState: () => state,
    subscribe: (listener: () => void) => {
      listeners.add(listener);
      return () => {
        listeners.delete(listener);
      };
    },
    dispatch,
    generation: () => state.generation,
    signIn,
    signOut,
    retry,
  };
}
export type SessionController = ReturnType<typeof createSessionController>;
export type { SessionState };
