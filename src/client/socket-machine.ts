import type { DependencyFailure } from "./dependency-failure.js";

export interface SocketState {
  phase: "idle" | "connecting" | "open" | "revalidating" | "waiting";
  attempt: number;
  failure: DependencyFailure | null;
}
export type SocketEvent =
  | { type: "start" | "stop" | "opened" | "timer" | "reconnect_now" }
  | { type: "closed"; code: number; failure?: DependencyFailure }
  | { type: "revalidated"; result: "alive" | "ended" | "dependency"; failure?: DependencyFailure };
export type SocketEffect =
  | "open"
  | "close"
  | "cancel_timer"
  | "schedule"
  | "revalidate"
  | "report_unauthorized"
  | "report_dependency";
export const initialSocketState = (): SocketState => ({ phase: "idle", attempt: 0, failure: null });
export function reduceSocket(
  state: SocketState,
  event: SocketEvent,
): { state: SocketState; effects: SocketEffect[] } {
  const next = (patch: Partial<SocketState>, ...effects: SocketEffect[]) => ({
    state: { ...state, ...patch },
    effects,
  });
  const same = { state, effects: [] };
  if (event.type === "stop") return next({ phase: "idle" }, "cancel_timer", "close");
  if (
    (event.type === "start" && state.phase === "idle") ||
    ((event.type === "timer" || event.type === "reconnect_now") && state.phase === "waiting")
  )
    return next({ phase: "connecting" }, "cancel_timer", "open");
  if (event.type === "opened" && state.phase === "connecting")
    return next({ phase: "open", attempt: 0, failure: null });
  if (event.type === "closed") {
    if (state.phase === "connecting" || (state.phase === "open" && event.code === 1006))
      return next({ phase: "revalidating" }, "revalidate");
    if (state.phase !== "open") return same;
    if (event.code === 4401) return next({ phase: "idle" }, "report_unauthorized");
    return next(
      { phase: "waiting", attempt: state.attempt + 1, failure: event.failure ?? state.failure },
      ...(event.code === 4503 ? ["report_dependency" as const] : []),
      "schedule",
    );
  }
  if (event.type === "revalidated" && state.phase === "revalidating") {
    if (event.result === "ended") return next({ phase: "idle" });
    return next(
      { phase: "waiting", attempt: state.attempt + 1, failure: event.failure ?? state.failure },
      ...(event.result === "dependency" ? ["report_dependency" as const] : []),
      "schedule",
    );
  }
  return same;
}
