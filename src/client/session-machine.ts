import type { DependencyFailure } from "./dependency-failure.js";
import type { InterlockSession, SessionEndedInfo, SignOutResponse } from "./types.js";

export type SessionPhase =
  | { kind: "loading" }
  | { kind: "unavailable"; failure: DependencyFailure }
  | { kind: "signed_in"; session: InterlockSession }
  | { kind: "signing_out"; session: InterlockSession | null; endedSessionId?: string }
  | { kind: "re_entering_login"; endedSessionId: string }
  | {
      kind: "signed_out";
      cause: "never" | "ended" | "signed_out";
      endedSessionId?: string;
      keycloakLogout?: SignOutResponse["keycloakLogout"];
      signOutIncomplete?: boolean;
    };
export interface SessionState {
  phase: SessionPhase;
  generation: number;
  reLoginUsedFor: string | null;
  dependency: DependencyFailure | null;
}
export type SessionEvent =
  | { type: "session_resolved"; session: InterlockSession | null }
  | { type: "session_unavailable"; failure: DependencyFailure }
  | { type: "unauthorized"; generation: number; reason?: "refresh_indeterminate" }
  | { type: "sign_out_requested" }
  | { type: "sign_out_completed"; result: SignOutResponse }
  | { type: "sign_out_failed" | "login_failed" | "dependency_failed"; failure: DependencyFailure }
  | { type: "dependency_recovered" };
export type SessionEffect =
  | { type: "notify_ended"; info: SessionEndedInfo }
  | { type: "re_enter_login" | "refetch_session" };
export const initialSessionState = (): SessionState => ({
  phase: { kind: "loading" },
  generation: 0,
  reLoginUsedFor: null,
  dependency: null,
});

export function reduceSession(
  state: SessionState,
  event: SessionEvent,
): { state: SessionState; effects: SessionEffect[] } {
  const { phase } = state;
  const same = { state, effects: [] };
  const next = (patch: Partial<SessionState>, effects: SessionEffect[] = []) => ({
    state: { ...state, ...patch },
    effects,
  });
  const end = (reason?: "refresh_indeterminate", reEnter = false) => {
    if (phase.kind !== "signed_in") return same;
    const sessionId = phase.session.session.id;
    const generation = state.generation + 1;
    return next(
      {
        generation,
        phase: reEnter
          ? { kind: "re_entering_login", endedSessionId: sessionId }
          : { kind: "signed_out", cause: "ended", endedSessionId: sessionId },
        reLoginUsedFor: reEnter ? sessionId : state.reLoginUsedFor,
      },
      [
        {
          type: "notify_ended",
          info: { sessionId, reason, generation, willReEnterLogin: reEnter },
        },
        { type: reEnter ? "re_enter_login" : "refetch_session" },
      ],
    );
  };
  switch (event.type) {
    case "unauthorized":
      return end(
        event.reason,
        phase.kind === "signed_in" &&
          event.reason === "refresh_indeterminate" &&
          event.generation === state.generation &&
          state.reLoginUsedFor !== phase.session.session.id,
      );
    case "session_resolved": {
      if (phase.kind === "signing_out") return same;
      if (!event.session) {
        if (phase.kind === "signed_in") return end();
        if (phase.kind === "loading" || phase.kind === "unavailable")
          return next({ phase: { kind: "signed_out", cause: "never" }, dependency: null });
        return same;
      }
      const id = event.session.session.id;
      if (
        (phase.kind === "signed_out" || phase.kind === "re_entering_login") &&
        id === phase.endedSessionId
      )
        return same;
      return next({
        phase: { kind: "signed_in", session: event.session },
        reLoginUsedFor: id === state.reLoginUsedFor ? state.reLoginUsedFor : null,
        dependency: state.dependency?.source === "session" ? null : state.dependency,
      });
    }
    case "session_unavailable":
      return next({
        dependency: event.failure,
        ...(["loading", "unavailable"].includes(phase.kind)
          ? { phase: { kind: "unavailable", failure: event.failure } as SessionPhase }
          : {}),
      });
    case "sign_out_requested":
      if (phase.kind === "signing_out") return same;
      return next({
        generation: state.generation + 1,
        phase: {
          kind: "signing_out",
          session: phase.kind === "signed_in" ? phase.session : null,
          endedSessionId:
            phase.kind === "signed_in"
              ? phase.session.session.id
              : "endedSessionId" in phase
                ? phase.endedSessionId
                : undefined,
        },
      });
    case "sign_out_completed":
      if (phase.kind !== "signing_out") return same;
      return next({
        phase: {
          kind: "signed_out",
          cause: "signed_out",
          endedSessionId: phase.endedSessionId,
          keycloakLogout: event.result.keycloakLogout,
          signOutIncomplete: event.result.incomplete,
        },
        dependency: null,
      });
    case "sign_out_failed":
      if (phase.kind !== "signing_out") return same;
      return next(
        {
          phase: phase.session
            ? { kind: "signed_in", session: phase.session }
            : { kind: "signed_out", cause: "never", endedSessionId: phase.endedSessionId },
          dependency: event.failure,
        },
        [{ type: "refetch_session" }],
      );
    case "login_failed":
      return next({
        dependency: event.failure,
        ...(phase.kind === "re_entering_login"
          ? {
              phase: {
                kind: "signed_out",
                cause: "ended",
                endedSessionId: phase.endedSessionId,
              } as SessionPhase,
            }
          : {}),
      });
    case "dependency_failed":
      return next({ dependency: event.failure });
    case "dependency_recovered":
      return state.dependency ? next({ dependency: null }) : same;
    default:
      return same;
  }
}
