import { describe, expect, it } from "vitest";

import { session } from "./__tests__/helpers/fake-ports.js";
import { dependencyFailure } from "./dependency-failure.js";
import {
  initialSessionState,
  reduceSession,
  type SessionEvent,
  type SessionState,
} from "./session-machine.js";

const signedIn = (): SessionState => ({
  ...initialSessionState(),
  phase: { kind: "signed_in", session: session() },
});
const ended = (generation = 0): SessionEvent => ({
  type: "unauthorized",
  reason: "refresh_indeterminate",
  generation,
});
const failure = dependencyFailure("session", "database", { status: 500 }, () => 1);
const step = (state: SessionState, event: SessionEvent) => reduceSession(state, event).state;

describe("session transitions", () => {
  it("plain 401 ends, increments generation, notifies, and never redirects", () => {
    const result = reduceSession(signedIn(), { type: "unauthorized", generation: 0 });
    expect(result.state).toMatchObject({
      generation: 1,
      phase: { kind: "signed_out", cause: "ended", endedSessionId: "s1" },
    });
    expect(result.effects).toEqual([
      {
        type: "notify_ended",
        info: { sessionId: "s1", generation: 1, reason: undefined, willReEnterLogin: false },
      },
      { type: "refetch_session" },
    ]);
  });
  it("current indeterminate consumes exactly one automatic login", () => {
    const result = reduceSession(signedIn(), ended());
    expect(result.state).toMatchObject({
      generation: 1,
      reLoginUsedFor: "s1",
      phase: { kind: "re_entering_login" },
    });
    expect(result.effects).toContainEqual({ type: "re_enter_login" });
    expect(step(result.state, ended(1))).toBe(result.state);
    const sameSession = { ...result.state, phase: signedIn().phase };
    expect(step(sameSession, ended(1)).phase.kind).toBe("signed_out");
  });
  it("stale-generation indeterminate is a plain end", () => {
    const result = reduceSession({ ...signedIn(), generation: 1 }, ended());
    expect(result.state.phase.kind).toBe("signed_out");
    expect(result.effects.map((effect) => effect.type)).not.toContain("re_enter_login");
  });
  it("provider null ends without navigation; late reason and stale session cannot restore it", () => {
    const result = reduceSession(signedIn(), { type: "session_resolved", session: null });
    expect(result.state.phase.kind).toBe("signed_out");
    expect(result.effects.map((effect) => effect.type)).not.toContain("re_enter_login");
    expect(step(result.state, ended())).toBe(result.state);
    expect(step(result.state, { type: "session_resolved", session: session() })).toBe(result.state);
  });
  it("a new session clears the automatic-login marker", () => {
    const state = step(signedIn(), ended());
    expect(step(state, { type: "session_resolved", session: session("s2") })).toMatchObject({
      phase: { kind: "signed_in" },
      reLoginUsedFor: null,
    });
  });
  it.each(["ended", "unconfirmed", "no_session"] as const)(
    "logout %s survives null and late 401",
    (keycloakLogout) => {
      const pending = step(signedIn(), { type: "sign_out_requested" });
      expect(pending.generation).toBe(1);
      expect(step(pending, ended())).toBe(pending);
      const done = step(pending, {
        type: "sign_out_completed",
        result: { keycloakLogout, incomplete: false },
      });
      expect(done.phase).toMatchObject({ kind: "signed_out", cause: "signed_out", keycloakLogout });
      expect(step(done, { type: "session_resolved", session: null })).toBe(done);
      expect(step(done, ended())).toBe(done);
      expect(step(done, { type: "session_resolved", session: session() })).toBe(done);
    },
  );
  it("503 sign_out_incomplete remains signed out and flagged", () => {
    const state = step(signedIn(), { type: "sign_out_requested" });
    expect(
      step(state, {
        type: "sign_out_completed",
        result: { keycloakLogout: "unconfirmed", incomplete: true },
      }).phase,
    ).toMatchObject({ kind: "signed_out", signOutIncomplete: true });
  });
  it("logout network failure restores session, reports dependency, and refetches", () => {
    const state = step(signedIn(), { type: "sign_out_requested" });
    const result = reduceSession(state, { type: "sign_out_failed", failure });
    expect(result.state).toMatchObject({ phase: { kind: "signed_in" }, dependency: failure });
    expect(result.effects).toEqual([{ type: "refetch_session" }]);
  });
  it("dependency failure preserves the session; success clears it", () => {
    const state = step(signedIn(), { type: "dependency_failed", failure });
    expect(state.phase.kind).toBe("signed_in");
    expect(step(state, { type: "dependency_recovered" }).dependency).toBeNull();
  });
  it("first-load 500 is unavailable; first-load null is never signed in", () => {
    expect(step(initialSessionState(), { type: "session_unavailable", failure }).phase.kind).toBe(
      "unavailable",
    );
    expect(step(initialSessionState(), { type: "session_resolved", session: null }).phase).toEqual({
      kind: "signed_out",
      cause: "never",
    });
    expect(step(signedIn(), { type: "session_unavailable", failure }).phase.kind).toBe("signed_in");
  });
  it("sign-out while signed out still increments generation and accepts no_session", () => {
    const initial = step(initialSessionState(), { type: "session_resolved", session: null });
    const state = step(initial, { type: "sign_out_requested" });
    expect(state.generation).toBe(1);
    expect(
      step(state, {
        type: "sign_out_completed",
        result: { keycloakLogout: "no_session", incomplete: false },
      }).phase,
    ).toMatchObject({ kind: "signed_out", keycloakLogout: "no_session" });
  });
});
