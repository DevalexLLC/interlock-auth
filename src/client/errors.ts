import type { DependencyFailure } from "./dependency-failure.js";

export class SessionEndedError extends Error {
  constructor(
    readonly generation: number,
    readonly reason?: "refresh_indeterminate",
  ) {
    super("The session ended");
    this.name = "SessionEndedError";
  }
}
export class DependencyFailureError extends Error {
  constructor(readonly failure: DependencyFailure) {
    super(failure.message ?? failure.reason);
    this.name = "DependencyFailureError";
  }
}
export class UpstreamError extends Error {
  constructor(
    readonly status: number,
    readonly body: unknown,
  ) {
    super(`Upstream returned ${status}`);
    this.name = "UpstreamError";
  }
}
