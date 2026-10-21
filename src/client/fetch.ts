import { classifyResponse } from "./classify.js";
import { dependencyFailure } from "./dependency-failure.js";
import type { Endpoints } from "./endpoints.js";
import { DependencyFailureError, SessionEndedError } from "./errors.js";
import type { SessionController } from "./session-controller.js";

export interface InterlockRequestInit extends RequestInit {
  json?: unknown;
  query?: Record<string, string | number | boolean | undefined>;
}
export type InterlockFetch = (path: string, init?: InterlockRequestInit) => Promise<Response>;
export function createInterlockFetch(
  endpoints: Endpoints,
  controller: SessionController,
  fetchImpl: typeof fetch = globalThis.fetch,
): InterlockFetch {
  return async (path, { json, query, ...init } = {}) => {
    const url = new URL(path, endpoints.origin);
    if (url.origin !== endpoints.origin)
      throw new TypeError("Interlock fetch requires its configured origin");
    for (const [key, value] of Object.entries(query ?? {}))
      if (value !== undefined) url.searchParams.set(key, String(value));
    const headers = new Headers(init.headers);
    if (json !== undefined) headers.set("content-type", "application/json");
    const body = json !== undefined ? JSON.stringify(json) : init.body;
    const generation = controller.generation();
    let response: Response;
    try {
      response = await fetchImpl(url, {
        ...init,
        headers,
        body,
        credentials: "include",
      });
    } catch (error) {
      if (!(error instanceof TypeError)) throw error;
      const failure = dependencyFailure("network", "unreachable");
      controller.dispatch({ type: "dependency_failed", failure });
      throw new DependencyFailureError(failure);
    }
    const result = await classifyResponse(response);
    if (result.kind === "session_ended") {
      controller.dispatch({ type: "unauthorized", generation, reason: result.reason });
      throw new SessionEndedError(generation, result.reason);
    }
    if (result.kind === "dependency_failure") {
      controller.dispatch({ type: "dependency_failed", failure: result.failure });
      throw new DependencyFailureError(result.failure);
    }
    if (result.kind === "ok") controller.dispatch({ type: "dependency_recovered" });
    return response;
  };
}
