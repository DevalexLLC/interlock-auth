import {
  DEPENDENCY_FAILURE,
  SESSION_INVALID,
  type DependencyFailureBody,
  type SessionInvalidBody,
} from "../core/grants/refresh-responses.js";
import { dependencyFailure, type DependencyFailure } from "./dependency-failure.js";

export type ResponseClassification =
  | { kind: "ok" | "pass_through" }
  | { kind: "session_ended"; reason?: SessionInvalidBody["reason"] }
  | { kind: "dependency_failure"; failure: DependencyFailure };

/** Clone only contract responses: callers retain the original stream. */
export async function classifyResponse(
  response: Response,
  now = Date.now,
): Promise<ResponseClassification> {
  if (response.ok) return { kind: "ok" };
  if (![401, 502, 503].includes(response.status)) return { kind: "pass_through" };
  let body: Partial<DependencyFailureBody | SessionInvalidBody> & {
    code?: string;
    reason?: string;
  } = {};
  try {
    body = (await response.clone().json()) ?? {};
  } catch {
    /* An unreadable 401 still ends the session. */
  }
  if (response.status === SESSION_INVALID.status)
    return {
      kind: "session_ended",
      ...(body.code === SESSION_INVALID.code && body.reason === "refresh_indeterminate"
        ? { reason: body.reason }
        : {}),
    };
  const reason = typeof body.reason === "string" ? body.reason : "unknown";
  const message = typeof body.message === "string" ? body.message : undefined;
  if (response.status === DEPENDENCY_FAILURE.status && body.code === DEPENDENCY_FAILURE.code) {
    return {
      kind: "dependency_failure",
      failure: dependencyFailure("bff", reason, { status: 503, message }, now),
    };
  }
  if (
    response.status === 502 &&
    ["upstream_rejected_token", "upstream_redirect", "upstream_handshake_failed"].includes(
      body.code ?? "",
    )
  ) {
    return {
      kind: "dependency_failure",
      failure: dependencyFailure("upstream", body.code ?? "unknown", { status: 502, message }, now),
    };
  }
  return { kind: "pass_through" };
}
