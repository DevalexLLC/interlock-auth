export const unauthorized = (reason?: "refresh_indeterminate") =>
  Response.json({ code: "session_invalid", reason }, { status: 401 });
export const unavailable = (reason = "database") =>
  Response.json({ code: "dependency_failure", reason }, { status: 503 });
export const rejected = (code = "upstream_rejected_token") =>
  Response.json({ code }, { status: 502 });
