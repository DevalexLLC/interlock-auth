/**
 * One log record: a message and the structured fields beside it. The package names its fields
 * clear of the fragments `token`, `secret`, `password` and `credential`, so a host logger that
 * redacts by key keeps them as values.
 */
export type LogRecord = { message: string } & Record<string, unknown>;

/**
 * Where the package logs. Every function that logs takes one explicitly; there is no default and
 * no singleton, because a silent logger would drop refused logout tokens and indeterminate
 * refreshes without a trace.
 *
 * Redaction is the host's job. The package never puts a token in a field of its own, but the
 * Better Auth records `createKeycloakAuthOptions` forwards carry Better Auth's own arguments
 * under `args`, and those can hold tokens, request bodies and database errors.
 */
export interface AuthLogger {
  debug(record: LogRecord): void;
  log(record: LogRecord): void;
  warn(record: LogRecord): void;
  error(record: LogRecord): void;
}
