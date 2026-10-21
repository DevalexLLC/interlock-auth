export interface BackoffOptions {
  baseMs?: number;
  capMs?: number;
}
export function backoffDelay(
  attempt: number,
  { baseMs = 1000, capMs = 30_000 }: BackoffOptions = {},
  random = Math.random,
) {
  return Math.floor(
    Math.min(capMs, baseMs * 2 ** Math.min(Math.max(0, attempt), 30)) *
      Math.min(1, Math.max(0, random())),
  );
}
