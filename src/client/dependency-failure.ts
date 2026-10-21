export interface DependencyFailure {
  source: "bff" | "upstream" | "network" | "socket" | "session";
  reason: string;
  status?: number;
  message?: string;
  at: number;
}
export function dependencyFailure(
  source: DependencyFailure["source"],
  reason: string,
  details: { status?: number; message?: string } = {},
  now = Date.now,
): DependencyFailure {
  return { source, reason, ...details, at: now() };
}
