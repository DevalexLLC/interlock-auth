import type { KeycloakLogout } from "../core/logout/keycloak-logout.js";

export interface InterlockSession {
  user: {
    id: string;
    name: string;
    username?: string | null;
    email: string;
    emailVerified: boolean;
    image?: string | null;
    createdAt: Date | string;
    updatedAt: Date | string;
  };
  session: { id: string; userId: string; expiresAt: Date | string; token: string };
}
export interface SessionEndedInfo {
  sessionId: string;
  reason?: "refresh_indeterminate";
  willReEnterLogin: boolean;
  generation: number;
}
export interface SignOutResponse {
  keycloakLogout: KeycloakLogout;
  incomplete: boolean;
}
export interface Timers {
  setTimeout(callback: () => void, ms: number): ReturnType<typeof setTimeout>;
  clearTimeout(id: ReturnType<typeof setTimeout>): void;
  now: () => number;
}
export const defaultTimers: Timers = {
  setTimeout: (callback, ms) => setTimeout(callback, ms),
  clearTimeout: (id) => clearTimeout(id),
  now: () => Date.now(),
};
export interface SocketMessage<T = unknown> {
  event: string;
  data: T;
}
export interface WebSocketPort {
  readyState: number;
  onopen: ((event: Event) => void) | null;
  onclose: ((event: CloseEvent) => void) | null;
  onmessage: ((event: MessageEvent) => void) | null;
  onerror: ((event: Event) => void) | null;
  send(data: string): void;
  close(code?: number): void;
}
export type WebSocketConstructor = new (url: string) => WebSocketPort;
