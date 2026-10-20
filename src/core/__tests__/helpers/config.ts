import { vi, type Mock } from "vitest";

import { REFRESH_DEFAULTS, type KeycloakAuthConfig, type RefreshConfig } from "../../config.js";
import type { AuthLogger, LogRecord } from "../../logger.js";

/** What the specs configure: the options' configuration and the refresher's bounds. */
export type TestConfig = KeycloakAuthConfig & { refresh: RefreshConfig };

/**
 * A complete, valid configuration: the values Interlock's own test setup uses. The
 * Keycloak issuer is on port 1, so Better Auth's startup discovery fetch is refused without a DNS
 * lookup unless a spec stubs `fetch`. Specs that change a value spread it; nothing mutates it.
 */
export const TEST_CONFIG: TestConfig = {
  betterAuth: {
    url: "https://interlock.test",
    secrets: [
      { version: 1, value: "test-secret-current" },
      { version: 0, value: "test-secret-previous" },
    ],
  },
  keycloak: {
    issuer: "https://127.0.0.1:1/realms/test",
    clientId: "interlock",
    clientSecret: "test-client-secret",
    backchannelLogoutPath: "/api/auth/backchannel-logout",
  },
  trustedOrigins: ["https://interlock.test"],
  cookieNamePolicy: "host",
  refresh: REFRESH_DEFAULTS,
};

/** `TEST_CONFIG` with the Keycloak settings changed. */
export const withKeycloak = (keycloak: Partial<TestConfig["keycloak"]>): TestConfig => ({
  ...TEST_CONFIG,
  keycloak: { ...TEST_CONFIG.keycloak, ...keycloak },
});

/** A logger whose four levels are mocks, so specs assert what was logged. */
export type TestLogger = { [Level in keyof AuthLogger]: Mock<(record: LogRecord) => void> };

export const testLogger = (): TestLogger => ({
  debug: vi.fn<(record: LogRecord) => void>(),
  log: vi.fn<(record: LogRecord) => void>(),
  warn: vi.fn<(record: LogRecord) => void>(),
  error: vi.fn<(record: LogRecord) => void>(),
});

/** The record of every call to one level. */
export const records = (level: Mock<(record: LogRecord) => void>) =>
  level.mock.calls.map(([record]) => record);

/** Every record the logger received, whatever the level. */
export const allRecords = (logger: TestLogger) =>
  [logger.debug, logger.log, logger.warn, logger.error].flatMap(records);

/** The value, or a thrown error naming what was missing; narrows where `expect` cannot. */
export function defined<T>(value: T | null | undefined, what = "value"): T {
  if (value === null || value === undefined) {
    throw new Error(`expected ${what} to be defined`);
  }
  return value;
}
