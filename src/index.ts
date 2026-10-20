// Root entry: the framework-agnostic core. Better Auth options for the Keycloak provider with
// session-scoped grants, the grant store and its refresher, the exposure allow-list, the
// back-channel receiver and RP-initiated logout, and claim normalization. Free of React and
// Next.js, so a server or a test process can import it without either.

export {
  cookieSettings,
  createKeycloakAuthOptions,
  createPostgresStore,
  KEYCLOAK_SCOPES,
  receiverRouteOf,
  type AuthDatabase,
  type KeycloakAuthOptions,
} from "./core/auth.options.js";
export {
  assertCallbackPath,
  resolveCallbackPath,
  StartupError,
  type CallbackPathOptions,
  type CallbackPathSource,
} from "./core/callback-path.js";
export { normalizeClaims, type NormalizedClaims } from "./core/claims.js";
export {
  COOKIE_NAME_POLICIES,
  drainBound,
  leaseBound,
  REFRESH_DEFAULTS,
  refreshBoundProblems,
  waitBound,
  type CookieNamePolicy,
  type KeycloakAuthConfig,
  type RefreshConfig,
  type VersionedSecret,
} from "./core/config.js";
export {
  AUTH_BASE_PATH,
  COMPLETE_BUDGET_MS,
  COOKIE_PREFIX,
  KEYCLOAK_CALLBACK_PATH,
  KEYCLOAK_PROVIDER_ID,
  LEASE_MARGIN_MS,
  POOL_CONNECTION_TIMEOUT_MS,
  STATEMENT_TIMEOUT_MS,
} from "./core/constants.js";
export {
  ACCOUNT_TOKENS_MESSAGE,
  ACCOUNT_TOKENS_TRIGGER,
  accountTokensProblems,
  ensureAccountTokensInvariant,
  type AccountTokensOptions,
} from "./core/database/account-tokens.js";
export { InFlightWork } from "./core/database/in-flight-work.js";
export { sessionGrant } from "./core/database/migrations/0001_session_grant.js";
export { appMigrations, type AppMigrations } from "./core/database/migrations/index.js";
export {
  EXPOSED_ROUTES,
  exposedRoutesFor,
  exposeRoutes,
  ID_TOKEN_FORBIDDEN,
  ROUTE_NOT_EXPOSED,
  scrubProviderTokens,
  stripProviderTokens,
} from "./core/exposure.js";
export {
  CALLBACK_ENDPOINT,
  callbackStartOf,
  composeAfterHooks,
  composeBeforeHooks,
  recordCallbackStart,
} from "./core/grants/callback-start.js";
export {
  GRANT_ID_TOKEN_MISSING,
  GRANT_NOT_CAPTURED,
  GRANT_NOT_CREATED,
  GRANT_REFRESH_EXPIRY_MISSING,
  GRANT_SID_MISSING,
  GRANT_UNSUPPORTED_LOGIN,
  type GrantErrorCode,
} from "./core/grants/grant-errors.js";
export { grantHooks, idTokenClaims, TOKEN_FIELDS } from "./core/grants/grant-hooks.js";
export {
  AmbiguousCommitError,
  CompletionBudgetError,
  deadlineFrom,
  KyselyGrantStore,
  type CompleteInput,
  type CompleteResult,
  type EndPredicate,
  type Grant,
  type GrantStore,
  type KyselyGrantStoreOptions,
  type LifetimeAnchor,
  type NewGrant,
  type RefreshedGrantTokens,
  type StoredGrant,
} from "./core/grants/grant-store.js";
export {
  emitRefreshEvent,
  type RefreshEventBase,
  type RefreshEventFields,
  type RefreshEventName,
} from "./core/grants/refresh-events.js";
export {
  DEPENDENCY_FAILURE,
  dependencyFailureBody,
  refreshResponse,
  SESSION_INVALID,
  type DependencyFailureBody,
  type DependencyFailureReason,
  type EndedReason,
  type RefreshResponse,
  type SessionInvalidBody,
  type UnavailableReason,
} from "./core/grants/refresh-responses.js";
export {
  createGrantRefresher,
  GrantRefresher,
  type AccessTokenOutcome,
  type AuthContext,
  type GrantRefresherConfig,
  type GrantRefresherOptions,
  type RefreshOptions,
  type RefreshOutcome,
  type ResolveOptions,
} from "./core/grants/refresh.js";
export {
  isPlaceholderEmail,
  keycloakAccountSubject,
  mapKeycloakProfile,
} from "./core/keycloak-profile.js";
export {
  httpTransport,
  refreshTokens,
  tokenLifetimes,
  type Lifetimes,
  type RefreshedTokens,
  type RefreshRequest,
  type RefreshResult,
  type TokenRequest,
  type TokenTransport,
  type TransportResult,
} from "./core/keycloak-token.js";
export type { AuthLogger, LogRecord } from "./core/logger.js";
export {
  assertReceiverRoute,
  BACKCHANNEL_LOGOUT_EVENT,
  BACKCHANNEL_LOGOUT_ROUTE,
  backchannelLogout,
  createKeyResolver,
  createLogoutTokenValidator,
  KEY_CACHE_MAX_AGE_MS,
  KEY_FETCH_BACKOFF_MS,
  KEY_REFETCH_COOLDOWN_MS,
  KeyResolutionFailure,
  LOGOUT_TOKEN_INVALID,
  LOGOUT_TOKEN_UNVERIFIABLE,
  realmKeys,
  UnknownKey,
  type BackchannelLogoutOptions,
  type KeyResolutionReason,
  type LogoutClaims,
  type LogoutTokenRejection,
  type LogoutTokenResult,
  type LogoutTokenValidatorOptions,
} from "./core/logout/backchannel.js";
export {
  endKeycloakSession,
  KEYCLOAK_LOGOUT_DEADLINE_MS,
  type KeycloakLogout,
  type KeycloakLogoutRequest,
  type KeycloakLogoutResult,
  type UnconfirmedReason,
} from "./core/logout/keycloak-logout.js";
export {
  captureSignOut,
  finishSignOut,
  SIGN_OUT_ENDPOINT,
  SIGN_OUT_INCOMPLETE,
  type SignOutOptions,
} from "./core/logout/sign-out.js";
export { isPlainObject } from "./core/plain-object.js";
