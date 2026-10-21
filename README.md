# @devalexllc/interlock-auth

The shared authentication package for Interlock and the applications that sign in through it:
the Better Auth wiring and claim normalization Interlock runs on, and the session clients its
Next.js and React applications use. One package, one session model, released on one cadence.

| Entry point | Contents                                                                                       | Status            |
| ----------- | ---------------------------------------------------------------------------------------------- | ----------------- |
| `.`         | Better Auth options for the Keycloak provider, session-scoped grants, and claim normalization  | Since 0.1.0 (3.5) |
| `./next`    | The Next.js session behavior: session reads, the session route handler, provider and monitor   | Empty until 8.1   |
| `./react`   | A session provider over `better-auth/react` and a fetch wrapper that applies the auth contract | Implemented (3.6) |

The root entry stays free of React and Next.js, so a server or a test process can import it
without either.

## The root entry

```ts
import {
  assertCallbackPath,
  assertReceiverRoute,
  createGrantRefresher,
  createKeycloakAuthOptions,
  createPostgresStore,
  InFlightWork,
  KyselyGrantStore,
  receiverRouteOf,
} from "@devalexllc/interlock-auth";
import { betterAuth } from "better-auth";

const auth = betterAuth(
  createKeycloakAuthOptions(config, {
    database: createPostgresStore(db, schema),
    grants: new KyselyGrantStore(db, schema),
    logger,
  }),
);
await assertCallbackPath(auth, { logger });
assertReceiverRoute(auth, receiverRouteOf(config));

const inFlight = new InFlightWork(); // the same one the pool's shutdown drains
const refresher = createGrantRefresher(new KyselyGrantStore(db, schema), config, {
  logger,
  inFlight,
});
```

`config` is a validated `KeycloakAuthConfig` (base URL and versioned secrets, the Keycloak
issuer, client and back-channel logout path, trusted origins, cookie-name policy), plus a
`RefreshConfig` for the refresher; `db` is a `Kysely` over the host's pool. What the root
entry exports:

- **Options.** `createKeycloakAuthOptions(config, { database, grants, logger, cookiePrefix? })`
  returns Better Auth options for a database-backed session (no cookie cache, no account
  cookie, encrypted provider tokens), the `genericOAuth` Keycloak provider with explicit
  endpoints beside discovery, the profile mapping keyed on `sub`, the grant hooks, the
  exposed-route allow-list, sign-out that ends the Keycloak session from the server, the
  back-channel logout receiver, and the cookie-name policy. It is pure: nothing connects until
  Better Auth initializes. `createPostgresStore`, `cookieSettings` and `KEYCLOAK_SCOPES` are
  the pieces it uses.
- **Username.** `user.username` carries Keycloak’s `preferred_username` independently of
  the display name. The optional, server-managed field is added by Better Auth’s migrator.
  `overrideUserInfo` refreshes mapped fields on login, so existing users acquire their
  username on their next login; no backfill is needed. The field stays `input: false`: a
  request-scoped provider-validation hook carries the verified username into user writes,
  because Better Auth 1.7.7 otherwise strips it from OAuth profiles too. `input: true` would
  avoid the hook, and Interlock's exposure allow-list already refuses every client route that
  writes a user, but a host that mounts Better Auth's full handler would then accept a
  username from the browser; the hook keeps the field server-owned under every host.
- **Session-scoped grants.** Each session's Keycloak tokens live on its own `session_grant`
  row, never on `account`. `KyselyGrantStore` is the runtime store; `GrantStore` is its
  interface. `createGrantRefresher` builds the refresh lease state machine, whose
  `resolveAccessToken` answers `ok`, `ended` or `unavailable`; `refreshResponse` and
  `dependencyFailureBody` turn those into the 401 and 503 bodies a BFF sends.
- **Startup checks.** `assertCallbackPath` fails startup unless Better Auth serves the realm's
  redirect URI; `assertReceiverRoute` fails it unless the receiver is the only endpoint at its
  route. Both throw `StartupError`.
- **Migrations.** `appMigrations(schema)` holds the package's own migration
  (`0001_session_grant`, for Kysely's `Migrator`, after Better Auth's tables exist);
  `ensureAccountTokensInvariant` scrubs and guards `account` against tokens and belongs in
  every migration run; `accountTokensProblems` verifies it.
- **Claims.** `normalizeClaims` maps Keycloak's claims to
  `{ roles, groups, tenants, sites, internal_groups }`. It is a stub until item 6.2 ships the
  mapping the APIs apply; `sites` stays empty until the realm has a source for it.

### Logging

Every function that logs takes an `AuthLogger` (`debug`, `log`, `warn`, `error`, each given a
`{ message, ...fields }` record) and none has a default: a silent logger would drop refused
logout tokens and indeterminate refreshes without a trace. The package's own fields are named
clear of the fragments `token`, `secret`, `password` and `credential` and never carry a token.

Better Auth's own log calls are forwarded as `{ message: "[better-auth] …", args }`, with
Better Auth's arguments under `args` as they are. Those can hold tokens, request bodies and
database errors whose `detail` quotes a row, so **the host's logger must redact** by key before
any transport sees a record.

### One copy of Better Auth

`better-auth` is a peer dependency pinned to one exact version, and the host must depend on
that same version. The hooks throw Better Auth's `APIError` and read its context types; with a
second copy installed, the router would not recognize the package's errors as its own. npm
refuses a conflicting peer at install time, but that does not prove a single copy, so check
`npm ls better-auth` after an install. `kysely` (`^0.29.0`) is a peer for the same reason;
`jose` is the package's own dependency.

**Better Auth bumps go to the package first, then to its consumers.** Bump the peer and the
development dependency here, run the suite (the route-table pin in `exposure.test.ts` fails
until a new or renamed route is reviewed against `EXPOSED_ROUTES`), release, and then move each
consumer to that release and that Better Auth version together.

### The database host contract

The host owns the pool; the package's timing assumes how it is configured. A host meets all
of these, and a new host (the `./next` entry's applications) must meet them for its own pool:

- One `pg` pool behind one `Kysely`, shared by the session store, the grant store and the
  refresher.
- The pool's `connectionTimeoutMillis` equals `POOL_CONNECTION_TIMEOUT_MS`, and every
  connection's server-side `statement_timeout` equals `STATEMENT_TIMEOUT_MS`. The refresher's
  read race and the lease bound (`leaseBound`, `waitBound`) assume exactly these numbers. Use
  the server's timeout, not `pg`'s `query_timeout`, which only rejects the promise and can
  return the connection to the pool inside an open transaction.
- `idle_in_transaction_session_timeout` is set, so the server ends a session left idle in a
  transaction.
- A socket inactivity timeout destroys an established connection that stops answering.
  Neither timeout above bounds that case, and a grant write would otherwise stay pending
  forever.
- `error` listeners on the pool and on every client. `pg-pool` drops its own listener at
  checkout, and a destroyed client emits `error`; an unheard `error` ends the process.
- Shutdown waits up to `drainBound(refresh)` for `inFlight.drained()`, on the `InFlightWork`
  passed to `createGrantRefresher`, after the HTTP server has closed and before the pool ends,
  so a dispatched refresh can still store its rotated tokens. The termination grace must allow
  that long.

### Configuration vocabulary

Hosts that read their configuration from the environment use these names, and
`refreshBoundProblems` words its problems in the `REFRESH_*` ones.

| Variable                     | `RefreshConfig` field | Default | Bound                                                            |
| ---------------------------- | --------------------- | ------- | ---------------------------------------------------------------- |
| `REFRESH_REQUEST_TIMEOUT_MS` | `requestTimeoutMs`    | 5000    | The token request's deadline                                     |
| `REFRESH_LEASE_MS`           | `leaseMs`             | 13000   | At least `leaseBound(requestTimeoutMs)`                          |
| `REFRESH_WAIT_MS`            | `waitMs`              | 5000    | `waitBound(waitMs)` less than `leaseMs`                          |
| `REFRESH_LEEWAY_MS`          | `leewayMs`            | 60000   | At least 1000                                                    |
| `COOKIE_NAME_POLICY`         | `cookieNamePolicy`    | (none)  | `host` (`__Host-<prefix>.*`) or `secure` (`__Secure-<prefix>.*`) |

## Development

```bash
npm test          # vitest
npm run fmt       # oxfmt (oxfmt --check in CI)
npm run lint      # oxlint --type-aware --type-check; this is the type check too
npm run build     # tsgo -> dist
npx changeset     # describe a change; CI opens the version PR
```

`lefthook` formats staged files on commit and runs the linter on push; `npm ci`
installs the hooks through the `prepare` script.

The suite runs in two vitest projects: `core` (Node) for the root entry under `src/core`, and
`dom` (jsdom) for the entry-point checks and the React and Next.js entries. The helpers in
`src/core/__tests__/helpers` (the memory grant store, the fake Keycloak, the auth instance) are
copies of Interlock's own test helpers, which its remaining suites still use; the two sets
drift unless they change together. A `./testing` entry is the way out if the React or Next.js
entries need the fakes too.

CI packs the package, installs the tarball into a throwaway project, and imports every entry
point by name, so a broken `exports` map fails the pull request rather than a consumer. It also
type-checks a consumer of the root entry under NodeNext resolution, the way Interlock imports
it, since the package itself builds with Bundler resolution.

Releases go out through the changesets action: merging the generated "chore: version
package" PR is what publishes. Nothing reaches npm without that merge.

Publishing uses [npm trusted publishing][tp] — the workflow exchanges a GitHub
OIDC token for short-lived credentials, so there is no npm token stored in the
repository. Every release carries a [provenance attestation][prov] linking the
tarball to the commit and workflow that built it:

```bash
npm audit signatures            # verify provenance of an installed copy
```

The one exception is `0.0.0`, published by hand to create the package on npm, because a
trusted publisher can only be configured on a package that already exists. It has no
provenance and the same empty contents as `0.0.1`.

Trusted publishing is configured against this repository and `release.yml` on
npmjs.com. It depends on Node >= 24.20 (npm >= 11.19) on the runner, and on the
npm-side organization name matching GitHub's canonical casing exactly.

[tp]: https://docs.npmjs.com/trusted-publishers
[prov]: https://docs.npmjs.com/generating-provenance-statements

## License

Apache License 2.0 — see [LICENSE](LICENSE). Copyright 2026 Devalex LLC.

## The `./react` entry

Install React 18.3 or 19 alongside the package. React is an optional peer so hosts using
only the server entry do not install it. The browser entry imports no server authentication
code and can also be imported in plain Node.

```tsx
import {
  InterlockProvider,
  useInterlockSession,
  useInterlockFetch,
  useCatalogClient,
  useNotificationSocket,
  useSocketEvent,
} from "@devalexllc/interlock-auth/react";

function Session() {
  const { phase, user, signIn, signOut, retry } = useInterlockSession();
  if (phase.kind === "loading") return <p>Loading…</p>;
  if (phase.kind === "unavailable") return <button onClick={retry}>Retry</button>;
  if (phase.kind !== "signed_in") return <button onClick={() => signIn()}>Sign in</button>;
  return <button onClick={signOut}>Sign out {user?.name}</button>;
}

// Clear application data synchronously here, before subscribers render signed out.
<InterlockProvider uri="https://interlock.example.com" onSessionEnded={() => clearUserCache()}>
  <Session />
</InterlockProvider>;
```

Provider configuration is fixed at mount; remount to change it. An absolute `uri` selects
that origin; omitted, empty, and relative values select the page origin. The auth and socket
paths are always `/api/auth` and `/ws/irongate`.

| Prop                                       | Default                          | Purpose                                                                         |
| ------------------------------------------ | -------------------------------- | ------------------------------------------------------------------------------- |
| `uri`                                      | Page origin                      | Interlock origin                                                                |
| `callbackURL`                              | Page URL at sign-in time         | Return URL for explicit and automatic login; a function is read at each sign-in |
| `onSessionEnded`                           | None                             | Synchronously clear user caches before publishing an ended state                |
| `refetchIntervalSeconds`                   | `60`                             | Better Auth session polling; `0` disables polling                               |
| `unavailableRetryMs`                       | `5000`                           | Retry first-load session failures; `0` disables the timer                       |
| `socket.enabled`                           | `true`                           | Connect notifications while signed in                                           |
| `socket.backoff`                           | `{ baseMs: 1000, capMs: 30000 }` | Full-jitter reconnect delay                                                     |
| `fetch`, `WebSocket`, `navigate`, `timers` | Browser implementations          | Injectable ports for hosts and tests                                            |

`useInterlockSession()` returns `{ phase, generation, reLoginUsedFor, dependency, user,
isSignedIn, signIn, signOut, retry }`. `phase.kind` is `loading`, `unavailable`, `signed_in`,
`signing_out`, `re_entering_login`, or `signed_out`. Better Auth reads the session on mount,
on refetch, when the page becomes visible, and periodically. A get-session failure preserves
an existing session; a failure before any session is known shows `unavailable`.

`useInterlockFetch()` returns `(path, { json?, query?, ...RequestInit }) => Promise<Response>`.
It always sends `credentials: "include"` to the configured origin. It never adds
`x-application-id`; Interlock derives application identity from the browser's Origin.

- Every 401 ends the session atomically and throws `SessionEndedError`. A plain 401 shows
  login without navigating. A current-generation `refresh_indeterminate` while signed in
  enters login once for that session ID. `onSessionEnded({ sessionId, reason, generation,
willReEnterLogin })` runs before subscribers see the new state.
- A 401 sent before logout cannot trigger automatic login after logout. Repeated 401s and
  Better Auth's stale copy of the ended session cannot restore it. A different session ID
  can sign in again. Provider-discovered session loss never redirects.
- A contract 503 `dependency_failure`, one of the three contract 502 codes, or a network
  failure throws `DependencyFailureError` and sets `dependency` without ending the session.
  The next successful BFF read clears that failure. Ordinary upstream errors pass through
  as Responses; caller cancellation is rethrown without declaring a dependency failure.
- `signOut()` is global and never retries automatically. Its 200 or 503
  `sign_out_incomplete` response leaves `signed_out` with `keycloakLogout` and
  `signOutIncomplete`. Display `unconfirmed` as **“Signed out of this application, SSO may
  still be active.”** A network failure retains the last session and refetches it.

`useNotificationSocket()` returns `{ phase, attempt, failure, send, subscribe, reconnectNow }`.
`subscribe` receives `{ event, data }`; `useSocketEvent<T>(event, handler)` subscribes to one
named event. `send({ event, data })` returns false unless open. There are no client pings.
The connector closes with 1000 as soon as the session leaves `signed_in`.

An established socket's 4401 uses the same session-ended transition. A 4503 preserves the
session, reports `database` or `upstream_unavailable`, and retries with backoff. Failed opens
and abnormal 1006 closes revalidate through **GET `/api/irongate/notifications/count`** using
the same fetch wrapper. Get-session does not run the grant refresher, so it cannot classify
these failures. Ordinary disconnects, including shutdown and backpressure, reconnect.

`useCatalogClient()` provides `listApplications()`, `groupsGranting(appId)`, `myGroups()`,
`listMyRequests(username)`, `createMemberRequest({ group, user, clientId })`,
`cancelRequest(id)`, `listNotifications(clientId)`, and `notificationCount()`. Every route
uses `/api/irongate`. A duplicate request returns `{ kind: "already_requested" }`; a created
request returns `{ kind: "created", request }`, with `request.id` normalized from `_id ?? id`.
Other non-contract upstream failures throw `UpstreamError` carrying the status and body.

The entry also exports the framework-free factories, reducers, error classes, and types:
`resolveEndpoints`, `classifyResponse`, `reduceSession`, `createSessionController`,
`createInterlockFetch`, `reduceSocket`, `createSocketConnector`, `createCatalogClient`, and
`backoffDelay`. These can be reused by another framework adapter without importing the
server entry.

### Compose demo

The unpublished `demo/` exercises username, catalog/groups, request/cancel, socket messages,
and the dependency and logout states. From this package checkout:

```sh
npm run demo
```

Open `https://demo.dev.home.arpa:5173`. The default Interlock origin is
`https://interlock.dev.home.arpa`; override it with `VITE_INTERLOCK_URI`. TLS defaults to
`../infralytics-stack/certs/dev.home.arpa.crt` and `.key`; override with `DEMO_TLS_CERT` and
`DEMO_TLS_KEY` when using a worktree elsewhere. No private key is copied into this package.

The Compose Interlock service must trust `https://demo.dev.home.arpa:5173`; this is
Compose-only development tooling, not a cluster-template setting. The browser needs the
local CA trust, hostname mapping, and Ann's client certificate. The host must run Better
Auth's migrator for `user.username` before serving this package version, and an existing user
must sign in again to populate it. Demo results are local Compose evidence only, never
cluster or enclave evidence.
