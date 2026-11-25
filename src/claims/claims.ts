/**
 * An object other than a list. Claims are read from any such object, a class instance included
 * (a payload hydrated by class-transformer), so a plain-object check would drop its roles.
 */
const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

/**
 * The claim shape the APIs authorize on. It keeps the previous OpenID provider's field names, but
 * `roles` namespaces client roles by client ID, where that provider issued one flat list.
 */
export interface NormalizedClaims {
  /**
   * Realm roles bare, and each client's roles as `<client>:<role>`, without repeats. A role whose
   * name holds `:` is dropped, so no entry can be read two ways.
   */
  roles: string[];
  /**
   * Group names, without repeats, as the token carries them: bare names, because the realm's group
   * mapper has `full.path` off. A path is passed through, not shortened.
   */
  groups: string[];
  /** Tenant identifiers, from `tenant_ids`, without repeats. */
  tenants: string[];
  /** Site names from the `sites` user attribute, without repeats. Empty when the claim is absent. */
  sites: string[];
  /** Names of groups under the internal root, without repeats. */
  internal_groups: string[];
}

/**
 * A claim the realm's contract fixes the shape of arrived in another shape. The caller refuses
 * the request: a refresh cannot repair it, so this is a 403 rather than a 401. Recognize it with
 * `isMalformedClaimError`, which also holds when two copies of the package are installed and
 * `instanceof` would compare against the other copy's class.
 */
export class MalformedClaimError extends Error {
  constructor(
    /** The claim's name, such as `sites`, or `payload` for the whole argument. Never its value. */
    readonly claim: string,
  ) {
    super(
      claim === "payload"
        ? "The token payload is not an object"
        : `The token's ${claim} claim is malformed`,
    );
    // An own property, as the client's errors set it, so a copy of the error's own fields (a log
    // serializer, `Object.entries`) keeps it. V8 writes the stack header lazily, so it reads
    // `MalformedClaimError:` too.
    this.name = "MalformedClaimError";
  }
}

/** What `isMalformedClaimError` establishes: the fields, not the class or `Error`'s other members. */
export interface MalformedClaim {
  name: "MalformedClaimError";
  claim: string;
}

/**
 * Whether `error` is a `MalformedClaimError`, from this copy of the package or another, from
 * another `vm` realm, or as a copy of its own fields. Checked by shape rather than by prototype:
 * `instanceof` compares against one copy's class and one realm's `Error`. It narrows to
 * `MalformedClaim`, not to the class, because the object it recognizes need not have the class's
 * other members. An error that crossed a structured clone (a worker's `postMessage`) is not
 * recognized: the clone resets its name to `Error` and drops `claim`, so classify it before it
 * crosses. Use it on what a `try` around `normalizeClaims()` caught, not on arbitrary objects: an
 * upstream error body of the same shape would match.
 */
export const isMalformedClaimError = (error: unknown): error is MalformedClaim => {
  if (typeof error !== "object" || error === null) return false;
  // Not `message`: an `Error`'s message is not enumerable, so a copy of the fields drops it.
  const { name, claim } = error as { name?: unknown; claim?: unknown };
  return name === "MalformedClaimError" && typeof claim === "string";
};

/**
 * The strings of a claim that should be a string array, without repeats, in first-seen order;
 * anything else is dropped.
 */
const strings = (value: unknown): string[] =>
  Array.isArray(value)
    ? [...new Set(value.filter((item): item is string => typeof item === "string" && item !== ""))]
    : [];

/**
 * `<object>.roles` of an access claim such as `realm_access`, without any role whose name holds a
 * `:`. Keycloak allows one, but a realm role named `irongate-api:admin` would read as that client's
 * role, and a client role `b:c` of client `a` as role `c` of client `a:b`. With no `:` in a role
 * name, every entry splits one way at its last `:`. A dropped role grants nothing.
 */
const rolesOf = (access: unknown): string[] =>
  isRecord(access) ? strings(access.roles).filter((role) => !role.includes(":")) : [];

/** `resource_access` as `<client>:<role>` entries. A client ID may hold `:` (SAML clients). */
const clientRoles = (resourceAccess: unknown): string[] =>
  isRecord(resourceAccess)
    ? Object.entries(resourceAccess).flatMap(([client, access]) =>
        // An empty client ID would give `:<role>`; Keycloak issues none, so it is skipped.
        client === "" ? [] : rolesOf(access).map((role) => `${client}:${role}`),
      )
    : [];

/**
 * Every control (`Cc`) and format (`Cf`) character, and the line and paragraph separators, except
 * the three format characters that belong to names in some scripts: the zero-width non-joiner and
 * joiner (U+200C, U+200D) and the soft hyphen (U+00AD). Refusing the whole categories, rather than
 * a list, covers what pasted text carries (a byte-order mark, a zero-width space, bidirectional
 * marks and controls, tag characters) without chasing each one.
 */
const INVISIBLE = /(?!\u200C|\u200D|\u00AD)[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u;

/**
 * `sites` is reductive: an absent claim means every site in the user's tenants, so a present
 * claim that is not what the realm issues must not read as absent. The mapper omits the claim
 * for a user with no value and never emits `[]`, so a present claim is a non-empty array of
 * non-empty strings or it is refused. A value is an exact `Site.name`, so one with leading or
 * trailing whitespace, or with a control or invisible character (`INVISIBLE`), which can match no site,
 * is refused too, rather than leaving the user an
 * empty result with nothing to diagnose. Repeats are dropped, as they are for every list. A key
 * holding `undefined` counts as absent: a JSON token cannot carry `undefined`, and a payload class
 * with a declared `sites` field holds it for every user without the attribute. Such a class must
 * leave the field undefined: a default of `[]` or `null` is refused, like any other malformed claim.
 */
const sitesOf = (claims: Record<string, unknown>): string[] => {
  const value = claims.sites;
  if (value === undefined) return [];
  if (
    !Array.isArray(value) ||
    value.length === 0 ||
    // `Array.from`, not `value.every`: `every` skips the holes of a sparse list built in code.
    !Array.from(value as unknown[]).every(
      (site) =>
        typeof site === "string" && site !== "" && site === site.trim() && !INVISIBLE.test(site),
    )
  )
    throw new MalformedClaimError("sites");
  return [...new Set(value as string[])];
};

/**
 * jose's `jwtVerify` result rather than its payload: exactly `payload` and `protectedHeader`, and
 * optionally `key`, with nothing else. A real token carries other claims (`iss`, `exp`), so one
 * that happens to hold claims of those names is still read, with or without a `sub`.
 */
const VERIFY_RESULT_KEYS = new Set(["payload", "protectedHeader", "key"]);
const isVerifyResult = (value: Record<string, unknown>): boolean =>
  isRecord(value.payload) &&
  isRecord(value.protectedHeader) &&
  Object.keys(value).every((key) => VERIFY_RESULT_KEYS.has(key));

/**
 * Maps Keycloak's claims onto `NormalizedClaims` (the `interlock` README, "Claims"): realm roles
 * stay bare and each `resource_access.<client>.roles` entry becomes `<client>:<role>`, `groups`
 * stays `groups`, `tenant_ids` becomes `tenants`, `sites` stays `sites`, and `internal_groups`
 * stays. For every claim but `sites`, a claim of the wrong shape, or an entry that is not a
 * non-empty string, is dropped rather than thrown on, which grants nothing. `sites` is checked
 * instead, because dropping it would widen access: a malformed one throws
 * `MalformedClaimError`, as does an argument that is not an object, is a list, is a promise, or
 * is a whole `jwtVerify` result. Pure.
 */
export function normalizeClaims(claims: object): NormalizedClaims {
  // A loosely typed caller can pass what is not a payload at all (a failed decode's `undefined`).
  // Refused like a malformed claim, so it is a 403 and not a `TypeError` that becomes a 500. Any
  // object other than a list is read, a class instance or a wrapped payload included, as before.
  // A thenable is refused too: it is what a forgotten `await` on an async verify passes. So is jose's
  // whole `jwtVerify` result where its `.payload` was meant. Read as payloads, either would yield a
  // caller with no claims rather than an error.
  if (!isRecord(claims) || typeof claims.then === "function" || isVerifyResult(claims))
    throw new MalformedClaimError("payload");
  return {
    roles: [...new Set([...rolesOf(claims.realm_access), ...clientRoles(claims.resource_access)])],
    groups: strings(claims.groups),
    tenants: strings(claims.tenant_ids),
    sites: sitesOf(claims),
    internal_groups: strings(claims.internal_groups),
  };
}
