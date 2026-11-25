import { isPlainObject } from "../core/plain-object.js";

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
  /** Group names, bare rather than paths, without repeats. */
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
  // On the prototype, not an instance field: a field is set after `super()` returns, by when the
  // stack trace has already been written with the inherited name `Error`.
  static {
    this.prototype.name = "MalformedClaimError";
  }

  constructor(
    /** The claim's name, such as `sites`. Never its value. */
    readonly claim: string,
  ) {
    super(`The token's ${claim} claim is malformed`);
  }
}

/**
 * Whether `error` is a `MalformedClaimError`, from this copy of the package or another, or from
 * another realm. Checked by shape rather than by prototype, as `isPlainObject` is: `instanceof`
 * compares against one copy's class and one realm's `Error`.
 */
export const isMalformedClaimError = (error: unknown): error is MalformedClaimError => {
  if (typeof error !== "object" || error === null) return false;
  const { name, claim, message } = error as { name?: unknown; claim?: unknown; message?: unknown };
  return name === "MalformedClaimError" && typeof claim === "string" && typeof message === "string";
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
  isPlainObject(access) ? strings(access.roles).filter((role) => !role.includes(":")) : [];

/** `resource_access` as `<client>:<role>` entries. A client ID may hold `:` (SAML clients). */
const clientRoles = (resourceAccess: unknown): string[] =>
  isPlainObject(resourceAccess)
    ? Object.entries(resourceAccess).flatMap(([client, access]) =>
        rolesOf(access).map((role) => `${client}:${role}`),
      )
    : [];

/**
 * `sites` is reductive: an absent claim means every site in the user's tenants, so a present
 * claim that is not what the realm issues must not read as absent. The mapper omits the claim
 * for a user with no value and never emits `[]`, so a present claim is a non-empty array of
 * non-empty strings or it is refused. A value is an exact `Site.name`, so one with leading or
 * trailing whitespace, which can match no site, is refused too, rather than leaving the user an
 * empty result with nothing to diagnose. Repeats are dropped, as they are for every list.
 */
const sitesOf = (claims: Record<string, unknown>): string[] => {
  const value = claims.sites;
  if (value === undefined) return [];
  if (
    !Array.isArray(value) ||
    value.length === 0 ||
    !value.every((site) => typeof site === "string" && site !== "" && site === site.trim())
  )
    throw new MalformedClaimError("sites");
  return [...new Set(value as string[])];
};

/**
 * Maps Keycloak's claims onto `NormalizedClaims` (the `interlock` README, "Claims"): realm roles
 * stay bare and each `resource_access.<client>.roles` entry becomes `<client>:<role>`, `groups`
 * stays `groups`, `tenant_ids` becomes `tenants`, `sites` stays `sites`, and `internal_groups`
 * stays. For every claim but `sites`, a claim of the wrong shape, or an entry that is not a
 * non-empty string, is dropped rather than thrown on, which grants nothing. `sites` is checked
 * instead, because dropping it would widen access: a malformed one throws
 * `MalformedClaimError`. Pure.
 */
export function normalizeClaims(claims: Record<string, unknown>): NormalizedClaims {
  return {
    roles: [...new Set([...rolesOf(claims.realm_access), ...clientRoles(claims.resource_access)])],
    groups: strings(claims.groups),
    tenants: strings(claims.tenant_ids),
    sites: sitesOf(claims),
    internal_groups: strings(claims.internal_groups),
  };
}
