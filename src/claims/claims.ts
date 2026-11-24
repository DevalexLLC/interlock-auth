import { isPlainObject } from "../core/plain-object.js";

/** The claim shape the APIs authorize on, as their previous OpenID provider issued it. */
export interface NormalizedClaims {
  /** Realm roles bare, and each client's roles as `<client>:<role>`, without repeats. */
  roles: string[];
  /** Group names, bare rather than paths. */
  groups: string[];
  /** Tenant identifiers, from `tenant_ids`. */
  tenants: string[];
  /** Site names from the `sites` user attribute. Empty when the token has no `sites` claim. */
  sites: string[];
  /** Names of groups under the internal root. */
  internal_groups: string[];
}

/**
 * A claim the realm's contract fixes the shape of arrived in another shape. The caller refuses
 * the request: a refresh cannot repair it, so this is a 403 rather than a 401.
 */
export class MalformedClaimError extends Error {
  override readonly name = "MalformedClaimError";

  constructor(
    /** The claim's name, such as `sites`. Never its value. */
    readonly claim: string,
  ) {
    super(`The token's ${claim} claim is malformed`);
  }
}

/** The strings of a claim that should be a string array; anything else is dropped. */
const strings = (value: unknown): string[] =>
  Array.isArray(value)
    ? value.filter((item): item is string => typeof item === "string" && item !== "")
    : [];

/** `<object>.roles` of an access claim such as `realm_access`. */
const rolesOf = (access: unknown): string[] => (isPlainObject(access) ? strings(access.roles) : []);

/** `resource_access` as `<client>:<role>` entries. */
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
 * non-empty strings or it is refused.
 */
const sitesOf = (claims: Record<string, unknown>): string[] => {
  const value = claims.sites;
  if (value === undefined) return [];
  if (
    !Array.isArray(value) ||
    value.length === 0 ||
    !value.every((site) => typeof site === "string" && site !== "")
  )
    throw new MalformedClaimError("sites");
  return [...(value as string[])];
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
