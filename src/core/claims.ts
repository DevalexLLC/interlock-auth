import { isPlainObject } from "./plain-object.js";

/** The claim shape the APIs authorize on, as their previous OpenID provider issued it. */
export interface NormalizedClaims {
  /** Realm roles and every client's roles, without repeats. */
  roles: string[];
  /** Group names, bare rather than paths. */
  groups: string[];
  /** Tenant identifiers, from `tenant_ids`. */
  tenants: string[];
  /** Site identifiers. Always empty until the realm has a `sites` source (R3). */
  sites: string[];
  /** Names of groups under the internal root. */
  internal_groups: string[];
}

/** The strings of a claim that should be a string array; anything else is dropped. */
const strings = (value: unknown): string[] =>
  Array.isArray(value)
    ? value.filter((item): item is string => typeof item === "string" && item !== "")
    : [];

/** `<object>.roles` of an access claim such as `realm_access`. */
const rolesOf = (access: unknown): string[] => (isPlainObject(access) ? strings(access.roles) : []);

/**
 * Maps Keycloak's claims onto `NormalizedClaims` (the `interlock` README, "Claims"): realm roles
 * plus each `resource_access.<client>.roles` become `roles`, `groups` stays `groups`,
 * `tenant_ids` becomes `tenants`, and `internal_groups` stays. A claim of the wrong shape, or an
 * entry that is not a non-empty string, is dropped rather than thrown on. Pure.
 *
 * A stub until item 6.2, which ships the real mapping in the APIs' guards and keeps this function
 * as the same code; `sites` stays empty until the realm issues it.
 */
export function normalizeClaims(claims: Record<string, unknown>): NormalizedClaims {
  const clients = isPlainObject(claims.resource_access)
    ? Object.values(claims.resource_access)
    : [];
  return {
    roles: [...new Set([...rolesOf(claims.realm_access), ...clients.flatMap(rolesOf)])],
    groups: strings(claims.groups),
    tenants: strings(claims.tenant_ids),
    sites: [],
    internal_groups: strings(claims.internal_groups),
  };
}
