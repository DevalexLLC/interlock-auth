import { describe, expect, it } from "vitest";

import { normalizeClaims } from "../claims.js";

describe("normalizeClaims", () => {
  it("should map Keycloak's claims onto the shape the APIs authorize on", () => {
    expect(
      normalizeClaims({
        sub: "f3a1",
        realm_access: { roles: ["user", "offline_access"] },
        resource_access: {
          interlock: { roles: ["viewer"] },
          api: { roles: ["admin", "user"] },
        },
        groups: ["tenant-a", "analysts"],
        tenant_ids: ["t-1", "t-2"],
        internal_groups: ["ops"],
      }),
    ).toEqual({
      roles: ["user", "offline_access", "viewer", "admin"],
      groups: ["tenant-a", "analysts"],
      tenants: ["t-1", "t-2"],
      sites: [],
      internal_groups: ["ops"],
    });
  });

  it("should give empty lists for claims that are missing", () => {
    expect(normalizeClaims({ sub: "f3a1" })).toEqual({
      roles: [],
      groups: [],
      tenants: [],
      sites: [],
      internal_groups: [],
    });
  });

  // Never thrown on: a token is the realm's to shape, and a bad claim
  // grants nothing rather than failing the request.
  it.each([
    ["a string instead of a list", { groups: "analysts", tenant_ids: "t-1" }],
    ["an object instead of a list", { groups: { 0: "analysts" }, internal_groups: {} }],
    ["null access claims", { realm_access: null, resource_access: null }],
    ["access claims without roles", { realm_access: {}, resource_access: { interlock: {} } }],
    ["roles that are not a list", { realm_access: { roles: "admin" } }],
    ["a client entry that is not an object", { resource_access: { interlock: ["admin"] } }],
  ])("should drop %s", (_case, claims) => {
    expect(normalizeClaims(claims)).toEqual({
      roles: [],
      groups: [],
      tenants: [],
      sites: [],
      internal_groups: [],
    });
  });

  it("should keep the strings of a list and drop every other entry", () => {
    expect(
      normalizeClaims({
        realm_access: { roles: ["user", 1, null, "", { name: "admin" }] },
        groups: ["analysts", 2, "", false],
      }),
    ).toMatchObject({ roles: ["user"], groups: ["analysts"] });
  });

  // The stub has no `sites` source to read (R3); 6.2 decides the claim.
  it("should leave sites empty even when the token carries the claim", () => {
    expect(normalizeClaims({ sites: ["s-1"] }).sites).toEqual([]);
  });
});
