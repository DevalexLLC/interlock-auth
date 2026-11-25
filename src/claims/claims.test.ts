import { runInNewContext } from "node:vm";

import { describe, expect, it } from "vitest";

import { isMalformedClaimError, MalformedClaimError, normalizeClaims } from "./claims.js";

const EMPTY = { roles: [], groups: [], tenants: [], sites: [], internal_groups: [] };

describe("normalizeClaims", () => {
  it("should map Keycloak's claims onto the shape the APIs authorize on", () => {
    expect(
      normalizeClaims({
        sub: "f3a1",
        realm_access: { roles: ["user", "offline_access"] },
        resource_access: {
          interlock: { roles: ["viewer"] },
          "irongate-api": { roles: ["admin", "user"] },
        },
        groups: ["tenant-a", "analysts"],
        tenant_ids: ["t-1", "t-2"],
        sites: ["site-a", "site-b"],
        internal_groups: ["ops"],
      }),
    ).toEqual({
      roles: [
        "user",
        "offline_access",
        "interlock:viewer",
        "irongate-api:admin",
        "irongate-api:user",
      ],
      groups: ["tenant-a", "analysts"],
      tenants: ["t-1", "t-2"],
      sites: ["site-a", "site-b"],
      internal_groups: ["ops"],
    });
  });

  // A backend may hand over a class instance (`Object.assign(new JwtUser(), payload)`).
  it("should read a payload that is a class instance", () => {
    class JwtUser {
      groups = ["NY"];
      sites = ["site-a"];
    }

    expect(normalizeClaims(new JwtUser() as unknown as Record<string, unknown>)).toMatchObject({
      groups: ["NY"],
      sites: ["site-a"],
    });
  });

  it("should read roles from nested access objects that are class instances", () => {
    class Access {
      constructor(readonly roles: string[]) {}
    }

    expect(
      normalizeClaims({
        realm_access: new Access(["user"]),
        resource_access: { "irongate-api": new Access(["admin"]) },
      }).roles,
    ).toEqual(["user", "irongate-api:admin"]);
  });

  it.each([
    ["undefined", undefined],
    ["null", null],
    ["a string", "token"],
    ["a list", []],
  ])("should refuse a payload that is %s", (_case, payload) => {
    expect(() => normalizeClaims(payload as unknown as Record<string, unknown>)).toThrow(
      expect.objectContaining({ name: "MalformedClaimError", claim: "payload" }),
    );
  });

  it("should give empty lists for claims that are missing", () => {
    expect(normalizeClaims({ sub: "f3a1" })).toEqual(EMPTY);
  });

  describe("roles", () => {
    // A realm role and a client role of the same name are different grants, so the prefix keeps
    // `irongate-api:admin` from reading as the realm's `admin`.
    it("should keep a realm role and a client role of the same name apart", () => {
      expect(
        normalizeClaims({
          realm_access: { roles: ["admin"] },
          resource_access: { "irongate-api": { roles: ["admin"] } },
        }).roles,
      ).toEqual(["admin", "irongate-api:admin"]);
    });

    it("should drop repeated realm and client roles", () => {
      expect(
        normalizeClaims({
          realm_access: { roles: ["user", "user"] },
          resource_access: { interlock: { roles: ["viewer", "viewer"] } },
        }).roles,
      ).toEqual(["user", "interlock:viewer"]);
    });

    it("should skip a client with no roles", () => {
      expect(
        normalizeClaims({
          resource_access: { account: {}, interlock: { roles: ["viewer"] } },
        }).roles,
      ).toEqual(["interlock:viewer"]);
    });

    // With no `:` in a role name, `<client>:<role>` splits one way at its last `:`, so no realm
    // role reads as a client role and no two client roles read alike.
    it("should drop a realm role whose name holds a colon", () => {
      expect(
        normalizeClaims({
          realm_access: { roles: ["user", "irongate-api:admin"] },
        }).roles,
      ).toEqual(["user"]);
    });

    it("should drop a client role whose name holds a colon", () => {
      expect(
        normalizeClaims({
          resource_access: { a: { roles: ["b:c", "d"] }, "a:b": { roles: ["c"] } },
        }).roles,
      ).toEqual(["a:d", "a:b:c"]);
    });

    it("should keep a client ID that holds a colon", () => {
      expect(
        normalizeClaims({
          resource_access: { "urn:example:sp": { roles: ["viewer"] } },
        }).roles,
      ).toEqual(["urn:example:sp:viewer"]);
    });
  });

  // Never thrown on: a bad claim of these grants nothing rather than failing the request.
  it.each([
    ["a string instead of a list", { groups: "analysts", tenant_ids: "t-1" }],
    ["an object instead of a list", { groups: { 0: "analysts" }, internal_groups: {} }],
    ["null access claims", { realm_access: null, resource_access: null }],
    ["access claims without roles", { realm_access: {}, resource_access: { interlock: {} } }],
    ["roles that are not a list", { realm_access: { roles: "admin" } }],
    ["a client entry that is not an object", { resource_access: { interlock: ["admin"] } }],
    ["resource_access that is a list", { resource_access: [{ roles: ["admin"] }] }],
  ])("should drop %s", (_case, claims) => {
    expect(normalizeClaims(claims)).toEqual(EMPTY);
  });

  it("should drop repeats from every list, keeping first-seen order", () => {
    expect(
      normalizeClaims({
        groups: ["NY", "NJ", "NY"],
        tenant_ids: ["ny", "ny"],
        internal_groups: ["ops", "ops"],
      }),
    ).toMatchObject({ groups: ["NY", "NJ"], tenants: ["ny"], internal_groups: ["ops"] });
  });

  it("should keep the strings of a list and drop every other entry", () => {
    expect(
      normalizeClaims({
        realm_access: { roles: ["user", 1, null, "", { name: "admin" }] },
        resource_access: { interlock: { roles: ["viewer", 2, ""] } },
        groups: ["analysts", 2, "", false],
      }),
    ).toMatchObject({ roles: ["user", "interlock:viewer"], groups: ["analysts"] });
  });

  describe("sites", () => {
    it("should be empty when the claim is absent", () => {
      expect(normalizeClaims({ groups: ["NY"] }).sites).toEqual([]);
    });

    // A payload class with a declared `sites` field holds `undefined` for a user without one.
    it("should read a key holding undefined as absent", () => {
      expect(normalizeClaims({ groups: ["NY"], sites: undefined }).sites).toEqual([]);
    });

    it.each([
      ["one value", ["site-a"]],
      ["two values", ["site-a", "site-b"]],
    ])("should keep %s", (_case, sites) => {
      expect(normalizeClaims({ sites }).sites).toEqual(sites);
    });

    // Reductive: dropping a malformed claim would read as "every site", so it is refused.
    it.each([
      ["an empty list", []],
      ["a string", "site-a"],
      ["an object", { 0: "site-a" }],
      ["null", null],
      ["a number", 1],
      ["a list with a non-string entry", ["site-a", 1]],
      ["a list with null", ["site-a", null]],
      ["a list with an empty string", ["site-a", ""]],
      // eslint-disable-next-line no-sparse-arrays
      ["a sparse list", [, "site-a"]],
      ["a list of holes", Object.assign<unknown[], { length: number }>([], { length: 2 })],
      ["a value with leading whitespace", [" site-a"]],
      ["a value with trailing whitespace", ["site-a "]],
      ["a value of whitespace only", ["  "]],
    ])("should refuse %s", (_case, sites) => {
      expect(() => normalizeClaims({ sites })).toThrow(MalformedClaimError);
    });

    it("should name the claim and not its value", () => {
      const error = (() => {
        try {
          normalizeClaims({ sites: "secret-site" });
        } catch (caught) {
          return caught;
        }
        return undefined;
      })();

      expect(error).toBeInstanceOf(MalformedClaimError);
      expect(error).toMatchObject({ name: "MalformedClaimError", claim: "sites" });
      expect((error as Error).message).not.toContain("secret-site");
    });

    it("should drop repeated sites and keep the first order", () => {
      expect(normalizeClaims({ sites: ["site-b", "site-a", "site-b"] }).sites).toEqual([
        "site-b",
        "site-a",
      ]);
    });

    it("should return a copy, not the token's list", () => {
      const sites = ["site-a"];
      expect(normalizeClaims({ sites }).sites).not.toBe(sites);
    });
  });

  describe("isMalformedClaimError", () => {
    it("should recognize the error", () => {
      expect(isMalformedClaimError(new MalformedClaimError("sites"))).toBe(true);
    });

    // Another installed copy of the package has its own class, so `instanceof` fails there.
    it("should recognize the error from another copy of the class", () => {
      class OtherCopy extends Error {
        override readonly name = "MalformedClaimError";
        readonly claim = "sites";
      }
      const error = new OtherCopy();

      expect(error instanceof MalformedClaimError).toBe(false);
      expect(isMalformedClaimError(error)).toBe(true);
    });

    // Another realm (a `vm` context, a test runner's sandbox) has its own `Error`.
    it("should recognize the error from another realm", () => {
      const foreign: unknown = runInNewContext(
        'Object.assign(new Error("x"), { name: "MalformedClaimError", claim: "sites" })',
      );

      expect(foreign instanceof Error).toBe(false);
      expect(isMalformedClaimError(foreign)).toBe(true);
    });

    it("should recognize a null-prototype copy of the fields", () => {
      const copy = Object.assign(Object.create(null) as object, {
        name: "MalformedClaimError",
        claim: "sites",
      });

      expect(isMalformedClaimError(copy)).toBe(true);
    });

    it("should keep its name in a copy of its own fields, which the guard recognizes", () => {
      const copy = Object.fromEntries(Object.entries(new MalformedClaimError("sites")));

      expect(copy).toMatchObject({ name: "MalformedClaimError", claim: "sites" });
      expect(isMalformedClaimError(copy)).toBe(true);
    });

    it("should have only `claim` and `name` as enumerable fields", () => {
      const inherited: string[] = [];
      // oxlint-disable-next-line guard-for-in
      for (const key in new MalformedClaimError("sites")) inherited.push(key);

      expect(inherited).toEqual(["claim", "name"]);
    });

    it("should name the error in its stack trace", () => {
      expect(new MalformedClaimError("sites").stack).toMatch(/^MalformedClaimError: /);
    });

    it.each([
      ["another error", new Error("sites")],
      [
        "an error of the same name without a claim",
        Object.assign(new Error("x"), { name: "MalformedClaimError" }),
      ],
      ["an object whose claim is not a string", { name: "MalformedClaimError", claim: 1 }],
      ["an object of another name", { name: "Error", claim: "sites" }],
      ["undefined", undefined],
    ])("should not recognize %s", (_case, value) => {
      expect(isMalformedClaimError(value)).toBe(false);
    });
  });
});
