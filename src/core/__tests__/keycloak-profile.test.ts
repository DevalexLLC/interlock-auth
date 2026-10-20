import { describe, expect, it } from "vitest";

import {
  isPlaceholderEmail,
  keycloakAccountSubject,
  mapKeycloakProfile,
} from "../keycloak-profile.js";

describe("mapKeycloakProfile", () => {
  it("should take name, email and verification from the claims", () => {
    expect(
      mapKeycloakProfile({
        sub: "f3a1",
        name: "Ann Example",
        preferred_username: "ann",
        email: "ann@example.com",
        email_verified: true,
      }),
    ).toEqual({ name: "Ann Example", email: "ann@example.com", emailVerified: true });
  });

  it.each([
    ["missing", undefined],
    ["empty", ""],
    ["blank", "  "],
    ["not a string", 42],
  ])("should fall back to preferred_username when name is %s", (_, name) => {
    expect(mapKeycloakProfile({ sub: "f3a1", name, preferred_username: "ann" }).name).toBe("ann");
  });

  it("should give a profile without email a placeholder that is never verified", () => {
    const user = mapKeycloakProfile({ sub: "f3a1", email: " ", email_verified: true });

    expect(user.email).toBe("f3a1@keycloak.invalid");
    expect(user.emailVerified).toBe(false);
    expect(isPlaceholderEmail(user.email)).toBe(true);
  });

  it("should not treat a truthy non-boolean email_verified as verified", () => {
    expect(
      mapKeycloakProfile({ sub: "f3a1", email: "ann@example.com", email_verified: "true" })
        .emailVerified,
    ).toBe(false);
  });
});

describe("keycloakAccountSubject", () => {
  it("should key the account on sub", () => {
    expect(keycloakAccountSubject({ profile: { sub: "f3a1", id: "other" } })).toBe("f3a1");
  });

  it.each([
    ["missing", undefined],
    ["empty", ""],
    ["blank", " "],
    ["null", null],
  ])("should throw rather than fall back to id when sub is %s", (_, sub) => {
    expect(() => keycloakAccountSubject({ profile: { sub, id: "other" } })).toThrow("no sub claim");
  });
});

describe("isPlaceholderEmail", () => {
  it.each([
    ["ann@example.com", false],
    ["keycloak.invalid@example.com", false],
    [null, false],
    [undefined, false],
  ])("should report %s as %s", (email, expected) => {
    expect(isPlaceholderEmail(email)).toBe(expected);
  });
});
