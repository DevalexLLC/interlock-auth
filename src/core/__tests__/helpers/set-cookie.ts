import { parseSetCookieHeader } from "better-auth/cookies";
import { expect } from "vitest";

import { defined } from "./config.js";

/** One `Set-Cookie` line, reduced to what the cookie specs compare. */
export interface EmittedCookie {
  name: string;
  maxAge: number | undefined;
}

/**
 * Asserts the Cookie attributes gate row on every `Set-Cookie` line of a
 * response: `Secure`, `HttpOnly`, `Path=/`, `SameSite=Lax`, and no `Domain`,
 * in any order. Returns each cookie's name and `Max-Age` so the caller can
 * check which cookies the step emitted.
 */
export function checkSetCookies(lines: readonly string[]): EmittedCookie[] {
  return lines.map((line) => {
    const parsed = [...parseSetCookieHeader(line)];
    expect(parsed).toHaveLength(1);
    const [name, attributes] = defined(parsed[0], "a parsed cookie");

    expect(attributes).toMatchObject({ secure: true, httponly: true, path: "/", samesite: "lax" });
    expect(attributes).not.toHaveProperty("domain");
    expect(line).not.toMatch(/;\s*domain\s*=/i);
    return { name, maxAge: attributes["max-age"] };
  });
}

/** The sorted names of what `checkSetCookies` returned, for an exact set comparison. */
export const namesOf = (cookies: readonly EmittedCookie[]) => cookies.map((c) => c.name).sort();
