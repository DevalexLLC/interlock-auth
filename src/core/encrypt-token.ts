import { setTokenUtil } from "better-auth/oauth2";

/** The context Better Auth's token helpers take (`await auth.$context`, or a hook's `context`). */
type TokenContext = Parameters<typeof setTokenUtil>[1];

/**
 * Encrypts a token as Better Auth stores an OAuth token under `encryptOAuthTokens`. Better Auth's
 * helper is typed for an absent token as well; given a non-empty string it returns one, and
 * anything else is refused here rather than stored.
 */
export async function encryptToken(token: string, ctx: TokenContext): Promise<string> {
  const encrypted = await setTokenUtil(token, ctx);
  if (typeof encrypted !== "string" || encrypted === "") {
    throw new Error("Better Auth returned no ciphertext for a token");
  }
  return encrypted;
}
