// `./claims` entry: claim normalization alone, for backends that verify Keycloak tokens. It imports
// nothing from Better Auth, Kysely, React, or Next.js, so a host installs it without those optional
// peers; `src/__tests__/entry-points.test.ts` and CI's package check hold it to that. The root
// entry re-exports it.

export { MalformedClaimError, normalizeClaims, type NormalizedClaims } from "./claims.js";
