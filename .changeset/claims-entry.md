---
"@devalexllc/interlock-auth": minor
---

Add the `./claims` entry with the real `normalizeClaims()`: realm roles stay bare, client roles become `<client>:<role>`, `sites` comes from the token, and a malformed `sites` claim throws `MalformedClaimError`. The root entry re-exports it. `better-auth` and `kysely` become optional peers, so a backend can install the package for `./claims` alone.
