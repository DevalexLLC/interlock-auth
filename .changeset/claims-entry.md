---
"@devalexllc/interlock-auth": minor
---

Add the `./claims` entry with the real `normalizeClaims()`, which the root entry re-exports. `sites` comes from the token, without repeats, and a malformed `sites` claim throws `MalformedClaimError`.

Breaking changes:

- `roles` keeps realm roles bare but now returns client roles as `<client>:<role>` instead of bare, and drops any role whose name holds `:`. A caller matching a bare client role must match the prefixed form.
- `better-auth` and `kysely` are now optional peers, so npm no longer installs them for you. A host of the root entry must declare both itself, at the versions in `peerDependencies`. A backend that uses only `./claims` needs neither.
