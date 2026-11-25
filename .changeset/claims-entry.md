---
"@devalexllc/interlock-auth": minor
---

Add the `./claims` entry with the real `normalizeClaims()`, which the root entry re-exports. Every list comes back without repeats, `sites` comes from the token, and a malformed `sites` claim throws `MalformedClaimError`.

Breaking changes:

- `roles` keeps realm roles bare but now returns client roles as `<client>:<role>` instead of bare, and drops any role whose name holds `:`. A caller matching a bare client role must match the prefixed form.
- `better-auth` and `kysely` are now optional peers, so npm no longer installs them for you. A host of the root entry must declare both itself, and a host of `./react` must declare `better-auth`, at the versions in `peerDependencies`. A backend that uses only `./claims` needs neither.
- `normalizeClaims()` now throws `MalformedClaimError` for a present `sites` claim that is not a non-empty array of non-empty strings. A value with leading or trailing whitespace is refused too. A caller catches it, recognizing it with `isMalformedClaimError()`, and refuses the request with 403; left uncaught it becomes a 500.
