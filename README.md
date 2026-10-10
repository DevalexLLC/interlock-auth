# @devalexllc/interlock-auth

The shared authentication package for Interlock and the applications that sign in through it:
the Better Auth wiring and claim normalization Interlock runs on, and the session clients its
Next.js and React applications use. One package, one session model, released on one cadence.

This release is a scaffold. The three entry points exist, resolve, and export nothing; the work
items that fill them are listed below. Do not depend on it yet.

| Entry point | Contents                                                                                       | Filled by |
| ----------- | ---------------------------------------------------------------------------------------------- | --------- |
| `.`         | Better Auth options for the Keycloak provider and claim normalization                          | 3.5       |
| `./next`    | The Next.js session behavior: session reads, the session route handler, provider and monitor   | 8.1       |
| `./react`   | A session provider over `better-auth/react` and a fetch wrapper that applies the auth contract | 3.6       |

The root entry stays free of React and Next.js, so a server or a test process can import it
without either. Peer dependencies (`better-auth`, `react`, `next`) arrive with the entry points
that need them.

## Development

```bash
npm test          # vitest
npm run fmt       # oxfmt (oxfmt --check in CI)
npm run lint      # oxlint --type-aware --type-check; this is the type check too
npm run build     # tsgo -> dist
npx changeset     # describe a change; CI opens the version PR
```

`lefthook` formats staged files on commit and runs the linter on push; `npm ci`
installs the hooks through the `prepare` script.

CI packs the package, installs the tarball into a throwaway project, and imports every entry
point by name, so a broken `exports` map fails the pull request rather than a consumer.

Releases go out through the changesets action: merging the generated "chore: version
package" PR is what publishes. Nothing reaches npm without that merge.

Publishing uses [npm trusted publishing][tp] — the workflow exchanges a GitHub
OIDC token for short-lived credentials, so there is no npm token stored in the
repository. Every release carries a [provenance attestation][prov] linking the
tarball to the commit and workflow that built it:

```bash
npm audit signatures            # verify provenance of an installed copy
```

The one exception is `0.0.0`, published by hand to create the package on npm, because a
trusted publisher can only be configured on a package that already exists. It has no
provenance and the same empty contents as `0.0.1`.

Trusted publishing is configured against this repository and `release.yml` on
npmjs.com. It depends on Node >= 24.20 (npm >= 11.19) on the runner, and on the
npm-side organization name matching GitHub's canonical casing exactly.

[tp]: https://docs.npmjs.com/trusted-publishers
[prov]: https://docs.npmjs.com/generating-provenance-statements

## License

Apache License 2.0 — see [LICENSE](LICENSE). Copyright 2026 Devalex LLC.
