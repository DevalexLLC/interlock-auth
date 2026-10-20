import type { Migration } from "kysely/migration";

import { sessionGrant } from "./0001_session_grant.js";

/** Migrations keyed by name, built for the schema they run in. */
export type AppMigrations = (schema: string) => Record<string, Migration>;

/**
 * The package's own migrations (the `session_grant` table), which the host's
 * migration command runs with Kysely's `Migrator` after Better Auth's tables
 * exist. Kysely applies them in the alphabetical order of their names,
 * so name them `NNNN_<what>`, and never rename or edit one that has shipped:
 * `kysely_migration` records names, and a changed migration does not run again.
 * Kysely also refuses to run when a recorded name is missing from this map or
 * a new name sorts before a recorded one.
 *
 * Every migration pending in one run is applied in one transaction (Kysely
 * 0.29's `migrateToLatest()` wraps the whole run, not each migration), so a
 * failure rolls back that run's entries and earlier runs stay applied. The
 * connection's `search_path` is the schema, but qualify statements with
 * `db.withSchema(schema)` anyway, as Better Auth's runtime does through
 * `database.schemaName`.
 */
export const appMigrations: AppMigrations = (schema) => ({
  "0001_session_grant": sessionGrant(schema),
});
