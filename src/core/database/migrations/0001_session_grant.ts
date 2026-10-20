import { sql, type Kysely } from "kysely";
import type { Migration } from "kysely/migration";

/**
 * `session_grant`: one row per Better Auth session, holding that session's
 * Keycloak tokens, so two logins of one user never share a refresh token.
 * The session's id is the key, and deleting the session (sign-out, revoke,
 * expiry cleanup, user deletion) cascades to its grant.
 *
 * Column names are camelCase and quoted, like Better Auth's tables. The
 * access and refresh tokens are Better Auth's ciphertext as its callback
 * produced it, and the ID token is encrypted the same way, under the
 * versioned `BETTER_AUTH_SECRETS`. `refreshTokenExpiresAt` is the realm's
 * refresh deadline from Keycloak's `refresh_expires_in` (null only on grants
 * written before 2.5); the lease, `dispatched` and `version` columns
 * coordinate the refresh (`grants/refresh.ts`). The table is not called
 * `grant`, a reserved word.
 */
export const sessionGrant = (schema: string): Migration => ({
  up: async (db: Kysely<unknown>) => {
    const timestamp = sql`timestamptz`;
    await db
      .withSchema(schema)
      .schema.createTable("session_grant")
      .addColumn("sessionId", "text", (col) =>
        col.primaryKey().references(`${schema}.session.id`).onDelete("cascade"),
      )
      .addColumn("keycloakSid", "text", (col) => col.notNull())
      .addColumn("keycloakSubject", "text", (col) => col.notNull())
      .addColumn("accessToken", "text", (col) => col.notNull())
      .addColumn("accessTokenExpiresAt", timestamp)
      .addColumn("refreshToken", "text", (col) => col.notNull())
      .addColumn("refreshTokenExpiresAt", timestamp)
      .addColumn("idToken", "text", (col) => col.notNull())
      .addColumn("leaseHolder", "text")
      .addColumn("leaseExpiresAt", timestamp)
      .addColumn("dispatched", "boolean", (col) => col.notNull().defaultTo(false))
      .addColumn("version", "integer", (col) => col.notNull().defaultTo(1))
      .addColumn("createdAt", timestamp, (col) => col.notNull())
      .addColumn("updatedAt", timestamp, (col) => col.notNull())
      .execute();
    // Back-channel logout (3.3) finds grants by Keycloak session and by subject.
    await db
      .withSchema(schema)
      .schema.createIndex("session_grant_keycloakSid_idx")
      .on("session_grant")
      .column("keycloakSid")
      .execute();
    await db
      .withSchema(schema)
      .schema.createIndex("session_grant_keycloakSubject_idx")
      .on("session_grant")
      .column("keycloakSubject")
      .execute();
  },
  down: async (db: Kysely<unknown>) => {
    await db.withSchema(schema).schema.dropTable("session_grant").execute();
  },
});
