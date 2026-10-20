import { sql, type Kysely } from "kysely";

/** The trigger, and the function it runs, that keep tokens off `account`. */
export const ACCOUNT_TOKENS_TRIGGER = "account_tokens_null";

/** What a write that would put a token on `account` fails with. */
export const ACCOUNT_TOKENS_MESSAGE =
  "account rows hold no tokens; Interlock keeps them on session_grant";

export interface AccountTokensOptions {
  /** Tests only: runs inside the transaction once the lock is held. */
  afterLock?: () => Promise<void>;
}

/**
 * The account token invariant: no `account` row holds a provider token,
 * because each session's tokens live on its `session_grant` row. The grant
 * hooks keep the runtime from writing one; this restores and guards the
 * invariant in the database, and the migration command runs it on every
 * run, not as a Kysely migration. Migration history records a step once,
 * and the invariant has to come back after any period in which an older
 * image wrote tokens (a rollback to v5.4.x, then a redeploy).
 *
 * In one transaction:
 *
 * 1. Locks `account` against concurrent writes, so a legacy replica still
 *    serving a callback cannot commit between the scrub and the guard; once
 *    the lock is released, such a write meets the trigger.
 * 2. Nulls the five token and expiry columns on every row that has any of
 *    them, and returns how many rows that was.
 * 3. Creates or replaces the trigger function, and creates the trigger if the
 *    table has none of that name.
 *
 * A trigger and not a CHECK constraint: a CHECK violation's `detail` is the
 * failing row, tokens included, and a legacy replica that hits it logs the
 * error object through a logger this release cannot change. The trigger's
 * exception carries its message only, with no row and no `detail`. The
 * schema's owner can create both; `plpgsql` is usable by `PUBLIC`.
 */
export async function ensureAccountTokensInvariant(
  db: Kysely<unknown>,
  schema: string,
  { afterLock }: AccountTokensOptions = {},
): Promise<number> {
  const account = sql.table(`${schema}.account`);
  const fn = sql.id(schema, ACCOUNT_TOKENS_TRIGGER);
  const trigger = sql.id(ACCOUNT_TOKENS_TRIGGER);

  return db.transaction().execute(async (trx) => {
    await sql`LOCK TABLE ${account} IN SHARE ROW EXCLUSIVE MODE`.execute(trx);
    await afterLock?.();

    const { numAffectedRows } = await sql`
      UPDATE ${account}
      SET "accessToken" = NULL, "refreshToken" = NULL, "idToken" = NULL,
        "accessTokenExpiresAt" = NULL, "refreshTokenExpiresAt" = NULL
      WHERE "accessToken" IS NOT NULL OR "refreshToken" IS NOT NULL OR "idToken" IS NOT NULL
        OR "accessTokenExpiresAt" IS NOT NULL OR "refreshTokenExpiresAt" IS NOT NULL
    `.execute(trx);

    await sql`
      CREATE OR REPLACE FUNCTION ${fn}() RETURNS trigger LANGUAGE plpgsql AS $$
      BEGIN
        IF NEW."accessToken" IS NOT NULL OR NEW."refreshToken" IS NOT NULL
          OR NEW."idToken" IS NOT NULL THEN
          RAISE EXCEPTION '${sql.raw(ACCOUNT_TOKENS_MESSAGE)}' USING ERRCODE = 'check_violation';
        END IF;
        RETURN NEW;
      END
      $$
    `.execute(trx);

    const { rows } = await sql`
      SELECT 1
      FROM pg_catalog.pg_trigger AS t
      JOIN pg_catalog.pg_class AS c ON c.oid = t.tgrelid
      JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
      WHERE n.nspname = ${schema} AND c.relname = 'account' AND t.tgname = ${ACCOUNT_TOKENS_TRIGGER}
    `.execute(trx);
    if (rows.length === 0) {
      await sql`
        CREATE TRIGGER ${trigger} BEFORE INSERT OR UPDATE ON ${account}
        FOR EACH ROW EXECUTE FUNCTION ${fn}()
      `.execute(trx);
    }

    return Number(numAffectedRows ?? 0);
  });
}

/**
 * Why a schema fails the invariant: a missing or disabled trigger, and the
 * number of rows holding a token. Empty when it holds. Counts, never values.
 */
export async function accountTokensProblems(db: Kysely<unknown>, schema: string) {
  const problems: string[] = [];
  const { rows: triggers } = await sql<{ enabled: string }>`
    SELECT t.tgenabled AS enabled
    FROM pg_catalog.pg_trigger AS t
    JOIN pg_catalog.pg_class AS c ON c.oid = t.tgrelid
    JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
    WHERE n.nspname = ${schema} AND c.relname = 'account' AND t.tgname = ${ACCOUNT_TOKENS_TRIGGER}
  `.execute(db);
  const [trigger] = triggers;
  if (trigger === undefined) {
    problems.push(`trigger ${ACCOUNT_TOKENS_TRIGGER} is missing`);
  } else if (!["O", "A"].includes(trigger.enabled)) {
    problems.push(`trigger ${ACCOUNT_TOKENS_TRIGGER} is disabled`);
  }

  const { rows } = await sql<{ count: string }>`
    SELECT count(*) AS count FROM ${sql.table(`${schema}.account`)}
    WHERE "accessToken" IS NOT NULL OR "refreshToken" IS NOT NULL OR "idToken" IS NOT NULL
  `.execute(db);
  const count = rows[0]?.count;
  if (count === undefined) {
    problems.push("the account rows could not be counted");
  } else if (Number(count) > 0) {
    problems.push(`${count} account row(s) hold tokens`);
  }
  return problems;
}
