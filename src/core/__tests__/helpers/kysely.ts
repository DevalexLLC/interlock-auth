import { Kysely, PostgresDialect } from "kysely";
import pg from "pg";

/** The schema the specs name; nothing is ever created in it. */
export const TEST_SCHEMA = "interlock";

/**
 * A Kysely over a pool pointed at port 1, where nothing listens: Postgres is refused at once,
 * without a DNS lookup. For specs that show that building the options or the instance never
 * touches the database. The caller destroys it, which ends the pool.
 */
export const unreachableKysely = () =>
  new Kysely<unknown>({
    dialect: new PostgresDialect({
      pool: new pg.Pool({
        connectionString: "postgresql://interlock:interlock@127.0.0.1:1/interlock",
      }),
    }),
  });
