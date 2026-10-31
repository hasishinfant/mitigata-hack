import pg from "pg";

// timestamptz -> ISO string (UTC) so output is stable regardless of the host timezone.
pg.types.setTypeParser(1184, (v) => new Date(v).toISOString());

export type Pool = pg.Pool;

export function createPool(connectionString: string | undefined, name = "DATABASE_URL_APP"): pg.Pool {
  if (!connectionString) throw new Error(`${name} is not set (see .env.example)`);
  return new pg.Pool({ connectionString, max: 5 });
}

export async function withTx<T>(pool: pg.Pool, fn: (c: pg.PoolClient) => Promise<T>): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query("begin");
    const out = await fn(client);
    await client.query("commit");
    return out;
  } catch (e) {
    await client.query("rollback").catch(() => {});
    throw e;
  } finally {
    client.release();
  }
}
