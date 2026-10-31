// API process entry. Binds to loopback only.
import { log } from "../log.ts";
import { startBoss } from "../scheduler/queue.ts";
import { createPool } from "../store/db.ts";
import { buildApi } from "./server.ts";

try { process.loadEnvFile(); } catch { /* no .env is fine */ }

const pool = createPool(process.env.DATABASE_URL_APP);
const boss = await startBoss(process.env.DATABASE_URL_APP!);
const app = buildApi({ pool, boss, adminToken: process.env.IX_ADMIN_TOKEN || undefined });
const port = Number(process.env.IX_API_PORT ?? 7070);
await app.listen({ host: "127.0.0.1", port });
log.info({ url: `http://localhost:${port}` }, "api + dashboard listening");

for (const sig of ["SIGINT", "SIGTERM"] as const)
  process.on(sig, async () => {
    await app.close();
    await boss.stop({ graceful: true });
    await pool.end();
    process.exit(0);
  });
