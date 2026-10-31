// Broker process entry: the only process with the master key and the broker DB role.
import { loadBrokerEnv } from "../envfiles.ts";
import { log } from "../log.ts";
import { createPool } from "../store/db.ts";
import { defaultSocketPath } from "./remote.ts";
import { parseMasterKey } from "./secrets.ts";
import { createBrokerServer, listenOnSocket } from "./server.ts";

loadBrokerEnv();
const masterKey = parseMasterKey(process.env.IX_MASTER_KEY);
const pool = createPool(process.env.DATABASE_URL_BROKER, "DATABASE_URL_BROKER");
const socketPath = defaultSocketPath();
const { app } = createBrokerServer({ pool, masterKey, envSecrets: process.env.IX_ALLOW_ENV_SECRETS === "1" });
await listenOnSocket(app, socketPath);
log.info({ socket: socketPath, env_secrets: process.env.IX_ALLOW_ENV_SECRETS === "1" }, "broker listening");

for (const sig of ["SIGINT", "SIGTERM"] as const)
  process.on(sig, async () => {
    await app.close();
    await pool.end();
    process.exit(0);
  });
