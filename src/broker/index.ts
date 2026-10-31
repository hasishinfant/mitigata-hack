// Broker process entry: the only process with the master key and the broker DB role.
import { loadBrokerEnv } from "../envfiles.ts";
import { log } from "../log.ts";
import { createPool } from "../store/db.ts";
import { defaultAdminSocketPath, defaultSocketPath } from "./remote.ts";
import { parseMasterKey } from "./secrets.ts";
import { createBrokerServer, listenOnSocket } from "./server.ts";

loadBrokerEnv();
const masterKey = parseMasterKey(process.env.IX_MASTER_KEY);
const pool = createPool(process.env.DATABASE_URL_BROKER, "DATABASE_URL_BROKER");
const socketPath = defaultSocketPath();
const adminSocketPath = defaultAdminSocketPath();
const adminToken = process.env.IX_BROKER_ADMIN_TOKEN || undefined;
const { app, adminApp } = createBrokerServer({ pool, masterKey, envSecrets: process.env.IX_ALLOW_ENV_SECRETS === "1", adminToken });
await listenOnSocket(app, socketPath);
await listenOnSocket(adminApp, adminSocketPath);
if (!adminToken) log.warn("IX_BROKER_ADMIN_TOKEN not set (.env.admin): admin routes (register, secrets, panic) are disabled");
log.info({ socket: socketPath, admin_socket: adminSocketPath, env_secrets: process.env.IX_ALLOW_ENV_SECRETS === "1" }, "broker listening");

for (const sig of ["SIGINT", "SIGTERM"] as const)
  process.on(sig, async () => {
    await app.close();
    await adminApp.close();
    await pool.end();
    process.exit(0);
  });
