// pnpm dev: run broker, api, scheduler and worker as separate processes in one terminal.
// pnpm dev --mock also starts the mock provider server on :4010 and lets the broker read the mock's
// fake IX_SECRET_* values from its environment.
// Only the broker receives broker secrets; the other processes get an environment with them stripped.
import { spawn, type ChildProcess } from "node:child_process";
import { randomBytes } from "node:crypto";
import { existsSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { withoutBrokerSecrets } from "./envfiles.ts";
import { defaultSocketPath } from "./broker/remote.ts";

const root = join(import.meta.dirname, "..");
const tsx = join(root, "node_modules/.bin/tsx");
const mock = process.argv.includes("--mock");
const children: ChildProcess[] = [];

function start(name: string, file: string, color: string, env: NodeJS.ProcessEnv): void {
  const child = spawn(tsx, [file], { cwd: root, env, stdio: ["ignore", "pipe", "pipe"] });
  const tag = `\x1b[${color}m${name.padEnd(9)}\x1b[0m│ `;
  const pipe = (stream: NodeJS.ReadableStream) => {
    let buf = "";
    stream.on("data", (d: Buffer) => {
      buf += d.toString();
      const lines = buf.split("\n");
      buf = lines.pop() ?? "";
      for (const l of lines) process.stdout.write(tag + l + "\n");
    });
  };
  pipe(child.stdout!);
  pipe(child.stderr!);
  child.on("exit", (code) => process.stdout.write(`${tag}exited (${code})\n`));
  children.push(child);
}

// The broker admin token: created once, mode 0600. The broker, API and CLI load it; workers and the scheduler never do.
const adminFile = join(root, ".env.admin");
if (!existsSync(adminFile)) {
  writeFileSync(adminFile, `# Unlocks the broker admin socket. Loaded by the broker, API and CLI only.\nIX_BROKER_ADMIN_TOKEN=${randomBytes(24).toString("hex")}\n`, { mode: 0o600 });
  process.stdout.write("created .env.admin (broker admin token)\n");
}

const brokerEnv = { ...process.env, ...(mock ? { IX_ALLOW_ENV_SECRETS: "1" } : {}) };
const appEnv = withoutBrokerSecrets(process.env); // also strips IX_BROKER_ADMIN_TOKEN

start("broker", "src/broker/index.ts", "31", brokerEnv);
if (mock) start("mock", "mock/server.ts", "90", appEnv);

// Wait for the broker socket before starting its clients.
const socket = defaultSocketPath(); // request socket; the admin socket is created right after it
const deadline = Date.now() + 15_000;
while (!existsSync(socket) && Date.now() < deadline) await new Promise((r) => setTimeout(r, 200));
start("api", "src/api/index.ts", "36", appEnv);
start("scheduler", "src/scheduler/index.ts", "35", appEnv);
start("worker", "src/worker/index.ts", "33", appEnv);

const stop = () => {
  for (const c of children) c.kill("SIGTERM");
  setTimeout(() => process.exit(0), 3000).unref();
};
process.on("SIGINT", stop);
process.on("SIGTERM", stop);
