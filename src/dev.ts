// pnpm dev: run api, scheduler and worker as separate processes in one terminal.
// pnpm dev --mock also starts the mock provider server on :4010.
import { spawn, type ChildProcess } from "node:child_process";
import { join } from "node:path";

const root = join(import.meta.dirname, "..");
const tsx = join(root, "node_modules/.bin/tsx");
const procs: [string, string, string][] = [
  ["api", "src/api/index.ts", "36"],
  ["scheduler", "src/scheduler/index.ts", "35"],
  ["worker", "src/worker/index.ts", "33"],
];
if (process.argv.includes("--mock")) procs.push(["mock", "mock/server.ts", "90"]);

const children: ChildProcess[] = [];
for (const [name, file, color] of procs) {
  const child = spawn(tsx, [file], { cwd: root, env: process.env, stdio: ["ignore", "pipe", "pipe"] });
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
const stop = () => {
  for (const c of children) c.kill("SIGTERM");
  setTimeout(() => process.exit(0), 3000).unref();
};
process.on("SIGINT", stop);
process.on("SIGTERM", stop);
