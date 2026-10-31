#!/usr/bin/env node
// ix CLI. Phase 1: validate, schema. More commands land in later phases.
import { readFile } from "node:fs/promises";
import { Command } from "commander";
import { connectorJsonSchema } from "../config/schema.ts";
import { validateConfigText, type Issue } from "../config/validate.ts";

try { process.loadEnvFile(); } catch { /* no .env is fine */ }

const tty = process.stdout.isTTY;
const c = (code: number, s: string) => (tty ? `\x1b[${code}m${s}\x1b[0m` : s);
const red = (s: string) => c(31, s);
const yellow = (s: string) => c(33, s);
const green = (s: string) => c(32, s);
const dim = (s: string) => c(2, s);

function printIssue(i: Issue, lines: string[]): void {
  const tag = i.severity === "error" ? red("error  ") : yellow("warning");
  console.log(`  ${`${i.line}:${i.col}`.padEnd(7)} ${tag}  ${i.path}: ${i.message}`);
  const src = lines[i.line - 1];
  if (src !== undefined && i.path !== "(root)") console.log(dim(`          | ${src.trimEnd()}`));
}

const program = new Command().name("ix").description("IntegrateX: config-driven security integrations");

program
  .command("validate")
  .description("validate connector config file(s): line-numbered errors and policy warnings")
  .argument("<files...>")
  .option("--json", "machine-readable output")
  .action(async (files: string[], opts: { json?: boolean }) => {
    let failed = false;
    const out: Record<string, unknown> = {};
    for (const file of files) {
      let text: string;
      try {
        text = await readFile(file, "utf8");
      } catch (e) {
        console.error(red(`${file}: ${(e as Error).message}`));
        failed = true;
        continue;
      }
      const res = validateConfigText(text);
      failed ||= !res.ok;
      if (opts.json) {
        out[file] = { ok: res.ok, errors: res.errors, warnings: res.warnings, config_hash: res.configHash };
        continue;
      }
      const lines = text.split("\n");
      console.log(res.ok ? `${green("✔")} ${file}` : `${red("✖")} ${file}`);
      [...res.errors, ...res.warnings].forEach((i) => printIssue(i, lines));
      console.log(dim(`  ${res.errors.length} error(s), ${res.warnings.length} warning(s)\n`));
    }
    if (opts.json) console.log(JSON.stringify(out, null, 2));
    process.exitCode = failed ? 1 : 0;
  });

program
  .command("schema")
  .description("print the ix/v1 connector JSON Schema (for editor autocompletion)")
  .action(() => console.log(JSON.stringify(connectorJsonSchema(), null, 2)));

await program.parseAsync();
