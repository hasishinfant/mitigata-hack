// Claude call for the incident advisor. Runs only inside the broker process (the only holder of secrets): the
// broker passes the API key from its encrypted store. Structured JSON output, refusal-aware, server-side fallback.
import Anthropic from "@anthropic-ai/sdk";
import { ADVISOR_JSON_SCHEMA } from "../security/advisor.ts";

export const ADVISOR_MODEL = "claude-opus-5-5";

export type ClaudeNarrative = { output: unknown | null; model: string; stop_reason: string | null; refusal?: string };

export async function claudeNarrative(o: { apiKey: string; baseURL?: string; system: string; user: string }): Promise<ClaudeNarrative> {
  const client = new Anthropic({ apiKey: o.apiKey, ...(o.baseURL ? { baseURL: o.baseURL } : {}), maxRetries: 2, timeout: 120_000 });
  const res = await client.beta.messages.create({
    model: ADVISOR_MODEL,
    max_tokens: 16000,
    // On a safety decline the API re-runs the request on Anthropic's recommended fallback model.
    betas: ["server-side-fallback-2026-07-01"],
    fallbacks: "default",
    output_config: { effort: "medium", format: { type: "json_schema", schema: ADVISOR_JSON_SCHEMA as unknown as Record<string, unknown> } },
    system: o.system,
    messages: [{ role: "user", content: o.user }],
  });
  if (res.stop_reason === "refusal") return { output: null, model: res.model, stop_reason: res.stop_reason, refusal: res.stop_details?.category ?? "declined" };
  const text = res.content.flatMap((b) => (b.type === "text" ? [b.text] : [])).join("");
  let output: unknown;
  try {
    output = JSON.parse(text);
  } catch {
    output = null; // validated (and dropped) by the caller
  }
  return { output, model: res.model, stop_reason: res.stop_reason };
}
