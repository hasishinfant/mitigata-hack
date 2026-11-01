// Groq call for the incident advisor (OpenAI-compatible chat completions). Runs only inside the broker process,
// which passes the API key from its encrypted store. Strict JSON-schema output; the caller still validates it.
import { request } from "undici";
import { ADVISOR_JSON_SCHEMA } from "../security/advisor.ts";
import type { ClaudeNarrative } from "./claude.ts";

export const GROQ_DEFAULT_MODEL = "openai/gpt-oss-120b";
export const GROQ_BASE_URL = "https://api.groq.com/openai/v1";

export async function groqNarrative(o: { apiKey: string; baseURL?: string; model?: string; system: string; user: string }): Promise<ClaudeNarrative> {
  const model = o.model || GROQ_DEFAULT_MODEL;
  const res = await request(`${(o.baseURL || GROQ_BASE_URL).replace(/\/$/, "")}/chat/completions`, {
    method: "POST",
    headers: { authorization: `Bearer ${o.apiKey}`, "content-type": "application/json" },
    body: JSON.stringify({
      model,
      temperature: 0.2,
      max_completion_tokens: 4000,
      response_format: { type: "json_schema", json_schema: { name: "advisor_output", strict: true, schema: ADVISOR_JSON_SCHEMA } },
      messages: [
        { role: "system", content: o.system },
        { role: "user", content: o.user },
      ],
    }),
    headersTimeout: 60_000,
    bodyTimeout: 60_000,
  });
  const text = await res.body.text();
  if (res.statusCode >= 300) {
    // Never echo request headers; the provider's error message carries no secret.
    let msg = `HTTP ${res.statusCode}`;
    try {
      msg += `: ${String((JSON.parse(text) as { error?: { message?: string } }).error?.message ?? "").slice(0, 160)}`;
    } catch {
      /* not JSON */
    }
    throw new Error(msg);
  }
  const json = JSON.parse(text) as { model?: string; choices?: { message?: { content?: string; refusal?: string | null }; finish_reason?: string }[] };
  const choice = json.choices?.[0];
  if (choice?.message?.refusal) return { output: null, model: json.model ?? model, stop_reason: "refusal", refusal: "declined" };
  let output: unknown;
  try {
    output = JSON.parse(choice?.message?.content ?? "");
  } catch {
    output = null; // validated (and dropped) by the caller
  }
  return { output, model: json.model ?? model, stop_reason: choice?.finish_reason ?? null };
}
