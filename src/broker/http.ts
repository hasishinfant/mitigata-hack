// One outbound HTTP call. No redirects (a redirect could leave the policy's hosts), hard timeout, size cap.
import { request } from "undici";
import { BrokerError } from "./types.ts";

export type HttpResult = { status: number; headers: Record<string, string>; body: string };

export async function httpCall(
  method: string,
  url: URL,
  headers: Record<string, string>,
  opts: { timeoutMs: number; maxBytes: number; body?: string },
): Promise<HttpResult> {
  let res;
  try {
    res = await request(url, {
      method: method as "GET",
      headers,
      body: opts.body,
      headersTimeout: opts.timeoutMs,
      bodyTimeout: opts.timeoutMs,
      signal: AbortSignal.timeout(opts.timeoutMs),
    });
  } catch (e) {
    throw classify(e, opts.timeoutMs);
  }
  const chunks: Buffer[] = [];
  let size = 0;
  try {
    for await (const chunk of res.body) {
      size += chunk.length;
      if (size > opts.maxBytes) {
        res.body.destroy();
        throw new BrokerError("too_large", `response larger than ${opts.maxBytes} bytes`);
      }
      chunks.push(chunk as Buffer);
    }
  } catch (e) {
    if (e instanceof BrokerError) throw e;
    throw classify(e, opts.timeoutMs);
  }
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(res.headers)) {
    const name = k.toLowerCase();
    if (name === "set-cookie" || v === undefined) continue;
    out[name] = Array.isArray(v) ? v.join(", ") : v;
  }
  return { status: res.statusCode, headers: out, body: Buffer.concat(chunks).toString("utf8") };
}

const TLS_CODE = /^(CERT_|UNABLE_TO_|SELF_SIGNED|DEPTH_ZERO|ERR_TLS|ERR_SSL|HOSTNAME_MISMATCH|ERR_TLS_CERT)/;

function classify(e: unknown, timeoutMs: number): BrokerError {
  const err = e as { name?: string; code?: string; message?: string; cause?: { code?: string } };
  const code = err.code ?? err.cause?.code ?? "";
  // Certificate problems are permanent: never retried, and a hint for local CA setup.
  if (TLS_CODE.test(code)) return new BrokerError("tls", `TLS verification failed: ${code} (if this machine lacks a CA bundle, set NODE_EXTRA_CA_CERTS)`);
  const timeoutCodes = ["UND_ERR_HEADERS_TIMEOUT", "UND_ERR_BODY_TIMEOUT", "UND_ERR_CONNECT_TIMEOUT"];
  if (err.name === "TimeoutError" || err.name === "AbortError" || timeoutCodes.includes(err.code ?? ""))
    return new BrokerError("timeout", `timed out after ${timeoutMs} ms`);
  // Only the error code/message: never headers or URLs with query strings.
  return new BrokerError("network", `network error: ${err.code ?? err.name ?? "unknown"}`);
}
