// "Test connection" (B-3): authenticate, fetch the first page, map a few records. Writes nothing.
import type { ResolvedConnector } from "../config/load.ts";
import { mapRecord, type MapResult } from "../mapping/mapper.ts";
import { redactValue } from "../mapping/scanner.ts";
import { BrokerError, type Broker, type CredentialInfo } from "../broker/types.ts";
import { createPaginator } from "./paginate/index.ts";
import { buildBaseUrl, extractRecords, RunFailure } from "./runner.ts";

export type StreamTest = {
  stream: string;
  ok: boolean;
  status?: number;
  durationMs?: number;
  recordsOnPage?: number;
  hasMorePages?: boolean;
  samples: { result: MapResult; raw?: unknown }[];
  error?: string;
  warning?: string;
};
export type ConnectionTest = { connectorId: string; ok: boolean; streams: StreamTest[]; credential: CredentialInfo };

export async function testConnection(conn: ResolvedConnector, broker: Broker, opts: { samples?: number; showRaw?: boolean } = {}): Promise<ConnectionTest> {
  const n = opts.samples ?? 3;
  const streams: StreamTest[] = [];
  for (const stream of conn.streams) {
    const t: StreamTest = { stream: stream.name, ok: false, samples: [] };
    try {
      const paginator = createPaginator(stream.pagination, stream.request.paging_in ?? "query");
      const req = paginator.start({ url: buildBaseUrl(conn, stream), ...(stream.request.body ? { body: structuredClone(stream.request.body) } : {}) });
      const res = await broker.request({ connectorId: conn.metadata.id, method: stream.request.method, url: req.url.href, body: req.body, headers: stream.request.headers });
      t.status = res.status;
      t.durationMs = res.durationMs;
      if (res.status === 401 || res.status === 403) throw new RunFailure("auth_failed", `HTTP ${res.status}: credentials rejected`);
      if (res.status < 200 || res.status >= 300) throw new RunFailure("failed", `HTTP ${res.status}: ${res.body.slice(0, 200)}`);
      const body = res.body.trim() === "" ? null : (JSON.parse(res.body) as unknown);
      const raws = extractRecords(body, stream.records_path);
      t.recordsOnPage = raws.length;
      t.hasMorePages = paginator.next({ req, headers: res.headers, body, records: raws.length }) !== null;
      t.samples = raws.slice(0, n).map((raw) => ({
        result: mapRecord(raw, stream.entity, stream.mapping),
        ...(opts.showRaw ? { raw: redactValue(raw) } : {}),
      }));
      t.ok = t.samples.every((s) => s.result.ok);
      if (!t.ok) t.error = "some sample records fail mapping (they would be quarantined)";
      if (raws.length === 0) t.warning = "authenticated, but the first page is empty (check permissions/scopes: some providers return 200 [] when access is missing)";
    } catch (e) {
      t.error = e instanceof BrokerError ? `${e.kind}: ${e.message}` : (e as Error).message;
    }
    streams.push(t);
  }
  return { connectorId: conn.metadata.id, ok: streams.every((s) => s.ok), streams, credential: await broker.credentialInfo(conn.metadata.id) };
}
