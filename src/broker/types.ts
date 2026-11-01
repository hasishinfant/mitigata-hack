// Contract between workers and the broker. Workers never see secrets: requests carry no
// credentials, responses carry only status, headers and body.

export type BrokerRequest = {
  connectorId: string;
  method: "GET" | "POST"; // POST only to the connector's declared read-only search paths
  url: string; // absolute; must match the connector's policy
  headers?: Record<string, string>;
  body?: unknown; // JSON body for read-only POST search
};

export type BrokerResponse = {
  status: number;
  headers: Record<string, string>; // lower-cased names, set-cookie removed
  body: string;
  durationMs: number;
  retries: number; // retries performed inside the broker for this request
  rateLimitedMs: number; // time spent waiting because the provider said so
};

export type CredentialInfo = {
  grantedScopes?: string[];
  scopeSource?: "token_response" | "response_header";
  tokenExpiresAt?: string;
};

export type BrokerErrorKind =
  | "policy_denied" | "secret_missing" | "auth_failed" | "tls" | "timeout" | "network" | "too_large" | "unknown_connector" | "rate_limited";

export class BrokerError extends Error {
  kind: BrokerErrorKind;
  retries = 0;
  rateLimitedMs = 0;
  constructor(kind: BrokerErrorKind, message: string) {
    super(message);
    this.kind = kind;
  }
}

export interface Broker {
  request(req: BrokerRequest): Promise<BrokerResponse>;
  /** What the broker learned about the credential (never the credential itself). */
  credentialInfo(connectorId: string): Promise<CredentialInfo>;
  /** Anchor a stored Sync Integrity Receipt's digest in the audit ledger (broker process only). */
  anchorReceipt?(receiptId: number): Promise<{ seq: number }>;
}

/** Where the broker gets secret values. */
export interface SecretSource {
  get(tenant: string, ref: string): Promise<string | undefined>;
}
