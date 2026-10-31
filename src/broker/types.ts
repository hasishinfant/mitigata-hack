// Contract between workers and the broker. Workers never see secrets: requests carry no
// credentials, responses carry only status, headers and body.

export type BrokerRequest = {
  connectorId: string;
  method: "GET";
  url: string; // absolute; must match the connector's policy
  headers?: Record<string, string>;
};

export type BrokerResponse = {
  status: number;
  headers: Record<string, string>; // lower-cased names, set-cookie removed
  body: string;
  durationMs: number;
};

export type BrokerErrorKind = "policy_denied" | "secret_missing" | "timeout" | "network" | "too_large" | "unknown_connector";

export class BrokerError extends Error {
  kind: BrokerErrorKind;
  constructor(kind: BrokerErrorKind, message: string) {
    super(message);
    this.kind = kind;
  }
}

export interface Broker {
  request(req: BrokerRequest): Promise<BrokerResponse>;
}

/** Where the broker gets secret values. Phase 2: env; Phase 6: encrypted store. */
export interface SecretSource {
  get(tenant: string, ref: string): Promise<string | undefined>;
}
