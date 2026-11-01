// DPoP (RFC 9449) sender-constrained tokens, against a mock provider that verifies proofs like a real server.
// The point: an access token stolen from the hub (memory dump, logs, a compromised worker) is useless without the
// private key, which exists only in broker memory, is never stored, and is replaced whenever the token is.
import { readFileSync } from "node:fs";
import type { AddressInfo } from "node:net";
import { join } from "node:path";
import { calculateJwkThumbprint, decodeJwt, decodeProtectedHeader, exportJWK, generateKeyPair, SignJWT, type JWK } from "jose";
import { createHash, randomUUID } from "node:crypto";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { createLocalBroker } from "../src/broker/client.ts";
import { envSecretSource } from "../src/broker/secrets.ts";
import { BrokerError } from "../src/broker/types.ts";
import { resolveConnector } from "../src/config/load.ts";
import { validateConfigText } from "../src/config/validate.ts";
import { buildMock, MOCK_TOKENS } from "../mock/server.ts";

const secrets = envSecretSource({ IX_SECRET_MOCK_CLIENT_ID: MOCK_TOKENS.clientId, IX_SECRET_MOCK_CLIENT_SECRET: MOCK_TOKENS.clientSecret });
const fixture = readFileSync(join(import.meta.dirname, "fixtures/configs/mock-okta-oauth.yaml"), "utf8")
  .replace("client_auth: private_key_jwt", "client_auth: client_secret_post")
  .replace("    private_key_ref: mock_private_key\n", "")
  .replace("    key_id: mock-kid-1\n", "");

async function setup(mockOpts: Parameters<typeof buildMock>[0], dpop = true) {
  const mock = buildMock(mockOpts);
  await mock.app.listen({ host: "127.0.0.1", port: 0 });
  const port = String((mock.app.server.address() as AddressInfo).port);
  const yaml = dpop ? fixture.replace("    scopes: [okta.users.read]\n", "    scopes: [okta.users.read]\n    dpop: true\n") : fixture;
  const v = validateConfigText(yaml, { env: { MOCK_PORT: port } });
  if (!v.ok || !v.config) throw new Error(JSON.stringify(v.errors));
  const conn = resolveConnector(v.config, v.configHash);
  const broker = createLocalBroker({ getConnector: () => conn, secrets });
  const url = `http://localhost:${port}/api/v1/users?limit=5`;
  return { mock, broker, url, port, get: () => broker.request({ connectorId: conn.metadata.id, method: "GET", url }) };
}

describe("DPoP sender-constrained tokens", () => {
  let s: Awaited<ReturnType<typeof setup>>;
  afterAll(async () => s?.mock.app.close());

  describe("provider requires DPoP", () => {
    beforeAll(async () => {
      s = await setup({ requireDpop: true });
    });
    beforeEach(() => {
      s.broker.forget();
      s.mock.dpop.proofs.length = 0;
      s.mock.dpop.rejected.length = 0;
    });

    it("token request and API calls carry fresh proofs; the token is DPoP-bound and works", async () => {
      expect((await s.get()).status).toBe(200);
      expect((await s.get()).status).toBe(200);
      const [tokenProof, call1, call2] = s.mock.dpop.proofs;
      const t = decodeJwt(tokenProof!);
      expect(t).toMatchObject({ htm: "POST", htu: `http://localhost:${s.port}/oauth2/v1/token` });
      expect(t.ath).toBeUndefined();
      const p1 = decodeJwt(call1!);
      const p2 = decodeJwt(call2!);
      expect(p1).toMatchObject({ htm: "GET", htu: `http://localhost:${s.port}/api/v1/users` }); // no query string in htu
      expect(p1.jti).not.toBe(p2.jti); // never reused
      const token = s.mock.dpop.issued.at(-1)!;
      expect(p1.ath).toBe(createHash("sha256").update(token).digest("base64url"));
      expect(decodeProtectedHeader(call1!)).toMatchObject({ typ: "dpop+jwt", alg: "ES256", jwk: { kty: "EC", crv: "P-256" } });
      expect((decodeProtectedHeader(call1!).jwk as JWK).d).toBeUndefined(); // public key only
      expect(s.mock.dpop.rejected).toEqual([]);
    });

    it("a STOLEN token is useless: as Bearer, with the attacker's own key, or with a replayed proof", async () => {
      expect((await s.get()).status).toBe(200);
      const stolen = s.mock.dpop.issued.at(-1)!; // what an attacker would lift from memory or a log
      const captured = s.mock.dpop.proofs.at(-1)!; // and a proof they sniffed
      const api = `http://localhost:${s.port}/api/v1/users?limit=5`;
      const htu = `http://localhost:${s.port}/api/v1/users`;

      const asBearer = await fetch(api, { headers: { authorization: `Bearer ${stolen}` } });
      expect(asBearer.status).toBe(401);

      const attacker = await generateKeyPair("ES256");
      const jwk = await exportJWK(attacker.publicKey);
      const ownProof = await new SignJWT({ htm: "GET", htu, jti: randomUUID(), ath: createHash("sha256").update(stolen).digest("base64url") })
        .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk })
        .setIssuedAt()
        .sign(attacker.privateKey);
      const withOwnKey = await fetch(api, { headers: { authorization: `DPoP ${stolen}`, dpop: ownProof } });
      expect(withOwnKey.status).toBe(401);

      const replay = await fetch(api, { headers: { authorization: `DPoP ${stolen}`, dpop: captured } });
      expect(replay.status).toBe(401);

      expect(s.mock.dpop.rejected).toEqual(["bound token presented as Bearer", "proof key is not the key the token is bound to", "replayed proof (jti seen before)"]);
      expect((await s.get()).status).toBe(200); // the hub itself still works
    });

    it("the key lives only in broker memory and is replaced with the token", async () => {
      await s.get();
      const k1 = await calculateJwkThumbprint(decodeProtectedHeader(s.mock.dpop.proofs.at(-1)!).jwk as JWK);
      s.broker.forget(); // disable, panic, config change: token and key dropped together
      await s.get();
      const k2 = await calculateJwkThumbprint(decodeProtectedHeader(s.mock.dpop.proofs.at(-1)!).jwk as JWK);
      expect(k2).not.toBe(k1);
    });

    it("a worker can't inject its own DPoP header", async () => {
      await expect(
        s.broker.request({ connectorId: "mock-okta-oauth", method: "GET", url: s.url, headers: { DPoP: "eyJ..." } }),
      ).rejects.toMatchObject({ kind: "policy_denied", message: expect.stringMatching(/header dpop may not be set/) });
    });
  });

  it("server nonces (RFC 9449 §8/§9): the broker learns the nonce and retries once, at the token endpoint and the API", async () => {
    const n = await setup({ requireDpop: true, dpopNonce: "nonce-abc-123" });
    try {
      expect((await n.get()).status).toBe(200);
      expect(n.mock.dpop.rejected).toEqual(["token endpoint: nonce required"]); // token endpoint asked once; the API proof already had it
      expect(decodeJwt(n.mock.dpop.proofs.at(-1)!).nonce).toBe("nonce-abc-123");
      expect(n.mock.oauth.tokenCalls).toBe(2);
    } finally {
      await n.mock.app.close();
    }
  });

  it("downgrade: a provider that returns a plain Bearer token is refused when the connector requires DPoP", async () => {
    const d = await setup({ requireDpop: false });
    try {
      const err = await d.get().catch((e) => e);
      expect(err).toBeInstanceOf(BrokerError);
      expect(err).toMatchObject({ kind: "auth_failed", message: expect.stringMatching(/Bearer token, not a DPoP-bound one; refusing it/) });
    } finally {
      await d.mock.app.close();
    }
  });

  it("without dpop: Bearer as before (and the posture card flags it)", async () => {
    const b = await setup({}, false);
    try {
      expect((await b.get()).status).toBe(200);
      expect(b.mock.dpop.proofs).toEqual([]);
    } finally {
      await b.mock.app.close();
    }
  });
});
