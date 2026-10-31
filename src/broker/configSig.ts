// The broker signs every config version it approves. At request time it only honours versions whose
// signature verifies, so a config row written by anyone else (compromised app role, tampered backup)
// can never send a stored secret to a new host.
import { createHmac, hkdfSync, timingSafeEqual } from "node:crypto";

export function configSigKey(masterKey: Buffer): Buffer {
  return Buffer.from(hkdfSync("sha256", masterKey, Buffer.alloc(0), "ix-config-signature-v1", 32));
}

export function signConfig(key: Buffer, connectorId: string, version: number, configHash: string): string {
  return createHmac("sha256", key).update(`${connectorId}\n${version}\n${configHash}`).digest("hex");
}

export function verifyConfigSig(key: Buffer, connectorId: string, version: number, configHash: string, sig: string | null): boolean {
  if (!sig || !/^[0-9a-f]{64}$/.test(sig)) return false;
  const want = Buffer.from(signConfig(key, connectorId, version, configHash), "hex");
  return timingSafeEqual(want, Buffer.from(sig, "hex"));
}
