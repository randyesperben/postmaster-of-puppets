// Fixed RSA public keys for the tests, one per size, in both DER forms DKIM records carry
// (SubjectPublicKeyInfo and PKCS#1, RFC 6376 §3.6.1). Generating them in each run took seconds
// for 4096 bits and timed out under load. Made once on 2026-11-18 with node:crypto
// generateKeyPairSync("rsa", { modulusLength }) and KeyObject.export({ type, format: "der" });
// the private keys were never kept.
import { readFileSync } from "node:fs";

type Bits = 512 | 1024 | 2048 | 4096;
const KEYS = JSON.parse(readFileSync(new URL("../fixtures/rsa-public-keys.json", import.meta.url), "utf8")) as Record<
  `${Bits}`,
  { spki: string; pkcs1: string }
>;

/** The base64 public key of that size, as it goes in p=. */
export function rsaKey(bits: Bits, type: "spki" | "pkcs1" = "spki"): string {
  return KEYS[`${bits}`][type];
}
