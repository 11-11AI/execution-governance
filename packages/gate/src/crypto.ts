// Cryptographic primitives. Ed25519 via node:crypto so there is no third party
// signing library in the trust path. SHA3-512 via @noble/hashes. Signing keys are
// handled as raw 32 byte seeds so a caller can supply a stable key.

import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  randomFillSync,
  sign as nodeSign,
  verify as nodeVerify,
  type KeyObject,
} from "node:crypto";
import { sha3_512 } from "@noble/hashes/sha3";

const enc = new TextEncoder();

// PKCS8 DER prefix for an Ed25519 private key, followed by the 32 byte seed.
const PKCS8_ED25519_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

export function sha3Bytes(data: string | Uint8Array): Uint8Array {
  return sha3_512(typeof data === "string" ? enc.encode(data) : data);
}

export function sha3Hex(data: string | Uint8Array): string {
  return Buffer.from(sha3Bytes(data)).toString("hex");
}

export function toB64u(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

export function fromB64u(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, "base64url"));
}

/** Generate a random 32 byte Ed25519 seed. */
export function generateSigningKey(): Uint8Array {
  const { privateKey } = generateKeyPairSync("ed25519");
  const jwk = privateKey.export({ format: "jwk" }) as { d: string };
  return fromB64u(jwk.d);
}

function privateKeyObject(seed: Uint8Array): KeyObject {
  if (seed.length !== 32) throw new Error("Ed25519 signing key must be a 32 byte seed");
  return createPrivateKey({
    key: Buffer.concat([PKCS8_ED25519_PREFIX, Buffer.from(seed)]),
    format: "der",
    type: "pkcs8",
  });
}

export function publicKeyBytes(seed: Uint8Array): Uint8Array {
  const jwk = createPublicKey(privateKeyObject(seed)).export({ format: "jwk" }) as { x: string };
  return fromB64u(jwk.x);
}

export function sign(seed: Uint8Array, message: Uint8Array): Uint8Array {
  return new Uint8Array(nodeSign(null, Buffer.from(message), privateKeyObject(seed)));
}

export function verify(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean {
  try {
    const pub = createPublicKey({
      key: { kty: "OKP", crv: "Ed25519", x: toB64u(publicKey) },
      format: "jwk",
    });
    return nodeVerify(null, Buffer.from(message), pub, Buffer.from(signature));
  } catch {
    return false; // any error verifying is a failure to verify
  }
}

/** sha3-512 fingerprint of a public key, first 16 hex chars. */
export function fingerprint(publicKey: Uint8Array): string {
  return sha3Hex(publicKey).slice(0, 16);
}

/** A time ordered uuid (version 7). */
export function uuidv7(): string {
  const ts = Date.now();
  const b = new Uint8Array(16);
  b[0] = Math.floor(ts / 2 ** 40) & 0xff;
  b[1] = Math.floor(ts / 2 ** 32) & 0xff;
  b[2] = Math.floor(ts / 2 ** 24) & 0xff;
  b[3] = Math.floor(ts / 2 ** 16) & 0xff;
  b[4] = Math.floor(ts / 2 ** 8) & 0xff;
  b[5] = ts & 0xff;
  randomFillSync(b, 6, 10);
  b[6] = (b[6]! & 0x0f) | 0x70; // version 7
  b[8] = (b[8]! & 0x3f) | 0x80; // variant
  const h = Buffer.from(b).toString("hex");
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}
