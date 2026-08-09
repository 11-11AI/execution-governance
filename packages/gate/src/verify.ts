import { readFileSync } from "node:fs";
import type { Receipt, VerifyReport, ReceiptBreak } from "./types.js";
import { jcs } from "./jcs.js";
import { fingerprint, fromB64u, sha3Bytes, sha3Hex, verify as edVerify } from "./crypto.js";

/**
 * A set of public keys to verify a receipt file against, for files that span a
 * key rotation. Either an array, or a kid-keyed map if you already know the
 * fingerprints.
 */
export type ReceiptKeySet = Map<string, Uint8Array>;

/** Normalise a key, an array of keys, or a kid-keyed map into a kid -> key map. */
function toKeySet(input: Uint8Array | Uint8Array[] | ReceiptKeySet): ReceiptKeySet {
  if (input instanceof Map) return input;
  const arr = Array.isArray(input) ? input : [input];
  const m: ReceiptKeySet = new Map();
  for (const k of arr) m.set(fingerprint(k), k);
  return m;
}

// Verify a JSONL receipt file: recompute every hash, verify every signature, and
// verify the prevReceiptHash chain. Any break is reported with its line number.
//
// KEY ROTATION
// ------------
// A receipt file outlives the key that signed the first line in it. Rotate a
// signing key and the file continues under a new kid, so a verifier holding one
// key can only ever confirm part of it -- and it reports the rest as "signature
// invalid", which reads as tampering rather than as rotation. That is the worst
// possible framing of a routine operation.
//
// So this accepts either a single key or a set. Each receipt names its kid; the
// verifier picks the matching key. A receipt whose kid is in no supplied key is
// reported as an unknown kid, distinct from a bad signature, because the two
// need different responses: one is "you are missing a key", the other is "this
// file has been altered".
//
// The single-key signature still works unchanged. Passing one key is exactly
// equivalent to passing a set of one.
export function verifyReceiptFile(
  path: string,
  publicKey: Uint8Array | Uint8Array[] | ReceiptKeySet,
): VerifyReport {
  let content: string;
  try {
    content = readFileSync(path, "utf8");
  } catch (e) {
    return {
      ok: false,
      total: 0,
      allows: 0,
      denies: 0,
      breaks: [{ line: 0, issue: `cannot read receipt file: ${(e as Error).message}` }],
    };
  }

  const lines = content
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l.length > 0);

  // kid -> key. Built once; every line is a lookup rather than a scan.
  const keys = toKeySet(publicKey);
  const singleKeyKid = keys.size === 1 ? [...keys.keys()][0] : null;
  const breaks: ReceiptBreak[] = [];
  let allows = 0;
  let denies = 0;
  let prevHash = "genesis";

  lines.forEach((line, idx) => {
    const ln = idx + 1;
    let r: Receipt;
    try {
      r = JSON.parse(line) as Receipt;
    } catch {
      breaks.push({ line: ln, issue: "invalid JSON" });
      return;
    }

    if (r.prevReceiptHash !== prevHash) {
      breaks.push({
        line: ln,
        issue: "chain break: prevReceiptHash does not match the previous receipt",
      });
    }
    const key = keys.get(r.kid);
    if (!key) {
      // Deliberately NOT reported as an invalid signature. An unknown kid means
      // the reader is missing a key; an invalid signature means the bytes do
      // not match one they have. Collapsing them would turn "fetch the other
      // public key" into "your evidence has been tampered with".
      breaks.push({
        line: ln,
        issue:
          keys.size === 1
            ? `kid ${r.kid} does not match the provided public key (${singleKeyKid})`
            : `no supplied key matches kid ${r.kid}`,
      });
    } else {
      const { sig, ...unsigned } = r as Receipt & { sig: string };
      let sigOk = false;
      try {
        sigOk = edVerify(key, sha3Bytes(jcs(unsigned)), fromB64u(sig));
      } catch {
        sigOk = false;
      }
      if (!sigOk) breaks.push({ line: ln, issue: "signature invalid" });
    }

    if (r.decision === "allow") allows++;
    else if (r.decision === "deny") denies++;
    else breaks.push({ line: ln, issue: `unknown decision value: ${String(r.decision)}` });

    prevHash = sha3Hex(jcs(r));
  });

  return { ok: breaks.length === 0, total: lines.length, allows, denies, breaks };
}
