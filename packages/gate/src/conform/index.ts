// Conformance checking for the execution-governance receipt format.
//
// This is NOT eg-verify. eg-verify answers "is this evidence sound", in one
// verdict, and its terseness is a feature: it is a trust tool whose exit code
// is a published contract. This answers "which rules did your implementation
// get right", per rule, with expected and actual, so a second implementer can
// debug against it. Bending either into the other makes the trust tool verbose
// and the debugging tool vague.
//
// Every rule below is checkable from docs/RECEIPTS.md alone. Nothing here
// requires access to anything private, which is the property that makes an
// outside implementation possible at all.
import { createHash, createPublicKey, verify as edVerify } from "node:crypto";
import { canonicalJson, NotCanonicalizable } from "./canonical.js";

export type Status = "pass" | "fail" | "not_applicable";

export interface Finding {
  /** Stable id, so a report can be diffed across runs and versions. */
  rule: string;
  title: string;
  status: Status;
  /** 1-based line in the receipts file, when the finding is line-scoped. */
  line?: number;
  /** What the spec requires. Present on every failure. */
  expected?: string;
  /** What the candidate produced. Present on every failure. */
  actual?: string;
  /** Where in docs/RECEIPTS.md the rule comes from. */
  reference: string;
  detail?: string;
}

export interface ConformanceReport {
  ok: boolean;
  receipts: number;
  passed: number;
  failed: number;
  findings: Finding[];
}

const HEX128 = /^[0-9a-f]{128}$/;
const HEX16 = /^[0-9a-f]{16}$/;
const GENESIS = "genesis";
const REQUIRED = [
  "receiptId", "ts", "sessionId", "tool", "argsHash",
  "decision", "reason", "policyVersion", "prevReceiptHash", "kid", "sig",
] as const;
const OPTIONAL = ["agentId", "parentReceiptId"] as const;

const sha3hex = (s: string): string => createHash("sha3-512").update(s, "utf8").digest("hex");
const sha3buf = (s: string): Buffer => createHash("sha3-512").update(s, "utf8").digest();

/** kid = first 16 hex chars of sha3-512 of the raw 32-byte public key. */
export function kidFor(publicKey: Uint8Array): string {
  return createHash("sha3-512").update(publicKey).digest("hex").slice(0, 16);
}

/**
 * uuidv7 by structure: version nibble 7 and RFC 4122 variant.
 *
 * Time-ordering is not checked across receipts. A conforming emitter may
 * legitimately produce two receipts inside one millisecond, and the spec does
 * not require monotonicity, so asserting it would fail correct implementations.
 */
function isUuidV7(s: string): boolean {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(s)) return false;
  return s[14] === "7" && "89ab".includes(s[19]!);
}

/** ISO 8601 with an explicit UTC designator, and a real instant. */
function isIsoUtc(s: string): boolean {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/.test(s)) return false;
  return Number.isFinite(Date.parse(s));
}

/**
 * The supplied key whose signature checks out for this receipt, if any.
 *
 * Used to tell "you derived kid wrong" apart from "this was signed by a key
 * you did not give me". Only the first answers a conformance question.
 */
function signerAmong(r: Record<string, unknown>, keys: Map<string, Uint8Array>): Uint8Array | undefined {
  if (typeof r.sig !== "string") return undefined;
  const { sig, ...unsigned } = r;
  let msg: Buffer;
  try { msg = sha3buf(canonicalJson(unsigned)); } catch { return undefined; }
  const sigBytes = Buffer.from(sig, "base64url");
  for (const k of keys.values()) {
    try {
      const pub = createPublicKey({
        key: { kty: "OKP", crv: "Ed25519", x: Buffer.from(k).toString("base64url") },
        format: "jwk",
      });
      if (edVerify(null, msg, pub, sigBytes)) return k;
    } catch { /* not this one */ }
  }
  return undefined;
}

export function checkConformance(lines: string[], keys: Map<string, Uint8Array>): ConformanceReport {
  const findings: Finding[] = [];
  const add = (f: Finding): void => { findings.push(f); };
  const parsed: Array<{ line: number; raw: string; r: Record<string, unknown> } | null> = [];

  // R01 -----------------------------------------------------------------
  lines.forEach((raw, i) => {
    const line = i + 1;
    try {
      const r = JSON.parse(raw) as unknown;
      if (r === null || typeof r !== "object" || Array.isArray(r)) {
        add({ rule: "R01", title: "each line is a JSON object", status: "fail", line,
          expected: "a JSON object", actual: Array.isArray(r) ? "an array" : String(r),
          reference: "RECEIPTS.md intro: one JSON object per line" });
        parsed.push(null); return;
      }
      parsed.push({ line, raw, r: r as Record<string, unknown> });
    } catch (e) {
      add({ rule: "R01", title: "each line is a JSON object", status: "fail", line,
        expected: "parseable JSON", actual: (e as Error).message,
        reference: "RECEIPTS.md intro: one JSON object per line" });
      parsed.push(null);
    }
  });
  if (!findings.some((f) => f.rule === "R01")) {
    add({ rule: "R01", title: "each line is a JSON object", status: "pass",
      reference: "RECEIPTS.md intro: one JSON object per line" });
  }

  const good = parsed.filter((p): p is NonNullable<typeof p> => p !== null);

  // R02, R03 ------------------------------------------------------------
  let missingSeen = false, typeSeen = false;
  for (const { line, r } of good) {
    for (const f of REQUIRED) {
      if (!(f in r)) {
        missingSeen = true;
        add({ rule: "R02", title: "all required fields present", status: "fail", line,
          expected: `field ${f}`, actual: "absent",
          reference: "RECEIPTS.md § Fields" });
      }
    }
    for (const f of [...REQUIRED, ...OPTIONAL]) {
      if (f in r && typeof r[f] !== "string") {
        typeSeen = true;
        add({ rule: "R03", title: "every field is a string", status: "fail", line,
          expected: `${f} is a string`, actual: `${f} is ${typeof r[f]}`,
          reference: "RECEIPTS.md § Fields" });
      }
    }
  }
  if (!missingSeen) add({ rule: "R02", title: "all required fields present", status: "pass", reference: "RECEIPTS.md § Fields" });
  if (!typeSeen) add({ rule: "R03", title: "every field is a string", status: "pass", reference: "RECEIPTS.md § Fields" });

  // R04..R08 ------------------------------------------------------------
  const scalar: Array<[string, string, (r: Record<string, unknown>) => boolean, string]> = [
    ["R04", "receiptId is a uuid v7", (r) => isUuidV7(String(r.receiptId)), "a uuid v7 (version nibble 7, RFC 4122 variant)"],
    ["R05", "ts is ISO 8601 UTC", (r) => isIsoUtc(String(r.ts)), "ISO 8601 with a Z designator"],
    ["R06", "argsHash is sha3-512 hex", (r) => HEX128.test(String(r.argsHash)), "128 lowercase hex chars"],
    ["R07", "decision is allow or deny", (r) => r.decision === "allow" || r.decision === "deny", '"allow" or "deny"'],
    ["R08", "kid is 16 hex chars", (r) => HEX16.test(String(r.kid)), "16 lowercase hex chars"],
  ];
  const field: Record<string, string> = { R04: "receiptId", R05: "ts", R06: "argsHash", R07: "decision", R08: "kid" };
  for (const [rule, title, ok, expected] of scalar) {
    let bad = false;
    for (const { line, r } of good) {
      if (!(field[rule]! in r)) continue; // R02 already reported the absence
      if (!ok(r)) {
        bad = true;
        add({ rule, title, status: "fail", line, expected,
          actual: JSON.stringify(r[field[rule]!]), reference: "RECEIPTS.md § Fields" });
      }
    }
    if (!bad) add({ rule, title, status: "pass", reference: "RECEIPTS.md § Fields" });
  }

  // R09 -----------------------------------------------------------------
  // Derivation, not just shape. A kid of the right shape that is not the
  // fingerprint of the key that signed is the interesting failure.
  let kidBad = false, kidChecked = false;
  for (const { line, r } of good) {
    const kid = String(r.kid);
    if (!HEX16.test(kid)) continue;
    const key = keys.get(kid);
    if (!key) {
      // DIFFERENT FROM eg-verify, DELIBERATELY, BUT ONLY WHEN PROVABLE.
      //
      // There, an unknown kid means the reader may be missing a key, and
      // calling it tampering would be a false accusation. Here the caller
      // SUPPLIED the keys and is asking whether their emitter is correct, so a
      // kid matching none of them can mean they derived it wrong. Deriving
      // from the base64url text of the key rather than its raw bytes is the
      // usual way, and it produces a kid of exactly the right shape, which is
      // why R08 passes while this fails.
      //
      // But an unknown kid has a second, innocent cause: the file spans a key
      // rotation and we were not given the other key. Accusing an implementer
      // of a derivation bug when they simply rotated would be exactly the
      // false accusation this tool exists to avoid. So only make the claim
      // when it can be PROVEN: the signature verifies under a key we hold, and
      // therefore the kid naming it is the part that is wrong. If nothing
      // verifies, this is an unknown key, and R11 reports it as that.
      const signer = signerAmong(r, keys);
      if (signer) {
        kidChecked = true;
        kidBad = true;
        add({ rule: "R09", title: "kid is the sha3-512 fingerprint of the public key", status: "fail", line,
          expected: kidFor(signer), actual: kid, reference: "RECEIPTS.md § Signature",
          detail: "this receipt's signature verifies under a supplied key, so the key is right and the kid is wrong. kid is the first 16 hex chars of sha3-512 over the RAW 32 key bytes, not over their base64url text" });
      }
      continue;
    }
    kidChecked = true;
    const derived = kidFor(key);
    if (derived !== kid) {
      kidBad = true;
      add({ rule: "R09", title: "kid is the sha3-512 fingerprint of the public key", status: "fail", line,
        expected: derived, actual: kid, reference: "RECEIPTS.md § Signature" });
    }
  }
  add({ rule: "R09", title: "kid is the sha3-512 fingerprint of the public key",
    status: kidChecked ? (kidBad ? "fail" : "pass") : "not_applicable",
    reference: "RECEIPTS.md § Signature",
    detail: kidChecked ? undefined : "no supplied key matched any kid in the file" });

  // R10 -----------------------------------------------------------------
  // Every value must have a canonical form. A receipt carrying a non-finite
  // number or a nested undefined cannot be signed deterministically, so this
  // is checked before the signature rather than surfacing as a bad signature.
  let canonBad = false;
  for (const { line, r } of good) {
    try { canonicalJson(r); } catch (e) {
      canonBad = true;
      add({ rule: "R10", title: "the receipt has a canonical form", status: "fail", line,
        expected: "every value canonicalizable under RFC 8785 rules",
        actual: e instanceof NotCanonicalizable ? e.message : String(e),
        reference: "RECEIPTS.md § Canonicalization" });
    }
  }
  if (!canonBad) add({ rule: "R10", title: "the receipt has a canonical form", status: "pass", reference: "RECEIPTS.md § Canonicalization" });

  // R11 -----------------------------------------------------------------
  // Two failures live here, and they must not be confused with each other.
  //
  // A receipt whose kid names no supplied key CANNOT be silently skipped. If it
  // were, a file that had receipts appended under a rotated key would report
  // R11 pass on the strength of the lines we could check, and stay quiet about
  // the ones we could not. A conformance tool that passes over evidence it
  // never examined is worse than no tool. So: no keys at all is
  // not_applicable, but a missing key for a kid we were asked to check is a
  // failure, and it names the kid.
  const RAW_SIG_HINTS: Array<[string, (r: Record<string, unknown>, raw: string) => Buffer]> = [
    ["signed the receipt INCLUDING its own sig field, rather than without it",
      (r) => sha3buf(canonicalJson(r))],
    // "receipt without sig" read as "sig present but blank". This is the most
    // common misreading of the rule, and it was the one an independently
    // written emitter actually made when tested against this tool.
    ['signed with sig present as an empty string, rather than the key absent. "Without sig" means the KEY is not there at all: a blank sig still contributes "sig":"" to the canonical bytes',
      (r) => { const { sig: _s, ...u } = r; return sha3buf(canonicalJson({ ...u, sig: "" })); }],
    ['signed with sig present as null, rather than the key absent',
      (r) => { const { sig: _s, ...u } = r; return sha3buf(canonicalJson({ ...u, sig: null })); }],
    ["signed the raw line as written, rather than its canonical form",
      (_r, raw) => sha3buf(raw)],
    ["signed the canonical bytes directly, rather than their sha3-512 digest",
      (r) => { const { sig: _s, ...u } = r; return Buffer.from(canonicalJson(u), "utf8"); }],
    ["signed JSON.stringify output in insertion order, rather than the canonical form",
      (r) => { const { sig: _s, ...u } = r; return sha3buf(JSON.stringify(u)); }],
  ];

  let sigBad = false;
  if (keys.size === 0) {
    add({ rule: "R11", title: "sig is Ed25519 over sha3-512 of the canonical receipt without sig",
      status: "not_applicable", reference: "RECEIPTS.md § Signature",
      detail: "no public keys were supplied, so no signature could be checked" });
  } else {
    for (const { line, raw, r } of good) {
      const kid = String(r.kid);
      const key = keys.get(kid);
      if (!key) {
        sigBad = true;
        add({ rule: "R11", title: "sig is Ed25519 over sha3-512 of the canonical receipt without sig",
          status: "fail", line,
          expected: `a public key whose kid is ${kid}`,
          actual: `no key was supplied for that kid (supplied: ${[...keys.keys()].join(", ") || "none"})`,
          reference: "RECEIPTS.md § Verifying across a key rotation",
          detail: "this receipt was signed by a key that was not offered for checking. If the file spans a key rotation, supply every public key with a repeated --key. Until then this line is unverified, which is not the same as valid." });
        continue;
      }
      if (typeof r.sig !== "string") continue; // R02/R03 own the absence
      const { sig, ...unsigned } = r;
      let pub;
      try {
        pub = createPublicKey({
          key: { kty: "OKP", crv: "Ed25519", x: Buffer.from(key).toString("base64url") },
          format: "jwk",
        });
      } catch {
        sigBad = true;
        add({ rule: "R11", title: "sig is Ed25519 over sha3-512 of the canonical receipt without sig",
          status: "fail", line, expected: "a 32-byte Ed25519 public key",
          actual: `${key.length} bytes, which is not a usable Ed25519 key`,
          reference: "RECEIPTS.md § Signature" });
        continue;
      }
      const sigBytes = Buffer.from(String(sig), "base64url");
      let ok = false;
      try { ok = edVerify(null, sha3buf(canonicalJson(unsigned)), pub, sigBytes); } catch { ok = false; }
      if (ok) continue;

      sigBad = true;
      // Say what they actually signed, rather than listing what they might
      // have. The probe is cheap and turns a dead end into a one-line fix.
      let detail: string | undefined;
      for (const [why, preimage] of RAW_SIG_HINTS) {
        try {
          if (edVerify(null, preimage(r, raw), pub, sigBytes)) { detail = `the signature verifies over a different preimage: ${why}`; break; }
        } catch { /* probe only */ }
      }
      add({ rule: "R11", title: "sig is Ed25519 over sha3-512 of the canonical receipt without sig",
        status: "fail", line,
        expected: "a signature verifying over sha3_512(canonicalJSON(receipt without sig))",
        actual: detail ? "verified over a different preimage, see detail" : "did not verify under any known preimage",
        reference: "RECEIPTS.md § Signature",
        detail: detail ?? "the receipt may have been edited after signing, or signed by a different key than its kid names" });
    }
    if (!sigBad) {
      add({ rule: "R11", title: "sig is Ed25519 over sha3-512 of the canonical receipt without sig",
        status: "pass", reference: "RECEIPTS.md § Signature" });
    }
  }

  // R12 -----------------------------------------------------------------
  if (good.length > 0) {
    const first = good[0]!;
    const got = String(first.r.prevReceiptHash);
    if (got !== GENESIS) {
      add({ rule: "R12", title: 'the first receipt chains to the literal string "genesis"', status: "fail",
        line: first.line, expected: `"${GENESIS}"`, actual: JSON.stringify(first.r.prevReceiptHash),
        reference: "RECEIPTS.md § Chain",
        detail: "a hash of the empty string, 128 zeros, or an empty value are the usual wrong answers here" });
    } else {
      add({ rule: "R12", title: 'the first receipt chains to the literal string "genesis"', status: "pass", reference: "RECEIPTS.md § Chain" });
    }
  }

  // R13 -----------------------------------------------------------------
  let chainBad = false;
  for (let i = 1; i < good.length; i++) {
    const prev = good[i - 1]!, cur = good[i]!;
    let expected: string;
    try { expected = sha3hex(canonicalJson(prev.r)); } catch { continue; } // R10 owns that failure
    const got = String(cur.r.prevReceiptHash);
    if (got !== expected) {
      chainBad = true;
      const { sig, ...withoutSig } = prev.r;
      let hint: string | undefined;
      try {
        if (got === sha3hex(canonicalJson(withoutSig))) {
          hint = "this is sha3-512 of the previous receipt WITHOUT its sig. The chain digest covers the full previous receipt, signature included.";
        }
      } catch { /* ignore */ }
      add({ rule: "R13", title: "prevReceiptHash is sha3-512 of the canonical previous receipt, including its sig",
        status: "fail", line: cur.line, expected, actual: got,
        reference: "RECEIPTS.md § Chain", detail: hint });
    }
  }
  if (!chainBad && good.length > 1) {
    add({ rule: "R13", title: "prevReceiptHash is sha3-512 of the canonical previous receipt, including its sig",
      status: "pass", reference: "RECEIPTS.md § Chain" });
  }

  const byRule = new Map<string, Status>();
  for (const f of findings) {
    const cur = byRule.get(f.rule);
    if (f.status === "fail" || cur === undefined) byRule.set(f.rule, f.status === "fail" ? "fail" : f.status);
  }
  const failed = [...byRule.values()].filter((s) => s === "fail").length;
  const passed = [...byRule.values()].filter((s) => s === "pass").length;
  return { ok: failed === 0, receipts: good.length, passed, failed, findings };
}
