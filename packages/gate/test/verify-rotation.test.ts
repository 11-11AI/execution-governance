// A receipt file outlives the key that signed its first line.
//
// These build a real chain across a real key rotation: lines 1-2 signed by key
// A, lines 3-4 by key B, with prevReceiptHash chained correctly all the way
// through. Before this change such a file could not be verified in one pass,
// and the half signed by the other key was reported as "signature invalid" --
// which reads as tampering rather than as a routine rotation.
//
// The chain is built with buildReceipt/receiptHash rather than by driving a
// Gate, deliberately: the thing under test is the verifier, and driving two
// gates would drag in their chain-continuation semantics, which are a separate
// concern with their own gap (see the PR).
import { describe, expect, it } from "vitest";
import { mkdtempSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildReceipt, receiptHash } from "../src/receipt.js";
import { verifyReceiptFile } from "../src/verify.js";
import { generateSigningKey, publicKeyBytes, fingerprint } from "../src/crypto.js";
import type { Receipt } from "../src/types.js";

/** Build a correctly chained file, switching signing key partway through. */
function chainedFile(spec: Array<{ seed: Uint8Array; n: number }>): string {
  const dir = mkdtempSync(join(tmpdir(), "eg-rot-"));
  const file = join(dir, "eg-receipts.jsonl");
  const out: Receipt[] = [];
  let prev = "genesis";
  let i = 0;
  for (const { seed, n } of spec) {
    const kid = fingerprint(publicKeyBytes(seed));
    for (let k = 0; k < n; k++, i++) {
      const r = buildReceipt(
        {
          sessionId: "rot",
          tool: "fs.read",
          argsHash: "a".repeat(8),
          decision: "allow",
          reason: `line ${i}`,
          policyVersion: "test-1",
        },
        prev,
        kid,
        seed,
      );
      out.push(r);
      prev = receiptHash(r);
    }
  }
  writeFileSync(file, out.map((r) => JSON.stringify(r)).join("\n") + "\n");
  return file;
}

describe("verifyReceiptFile across a key rotation", () => {
  const A = generateSigningKey();
  const B = generateSigningKey();

  it("verifies a file spanning two keys when given both", () => {
    const f = chainedFile([
      { seed: A, n: 2 },
      { seed: B, n: 2 },
    ]);
    const r = verifyReceiptFile(f, [publicKeyBytes(A), publicKeyBytes(B)]);
    expect(r.breaks).toEqual([]);
    expect(r.ok).toBe(true);
    expect(r.total).toBe(4);
  });

  it("reports an UNKNOWN KID, not a bad signature, when a key is missing", () => {
    const f = chainedFile([
      { seed: A, n: 2 },
      { seed: B, n: 2 },
    ]);
    // Only the OLD key. The new lines are unverifiable, but they are not forged,
    // and the report must not say they were.
    const r = verifyReceiptFile(f, publicKeyBytes(A));
    expect(r.ok).toBe(false);
    const issues = r.breaks.map((x) => x.issue).join(" | ");
    expect(issues).toContain("does not match the provided public key");
    expect(issues).not.toContain("signature invalid");
  });

  it("still detects a forged line when every key is supplied", () => {
    const f = chainedFile([{ seed: A, n: 3 }]);
    const lines = readFileSync(f, "utf8").trim().split("\n");
    const t = JSON.parse(lines[1]) as Receipt;
    t.decision = "deny";
    lines[1] = JSON.stringify(t);
    writeFileSync(f, lines.join("\n") + "\n");

    const r = verifyReceiptFile(f, publicKeyBytes(A));
    expect(r.ok).toBe(false);
    expect(r.breaks.map((x) => x.issue).join(" | ")).toContain("signature invalid");
  });

  it("accepts a kid-keyed Map for callers that already know fingerprints", () => {
    const f = chainedFile([{ seed: A, n: 2 }]);
    const pub = publicKeyBytes(A);
    expect(verifyReceiptFile(f, new Map([[fingerprint(pub), pub]])).ok).toBe(true);
  });

  it("the single-key call shape is unchanged for existing callers", () => {
    const f = chainedFile([{ seed: A, n: 3 }]);
    const r = verifyReceiptFile(f, publicKeyBytes(A));
    expect(r.ok).toBe(true);
    expect(r.total).toBe(3);
  });

  it("one key is exactly equivalent to a set of one", () => {
    const f = chainedFile([{ seed: A, n: 2 }]);
    const pub = publicKeyBytes(A);
    expect(verifyReceiptFile(f, pub)).toEqual(verifyReceiptFile(f, [pub]));
  });

  it("an extra unrelated key changes nothing", () => {
    const f = chainedFile([{ seed: A, n: 2 }]);
    const C = generateSigningKey();
    const r = verifyReceiptFile(f, [publicKeyBytes(A), publicKeyBytes(C)]);
    expect(r.ok).toBe(true);
  });
});
