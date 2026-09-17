// argsHash must commit to the arguments. That is the entire job of the field.
//
// THE DEFECT THIS LOCKS OUT
//
// Gate#canonicalArgs used to be:
//
//   try { return jcs(args ?? null); }
//   catch { return JSON.stringify(String(args)); }
//
// String(obj) is "[object Object]" for every object, so every argument value
// JCS refused collapsed to the same hash input and therefore the same argsHash,
// while the receipt still signed and verified perfectly. Measured, before the
// fix, all three of {n: Infinity}, {n: NaN} and {b: 1n} produced argsHash
// 623060f7f45305651c57bef3... Distinct arguments, one commitment.
//
// It was reachable by anyone who could influence a single argument, which makes
// it a soundness defect in the guarantee the receipt is sold on, not a
// formatting gap. An argument that cannot be canonicalized cannot be governed,
// so the call now fails closed and nothing is written.
import { describe, it, expect } from "vitest";
import { resolve } from "node:path";
import {
  createGate,
  generateSigningKey,
  UncanonicalizableArgsError,
  type Receipt,
} from "@11ai/execution-governance";
import { sha3Hex } from "../src/crypto.js";
import { jcs } from "../src/jcs.js";

const STARTER = resolve(process.cwd(), "tests/fixtures/starter-policy.yaml");

function makeGate() {
  const receipts: Receipt[] = [];
  const gate = createGate({
    policy: STARTER,
    signingKey: generateSigningKey(),
    receiptSink: (r) => receipts.push(r),
  });
  return { gate, receipts };
}

// Everything JCS refuses. Top-level undefined is excluded deliberately: it is
// `args ?? null`, a real canonical form, and is pinned separately below.
const UNCANONICALIZABLE: Array<[string, unknown]> = [
  ["Infinity", { n: Infinity }],
  ["-Infinity", { n: -Infinity }],
  ["NaN", { n: NaN }],
  ["bigint", { b: 1n }],
  ["function", { f: () => 1 }],
  ["symbol", { s: Symbol("x") }],
  ["nested Infinity", { a: { b: [1, Infinity] } }],
  ["Infinity in an array", { a: [NaN] }],
];

describe("arguments with no canonical form fail closed", () => {
  for (const [label, args] of UNCANONICALIZABLE) {
    it(`${label} is denied, not hashed`, async () => {
      const { gate, receipts } = makeGate();
      await expect(gate.authorize({ sessionId: "s", tool: "http.get", args })).rejects.toThrow(
        UncanonicalizableArgsError,
      );
      // Nothing is written: there is no argsHash this receipt could honestly
      // carry, so there is no receipt.
      expect(receipts, `${label} wrote a receipt`).toHaveLength(0);
    });
  }

  it("names the failure distinctly from a policy denial", async () => {
    const { gate } = makeGate();
    try {
      await gate.authorize({ sessionId: "s", tool: "http.get", args: { n: NaN } });
      throw new Error("should have thrown");
    } catch (e) {
      // An operator has to be able to tell "policy denied this" from "this
      // could not be represented". Collapsing them is the same error as
      // reporting a skipped check as a passing one.
      expect((e as Error).name).toBe("UncanonicalizableArgsError");
      expect((e as Error).message).toContain("no canonical form");
      expect((e as Error).message).not.toContain("Denied by Execution Governance policy");
    }
  });

  it("never runs the action through govern()", async () => {
    const { gate } = makeGate();
    let ran = false;
    await expect(
      gate.govern({ sessionId: "s", tool: "http.get", args: { n: Infinity } }, async () => {
        ran = true;
        return "done";
      }),
    ).rejects.toThrow(UncanonicalizableArgsError);
    expect(ran, "the action ran despite uncanonicalizable args").toBe(false);
  });

  it("does not advance the chain, so a later call still chains to genesis", async () => {
    const { gate, receipts } = makeGate();
    await expect(
      gate.authorize({ sessionId: "s", tool: "http.get", args: { b: 1n } }),
    ).rejects.toThrow();
    await gate.authorize({ sessionId: "s", tool: "http.get", args: { ok: 1 } });
    expect(receipts).toHaveLength(1);
    expect(receipts[0]!.prevReceiptHash).toBe("genesis");
  });
});

describe("argsHash commits to the arguments", () => {
  // THE PROPERTY THAT WAS VIOLATED. Pinned directly rather than inferred from
  // the absence of the old fallback.
  it("gives distinct arguments distinct hashes, with no collisions", async () => {
    const distinct: unknown[] = [
      undefined,
      null,
      {},
      [],
      "",
      0,
      false,
      { a: 1 },
      { a: 2 },
      { b: 1 },
      { a: "1" },
      { a: 1, b: 2 },
      { b: 2, a: 1 }, // same object, key order must not matter
      { n: 0 },
      { n: -0 },
      { n: 0.1 },
      { n: 1e21 },
      { n: 1e-7 },
      { s: "x" },
      { s: "X" },
      { s: "café" },
      { s: "café" },
      { nested: { deep: [1, 2, 3] } },
      { nested: { deep: [1, 2, 4] } },
    ];
    const seen = new Map<string, string>();
    for (const args of distinct) {
      const { gate, receipts } = makeGate();
      await gate.authorize({ sessionId: "s", tool: "http.get", args });
      const hash = receipts[0]!.argsHash;
      const canonical = jcs(args ?? null);
      const prior = seen.get(hash);
      if (prior !== undefined && prior !== canonical) {
        throw new Error(`collision: ${prior} and ${canonical} share argsHash ${hash}`);
      }
      seen.set(hash, canonical);
      expect(hash).toMatch(/^[0-9a-f]{128}$/);
    }
    // Derived, not hardcoded: the number of distinct hashes must equal the
    // number of distinct CANONICAL FORMS. undefined and null both canonicalize
    // to `null`, and {a:1,b:2} and {b:2,a:1} are the same value, so the input
    // list is deliberately longer than the set of forms.
    const forms = new Set(distinct.map((a) => jcs(a ?? null)));
    expect(seen.size).toBe(forms.size);
    expect(forms.size).toBeLessThan(distinct.length); // the duplicates are intentional
  });

  // The exact regression. Before the fix these were equal, both
  // 623060f7f45305651c57bef3..., because String() flattened them to
  // "[object Object]". Now neither produces a hash at all.
  it("623060f7: {n: Infinity} and {b: 1n} can never share a hash again", async () => {
    const hashes: string[] = [];
    for (const args of [{ n: Infinity }, { b: 1n }]) {
      const { gate, receipts } = makeGate();
      await expect(gate.authorize({ sessionId: "s", tool: "http.get", args })).rejects.toThrow(
        UncanonicalizableArgsError,
      );
      for (const r of receipts) hashes.push(r.argsHash);
    }
    expect(hashes, "neither may produce an argsHash at all").toEqual([]);
  });

  it("absent args hash the literal null, which is a canonical form and not a substitution", async () => {
    const { gate, receipts } = makeGate();
    await gate.authorize({ sessionId: "s", tool: "http.get" });
    expect(receipts[0]!.argsHash).toBe(sha3Hex("null"));
  });
});
