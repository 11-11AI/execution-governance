// Conformance rules, and the parity check that keeps the spec-derived
// canonicalizer honest.
//
// The positive cases matter less than the negative ones. A conformance checker
// that says CONFORMANT to everything is worse than none: it certifies bugs.
import { describe, it, expect } from "vitest";
import { createHash, generateKeyPairSync, sign as edSign } from "node:crypto";
import { checkConformance, kidFor } from "../src/conform/index.js";
import { canonicalJson, NotCanonicalizable } from "../src/conform/canonical.js";
import { jcs } from "../src/jcs.js";

const h = (s: string): string => createHash("sha3-512").update(s, "utf8").digest("hex");
const hb = (s: string): Buffer => createHash("sha3-512").update(s, "utf8").digest();

function chain(n: number, mutate?: (r: Record<string, unknown>, i: number) => void) {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const pub = Buffer.from((publicKey.export({ format: "jwk" }) as { x: string }).x, "base64url");
  const kid = kidFor(pub);
  const lines: string[] = [];
  let prev = "genesis";
  for (let i = 0; i < n; i++) {
    const u: Record<string, unknown> = {
      receiptId: `019f7833-fddc-7a2b-8070-fa732536e9${String(i).padStart(2, "0")}`,
      ts: "2026-09-16T00:00:00.000Z",
      sessionId: "s",
      tool: "http.get",
      argsHash: h("{}"),
      decision: i === 0 ? "deny" : "allow",
      reason: "r",
      policyVersion: "v1",
      prevReceiptHash: prev,
      kid,
    };
    const sig = edSign(null, hb(canonicalJson(u)), privateKey).toString("base64url");
    const r: Record<string, unknown> = { ...u, sig };
    mutate?.(r, i);
    lines.push(JSON.stringify(r));
    prev = h(canonicalJson(r));
  }
  return { lines, keys: new Map([[kid, new Uint8Array(pub)]]), pub };
}

const ruleOf = (r: ReturnType<typeof checkConformance>, id: string) =>
  r.findings.filter((f) => f.rule === id);
const failed = (r: ReturnType<typeof checkConformance>, id: string) =>
  ruleOf(r, id).some((f) => f.status === "fail");

describe("a conforming chain", () => {
  it("passes every rule", () => {
    const { lines, keys } = chain(3);
    const r = checkConformance(lines, keys);
    expect(r.ok).toBe(true);
    expect(r.failed).toBe(0);
    expect(r.findings.filter((f) => f.status === "fail")).toEqual([]);
  });
});

describe("each rule fails independently, and says why", () => {
  it("R01 non-JSON line", () => {
    const r = checkConformance(["not json"], new Map());
    expect(failed(r, "R01")).toBe(true);
  });

  it("R02 missing required field", () => {
    const { lines, keys } = chain(1, (rec) => {
      delete rec.reason;
    });
    const r = checkConformance(lines, keys);
    expect(failed(r, "R02")).toBe(true);
    expect(ruleOf(r, "R02").find((f) => f.status === "fail")?.expected).toContain("reason");
  });

  it("R04 receiptId that is not uuidv7", () => {
    const { lines, keys } = chain(1, (rec) => {
      rec.receiptId = "019f7833-fddc-4a2b-8070-fa732536e98b";
    });
    expect(failed(checkConformance(lines, keys), "R04")).toBe(true);
  });

  it("R05 timestamp without a UTC designator", () => {
    const { lines, keys } = chain(1, (rec) => {
      rec.ts = "2026-09-16T00:00:00+01:00";
    });
    expect(failed(checkConformance(lines, keys), "R05")).toBe(true);
  });

  it("R07 a decision that is neither allow nor deny", () => {
    const { lines, keys } = chain(1, (rec) => {
      rec.decision = "maybe";
    });
    expect(failed(checkConformance(lines, keys), "R07")).toBe(true);
  });

  // The most likely first mistake, and it produces a kid of the right SHAPE,
  // so R08 passes while R09 fails. That separation is the point.
  it("R09 kid derived from the base64url text rather than the raw key bytes", () => {
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const pub = Buffer.from((publicKey.export({ format: "jwk" }) as { x: string }).x, "base64url");
    // The mistake: hash the base64url TEXT of the key, not its raw bytes.
    const wrongKid = createHash("sha3-512")
      .update(pub.toString("base64url"))
      .digest("hex")
      .slice(0, 16);
    const u: Record<string, unknown> = {
      receiptId: "019f7833-fddc-7a2b-8070-fa732536e98b",
      ts: "2026-09-16T00:00:00.000Z",
      sessionId: "s",
      tool: "http.get",
      argsHash: h("{}"),
      decision: "allow",
      reason: "r",
      policyVersion: "v1",
      prevReceiptHash: "genesis",
      kid: wrongKid,
    };
    const sig = edSign(null, hb(canonicalJson(u)), privateKey).toString("base64url");
    const lines = [JSON.stringify({ ...u, sig })];
    const keys = new Map([[kidFor(pub), new Uint8Array(pub)]]);
    const r = checkConformance(lines, keys);
    expect(failed(r, "R08")).toBe(false);
    expect(failed(r, "R09")).toBe(true);
    expect(ruleOf(r, "R09").find((f) => f.status === "fail")?.detail).toContain("RAW 32 key bytes");
  });

  it("R11 a signature over the receipt INCLUDING sig", () => {
    const { lines, keys } = chain(2);
    const tampered = lines.map((l) => {
      const r = JSON.parse(l);
      r.tool = "http.delete";
      return JSON.stringify(r);
    });
    expect(failed(checkConformance(tampered, keys), "R11")).toBe(true);
  });

  it("R12 genesis written as 128 zeros", () => {
    const { lines, keys } = chain(1, (rec, i) => {
      if (i === 0) rec.prevReceiptHash = "0".repeat(128);
    });
    const r = checkConformance(lines, keys);
    expect(failed(r, "R12")).toBe(true);
    expect(ruleOf(r, "R12").find((f) => f.status === "fail")?.expected).toBe('"genesis"');
  });

  // The subtlest of the chain mistakes, so the tool names it rather than
  // printing two hashes and leaving the reader to guess.
  it("R13 chain digest taken over the previous receipt WITHOUT its sig", () => {
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const pub = Buffer.from((publicKey.export({ format: "jwk" }) as { x: string }).x, "base64url");
    const kid = kidFor(pub);
    const lines: string[] = [];
    let prev = "genesis";
    for (let i = 0; i < 2; i++) {
      const u: Record<string, unknown> = {
        receiptId: `019f7833-fddc-7a2b-8070-fa732536e9${i}0`,
        ts: "2026-09-16T00:00:00.000Z",
        sessionId: "s",
        tool: "http.get",
        argsHash: h("{}"),
        decision: "allow",
        reason: "r",
        policyVersion: "v1",
        prevReceiptHash: prev,
        kid,
      };
      const sig = edSign(null, hb(canonicalJson(u)), privateKey).toString("base64url");
      lines.push(JSON.stringify({ ...u, sig }));
      prev = h(canonicalJson(u)); // the mistake: without sig
    }
    const r = checkConformance(lines, new Map([[kid, new Uint8Array(pub)]]));
    expect(failed(r, "R13")).toBe(true);
    expect(ruleOf(r, "R13").find((f) => f.status === "fail")?.detail).toContain("WITHOUT its sig");
  });
});

describe("the spec-derived canonicalizer agrees with the gate's", () => {
  it("byte for byte over gate-shaped receipts", () => {
    const { lines } = chain(3);
    for (const l of lines) {
      const r = JSON.parse(l) as Record<string, unknown>;
      expect(canonicalJson(r)).toBe(jcs(r));
      const unsigned = { ...r };
      delete unsigned.sig;
      expect(canonicalJson(unsigned)).toBe(jcs(unsigned));
    }
  });

  it("and over the shapes that break canonicalizers", () => {
    const cases: unknown[] = [
      { b: 1, a: 2, C: 3, "": 4 },
      { nested: { z: [1, { y: null }], a: "x" } },
      { s: 'quote " backslash \\ newline \n tab \t' },
      { u: "café ünïcode 日本語 🔑" },
      { n: [0, -0, 1e21, 1e-7, 0.1, -2.25] },
      { t: true, f: false, nul: null },
      [1, "two", { three: 3 }],
      "bare",
      42,
    ];
    for (const c of cases) expect(canonicalJson(c)).toBe(jcs(c));
  });

  it("refuses the same uncanonicalizable values", () => {
    for (const bad of [NaN, Infinity, -Infinity]) {
      expect(() => canonicalJson(bad)).toThrow(NotCanonicalizable);
      expect(() => jcs(bad)).toThrow();
    }
  });
});

// ---------------------------------------------------------------------------
// The six negative vectors.
//
// Four are the ones already proven against the reference verifier in
// packages/gate/test/receipt-integrity.test.ts: a tampered field, a removed
// receipt, a corrupted signature, and the wrong key. A conformance checker
// that cannot reproduce the reference verifier's own negatives has no standing
// to tell anyone else they are wrong.
//
// Two are the ones that bit us in development, and they are here because both
// are silent failures: they produce output that LOOKS fine.
// ---------------------------------------------------------------------------
describe("the six negative vectors", () => {
  it("V1 a tampered field is caught, and the signature is named as the break", () => {
    const { lines, keys } = chain(3);
    const t = lines.map((l, i) => {
      if (i !== 1) return l;
      const r = JSON.parse(l);
      r.reason = "tampered";
      return JSON.stringify(r);
    });
    const r = checkConformance(t, keys);
    expect(r.ok).toBe(false);
    expect(failed(r, "R11")).toBe(true);
    expect(ruleOf(r, "R11").find((f) => f.status === "fail")?.line).toBe(2);
  });

  it("V2 a removed receipt breaks the chain at the line that followed it", () => {
    const { lines, keys } = chain(4);
    const shortened = [lines[0]!, lines[2]!, lines[3]!]; // receipt 2 deleted
    const r = checkConformance(shortened, keys);
    expect(r.ok).toBe(false);
    expect(failed(r, "R13")).toBe(true);
    // Every signature still verifies: deletion does not forge anything, it
    // orphans. The chain rule is the only thing that can see it.
    expect(failed(r, "R11")).toBe(false);
    expect(ruleOf(r, "R13").find((f) => f.status === "fail")?.line).toBe(2);
  });

  it("V3 a corrupted signature fails R11 and nothing else", () => {
    const { lines, keys } = chain(2);
    const t = lines.map((l, i) => {
      if (i !== 0) return l;
      const r = JSON.parse(l);
      const s = String(r.sig);
      r.sig = (s[0] === "A" ? "B" : "A") + s.slice(1);
      return JSON.stringify(r);
    });
    const r = checkConformance(t, keys);
    expect(failed(r, "R11")).toBe(true);
    // And R13 too, which is the documented cascade rather than a second bug:
    // the chain digest covers the previous receipt INCLUDING its sig, so
    // corrupting a signature also invalidates every link after it.
    expect(failed(r, "R13")).toBe(true);
    // The key itself is fine, so the kid rule must stay quiet.
    expect(failed(r, "R09")).toBe(false);
  });

  it("V4 the wrong key is reported as a key that does not match the kid", () => {
    const { lines } = chain(2);
    const other = generateKeyPairSync("ed25519");
    const otherPub = Buffer.from(
      (other.publicKey.export({ format: "jwk" }) as { x: string }).x,
      "base64url",
    );
    // Same kid the receipts name, but the wrong bytes behind it.
    const kid = JSON.parse(lines[0]!).kid as string;
    const r = checkConformance(lines, new Map([[kid, new Uint8Array(otherPub)]]));
    expect(r.ok).toBe(false);
    expect(failed(r, "R09")).toBe(true);
    expect(failed(r, "R11")).toBe(true);
    const f = ruleOf(r, "R09").find((x) => x.status === "fail")!;
    expect(f.expected).toBe(kidFor(otherPub));
    expect(f.actual).toBe(kid);
  });

  // TRAP 1. This bit us for real. Receipts appended under a rotated key still
  // chain perfectly and still carry well-formed signatures. If the checker
  // skips a receipt whose kid it holds no key for, it reports PASS over lines
  // it never looked at.
  it("V5 receipts appended under a rotated key are never silently skipped", () => {
    const a = chain(2);
    const kb = generateKeyPairSync("ed25519");
    const pubB = Buffer.from(
      (kb.publicKey.export({ format: "jwk" }) as { x: string }).x,
      "base64url",
    );
    const kidB = kidFor(pubB);
    const prev = h(canonicalJson(JSON.parse(a.lines[1]!)));
    const u: Record<string, unknown> = {
      receiptId: "019f7833-fddc-7a2b-8070-fa732536e9ff",
      ts: "2026-09-16T00:00:00.000Z",
      sessionId: "s",
      tool: "http.get",
      argsHash: h("{}"),
      decision: "allow",
      reason: "r",
      policyVersion: "v1",
      prevReceiptHash: prev,
      kid: kidB,
    };
    const sig = edSign(null, hb(canonicalJson(u)), kb.privateKey).toString("base64url");
    const lines = [...a.lines, JSON.stringify({ ...u, sig })];

    // Only the OLD key is offered. The appended line must not pass unnoticed.
    const partial = checkConformance(lines, a.keys);
    expect(partial.ok).toBe(false);
    const f = ruleOf(partial, "R11").find((x) => x.status === "fail")!;
    expect(f.line).toBe(3);
    expect(f.expected).toContain(kidB);
    expect(f.detail).toContain("rotation");
    // And it must NOT be misreported as a botched kid derivation.
    expect(failed(partial, "R09")).toBe(false);

    // Offered both keys, the same file is fully conformant.
    const both = new Map(a.keys);
    both.set(kidB, new Uint8Array(pubB));
    expect(checkConformance(lines, both).ok).toBe(true);
  });

  // TRAP 2. The other one that bit us. JSON.stringify(undefined) returns the
  // VALUE undefined, not a string, so `"k":" + JSON.stringify(v)` concatenates
  // the bare token `undefined` into the output. It is not JSON, it will not
  // parse, and it changes the bytes that get signed.
  it("V6 undefined never renders as a bare token in canonical JSON", () => {
    expect(canonicalJson({ a: 1, b: undefined })).toBe('{"a":1}');
    expect(canonicalJson({ a: [1, undefined, 3] })).toBe('{"a":[1,null,3]}');
    expect(() => canonicalJson(undefined)).toThrow(NotCanonicalizable);
    for (const v of [{ a: undefined }, { a: [undefined] }, { a: { b: undefined } }]) {
      expect(canonicalJson(v)).not.toContain("undefined");
      expect(() => JSON.parse(canonicalJson(v))).not.toThrow();
      expect(canonicalJson(v)).toBe(jcs(v));
    }
  });

  it("V6 a line carrying a bare undefined token is rejected at R01", () => {
    const r = checkConformance(['{"receiptId":undefined}'], new Map());
    expect(failed(r, "R01")).toBe(true);
    expect(r.ok).toBe(false);
  });
});
