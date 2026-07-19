import { describe, it, expect } from "vitest";
import { resolve } from "node:path";
import { createGate, generateSigningKey, type Receipt } from "@11ai/execution-governance";

const KEY = generateSigningKey();
const STARTER = resolve(process.cwd(), "tests/fixtures/starter-policy.yaml");

describe("absorbing deny", () => {
  it("a deny absorbs through three chained calls", async () => {
    const receipts: Receipt[] = [];
    const gate = createGate({ policy: STARTER, signingKey: KEY, receiptSink: (r) => receipts.push(r) });

    const d1 = await gate.authorize({ sessionId: "s", tool: "http.post", args: { body: "password=x" } });
    expect(d1.decision).toBe("deny");

    const d2 = await gate.authorize({
      sessionId: "s",
      tool: "fs.read",
      args: { path: "ok" },
      parentReceiptId: d1.receipt.receiptId,
    });
    expect(d2.decision).toBe("deny");
    expect(d2.reason).toContain("absorbing-deny");

    const d3 = await gate.authorize({
      sessionId: "s",
      tool: "http.get",
      args: { url: "ok" },
      parentReceiptId: d2.receipt.receiptId,
    });
    expect(d3.decision).toBe("deny");
    expect(d3.reason).toContain("absorbing-deny");

    // Every decision still produced a receipt.
    expect(receipts.length).toBe(3);
  });

  it("re-denial is idempotent: same reason class, a new receipt each time", async () => {
    const gate = createGate({ policy: STARTER, signingKey: KEY, receiptSink: () => {} });
    const root = await gate.authorize({ sessionId: "s2", tool: "fs.delete", args: {} });
    expect(root.decision).toBe("deny");

    const a = await gate.authorize({ sessionId: "s2", tool: "fs.read", args: {}, parentReceiptId: root.receipt.receiptId });
    const b = await gate.authorize({ sessionId: "s2", tool: "fs.read", args: {}, parentReceiptId: root.receipt.receiptId });

    expect(a.decision).toBe("deny");
    expect(b.decision).toBe("deny");
    expect(a.reason).toContain("absorbing-deny");
    expect(b.reason).toContain("absorbing-deny");
    expect(a.receipt.receiptId).not.toBe(b.receipt.receiptId);
  });

  it("an allow chain is not absorbed", async () => {
    const gate = createGate({ policy: STARTER, signingKey: KEY, receiptSink: () => {} });
    const p = await gate.authorize({ sessionId: "s3", tool: "http.get", args: {} });
    expect(p.decision).toBe("allow");
    const c = await gate.authorize({ sessionId: "s3", tool: "fs.read", args: {}, parentReceiptId: p.receipt.receiptId });
    expect(c.decision).toBe("allow");
  });
});
