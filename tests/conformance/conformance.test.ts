import { describe, it, expect, afterAll } from "vitest";
import { resolve } from "node:path";
import { createGate, generateSigningKey, type Receipt } from "@11ai/execution-governance";

// Named conformance tests mapping to governance properties. The table at the end
// is the public conformance claim.

const KEY = generateSigningKey();
const STARTER = resolve(process.cwd(), "tests/fixtures/starter-policy.yaml");

const results: Record<string, string> = {
  absorption: "FAIL",
  "monotone-evidence-growth": "FAIL",
  "non-commutativity": "FAIL",
};

describe("conformance", () => {
  it("absorption: a decision downstream of a deny is denied", async () => {
    const gate = createGate({ policy: STARTER, signingKey: KEY, receiptSink: () => {} });
    const root = await gate.authorize({ sessionId: "c", tool: "fs.delete", args: {} });
    expect(root.decision).toBe("deny");
    const child = await gate.authorize({
      sessionId: "c",
      tool: "http.get",
      args: {},
      parentReceiptId: root.receipt.receiptId,
    });
    expect(child.decision).toBe("deny");
    results.absorption = "PASS";
  });

  it("monotone evidence growth: exactly one receipt per decision, count strictly increases", async () => {
    const receipts: Receipt[] = [];
    const gate = createGate({ policy: STARTER, signingKey: KEY, receiptSink: (r) => receipts.push(r) });
    let prev = receipts.length;
    for (const tool of ["http.get", "fs.delete", "http.get", "payments.charge"]) {
      await gate.authorize({ sessionId: "c", tool, args: {} });
      expect(receipts.length).toBe(prev + 1);
      prev = receipts.length;
    }
    results["monotone-evidence-growth"] = "PASS";
  });

  it("non-commutativity: govern never executes the action before authorize resolves allow", async () => {
    // Deny path: the action never runs.
    const gate = createGate({ policy: STARTER, signingKey: KEY, receiptSink: () => {} });
    let ran = false;
    await expect(
      gate.govern({ sessionId: "c", tool: "fs.delete", args: {} }, async () => {
        ran = true;
      }),
    ).rejects.toThrow();
    expect(ran).toBe(false);

    // Allow path: the receipt (authorize) is recorded before the action runs.
    const order: string[] = [];
    const g2 = createGate({ policy: STARTER, signingKey: KEY, receiptSink: () => order.push("receipt") });
    await g2.govern({ sessionId: "c", tool: "http.get", args: {} }, async () => {
      order.push("action");
    });
    expect(order).toEqual(["receipt", "action"]);
    results["non-commutativity"] = "PASS";
  });
});

afterAll(() => {
  console.log("\n  Conformance properties");
  console.log("  " + "property".padEnd(28) + "status");
  for (const [property, status] of Object.entries(results)) {
    console.log("  " + property.padEnd(28) + status);
  }
  console.log("");
});
