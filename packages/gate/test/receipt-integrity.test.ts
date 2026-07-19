import { describe, it, expect } from "vitest";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import {
  createGate,
  generateSigningKey,
  verifyReceiptFile,
  fromB64u,
  type Receipt,
} from "@11ai/execution-governance";

const KEY = generateSigningKey();
const STARTER = resolve(process.cwd(), "tests/fixtures/starter-policy.yaml");

async function makeReceipts(n: number): Promise<{ lines: string[]; pub: Uint8Array }> {
  const receipts: Receipt[] = [];
  const gate = createGate({
    policy: STARTER,
    signingKey: KEY,
    receiptSink: (r) => receipts.push(r),
  });
  for (let i = 0; i < n; i++) {
    await gate.authorize({
      sessionId: "s",
      tool: i % 2 === 0 ? "fs.delete" : "http.get",
      args: { i },
    });
  }
  return { lines: receipts.map((r) => JSON.stringify(r)), pub: fromB64u(gate.publicKey()) };
}

function writeLines(lines: string[]): string {
  const p = join(mkdtempSync(join(tmpdir(), "eg-")), "receipts.jsonl");
  writeFileSync(p, lines.join("\n") + "\n");
  return p;
}

describe("receipt integrity", () => {
  it("a valid chain verifies", async () => {
    const { lines, pub } = await makeReceipts(4);
    const rep = verifyReceiptFile(writeLines(lines), pub);
    expect(rep.ok).toBe(true);
    expect(rep.total).toBe(4);
    expect(rep.breaks).toEqual([]);
  });

  it("tampering one field fails verification at that line", async () => {
    const { lines, pub } = await makeReceipts(3);
    lines[1] = lines[1]!.replace(/"reason":"[^"]*"/, '"reason":"tampered"');
    const rep = verifyReceiptFile(writeLines(lines), pub);
    expect(rep.ok).toBe(false);
    expect(rep.breaks.some((b) => b.line === 2)).toBe(true);
  });

  it("reordering lines is reported as a chain break", async () => {
    const { lines, pub } = await makeReceipts(3);
    const swapped = [lines[1]!, lines[0]!, lines[2]!];
    const rep = verifyReceiptFile(writeLines(swapped), pub);
    expect(rep.ok).toBe(false);
    expect(rep.breaks.some((b) => /chain break/.test(b.issue))).toBe(true);
  });

  it("verifying with the wrong public key fails", async () => {
    const { lines } = await makeReceipts(2);
    const otherPub = fromB64u(
      createGate({
        policy: STARTER,
        signingKey: generateSigningKey(),
        receiptSink: () => {},
      }).publicKey(),
    );
    const rep = verifyReceiptFile(writeLines(lines), otherPub);
    expect(rep.ok).toBe(false);
  });
});
