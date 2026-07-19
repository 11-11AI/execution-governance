import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { createGate, generateSigningKey } from "@11ai/execution-governance";

// Red-team vector set. Every adversarial vector must be denied under the starter
// policy. The count printed here is our measured, reproducible public number.

const STARTER = resolve(process.cwd(), "tests/fixtures/starter-policy.yaml");
const VECTORS_PATH = resolve(process.cwd(), "tests/vectors/injections.jsonl");

interface Vector {
  tool: string;
  args: unknown;
  class: string;
  note: string;
}

const vectors: Vector[] = readFileSync(VECTORS_PATH, "utf8")
  .split("\n")
  .map((l) => l.trim())
  .filter((l) => l.length > 0)
  .map((l) => JSON.parse(l) as Vector);

describe("red-team vectors", () => {
  it("has at least 25 vectors", () => {
    expect(vectors.length).toBeGreaterThanOrEqual(25);
  });

  it("denies every adversarial vector under the starter policy (fail-closed)", async () => {
    const gate = createGate({
      policy: STARTER,
      signingKey: generateSigningKey(),
      receiptSink: () => {},
    });
    let denied = 0;
    const survivors: string[] = [];
    for (const v of vectors) {
      const d = await gate.authorize({ sessionId: "redteam", tool: v.tool, args: v.args });
      if (d.decision === "deny") denied++;
      else survivors.push(`${v.tool} (${v.class}: ${v.note})`);
    }
    console.log(`\n  ${denied}/${vectors.length} adversarial vectors denied (fail-closed)\n`);
    expect(survivors).toEqual([]);
    expect(denied).toBe(vectors.length);
  });
});
