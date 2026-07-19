import { describe, it, expect } from "vitest";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import {
  createGate,
  RemotePolicyEngine,
  generateSigningKey,
  type ActionRequest,
  type PolicyEngine,
} from "@11ai/execution-governance";

const KEY = generateSigningKey();
const REQ: ActionRequest = { sessionId: "s", tool: "x.y", args: { a: 1 } };
const STARTER = resolve(process.cwd(), "tests/fixtures/starter-policy.yaml");

class ThrowingEngine implements PolicyEngine {
  version() {
    return "throwing";
  }
  async evaluate() {
    throw new Error("engine exploded");
  }
}

class HangingEngine implements PolicyEngine {
  version() {
    return "hanging";
  }
  evaluate(): Promise<never> {
    return new Promise<never>(() => {});
  }
}

class MalformedDecisionEngine implements PolicyEngine {
  version() {
    return "malformed";
  }
  async evaluate() {
    return { decision: "maybe" as unknown as "allow", reason: "?", policyVersion: "malformed" };
  }
}

describe("fail-closed", () => {
  it("an engine that throws results in deny", async () => {
    const gate = createGate({ policy: new ThrowingEngine(), signingKey: KEY, receiptSink: () => {} });
    const d = await gate.authorize(REQ);
    expect(d.decision).toBe("deny");
    expect(d.reason).toContain("fail-closed");
  });

  it("an engine timeout results in deny", async () => {
    const gate = createGate({
      policy: new HangingEngine(),
      signingKey: KEY,
      decisionTimeoutMs: 50,
      receiptSink: () => {},
    });
    const d = await gate.authorize(REQ);
    expect(d.decision).toBe("deny");
    expect(d.reason).toMatch(/timeout/);
  });

  it("an engine that returns a malformed decision results in deny", async () => {
    const gate = createGate({ policy: new MalformedDecisionEngine(), signingKey: KEY, receiptSink: () => {} });
    const d = await gate.authorize(REQ);
    expect(d.decision).toBe("deny");
    expect(d.reason).toContain("fail-closed");
  });

  it("a malformed policy throws at gate construction, never silently permissive", () => {
    const dir = mkdtempSync(join(tmpdir(), "eg-"));
    const p = join(dir, "bad.yaml");
    writeFileSync(p, "rules:\n  - tool: x\n    effect: sometimes\n");
    expect(() => createGate({ policy: p, signingKey: KEY, receiptSink: () => {} })).toThrow(/malformed policy/);
  });

  it("a policy path that does not exist throws at construction", () => {
    expect(() => createGate({ policy: "/no/such/policy.yaml", signingKey: KEY, receiptSink: () => {} })).toThrow(
      /malformed policy/,
    );
  });

  it("the starter policy denies an unmatched tool by default", async () => {
    const gate = createGate({ policy: STARTER, signingKey: KEY, receiptSink: () => {} });
    const d = await gate.authorize({ sessionId: "s", tool: "some.unknown.tool", args: {} });
    expect(d.decision).toBe("deny");
    expect(d.reason).toContain("deny by default");
  });

  it("remote engine non-200 results in deny", async () => {
    const fetchImpl = (async () => ({ ok: false, status: 500 })) as unknown as typeof fetch;
    const eng = new RemotePolicyEngine({ url: "https://rt.test", apiKey: "k", fetchImpl });
    expect((await eng.evaluate(REQ)).decision).toBe("deny");
  });

  it("remote engine unreachable results in deny", async () => {
    const fetchImpl = (async () => {
      throw new Error("ECONNREFUSED");
    }) as unknown as typeof fetch;
    const eng = new RemotePolicyEngine({ url: "https://rt.test", apiKey: "k", fetchImpl });
    const d = await eng.evaluate(REQ);
    expect(d.decision).toBe("deny");
    expect(d.reason).toContain("fail-closed");
  });

  it("remote engine malformed body results in deny", async () => {
    const fetchImpl = (async () => ({ ok: true, status: 200, json: async () => ({ nope: true }) })) as unknown as typeof fetch;
    const eng = new RemotePolicyEngine({ url: "https://rt.test", apiKey: "k", fetchImpl });
    expect((await eng.evaluate(REQ)).decision).toBe("deny");
  });
});
