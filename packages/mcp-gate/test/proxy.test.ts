import { describe, it, expect } from "vitest";
import { GateProxy, type ProxyIO } from "@11ai/mcp-gate";
import type { ActionRequest, Decision, Gate, Receipt, VerifyReport } from "@11ai/execution-governance";

function fakeReceipt(id: string, decision: "allow" | "deny", reason: string): Receipt {
  return {
    receiptId: id,
    ts: "2026-01-01T00:00:00.000Z",
    sessionId: "sess",
    tool: "srv.tool",
    argsHash: "hash",
    decision,
    reason,
    policyVersion: "v",
    prevReceiptHash: "genesis",
    kid: "0000000000000000",
    sig: "AA",
  };
}

class MockGate implements Gate {
  constructor(private readonly behavior: (req: ActionRequest) => Decision | "throw") {}
  async authorize(req: ActionRequest): Promise<Decision> {
    const b = this.behavior(req);
    if (b === "throw") throw new Error("gate crashed");
    return b;
  }
  async govern<T>(): Promise<T> {
    throw new Error("not used in these tests");
  }
  async verifyReceipts(): Promise<VerifyReport> {
    return { ok: true, total: 0, allows: 0, denies: 0, breaks: [] };
  }
  publicKey(): string {
    return "pub";
  }
}

function collectIO() {
  const state = { server: [] as string[], client: [] as string[], fatal: null as Error | null };
  const io: ProxyIO = {
    toServer: (l) => state.server.push(l),
    toClient: (l) => state.client.push(l),
    onFatal: (e) => {
      state.fatal = e;
    },
  };
  return { io, state };
}

const allow = (): Decision => ({ decision: "allow", reason: "ok", policyVersion: "v", receipt: fakeReceipt("r-allow", "allow", "ok") });
const deny = (): Decision => ({ decision: "deny", reason: "blocked", policyVersion: "v", receipt: fakeReceipt("r-deny", "deny", "blocked") });

describe("mcp gate proxy", () => {
  it("a denied tools/call is not forwarded and the client gets a JSON-RPC error", async () => {
    const { io, state } = collectIO();
    const proxy = new GateProxy(new MockGate(deny), "srv", "sess", io);
    await proxy.handleClientLine(
      JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "http_post", arguments: {} } }),
    );
    expect(state.server).toEqual([]);
    expect(state.client.length).toBe(1);
    const resp = JSON.parse(state.client[0]!);
    expect(resp.id).toBe(1);
    expect(resp.error.message).toContain("Denied by Execution Governance policy");
    expect(resp.error.message).toContain("Receipt r-deny");
  });

  it("an allowed tools/call is forwarded unchanged", async () => {
    const { io, state } = collectIO();
    const proxy = new GateProxy(new MockGate(allow), "srv", "sess", io);
    const line = JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "fs_read" } });
    await proxy.handleClientLine(line);
    expect(state.server).toEqual([line]);
    expect(state.client).toEqual([]);
  });

  it("non tools/call traffic passes through untouched", async () => {
    const { io, state } = collectIO();
    const proxy = new GateProxy(
      new MockGate(() => {
        throw new Error("gate should not be called for passthrough traffic");
      }),
      "srv",
      "sess",
      io,
    );
    for (const m of [
      { jsonrpc: "2.0", id: 1, method: "initialize" },
      { jsonrpc: "2.0", id: 2, method: "tools/list" },
      { jsonrpc: "2.0", method: "notifications/progress" },
    ]) {
      const line = JSON.stringify(m);
      await proxy.handleClientLine(line);
      expect(state.server[state.server.length - 1]).toBe(line);
    }
    expect(state.fatal).toBeNull();
  });

  it("a gate crash triggers onFatal, so the proxy never runs ungated", async () => {
    const { io, state } = collectIO();
    const proxy = new GateProxy(new MockGate(() => "throw"), "srv", "sess", io);
    await proxy.handleClientLine(
      JSON.stringify({ jsonrpc: "2.0", id: 9, method: "tools/call", params: { name: "x" } }),
    );
    expect(state.fatal).toBeInstanceOf(Error);
    expect(state.server).toEqual([]);
  });

  it("server responses are forwarded to the client", () => {
    const { io, state } = collectIO();
    const proxy = new GateProxy(new MockGate(allow), "srv", "sess", io);
    const resp = '{"jsonrpc":"2.0","id":1,"result":{"ok":true}}';
    proxy.handleServerLine(resp);
    expect(state.client).toEqual([resp]);
  });
});
