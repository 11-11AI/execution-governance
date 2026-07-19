import { describe, it, expect } from "vitest";
import { resolve } from "node:path";
import { LocalPolicyEngine, type ActionRequest } from "@11ai/execution-governance";

const STARTER = resolve(process.cwd(), "tests/fixtures/starter-policy.yaml");
const engine = new LocalPolicyEngine(STARTER);

function req(tool: string, args: unknown = {}): ActionRequest {
  return { sessionId: "s", tool, args };
}

describe("local policy engine", () => {
  it("allows explicitly allowed tools", async () => {
    expect((await engine.evaluate(req("fs.read", { path: "x" }))).decision).toBe("allow");
    expect((await engine.evaluate(req("http.get", { url: "x" }))).decision).toBe("allow");
    expect((await engine.evaluate(req("log.info", { msg: "hi" }))).decision).toBe("allow");
  });

  it("denies unmatched tools by default", async () => {
    const d = await engine.evaluate(req("weird.tool"));
    expect(d.decision).toBe("deny");
    expect(d.reason).toContain("deny by default");
  });

  it("denies exfiltration only when args carry secret material", async () => {
    expect((await engine.evaluate(req("http.post", { body: "API_KEY=sk-1" }))).decision).toBe(
      "deny",
    );
    // http.post without a secret matches no allow rule, so deny by default.
    const benign = await engine.evaluate(req("http.post", { body: "hello world" }));
    expect(benign.decision).toBe("deny");
  });

  it("denies irreversible, spend, and identity-change tools", async () => {
    expect((await engine.evaluate(req("shell.exec", { cmd: "ls" }))).decision).toBe("deny");
    expect((await engine.evaluate(req("payments.charge", { amount: 1 }))).decision).toBe("deny");
    expect((await engine.evaluate(req("iam.attachPolicy", {}))).decision).toBe("deny");
  });

  it("matches tool globs case-insensitively", async () => {
    expect((await engine.evaluate(req("USER.SetRole", { role: "admin" }))).decision).toBe("deny");
    expect((await engine.evaluate(req("FS.DELETE", { path: "/" }))).decision).toBe("deny");
  });

  it("reports a stable policy version", () => {
    expect(engine.version()).toBe("starter-1");
  });
});
