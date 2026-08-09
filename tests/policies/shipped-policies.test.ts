// Every policy this repository ships must load in the engine, and the schema
// that describes policies must not disagree with the engine that parses them.
//
// WHY THIS FILE EXISTS
// --------------------
// `schemas/eg-policy.schema.json` and `packages/gate/src/engines/local.ts` are
// two descriptions of one format. Two descriptions of one thing drift, and the
// drift is silent: an editor shows a policy as valid while the engine refuses
// it, or worse, the schema permits a key the engine ignores and a rule someone
// believes is enforced never runs.
//
// A shipped policy that does not load is a worse failure than a broken example.
// The starter policies are what people copy, so a policy that denies everything
// because it failed to parse would look like a very strict policy.
import { describe, expect, it } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { LocalPolicyEngine } from "../../packages/gate/src/engines/local.js";

const ROOT = join(__dirname, "..", "..");
const SCHEMA = JSON.parse(readFileSync(join(ROOT, "schemas", "eg-policy.schema.json"), "utf8"));

/** Every .yaml policy shipped in the repo, discovered rather than listed. */
function shippedPolicies(): string[] {
  const found: string[] = [];
  const walk = (dir: string) => {
    for (const e of readdirSync(dir, { withFileTypes: true })) {
      const p = join(dir, e.name);
      if (e.isDirectory()) {
        if (e.name === "node_modules" || e.name === ".git" || e.name === "dist") continue;
        walk(p);
      } else if (
        /(^eg-policy|policy|agent)\.ya?ml$/.test(e.name) ||
        /-agent\.ya?ml$/.test(e.name)
      ) {
        found.push(p);
      }
    }
  };
  walk(join(ROOT, "examples"));
  walk(join(ROOT, "tests", "fixtures"));
  return found;
}

describe("shipped policies", () => {
  const policies = shippedPolicies();

  // Discovery, not a hardcoded list: a new starter policy is covered the moment
  // it is added. If this ever finds nothing, the suite would pass by testing
  // nothing at all, which is the failure mode this assertion exists to prevent.
  it("finds the policies it is supposed to check", () => {
    expect(policies.length).toBeGreaterThanOrEqual(4);
  });

  it.each(policies)("loads in the engine: %s", (path) => {
    expect(() => new LocalPolicyEngine(path)).not.toThrow();
  });

  it.each(policies)("declares a version, so receipts can name it: %s", (path) => {
    const engine = new LocalPolicyEngine(path);
    expect(engine.version()).not.toBe("unversioned");
  });
});

describe("schema and engine do not disagree", () => {
  // The keys the engine reads, taken from local.ts. If the engine learns a new
  // key and the schema is not updated, this fails -- which is the point.
  const ENGINE_ROOT_KEYS = ["version", "actionClasses", "rules"];
  const ENGINE_RULE_KEYS = ["effect", "class", "tool", "argsPattern", "reason"];
  const ENGINE_CLASS_KEYS = ["tools", "argsPattern"];

  it("schema root properties match what the engine reads", () => {
    expect(Object.keys(SCHEMA.properties).sort()).toEqual([...ENGINE_ROOT_KEYS].sort());
  });

  it("schema rule properties match what the engine reads", () => {
    const ruleProps = Object.keys(SCHEMA.properties.rules.items.properties);
    expect(ruleProps.sort()).toEqual([...ENGINE_RULE_KEYS].sort());
  });

  it("schema actionClass properties match what the engine reads", () => {
    const classProps = Object.keys(SCHEMA.properties.actionClasses.additionalProperties.properties);
    expect(classProps.sort()).toEqual([...ENGINE_CLASS_KEYS].sort());
  });

  it("schema forbids unknown keys, matching the engine's strictness", () => {
    expect(SCHEMA.additionalProperties).toBe(false);
    expect(SCHEMA.properties.rules.items.additionalProperties).toBe(false);
  });

  it("effect is constrained to the two values the engine accepts", () => {
    expect(SCHEMA.properties.rules.items.properties.effect.enum.sort()).toEqual(["allow", "deny"]);
  });
});

// Parsing a policy proves it is well formed. It does not prove it denies what
// its comments claim, and a starter policy is copied precisely because people
// trust the claim. These assert behaviour.
//
// They also guard a YAML trap. Prettier rewrites single-quoted YAML scalars to
// double-quoted ones, and YAML processes escapes inside double quotes but not
// inside single quotes. A pattern containing a backslash can therefore change
// meaning when the file is merely reformatted. Nothing here relies on
// eyeballing that: the regexes are exercised.
describe("starter policies deny what they claim to deny", () => {
  // evaluate() is async. Calling it without awaiting returns a Promise, which
  // is truthy and has no .decision -- every assertion would compare undefined
  // and fail, or worse, pass against a typo.
  const decide = async (policy: string, tool: string, args: Record<string, unknown>) =>
    await new LocalPolicyEngine(join(ROOT, policy)).evaluate({ sessionId: "t", tool, args });

  const BROWSER = "examples/policies/browser-agent.yaml";
  const FINANCE = "examples/policies/finance-agent.yaml";

  it("browser: typing a password is denied", async () => {
    expect(
      (await decide(BROWSER, "browser.type", { value: "hunter2", field: "password" })).decision,
    ).toBe("deny");
  });

  it("browser: typing ordinary text is allowed", async () => {
    expect((await decide(BROWSER, "browser.type", { value: "london" })).decision).toBe("allow");
  });

  it("browser: reading cookies is denied", async () => {
    expect((await decide(BROWSER, "browser.cookies", {})).decision).toBe("deny");
  });

  it("browser: clicking checkout is denied, ordinary clicking is not", async () => {
    expect((await decide(BROWSER, "browser.click", { text: "Place order" })).decision).toBe("deny");
    expect((await decide(BROWSER, "browser.click", { text: "Next page" })).decision).toBe("allow");
  });

  it("browser: navigation and reading are allowed", async () => {
    expect((await decide(BROWSER, "browser.goto", { url: "https://example.com" })).decision).toBe(
      "allow",
    );
    expect((await decide(BROWSER, "browser.extractText", {})).decision).toBe("allow");
  });

  it("finance: a transfer is denied", async () => {
    expect((await decide(FINANCE, "payments.transfer", { amount: 1 })).decision).toBe("deny");
  });

  it("finance: changing a payee is denied", async () => {
    expect((await decide(FINANCE, "payee.update", { iban: "x" })).decision).toBe("deny");
  });

  it("finance: self-approval is denied", async () => {
    expect((await decide(FINANCE, "invoice.approve", { id: "1" })).decision).toBe("deny");
  });

  it("finance: reading and drafting are allowed", async () => {
    expect((await decide(FINANCE, "ledger.read", {})).decision).toBe("allow");
    expect((await decide(FINANCE, "payment.draft", { amount: 1 })).decision).toBe("allow");
  });

  it("finance: an unlisted tool is denied by default", async () => {
    expect((await decide(FINANCE, "something.unforeseen", {})).decision).toBe("deny");
  });
});
