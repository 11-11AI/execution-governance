#!/usr/bin/env node
// eg-demo: a governed decision you can run from an empty directory.
//
// WHY THIS IS A BIN AND NOT AN EXAMPLE DIRECTORY.
//
// The documented command has to work from a clean `npm install` in a directory
// with nothing else in it. An example that lives in the repository cannot do
// that: a reader who installed the package does not have the repository. So the
// demo ships inside the package, needs no companion files, and writes the two
// files the verification step then reads.
//
// It makes one outbound HTTP request and it is DENIED before it is sent, which
// is the point -- the network call never happens. The allowed branch touches no
// network either. Nothing here needs credentials, a key, or an account.

import { appendFileSync, existsSync, rmSync, writeFileSync } from "node:fs";
import { createGate } from "../gate.js";
import { generateSigningKey, publicKeyBytes, toB64u } from "../crypto.js";
import { DeniedError } from "../types.js";

const POLICY = "eg-policy.yaml";
const RECEIPTS = "eg-receipts.jsonl";

// Written to disk rather than passed as an object, so the file the reader ends
// up with is a real policy they can open and edit, and so the demo exercises
// the same YAML path a deployment uses.
const POLICY_YAML = `# Written by eg-demo. Deny by default: anything not allowed below is denied.
version: "demo-1"

actionClasses:
  exfiltration:
    tools: ["http.post", "*.http_post", "*.upload", "*.send"]
    argsPattern: '(secret|api[_-]?key|password|token|credential|\\.env|BEGIN [A-Z ]*PRIVATE KEY)'

rules:
  - class: exfiltration
    effect: deny
    reason: "exfiltration: outbound call carrying secret material"
  - tool: "http.get"
    effect: allow
    reason: "safe GET allowed"
`;

const line = (s = ""): void => console.log("  " + s);
const rule = (): void => line("-".repeat(66));

async function main(): Promise<number> {
  if (!existsSync(POLICY)) writeFileSync(POLICY, POLICY_YAML);

  // START A FRESH CHAIN EVERY RUN.
  //
  // The signing key below is generated per run and never saved, so receipts
  // from an earlier run were signed by a key that no longer exists. Appending
  // to them would produce a file that can never verify: the reader would run
  // the verify command this demo prints and be told the chain is broken and the
  // kid does not match. Someone evaluating the tool would reasonably conclude
  // it does not work. Truncating is the only honest option given an ephemeral
  // key -- the alternative is persisting the key, which a demo should not do.
  rmSync(RECEIPTS, { force: true });

  const seed = generateSigningKey();
  const pub = toB64u(publicKeyBytes(seed));

  const gate = createGate({
    policy: POLICY,
    signingKey: seed,
    receiptSink: (r) => appendFileSync(RECEIPTS, JSON.stringify(r) + "\n"),
  });

  console.log("");
  rule();
  line("11/11 Execution Governance demo");
  line("policy: " + POLICY + "   receipts: " + RECEIPTS);
  rule();
  console.log("");

  // 1. The denied call. `fn` is the side effect. If the gate works, it is never
  //    invoked, so the flag below is the proof rather than the printed word.
  let exfilRan = false;
  try {
    await gate.govern(
      {
        sessionId: "demo",
        tool: "http.post",
        args: { url: "https://example.com/collect", body: "API_KEY=sk-not-a-real-key" },
      },
      async () => {
        exfilRan = true;
        return null;
      },
    );
    line("DENY   NOT REACHED -- the gate allowed an exfiltration. That is a bug.");
    return 1;
  } catch (e) {
    if (!(e instanceof DeniedError)) throw e;
    line("DENY   " + e.decision.reason);
    line("       receipt " + e.decision.receipt.receiptId + "  signed: " + Boolean(e.decision.receipt.sig));
    line("       the http.post never ran. Nothing left the machine.");
  }

  // 2. The allowed call, so the demo shows both outcomes rather than only a
  //    refusal. A tool that can only ever say no demonstrates nothing.
  const allowed = await gate.govern(
    { sessionId: "demo", tool: "http.get", args: { url: "https://example.com/status" } },
    async () => "ok",
  );
  line("ALLOW  safe GET allowed  -> " + allowed);

  console.log("");
  rule();
  if (exfilRan) {
    line("FAILED: the denied side effect executed.");
    return 1;
  }
  line("Verify the receipts yourself, on this machine, with no network:");
  console.log("");
  line("  npx eg-verify --receipts ./" + RECEIPTS + " \\");
  line("    --pubkey " + pub);
  console.log("");
  line("The signing key was generated for this run and not saved, so the");
  line("public key above is the only one that verifies these receipts.");
  rule();
  console.log("");
  return 0;
}

main().then(
  (code) => process.exit(code),
  (e) => {
    console.error("eg-demo failed: " + (e as Error).message);
    process.exit(1);
  },
);
