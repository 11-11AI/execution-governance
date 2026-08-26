// Quickstart: install to first deny receipt, then verify that receipt yourself.
//
// With the starter policy this denies a secret-bearing outbound POST before
// fetch runs, prints the receipt, and prints the exact eg-verify command that
// checks it.
//
// Flags match mcp-gate's, and so does the key file format:
//   --key <path>       Ed25519 seed, base64url. Created on the first run.
//   --receipts <path>  where receipts are appended. Default ./eg-receipts.jsonl.
import { appendFileSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  createGate,
  DeniedError,
  fromB64u,
  generateSigningKey,
  toB64u,
} from "@11ai/execution-governance";

const here = dirname(fileURLToPath(import.meta.url));

function arg(name, fallback) {
  const i = process.argv.indexOf(name);
  return i >= 0 && process.argv[i + 1] ? process.argv[i + 1] : fallback;
}

const DEFAULT_RECEIPTS = "./eg-receipts.jsonl";
const keyPath = arg("--key", "./eg-signing.key");
const receiptsPath = arg("--receipts", DEFAULT_RECEIPTS);

// A stable signing key, generated once and reused. Without one the gate makes a
// new key every run and nothing keeps the public half, so the receipts it writes
// can never be verified again -- including by you, one minute later. That is the
// difference between a signed record and a signed record that proves something.
if (!existsSync(keyPath)) {
  writeFileSync(keyPath, toB64u(generateSigningKey()), { mode: 0o600 });
  console.log(`created signing key ${keyPath} (private: keep it out of version control)`);
}
const signingKey = fromB64u(readFileSync(keyPath, "utf8").trim());

// The SDK continues an existing chain only for its own default sink at
// ./eg-receipts.jsonl. A custom receiptSink starts again at genesis, so pointing
// one at a file that already has receipts in it produces a chain break rather
// than a longer chain. Rather than write an unverifiable file, stop and say so.
const customSink = resolve(receiptsPath) !== resolve(DEFAULT_RECEIPTS);
if (customSink && existsSync(receiptsPath)) {
  console.error(`${receiptsPath} already exists, and a custom --receipts path starts a new chain.`);
  console.error(`Move it aside, or drop --receipts to append to ${DEFAULT_RECEIPTS}.`);
  process.exit(1);
}

const gate = createGate({
  policy: join(here, "eg-policy.yaml"),
  signingKey,
  ...(customSink
    ? { receiptSink: (r) => appendFileSync(receiptsPath, JSON.stringify(r) + "\n") }
    : {}),
});

const url = "https://example.com/collect";
const body = "API_KEY=sk-123";

try {
  await gate.govern({ sessionId: "s1", tool: "http.post", args: { url, body } }, () =>
    fetch(url, { method: "POST", body }),
  );
  console.log("allowed and executed");
} catch (e) {
  if (!(e instanceof DeniedError)) throw e;
  console.log("denied:", e.decision.reason);
  console.log("receipt:", e.decision.receipt.receiptId);
}

console.log("");
console.log("verify it yourself:");
console.log(`  npx eg-verify --receipts ${receiptsPath} --pubkey ${gate.publicKey()}`);
