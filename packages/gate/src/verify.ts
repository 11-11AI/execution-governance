import { readFileSync } from "node:fs";
import type { Receipt, VerifyReport, ReceiptBreak } from "./types.js";
import { jcs } from "./jcs.js";
import { fingerprint, fromB64u, sha3Bytes, sha3Hex, verify as edVerify } from "./crypto.js";

// Verify a JSONL receipt file: recompute every hash, verify every signature, and
// verify the prevReceiptHash chain. Any break is reported with its line number.
export function verifyReceiptFile(path: string, publicKey: Uint8Array): VerifyReport {
  let content: string;
  try {
    content = readFileSync(path, "utf8");
  } catch (e) {
    return {
      ok: false,
      total: 0,
      allows: 0,
      denies: 0,
      breaks: [{ line: 0, issue: `cannot read receipt file: ${(e as Error).message}` }],
    };
  }

  const lines = content
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l.length > 0);

  const expectedKid = fingerprint(publicKey);
  const breaks: ReceiptBreak[] = [];
  let allows = 0;
  let denies = 0;
  let prevHash = "genesis";

  lines.forEach((line, idx) => {
    const ln = idx + 1;
    let r: Receipt;
    try {
      r = JSON.parse(line) as Receipt;
    } catch {
      breaks.push({ line: ln, issue: "invalid JSON" });
      return;
    }

    if (r.prevReceiptHash !== prevHash) {
      breaks.push({
        line: ln,
        issue: "chain break: prevReceiptHash does not match the previous receipt",
      });
    }
    if (r.kid !== expectedKid) {
      breaks.push({ line: ln, issue: "kid does not match the provided public key" });
    }

    const { sig, ...unsigned } = r as Receipt & { sig: string };
    let sigOk = false;
    try {
      sigOk = edVerify(publicKey, sha3Bytes(jcs(unsigned)), fromB64u(sig));
    } catch {
      sigOk = false;
    }
    if (!sigOk) breaks.push({ line: ln, issue: "signature invalid" });

    if (r.decision === "allow") allows++;
    else if (r.decision === "deny") denies++;
    else breaks.push({ line: ln, issue: `unknown decision value: ${String(r.decision)}` });

    prevHash = sha3Hex(jcs(r));
  });

  return { ok: breaks.length === 0, total: lines.length, allows, denies, breaks };
}
