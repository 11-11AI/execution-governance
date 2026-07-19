#!/usr/bin/env node
// eg-verify: recompute hashes, verify signatures, and verify the chain of a
// receipt file. Exit code 0 means verified, 1 means a break was found.

import { fromB64u } from "../crypto.js";
import { verifyReceiptFile } from "../verify.js";

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(name);
  return i >= 0 ? process.argv[i + 1] : undefined;
}

function main(): number {
  const path = arg("--receipts");
  const pubkey = arg("--pubkey") ?? process.env.EG_PUBLIC_KEY;
  if (!path || !pubkey) {
    console.error("usage: eg-verify --receipts <path.jsonl> --pubkey <base64url>");
    console.error("       the public key may also be set as EG_PUBLIC_KEY");
    return 2;
  }
  let pub: Uint8Array;
  try {
    pub = fromB64u(pubkey);
  } catch {
    console.error("eg-verify: --pubkey is not valid base64url");
    return 2;
  }

  const report = verifyReceiptFile(path, pub);
  console.log("");
  console.log("  eg-verify: " + path);
  console.log(
    "  receipts: " + report.total + ", allows: " + report.allows + ", denies: " + report.denies,
  );
  if (report.breaks.length > 0) {
    console.log("  breaks:");
    for (const b of report.breaks) console.log("    line " + b.line + ": " + b.issue);
  }
  console.log("  RESULT: " + (report.ok ? "VERIFIED" : "FAILED"));
  console.log("");
  return report.ok ? 0 : 1;
}

process.exit(main());
