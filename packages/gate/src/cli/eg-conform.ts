#!/usr/bin/env node
// eg-conform: does your receipt emitter follow the format?
//
//   npx -p @11ai/execution-governance eg-conform receipts.ndjson --key <base64url public key>
//
// Exit 0 every rule passed, 1 a rule failed, 2 could not be read.
//
// This reports per rule, not one verdict, because the reader is an implementer
// with a bug rather than an auditor with a question. A failing rule prints what
// the specification requires and what the file actually contains, so the next
// action is obvious without reading our source.
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { checkConformance } from "../conform/index.js";

const EXIT_OK = 0,
  EXIT_FAILED = 1,
  EXIT_UNREADABLE = 2;

const USAGE = `eg-conform - conformance checker for the execution-governance receipt format

  npx -p @11ai/execution-governance eg-conform <receipts.ndjson> --key <base64url> [--json] [--quiet]

  --key, -k    Ed25519 public key, base64url, or @path to a file holding one.
               Repeatable, for a file that spans a key rotation.
  --json       machine-readable report
  --quiet, -q  exit code only
  --help, -h   this text

exit 0 conformant | 1 a rule failed | 2 unreadable

Checks the receipt format only: field shapes, canonical form, signature
construction, and chain linkage. It does not evaluate policy and makes no claim
about whether a decision was correct.

No network. No telemetry.`;

interface Args {
  file: string | null;
  keys: string[];
  json: boolean;
  quiet: boolean;
  help: boolean;
}

function parseArgs(argv: string[]): Args {
  const a: Args = { file: null, keys: [], json: false, quiet: false, help: false };
  for (let i = 0; i < argv.length; i++) {
    const v = argv[i]!;
    if (v === "--json") a.json = true;
    else if (v === "--quiet" || v === "-q") a.quiet = true;
    else if (v === "--help" || v === "-h") a.help = true;
    else if (v === "--key" || v === "-k") {
      const n = argv[++i];
      if (n === undefined) throw new Error("--key needs a value");
      a.keys.push(n);
    } else if (v.startsWith("-")) throw new Error(`unknown flag: ${v}`);
    else if (a.file === null) a.file = v;
    else throw new Error(`unexpected extra argument: ${v}`);
  }
  return a;
}

function loadKey(spec: string): Uint8Array {
  const raw = spec.startsWith("@") ? readFileSync(spec.slice(1), "utf8").trim() : spec;
  const b = Buffer.from(raw, "base64url");
  if (b.length !== 32)
    throw new Error(`a key must be 32 bytes of base64url Ed25519 public key, got ${b.length}`);
  return b;
}

const MARK: Record<string, string> = { pass: "PASS", fail: "FAIL", not_applicable: "n/a " };

function report(r: ReturnType<typeof checkConformance>, file: string): void {
  console.log("");
  console.log(`  eg-conform: ${file}`);
  console.log(`  ${r.receipts} receipt(s), ${r.passed} rule(s) passed, ${r.failed} failed`);
  console.log("");

  const seen = new Set<string>();
  const order = r.findings.map((f) => f.rule).filter((x) => !seen.has(x) && seen.add(x));
  for (const rule of order.sort()) {
    const all = r.findings.filter((f) => f.rule === rule);
    const worst = all.some((f) => f.status === "fail")
      ? "fail"
      : all.every((f) => f.status === "not_applicable")
        ? "not_applicable"
        : "pass";
    const head = all[0]!;
    console.log(`  ${MARK[worst]}  ${rule}  ${head.title}`);
    if (worst === "not_applicable" && head.detail) console.log(`          ${head.detail}`);
    if (worst !== "fail") continue;
    // Rules that also emit a summary finding would otherwise print a
    // line-less "line -" entry underneath their real ones.
    const detailed = all.filter((x) => x.status === "fail" && x.line !== undefined);
    for (const f of detailed.length > 0 ? detailed : all.filter((x) => x.status === "fail")) {
      if (f.line !== undefined) console.log(`          line ${f.line}`);
      if (f.expected !== undefined) console.log(`            expected  ${f.expected}`);
      if (f.actual !== undefined) console.log(`            actual    ${f.actual}`);
      if (f.detail) console.log(`            note      ${f.detail}`);
    }
    console.log(`          see ${head.reference}`);
  }
  console.log("");
  console.log(r.ok ? "  RESULT: CONFORMANT" : "  RESULT: NOT CONFORMANT");
  console.log("");
}

function main(): number {
  let args: Args;
  try {
    args = parseArgs(process.argv.slice(2));
  } catch (e) {
    console.error(`  ${(e as Error).message}\n`);
    console.error(USAGE);
    return EXIT_UNREADABLE;
  }

  if (args.help) {
    console.log(USAGE);
    return EXIT_OK;
  }
  if (!args.file) {
    console.error("  no receipt file given\n");
    console.error(USAGE);
    return EXIT_UNREADABLE;
  }

  let content: string;
  try {
    content = readFileSync(args.file, "utf8");
  } catch (e) {
    console.error(`  cannot read ${args.file}: ${(e as Error).message}`);
    return EXIT_UNREADABLE;
  }

  const keys = new Map<string, Uint8Array>();
  try {
    for (const s of args.keys) {
      const k = loadKey(s);
      keys.set(createHash("sha3-512").update(k).digest("hex").slice(0, 16), k);
    }
  } catch (e) {
    console.error(`  ${(e as Error).message}`);
    return EXIT_UNREADABLE;
  }

  const lines = content
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l.length > 0);
  if (lines.length === 0) {
    console.error(`  ${args.file} contains no receipts`);
    return EXIT_UNREADABLE;
  }

  const r = checkConformance(lines, keys);
  if (args.json) console.log(JSON.stringify(r, null, 2));
  else if (!args.quiet) report(r, args.file);
  return r.ok ? EXIT_OK : EXIT_FAILED;
}

process.exit(main());
