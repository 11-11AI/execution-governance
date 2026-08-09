#!/usr/bin/env node
// mcp-gate: wrap an MCP server, gate its tools/call requests, fail closed.
//
//   mcp-gate --policy eg-policy.yaml -- node their-server.js
//
// Flags: --policy <path> (required unless EG_CONTROL_PLANE_URL is set),
//        --receipts <path>, --key <path to Ed25519 seed>, --timeout <ms>,
//        --name <serverName>.

import { spawn } from "node:child_process";
import { appendFileSync, readFileSync } from "node:fs";
import { randomUUID } from "node:crypto";
import {
  createGate,
  fromB64u,
  LocalPolicyEngine,
  RemotePolicyEngine,
  type GateOptions,
  type Receipt,
} from "@11ai/execution-governance";
import { deriveServerName, GateProxy, makeLineHandler } from "./proxy.js";

function die(msg: string): never {
  console.error(`eg: ${msg}`);
  process.exit(1);
}

const USAGE = `mcp-gate — fail-closed MCP proxy. Gates tools/call against policy.

Usage:
  mcp-gate --policy <file> [options] -- <server-command> [args...]

Options:
  --policy <path>     policy file (required unless EG_CONTROL_PLANE_URL is set)
  --receipts <path>   append signed receipts here (default ./eg-receipts.jsonl)
  --key <path>        Ed25519 seed for a stable signing key
  --timeout <ms>      policy evaluation timeout
  --name <name>       server name recorded in receipts
  --validate          check the policy and exit; starts no server
  -h, --help          show this help

Typical use is in an MCP client config, wrapping an existing server:
  "args": ["-y", "@11ai/mcp-gate", "--policy", "eg-policy.yaml", "--", "node", "server.js"]

Docs: https://github.com/11-11AI/execution-governance`;

// --help must succeed. Exiting non-zero on an explicit help request makes the
// binary look broken to anyone checking whether the install worked.
function helpAndExit(): never {
  console.log(USAGE);
  process.exit(0);
}

function parseArgs(argv: string[]) {
  const sep = argv.indexOf("--");
  const beforeSep = sep >= 0 ? argv.slice(0, sep) : argv;
  if (beforeSep.includes("--help") || beforeSep.includes("-h")) helpAndExit();
  const flags = sep >= 0 ? argv.slice(0, sep) : argv;
  const wrapped = sep >= 0 ? argv.slice(sep + 1) : [];
  const get = (name: string): string | undefined => {
    const i = flags.indexOf(name);
    return i >= 0 ? flags[i + 1] : undefined;
  };
  return {
    policy: get("--policy"),
    receipts: get("--receipts"),
    key: get("--key"),
    timeout: get("--timeout"),
    name: get("--name"),
    validate: flags.includes("--validate"),
    wrapped,
  };
}

/**
 * Check a policy and exit. Starts no server and writes no receipts.
 *
 * This deliberately runs the ENGINE'S OWN parser rather than validating against
 * `schemas/eg-policy.schema.json`. The engine rejects things a JSON Schema
 * cannot express -- a rule naming an actionClass that was never declared, an
 * argsPattern that is not a compilable regex -- and those are the mistakes
 * people actually make. A policy that satisfies the schema and fails here would
 * still deny every call in production, so the schema is the weaker check and
 * this is the one worth exiting non-zero on.
 *
 * The value is in the timing. Without it, the first evidence that a policy is
 * broken is an MCP client failing to start, or -- worse under a remote engine
 * -- every call being denied at runtime, which looks like a policy that is
 * working very hard.
 */
function validateAndExit(policyPath: string): never {
  try {
    // LocalPolicyEngine, not createGate. createGate would generate a signing key
    // and print an ephemeral-key warning, and a validate run that warns about
    // keys it never uses trains people to ignore that warning where it matters.
    // The engine constructor is also exactly where policy parsing happens, so
    // this is the narrowest thing that can answer the question.
    const engine = new LocalPolicyEngine(policyPath);
    console.log(`policy OK: ${policyPath}`);
    console.log(`  version: ${engine.version()}`);
    process.exit(0);
  } catch (e) {
    console.error(`policy INVALID: ${policyPath}`);
    console.error(`  ${(e as Error).message}`);
    process.exit(1);
  }
}

function loadKey(path: string): Uint8Array {
  const text = readFileSync(path, "utf8").trim();
  try {
    const k = fromB64u(text);
    if (k.length === 32) return k;
  } catch {
    // fall through to hex
  }
  if (/^[0-9a-fA-F]{64}$/.test(text)) return new Uint8Array(Buffer.from(text, "hex"));
  return die(`--key file ${path} is not a 32 byte Ed25519 seed (base64url or hex)`);
}

function main(): void {
  const args = parseArgs(process.argv.slice(2));

  // Handled before the server-command check, because --validate deliberately
  // takes no server command: it is the thing you run in CI, where there is no
  // MCP client and nothing to wrap.
  if (args.validate) {
    if (!args.policy) die("--validate requires --policy <path>");
    validateAndExit(args.policy);
  }

  if (args.wrapped.length === 0) {
    die("no server command. Usage: mcp-gate --policy eg-policy.yaml -- <command> [args...]");
  }
  const useRemote = Boolean(process.env.EG_CONTROL_PLANE_URL);
  if (!args.policy && !useRemote) {
    die("requires --policy <path> unless EG_CONTROL_PLANE_URL is set");
  }

  const timeoutMs = args.timeout ? Number(args.timeout) : undefined;

  // Build the gate. A malformed policy or a bad key throws here, before any
  // server process is started. That is fail-closed.
  let gate;
  try {
    const opts: GateOptions = {
      policy: useRemote ? RemotePolicyEngine.fromEnv(process.env, timeoutMs) : args.policy!,
      ...(args.key ? { signingKey: loadKey(args.key) } : {}),
      ...(args.receipts
        ? { receiptSink: (r: Receipt) => appendFileSync(args.receipts!, JSON.stringify(r) + "\n") }
        : {}),
      ...(timeoutMs ? { decisionTimeoutMs: timeoutMs } : {}),
    };
    gate = createGate(opts);
  } catch (e) {
    return die(`fail-closed: ${(e as Error).message}`);
  }

  const serverName = deriveServerName(args.wrapped, args.name);
  const sessionId = randomUUID();
  const policyLabel = useRemote ? "remote (EG_CONTROL_PLANE_URL)" : args.policy!;

  const cmd = args.wrapped[0]!;
  const rest = args.wrapped.slice(1);
  const child = spawn(cmd, rest, { stdio: ["pipe", "pipe", "inherit"] });

  let exiting = false;
  const shutdown = (code: number) => {
    if (exiting) return;
    exiting = true;
    try {
      child.kill();
    } catch {
      // ignore
    }
    process.exit(code);
  };

  const proxy = new GateProxy(gate, serverName, sessionId, {
    toServer: (line) => {
      try {
        child.stdin!.write(line + "\n");
      } catch {
        // ignore write errors on a closing pipe
      }
    },
    toClient: (line) => {
      process.stdout.write(line + "\n");
    },
    onFatal: (err) => {
      console.error(`eg: gate error, exiting to avoid ungated traffic: ${err.message}`);
      shutdown(1);
    },
  });

  process.stdin.on(
    "data",
    makeLineHandler((line) => {
      void proxy.handleClientLine(line);
    }),
  );
  process.stdin.on("end", () => {
    try {
      child.stdin!.end();
    } catch {
      // ignore
    }
  });

  child.stdout!.on(
    "data",
    makeLineHandler((line) => proxy.handleServerLine(line)),
  );
  child.on("exit", (code) => shutdown(code ?? 0));
  child.on("error", (e) => die(`failed to start server: ${e.message}`));

  process.stderr.write(
    `eg: gating ${serverName} declared tools, policy ${policyLabel}, fail-closed\n`,
  );
}

main();
