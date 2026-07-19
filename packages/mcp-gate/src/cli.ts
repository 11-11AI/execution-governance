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
  RemotePolicyEngine,
  type GateOptions,
  type Receipt,
} from "@11ai/execution-governance";
import { deriveServerName, GateProxy, makeLineHandler } from "./proxy.js";

function die(msg: string): never {
  console.error(`eg: ${msg}`);
  process.exit(1);
}

function parseArgs(argv: string[]) {
  const sep = argv.indexOf("--");
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
    wrapped,
  };
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
