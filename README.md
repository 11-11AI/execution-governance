# Execution Governance

[![CI](https://github.com/11ai/execution-governance/actions/workflows/ci.yml/badge.svg)](https://github.com/11ai/execution-governance/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Pre-execution authorization for AI agent tool calls: allow or deny before execution, fail-closed, with a signed receipt for every decision.

Request → Verify → Allow or Deny → Execute → Proof.

Execution Governance™ evaluates each action against a policy and returns allow or deny before the action runs, and writes a signed receipt for every decision. The proprietary policy core stays behind an interface: this repository ships a small SDK, a basic local engine, an MCP proxy, and the receipt format. Pre-execution authorization. Fail-closed enforcement. Cryptographic proof on every action.

## Packages

- `@11ai/execution-governance`: the SDK. Authorize a call, run it only on allow, verify receipts.
- `@11ai/mcp-gate`: a stdio MCP proxy. Gate an existing MCP server by changing one line of config.

## Quickstart

```
npm install @11ai/execution-governance
```

```ts
import { createGate } from "@11ai/execution-governance";

const gate = createGate({ policy: "./eg-policy.yaml" });

const result = await gate.govern({ sessionId: "s1", tool: "http.post", args: { url, body } }, () =>
  fetch(url, { method: "POST", body }),
);
```

With the starter policy, a secret-bearing outbound POST is denied before `fetch` runs, and a signed receipt is appended to `./eg-receipts.jsonl`. See `examples/quickstart`.

## Gate an MCP server with one line

Change the server command in your MCP client config to wrap it:

```json
{
  "command": "npx",
  "args": ["-y", "@11ai/mcp-gate", "--policy", "eg-policy.yaml", "--", "node", "their-server.js"]
}
```

`initialize`, `tools/list`, resources, and notifications pass through untouched. A `tools/call` is gated. A denied call is answered to the client with a JSON-RPC error and is never forwarded to the server.

## Demo

```
npm run demo
```

An agent reads a briefing that carries a prompt injection telling it to exfiltrate `.env`. The agent obeys. The gate denies the exfiltration before it runs, and prints a verified receipt chain. No API keys, no network.

<!-- demo gif placeholder: docs/demo.gif -->

## A receipt

```json
{
  "receiptId": "019f7833-fddc-7a2b-8070-fa732536e98b",
  "ts": "2026-07-19T02:30:00.000Z",
  "sessionId": "s1",
  "tool": "http.post",
  "argsHash": "...",
  "decision": "deny",
  "reason": "exfiltration: outbound call carrying secret material",
  "policyVersion": "starter-1",
  "prevReceiptHash": "genesis",
  "kid": "4a45b7f302b1db21",
  "sig": "..."
}
```

Each receipt is canonical JSON, sha3-512 hashed, Ed25519 signed, and chained. Verify a file with:

```
eg-verify --receipts eg-receipts.jsonl --pubkey <base64url public key>
```

## Fail-closed

Any error, timeout, unreachable engine, malformed policy, or missing decision results in deny. There is no fail-open path. A denied call in a chain absorbs: dependent calls downstream are denied without calling the engine.

## Measured

- Conformance properties checked in CI: absorption, monotone evidence growth, non-commutativity.
- 26 of 26 adversarial vectors denied under the starter policy, reproducible in CI.

## Docs

- `docs/RECEIPTS.md`: the exact receipt format and verification.
- `docs/POLICY.md`: the policy schema and the canonical starter policy.
- `RELEASING.md`: how to publish.

## Research

- Research corpus: [Zenodo, 11/11 AI community](https://zenodo.org/communities/11-11-ai).
- Category paper: [Execution Governance: A Proposed Infrastructure Category, DOI 10.5281/zenodo.20453136](https://doi.org/10.5281/zenodo.20453136).

## Disclaimer

This software is provided under the Apache License 2.0, on an AS IS basis, without warranties or conditions of any kind. See the LICENSE for the full disclaimer of warranty and limitation of liability.

Execution Governance enforces the policy you configure. It is one control, not a complete security solution, and it does not guarantee that every unsafe action is denied or that every safe action is allowed. You are responsible for your policy, your deployment, your signing keys, and the outcomes on your own systems. To the extent permitted by law, the authors and copyright holders are not liable for any harm to your systems, data, or operations, including missed denials, wrongful denials, downtime, or data loss, arising from the use of this software.

## License

Apache-2.0. See LICENSE and NOTICE.
