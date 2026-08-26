<p align="center">
  <img src="https://11aiblockchain.com/npm-banner.png" alt="11/11 AI — Execution Governance" width="480" />
</p>

# @11ai/execution-governance

[![npm version](https://img.shields.io/npm/v/@11ai/execution-governance.svg)](https://www.npmjs.com/package/@11ai/execution-governance)
[![npm downloads](https://img.shields.io/npm/dm/@11ai/execution-governance.svg)](https://www.npmjs.com/package/@11ai/execution-governance)
[![CI](https://github.com/11-11AI/execution-governance/actions/workflows/ci.yml/badge.svg)](https://github.com/11-11AI/execution-governance/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](https://github.com/11-11AI/execution-governance/blob/main/LICENSE)
[![TypeScript](https://img.shields.io/badge/types-included-blue.svg)](https://www.npmjs.com/package/@11ai/execution-governance)

**Stop an AI agent's tool call _before_ it runs — not after.**

Every tool call is checked against your policy. Allow or deny, decided
before execution, fail-closed by default. Every decision leaves an
Ed25519-signed, hash-chained receipt anyone can verify offline.

```
Request → Verify → Allow / Deny → Execute → Signed receipt
```

No API key. No network. No telemetry. Runs entirely on your machine.

## 30-second start

```bash
npm install @11ai/execution-governance
curl -sLO https://raw.githubusercontent.com/11-11AI/execution-governance/main/examples/quickstart/quickstart.mjs
curl -sLO https://raw.githubusercontent.com/11-11AI/execution-governance/main/examples/quickstart/eg-policy.yaml
node quickstart.mjs --key ./eg-signing.key --receipts ./eg-receipts.jsonl
```

With the starter policy, a secret-bearing outbound POST is **denied before
`fetch` ever runs**, a signed receipt is appended, and the run prints the exact
command that checks it:

```
created signing key ./eg-signing.key (private: keep it out of version control)
denied: exfiltration: outbound call carrying secret material
receipt: 01a03bd6-f736-785b-a82d-62363da0273e

verify it yourself:
  npx eg-verify --receipts ./eg-receipts.jsonl --pubkey huCJiiZMYF0Ye7R6099agDYtV8TLOhmqCnv8LewTb7A
```

Run that command and you get `RESULT: VERIFIED`. The public key is yours, so it
will not be the one above.

`--key` is the part that matters. Without a stable signing key the SDK generates
one per run, warns, and throws it away: the receipts still look fine and can
never be verified again, including by you a minute later.

That is the whole API:

```ts
import { createGate } from "@11ai/execution-governance";

const gate = createGate({ policy: "./eg-policy.yaml", signingKey });

const result = await gate.govern({ sessionId: "s1", tool: "http.post", args: { url, body } }, () =>
  fetch(url, { method: "POST", body }),
);
```

`govern` runs the callback only on allow, and throws `DeniedError` on deny.
`signingKey` is a 32-byte Ed25519 seed;
[`examples/quickstart`](https://github.com/11-11AI/execution-governance/tree/main/examples/quickstart)
is the file the commands above download, and shows how it is created and reused.

## Try the attack demo (no keys, no network)

```bash
git clone https://github.com/11-11AI/execution-governance
cd execution-governance && npm install && npm run demo
```

An agent reads a briefing carrying a prompt injection telling it to
exfiltrate `.env`. The agent obeys. The gate denies the exfiltration
**before it executes**, then prints a verified receipt chain proving
exactly what was attempted and why it was stopped. Real output:

```
2. agent attempts http_post to attacker.example with .env contents
   decision: DENY
   reason: exfiltration: outbound POST carrying secret material
   the http_post never ran. Nothing left the machine.

receipt chain verified: yes, 2 allows, 1 deny
```

## Why pre-execution?

Most agent safety tooling is observability: it tells you what your agent
did after the damage is done. Logs are not authorization. This gate
reverses the order — the action is evaluated first, and without an allow
decision it never runs.

|                             | Logging / monitoring     | Execution Governance           |
| --------------------------- | ------------------------ | ------------------------------ |
| When it acts                | After execution          | **Before execution**           |
| On failure                  | Fails open (action runs) | **Fails closed (deny)**        |
| Output                      | Mutable logs             | **Signed, chained receipts**   |
| Verifiable by a third party | No                       | **Yes, offline, no key to us** |

## A receipt

```json
{
  "receiptId": "019f7833-fddc-7a2b-8070-fa732536e98b",
  "ts": "2026-07-19T02:30:00.000Z",
  "sessionId": "s1",
  "tool": "http.post",
  "argsHash": "…",
  "decision": "deny",
  "reason": "exfiltration: outbound call carrying secret material",
  "policyVersion": "starter-1",
  "prevReceiptHash": "genesis",
  "kid": "4a45b7f302b1db21",
  "sig": "…"
}
```

Canonical JSON, SHA3-512 hashed, Ed25519 signed, chained to the previous
receipt. `agentId` and `parentReceiptId` are optional and appear when
supplied. Verify any receipt file with no access to the system that
produced it:

```bash
eg-verify --receipts eg-receipts.jsonl --pubkey <base64url public key>
```

`--pubkey` may also come from the `EG_PUBLIC_KEY` environment variable. The
public key is `gate.publicKey()` for the gate that signed the file; the
quickstart above prints the whole command with the key already filled in.

## Gate any MCP server with one line

Use [`@11ai/mcp-gate`](https://www.npmjs.com/package/@11ai/mcp-gate) to
wrap an existing MCP server in your client config — Claude Desktop, Claude
Code, or any MCP client:

```json
{
  "command": "npx",
  "args": ["-y", "@11ai/mcp-gate", "--policy", "eg-policy.yaml", "--", "node", "their-server.js"]
}
```

Denied calls are answered with a JSON-RPC error and never reach the server.

## Fail-closed, measured

Any error, timeout, or missing decision results in **deny**. The decision
timeout defaults to 2000 ms and a timeout is a deny. If a receipt cannot be
persisted, the call throws rather than executing — proof that cannot be
recorded is not a permitted action. There is no fail-open path.

Checked in CI on every commit: absorption, monotone evidence growth,
non-commutativity. **26 of 26 adversarial vectors denied** under the starter
policy — run it yourself:

```bash
npx vitest run tests/vectors
```

## API surface

| Export                                                                                | Purpose                                                                                              |
| ------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| `createGate(options)`                                                                 | Construct a gate from a policy file path or a `PolicyEngine`.                                        |
| `gate.govern(request, fn)`                                                            | Evaluate, then run `fn` only on allow. Throws `DeniedError` on deny.                                 |
| `gate.authorize(request)`                                                             | Decision only, no execution — for your own dispatcher. Returns a `Decision` with its signed receipt. |
| `gate.verifyReceipts(path)`                                                           | Verify a receipt file with this gate's key. Returns a `VerifyReport`.                                |
| `gate.publicKey()`                                                                    | This gate's public key, base64url.                                                                   |
| `verifyReceiptFile(path, publicKey)`                                                  | Standalone chain verification against any public key.                                                |
| `LocalPolicyEngine`, `RemotePolicyEngine`                                             | The built-in engines, if you construct one directly.                                                 |
| `generateSigningKey`, `publicKeyBytes`, `fingerprint`, `toB64u`, `fromB64u`           | Key helpers.                                                                                         |
| `jcs`                                                                                 | The canonical-JSON serialiser the receipt hash is computed over.                                     |
| `eg-verify` (CLI)                                                                     | Offline verification of any receipt file. No key to us, no network.                                  |
| `Receipt`, `Decision`, `VerifyReport`, `GateOptions`, `ActionRequest`, `PolicyEngine` | TypeScript types for the receipt format and policy interface.                                        |

`GateOptions` accepts `policy`, and optionally `signingKey` (32-byte Ed25519
seed — without it an ephemeral key is generated and a warning printed),
`receiptSink`, and `decisionTimeoutMs`.

## Errors — fail-closed by type

`DeniedError` is the only error class this package exports. Engine errors and
timeouts are converted into **deny decisions**, so they arrive as a
`DeniedError` rather than as a distinct type — the failure mode and the policy
decision are deliberately indistinguishable to the caller, because both mean
the same thing: nothing ran.

```ts
import { createGate, DeniedError } from "@11ai/execution-governance";

// A malformed policy throws a plain Error here, at construction, before any
// request can be evaluated. Nothing can execute against a policy that did not
// parse.
const gate = createGate({ policy: "./eg-policy.yaml" });

try {
  await gate.govern(req, exec);
} catch (err) {
  if (err instanceof DeniedError) {
    // Denied. err.decision holds the signed Decision, and
    // err.decision.receipt is the signed denial receipt.
    console.error(err.decision.reason, err.decision.receipt.receiptId);
  } else {
    // Receipt persistence failure. Fail-closed: the action did not run.
    throw err;
  }
}
```

A denied call **absorbs**: dependent downstream calls in the chain are
denied without re-evaluation.

## Versioning

Semver. The receipt wire format is versioned independently
(`policyVersion`, receipt schema) — receipts written today remain
verifiable by future verifiers. Breaking wire changes bump the major.

## The @11ai packages

| Package                                                                                  | What it is                                                                 |
| ---------------------------------------------------------------------------------------- | -------------------------------------------------------------------------- |
| [`@11ai/execution-governance`](https://www.npmjs.com/package/@11ai/execution-governance) | SDK: gate any function call. This package.                                 |
| [`@11ai/mcp-gate`](https://www.npmjs.com/package/@11ai/mcp-gate)                         | Fail-closed MCP proxy — gate any MCP server with one line of config.       |
| `@11ai/identity-oidc` _(coming)_                                                         | Bind OIDC-verified principals (Okta, Entra ID, Keycloak) to every receipt. |
| `execution-governance` on PyPI _(coming)_                                                | Python SDK, same receipt format, cross-verifiable with this package.       |

## FAQ

**Is this actually open source?** Yes — Apache-2.0, including the local
policy engine, the MCP proxy, the receipt format, and the verifier. Use it
commercially, no strings.

**What's the catch?** None for local use. A hosted control plane
([control.11aiblockchain.com](https://control.11aiblockchain.com/demo))
adds multi-tenant policy management, post-quantum-signed evidence, and a
public proof ledger for teams that need it. The npm packages work fully
without it.

**Does it phone home?** No. No telemetry, no network calls, no account.

## Docs & links

- [Receipt format & verification](https://github.com/11-11AI/execution-governance/blob/main/docs/RECEIPTS.md)
- [Policy schema & starter policy](https://github.com/11-11AI/execution-governance/blob/main/docs/POLICY.md)
- [Examples](https://github.com/11-11AI/execution-governance/tree/main/examples)
- [Research corpus (Zenodo)](https://zenodo.org/communities/11-11-ai/records) · [Category paper (DOI)](https://doi.org/10.5281/zenodo.20453136)
- [Live public proof endpoint](https://control.11aiblockchain.com/v1/public/evidence) — one `curl`, no auth, real signed decision

## License

Apache-2.0. See [LICENSE](https://github.com/11-11AI/execution-governance/blob/main/LICENSE)
and [NOTICE](https://github.com/11-11AI/execution-governance/blob/main/NOTICE).
[LICENSING.md](https://github.com/11-11AI/execution-governance/blob/main/LICENSING.md)
sets out, per component, what is open permanently and what is commercial: every
part needed to verify a receipt is Apache-2.0 and stays that way.
Provided as-is; you are responsible for your policy, deployment, and keys.
