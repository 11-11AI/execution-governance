# @11ai/execution-governance

Pre-execution authorization for AI agent tool calls: allow or deny before execution, fail-closed, with a signed receipt for every decision.

Request, Verify, Allow or Deny, Execute, Proof.

## Install

```
npm install @11ai/execution-governance
```

## Use

```ts
import { createGate } from "@11ai/execution-governance";

const gate = createGate({ policy: "./eg-policy.yaml" });

const result = await gate.govern(
  { sessionId: "s1", tool: "http.post", args: { url, body } },
  () => fetch(url, { method: "POST", body }),
);
```

With the starter policy this denies a secret-bearing outbound call before `fetch` runs, and throws `DeniedError`. Every decision, allow or deny, appends a signed receipt to `./eg-receipts.jsonl`.

## What it does

- `authorize(req)`: evaluate policy and sign a receipt. Does not execute anything.
- `govern(req, fn)`: authorize, then run `fn` only on allow. Throws `DeniedError` on deny.
- `verifyReceipts(path)`: recompute hashes, verify signatures, verify the chain.
- `publicKey()`: the gate public key, base64url.

## Policy engines

- `LocalPolicyEngine`: deny by default. YAML rules match on tool name (glob), arg content (regex over the JSON string of args), and named action classes. See `docs/POLICY.md`.
- `RemotePolicyEngine`: POSTs the request to `EG_CONTROL_PLANE_URL` with a bearer token from `EG_API_KEY`. Timeout, non-200, or a malformed response all resolve to deny.

## Fail-closed

Any error, timeout, unreachable engine, malformed policy, or missing decision results in deny. There is no fail-open path. A denied call in a chain absorbs: dependent calls downstream are denied without calling the engine.

## Receipts

Each receipt is canonical JSON, sha3-512 hashed, Ed25519 signed, and chained by `prevReceiptHash`. See `docs/RECEIPTS.md` for the exact format. Verify from the command line with `eg-verify --receipts eg-receipts.jsonl --pubkey <base64url>`.

## License

Apache-2.0. See NOTICE.
