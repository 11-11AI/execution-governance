# Receipts

Every decision, allow or deny, produces one signed receipt. Receipts are written as JSONL, one JSON object per line, and chained so any tampering breaks verification.

## Canonicalization

Receipts and args are serialized with canonical JSON, RFC 8785 style:

- Object keys are sorted by their UTF-16 code units.
- No insignificant whitespace.
- Standard JSON string escaping.
- Keys whose value is undefined are omitted.

Signer and verifier must serialize identically or signatures will not verify.

## Fields

Each receipt object has these fields:

- `receiptId`: a uuid version 7 (time ordered).
- `ts`: ISO 8601 UTC timestamp.
- `sessionId`: the caller session id.
- `agentId`: optional logical agent id.
- `tool`: the namespaced tool name, for example `fs.write`.
- `argsHash`: sha3-512 hex of the canonical JSON of the request args.
- `decision`: `allow` or `deny`.
- `reason`: a short human readable reason.
- `policyVersion`: the policy version string reported by the engine.
- `parentReceiptId`: optional, the receipt this call depends on, used for absorbing deny.
- `prevReceiptHash`: sha3-512 hex of the previous receipt in this sink, or the string `genesis` for the first receipt.
- `kid`: the first 16 hex chars of the sha3-512 of the public key.
- `sig`: the signature, base64url. See below.

## Signature

The signature is Ed25519 over the sha3-512 of the canonical JSON of the receipt without the `sig` field.

```
message = sha3_512( canonicalJSON( receipt without sig ) )
sig     = base64url( Ed25519_sign( privateKey, message ) )
```

The public key is Ed25519, shared as base64url of the 32 byte key. `kid` is the first 16 hex chars of `sha3_512(publicKey)`.

## Chain

Each receipt links to the previous one:

```
prevReceiptHash(receipt N) = sha3_512_hex( canonicalJSON( receipt N-1 with sig ) )
prevReceiptHash(receipt 0) = "genesis"
```

Because the chain hash covers the full previous receipt including its signature, reordering or editing any earlier receipt breaks the chain from that point on.

## Verification

`verifyReceipts(path)` on the gate, and the `eg-verify` command, do all of the following and report any break with its line number:

1. Recompute each receipt signature and verify it against the public key.
2. Check that `kid` matches the public key.
3. Check the `prevReceiptHash` chain, starting from `genesis`.
4. Count allows and denies.

```
eg-verify --receipts eg-receipts.jsonl --pubkey <base64url public key>
```

Exit code 0 means verified, 1 means at least one break was found.

## Example

```json
{"receiptId":"019f7833-fddc-7a2b-8070-fa732536e98b","ts":"2026-07-19T02:30:00.000Z","sessionId":"s1","tool":"http.post","argsHash":"...","decision":"deny","reason":"exfiltration: outbound call carrying secret material","policyVersion":"starter-1","prevReceiptHash":"genesis","kid":"4a45b7f302b1db21","sig":"..."}
```
