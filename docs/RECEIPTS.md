# Receipts

Every decision, allow or deny, produces one signed receipt. Receipts are written as JSONL, one JSON object per line, and chained so any tampering breaks verification.

## Canonicalization

Receipts and args are serialized with canonical JSON, RFC 8785 style:

- Object keys are sorted by their UTF-16 code units.
- No insignificant whitespace.
- Standard JSON string escaping.
- Keys whose value is undefined are omitted.

### Numbers

Every receipt field is a string, so this rule does not affect receipts
themselves. It applies to `args`, which is canonicalized and hashed into
`argsHash`, and an implementation that formats numbers differently there will
produce a different `argsHash` for the same call.

- A number is serialized exactly as ECMAScript renders it, the shortest
  representation that round-trips to the same IEEE-754 double. This is what
  `JSON.stringify` emits, and what RFC 8785 § 3.2.2.3 requires.
- No trailing `.0`, no leading `+`, no leading zeros: `1`, not `1.0`; `0.1`,
  not `.1` or `0.10`.
- `-0` serializes as `0`.
- Exponential notation follows ECMAScript exactly: used at or above `1e21`
  (`1e+21`) and for small magnitudes (`1e-7`), decimal in between.
- `NaN`, `Infinity` and `-Infinity` have no canonical form. Refuse to
  canonicalize them rather than substituting `null`.
- `undefined` has no canonical form either. As an object value the key is
  omitted; as an array element it becomes `null`, because omitting it would
  change the array's length. It must never be rendered as a bare `undefined`
  token, which is not JSON and which naive string concatenation will produce.

Signer and verifier must serialize identically or signatures will not verify.

## Fields

Each receipt object has these fields:

- `receiptId`: a uuid version 7. The version nibble and the RFC 4122 variant
  bits are normative. **Time ordering is NOT normative**: do not rely on
  receipts being sorted by id, and do not reject a file because they are not.
  Clock adjustment and concurrent emitters make ordering unenforceable, and an
  unenforceable rule should not be a requirement. Ordering is established by the
  chain, not by the id.
- `ts`: ISO 8601 UTC with **exactly three fractional digits and a `Z`**, for
  example `2026-09-16T00:00:00.000Z`. This is what `new Date().toISOString()`
  produces and it is normative. Whole seconds (`...:00Z`) and microsecond
  precision are both non-conformant: the same instant written two ways is two
  different canonical forms, and therefore two different signatures.
- `sessionId`: the caller session id.
- `agentId`: optional logical agent id.
- `tool`: the namespaced tool name, for example `fs.write`.
- `argsHash`: sha3-512 hex of the UTF-8 bytes of the canonical JSON of the
  request args. When args are absent the canonical form is the literal `null`,
  four bytes, so `argsHash` is `sha3_512("null")`. If the args have **no**
  canonical form -- a non-finite number, a bigint, a function, a symbol -- the
  call is refused and no receipt is written. There is no substitute value: a
  receipt that cannot commit to its arguments must not claim to.
- `decision`: `allow` or `deny`.
- `reason`: a short human readable reason.
- `policyVersion`: the policy version string reported by the engine.
- `parentReceiptId`: optional, the receipt this call depends on, used for absorbing deny.
- `prevReceiptHash`: sha3-512 hex of the previous receipt in this sink, or the string `genesis` for the first receipt.
- `kid`: the first 16 hex chars of the sha3-512 of the public key.
- `sig`: the signature, base64url, **unpadded**. No `=` characters. A padded
  encoding is a different string, and therefore different canonical bytes and a
  different chain hash.

`agentId` and `parentReceiptId` are **omitted entirely** when absent. They are
not written as `null`. An explicit null is a different canonical form and will
not verify.

## Signature

The signature is Ed25519 over the sha3-512 of the canonical JSON of the receipt without the `sig` field.

```
message = sha3_512( canonicalJSON( receipt without sig ) )
sig     = base64url( Ed25519_sign( privateKey, message ) )
```

The public key is Ed25519, shared as base64url of the 32 byte key. `kid` is the first 16 hex chars of `sha3_512(publicKey)`.

Three details that decide whether a second implementation agrees with this one:

- **`sha3-512` means SHA3-512 as standardised in FIPS 202**, not Keccak-512.
  The two differ in padding and produce entirely different digests.
- **The message signed is the 64 raw digest bytes**, not their 128-character hex
  representation. Ed25519 is used directly over those bytes; this is not
  Ed25519ph.
- **The canonical JSON string is encoded as UTF-8** before hashing.

`kid` is computed over the **raw 32 key bytes**, not over their base64url text.

## Chain

Each receipt links to the previous one:

```
prevReceiptHash(receipt N) = sha3_512_hex( canonicalJSON( receipt N-1 with sig ) )
prevReceiptHash(receipt 0) = "genesis"
```

Because the chain hash covers the full previous receipt including its signature, reordering or editing any earlier receipt breaks the chain from that point on.

## Limitation: a refused call leaves no receipt

Stated plainly, because it is a real gap in a product that claims proof on every
action.

When arguments have no canonical form the call is refused and **nothing is
written**. The action does not run, which is the half that matters. But there is
no record that it was attempted, so a caller can avoid leaving a trace by
sending arguments the format cannot represent -- a non-finite number or a bigint
is enough.

The alternative was a receipt carrying a placeholder `argsHash`, and that is the
defect this refusal replaced: a receipt that verifies perfectly while committing
to nothing. A record that lies is worse than a record that is absent.

Today the refusal is **silent at the gate**. It surfaces only as a thrown
`UncanonicalizableArgsError` propagating to the caller; the gate has no logging
hook, and `GateOptions` exposes no error sink. Whether an operator ever sees it
depends entirely on the host application's error handling, and an application
that catches and discards the exception records nothing anywhere.

The intended resolution is a refusal record that is operator-visible and does
**not** pretend to be an authorization receipt: a separate stream that says an
attempt was refused and why, without occupying a field it cannot honestly fill.
That is not implemented.

## Unknown fields

A receipt may carry fields not listed above. They are **permitted**, and they
are part of the canonical form, which means they are signed and covered by the
chain hash like any other field.

A verifier **MUST** include unknown fields when it recomputes the canonical JSON
for a signature or a chain hash. Dropping a field it does not recognise changes
the bytes and verification will fail. This is the forward-compatibility
mechanism: an older verifier can still check a receipt written by a newer
emitter, provided it does not discard what it cannot interpret.

## File format

Receipts are written as JSONL: one JSON object per line, UTF-8, `\n` separated,
with a trailing newline after the final receipt. Readers should ignore blank
lines. The chain order is file order.

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

## Verifying across a key rotation

A receipt file outlives the key that signed its first line. Rotate a signing key
and the file continues under a new `kid`.

Pass every key the file spans:

```ts
import { verifyReceiptFile } from "@11ai/execution-governance";

verifyReceiptFile("eg-receipts.jsonl", [oldPublicKey, newPublicKey]);
```

A single key still works and is exactly equivalent to a set of one, so nothing
that calls this today needs changing:

```ts
verifyReceiptFile("eg-receipts.jsonl", publicKey);
```

A kid-keyed `Map` is also accepted, for callers that already hold fingerprints.

### Unknown kid and invalid signature are different findings

Verify a rotated file with only the old key and every line signed by the new one
is reported as **`no supplied key matches kid …`** — not as an invalid
signature.

That distinction is the point of this feature. "Signature invalid" means the
bytes do not match a key you hold: the file has been altered. "Unknown kid"
means you are missing a key. Collapsing them turns _fetch the other public key_
into _your evidence has been tampered with_, which is the worst possible framing
of a routine operation, delivered to whoever is least equipped to dismiss it.

### Rotating without breaking the chain

Signature verification and chain verification are independent. A rotated file
verifies signature-wise with both keys, but the `prevReceiptHash` chain must
still be continuous across the switch.

The default receipt sink handles this: it reads the existing file and continues
from its head. **A custom `receiptSink` cannot**, because the gate has no idea
where those receipts went — a new gate with a custom sink starts a fresh chain
at `genesis`, and the verifier will correctly report a chain break at the
rotation point.

If you supply your own sink and rotate keys, you are responsible for chain
continuity across the change. There is currently no option to seed a gate with
an existing chain head.
