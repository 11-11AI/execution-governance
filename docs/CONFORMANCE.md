# eg-conform

Does your receipt emitter follow the format?

Ships as a bin of `@11ai/execution-governance`, alongside `eg-verify` and
`eg-demo`. A separate tool, not a separate package.

```bash
npx -p @11ai/execution-governance eg-conform receipts.ndjson --key <base64url public key>
```

Reports **per rule**, with what the specification requires and what your file
actually contains.

```
  PASS  R08  kid is 16 hex chars
  FAIL  R09  kid is the sha3-512 fingerprint of the public key
          line 1
            expected  7cea1105f8f5a1f9
            actual    188b906d801532ec
            note      kid is the first 16 hex chars of sha3-512 over the RAW 32
                      key bytes, not over their base64url text
          see RECEIPTS.md § Signature
```

## This is not eg-verify

`eg-verify` answers *is this evidence sound* — one verdict, exit 0 or 1. Its
terseness is a feature: it is a trust tool whose exit code is a published
contract.

This answers *which rules did my implementation get right*. The reader is an
implementer with a bug, not an auditor with a question. Bending either tool into
the other makes the trust tool verbose and the debugging tool vague.

## The rules

| | |
| --- | --- |
| R01 | each line is a JSON object |
| R02 | all required fields present |
| R03 | every field is a string |
| R04 | `receiptId` is a uuid v7 |
| R05 | `ts` is ISO 8601 UTC |
| R06 | `argsHash` is sha3-512 hex |
| R07 | `decision` is `allow` or `deny` |
| R08 | `kid` is 16 hex chars |
| R09 | `kid` is the sha3-512 fingerprint of the public key |
| R10 | the receipt has a canonical form |
| R11 | `sig` is Ed25519 over sha3-512 of the canonical receipt without `sig` |
| R12 | the first receipt chains to the literal string `genesis` |
| R13 | `prevReceiptHash` is sha3-512 of the canonical previous receipt, including its `sig` |

Every rule is checkable from `docs/RECEIPTS.md` alone. Nothing here needs
access to anything private, which is what makes an outside implementation
possible at all.

## Why the canonicalizer is not imported from the gate

A conformance checker that imports the reference implementation's canonicalizer
does not test conformance to the specification. It tests agreement with one
implementation: it would pass a candidate that matched our bug and fail one that
matched the written rule.

`src/canonical.ts` is therefore written from `docs/RECEIPTS.md`, and the test
suite asserts it produces byte-identical output to the gate's `jcs()` over
gate-generated receipts. If they ever disagree, one of them contradicts the
document, and that is a finding rather than a merge conflict.

## Exit codes

| code | meaning |
| ---- | ------- |
| 0 | every rule passed |
| 1 | a rule failed |
| 2 | unreadable: missing file, bad key, bad arguments |

A `deny` in the file is not a failure. This checks the **format**, not the
decisions, and makes no claim about whether a decision was correct.

## What it does not check

Policy evaluation. Whether a decision was *right* is a question about the
policy, not the receipt. It also makes no claim about the control plane's
evidence root.

No network. No telemetry. No credential reads.
