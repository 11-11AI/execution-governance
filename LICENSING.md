# Licensing

What you may do with each part of Execution Governance.

| Component                                    | Package                                                       | Licence               | Redistributable | Commercial |
| -------------------------------------------- | ------------------------------------------------------------- | --------------------- | --------------- | ---------- |
| SDK and gate                                 | `@11ai/execution-governance`                                  | Apache-2.0            | Yes             | No         |
| stdio MCP proxy                              | `@11ai/mcp-gate`                                              | Apache-2.0            | Yes             | No         |
| Receipt verifier CLI                         | `eg-verify`, shipped as a bin in `@11ai/execution-governance` | Apache-2.0            | Yes             | No         |
| Receipt format and signature suite           | Specification, [`docs/RECEIPTS.md`](docs/RECEIPTS.md)         | Apache-2.0, permanent | Yes             | No         |
| Control plane, key custody, transparency log | Hosted service, not distributed                               | Commercial            | No              | Yes        |

"Redistributable" means you may copy, modify, and ship it inside your own
product, including a paid one, under the terms of the Apache License 2.0.
"Commercial" means a paid agreement with 11 AI is required to use it.

Everything needed to verify a receipt is Apache-2.0 and stays that way: the
receipt format, the signature suite, the verifier, and the SDK that produces
receipts. This is not a courtesy. A receipt is evidence about what an agent was
allowed to do, and evidence you can only check with the issuer's permission is
not evidence. If verification required a licence, a key, an account, or a
running service under our control, the claim that a decision is verifiable would
reduce to a claim that we say so. So the verification path is open, offline, and
implementable by anyone from the specification alone, including by a party
adverse to us.

What is commercial is the operation of the service, not the ability to check its
output: policy evaluation at scale, custody of signing keys, the transparency
log, and the console. These are the parts that cost money to run and carry
liability to run correctly. The local engine in this repository is deliberately
basic; the proprietary policy core sits behind the same interface, and a paid
deployment substitutes it without changing the receipt format or the verifier
you already have.

The Apache-2.0 grant on every version already published is irrevocable by its
own terms, so the boundary above is a commitment rather than a current posture:
no future decision by 11 AI can withdraw the licence on code and specifications
already released.
