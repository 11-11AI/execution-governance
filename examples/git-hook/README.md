# Gate your own git pushes

A `pre-push` hook that asks the gate whether a push is allowed, and blocks it
before it leaves your machine.

This is the artifact behind "we gate our own AI agents with this". An agent with
push access can force-push over shared history or land straight on `main`; both
are ordinary git operations that no amount of after-the-fact log review undoes.

Everything here uses the published `@11ai/execution-governance` API. No hosted
dependency, no account, no network.

## Install

```bash
cp examples/git-hook/pre-push .git/hooks/pre-push
chmod +x .git/hooks/pre-push
```

Start in shadow mode, which is the default:

```bash
git push                      # decides, records a receipt, never blocks
EG_MODE=enforce git push      # a deny exits 1 and git abandons the push
```

**Run shadow first.** You find out what the policy would have done to your real
workflow before it can cost you a push. A policy that blocks the wrong thing on
day one gets uninstalled on day one, and an uninstalled gate denies nothing.

## What the starter policy denies

[`eg-policy.yaml`](eg-policy.yaml), deny by default:

| Push                                  | Decision                              |
| ------------------------------------- | ------------------------------------- |
| force push to any branch              | **deny** — rewrites published history |
| push to `main`, `master`, `release/*` | **deny** — open a pull request        |
| push to a feature branch              | allow                                 |

Measured, not asserted — all seven paths run against a real repo and a real
remote:

```
main + enforce            deny — direct push to a protected branch   BLOCKED
main + shadow             deny — same reason                         pushed
feature/x + enforce       allow — push to a feature branch           pushed
force + enforce           deny — force push rewrites history         BLOCKED
force + shadow            deny — same reason                         pushed
malformed policy+enforce  failing closed                             BLOCKED
malformed policy+shadow   not blocking                               pushed
```

## Configuration

| Variable         | Default                            | Purpose                                                                                                                                                            |
| ---------------- | ---------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `EG_MODE`        | `shadow`                           | `shadow` decides and records without blocking; `enforce` blocks a deny.                                                                                            |
| `EG_POLICY`      | `examples/git-hook/eg-policy.yaml` | Policy file.                                                                                                                                                       |
| `EG_SIGNING_KEY` | none                               | Path to a file holding a base64url Ed25519 seed. Without it the SDK generates a key per run, warns, and the receipts stop being verifiable once the process exits. |
| `EG_SESSION`     | `push-<pid>`                       | Session id recorded in receipts.                                                                                                                                   |

## Where force detection happens, and why

In the shell hook, not in the policy. Only git knows whether a push is a force:
it is a force when the remote ref already exists and is **not an ancestor** of
what you are pushing, which is exactly the case where history someone else may
have pulled is about to be replaced. `git push --force` on a branch nobody has
diverged from is a fast-forward and is not flagged, correctly.

The hook computes that from the refs git supplies on stdin and passes the result
as an argument. The policy then matches on it like any other argument.

## Fail-closed, and the one place it does not apply

In **enforce** mode, any error blocks the push — an unreadable policy, a
malformed policy, a gate that throws. A gate that lets the action through when
it cannot reach a decision is not a gate.

In **shadow** mode, errors do not block. Shadow's entire contract is that it
never blocks. A shadow deployment that started failing pushes would be a broken
promise, and would teach people to remove it — which costs more than the error.

## Receipts

Every decision, allow or deny, appends a signed receipt to
`./eg-receipts.jsonl`. Verify the file with no access to the machine that wrote
it:

```bash
eg-verify --receipts eg-receipts.jsonl --pubkey <base64url public key>
```

Set `EG_SIGNING_KEY` first, or the key that signed them will not exist by the
time you try.
