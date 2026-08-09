# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

`@11ai/execution-governance` and `@11ai/mcp-gate` are versioned in lockstep and
published together, so one changelog covers both. Where an entry affects only
one package it says so.

The **receipt wire format is versioned independently** of these releases, by
`policyVersion` and the receipt schema. Receipts written by any version here
remain verifiable by later verifiers. A breaking change to the wire format
bumps the major.

## [Unreleased]

Nothing yet.

## [0.1.2] - 2026-08-09

Additive throughout. **No public API changed**: `packages/gate/src` is
byte-identical to 0.1.1, and the gate package's export list and every interface
in it are unchanged. `@11ai/mcp-gate` gained one optional CLI flag and nothing
else. Existing code keeps working without edits.

`@11ai/execution-governance` is therefore functionally identical to 0.1.1. It is
republished so the two packages stay in lockstep and so the npm page carries the
new README.

### Added

- **`@11ai/mcp-gate`**: `--validate` checks a policy and exits, starting no
  server and writing no receipts. It runs the engine's own parser rather than a
  schema check, so it catches a rule naming an `actionClass` that was never
  declared, and an `argsPattern` that is not a compilable regex. Both produce a
  policy that loads as valid YAML and then denies every call, which is
  indistinguishable at a glance from a very strict policy.
- **`schemas/eg-policy.schema.json`**: JSON Schema for `eg-policy.yaml`, for
  editor completion and for CI on non-JavaScript toolchains. It is the weaker
  check of the two; a test asserts it and the engine accept the same key set so
  the pair cannot drift silently.
- **Starter policies**: `examples/policies/browser-agent.yaml` and
  `examples/policies/finance-agent.yaml`, each deny-by-default and each covered
  by tests asserting it denies what its comments claim rather than only that it
  parses.
- **`examples/git-hook/`**: a `pre-push` hook that gates git pushes with the
  local engine. Shadow mode by default, enforce mode blocks. Denies force pushes
  and pushes to protected branches.
- **Release workflow**: `.github/workflows/release.yml` publishes both packages
  on a `v*` tag using npm trusted publishing, with no `NPM_TOKEN`. Provenance is
  automatic. A guard fails the run before publishing anything if the tag and
  either manifest disagree.
- **`CHANGELOG.md`**, backfilled to 0.1.0 and 0.1.1.

### Changed

- **Both package READMEs rewritten** for the npm pages, and corrected against
  source. The drafts named five things that do not exist: `gate.decide()` (the
  method is `gate.authorize()`), a standalone `verifyReceipts(file, pubkey)`
  (the export is `verifyReceiptFile`), `PolicyError` and
  `EngineUnreachableError` (neither exists; `DeniedError` is the only exported
  error class), and `err.receipt` (it is `err.decision`).
- **`@11ai/mcp-gate` CLI documentation**: `--key`, `--timeout`, `--name` and
  `--help` were undocumented. `--key` now carries an explicit warning, because
  without it a signing key is generated per run and receipts stop being
  verifiable across restarts — and nothing looks wrong at the time, since each
  run's receipts verify against that run's own key.
- **`--name` is documented as a policy-matching prefix**, not a label. Tool
  calls are evaluated as `<name>.<tool>`, so changing it changes what rules
  match.
- **Keywords** added to both packages for npm discovery.
- **Repository links** point at the `11-11AI` organisation following the
  transfers of `verify-11ai-proof`, `execution-governance-doctrine`,
  `11-11-lineage-verifier` and `11-11-governance-profiles`.
- **`RELEASING.md`** describes the CI publish. It previously said publishing was
  manual and that CI does not publish, which the release workflow made false.
- Demo GIF in the repository README, generated from a committed
  `examples/injection-demo/demo.tape` so it can be regenerated rather than
  drifting from what the demo prints.

## [0.1.1] - 2026-08-02

Both packages published to npm on 2026-08-02.

### Fixed

- **`@11ai/mcp-gate`**: the end-to-end test now builds before it runs, so a
  fresh clone passes. Previously the suite depended on a `dist` that only
  existed if you had built earlier, which meant it passed for contributors who
  had and failed for anyone arriving new. ([#1](https://github.com/11-11AI/execution-governance/pull/1))
- **`@11ai/mcp-gate`**: `--help` exits `0`. Exiting non-zero on an explicit
  help request breaks any wrapper that checks the status of a help probe.
  ([#2](https://github.com/11-11AI/execution-governance/pull/2))
- The commands printed in the README and in the quickstart now work as written.
  ([#2](https://github.com/11-11AI/execution-governance/pull/2))

## [0.1.0] - 2026-07-19

First public release. Both packages published to npm on 2026-07-19.

### Added

- **`@11ai/execution-governance`**: the SDK. `createGate`, `gate.authorize` for
  a decision without execution, `gate.govern` to run a function only on allow,
  `gate.verifyReceipts`, and the local and remote policy engines.
- **Receipts**: canonical JSON (JCS), SHA3-512 hashed, Ed25519 signed, and
  hash-chained to the previous receipt. `verifyReceiptFile` for programmatic
  verification and the `eg-verify` CLI for verifying a receipt file offline,
  with no access to the system that produced it.
- **`@11ai/mcp-gate`**: a fail-closed stdio MCP proxy. `tools/call` is
  evaluated against policy before being forwarded; `initialize`, `tools/list`,
  resources and notifications pass through untouched.
- **Fail-closed behaviour throughout**: policy errors, engine errors, decision
  timeouts and unpersistable receipts all resolve to deny. A denied call
  absorbs, so dependent downstream calls are denied without re-evaluation.
- **Tests**: fail-closed behaviour, absorbing deny, receipt integrity, a
  conformance table, and 26 adversarial vectors, all 26 denied under the
  starter policy.
- **Examples**: the prompt-injection demo and a quickstart, with a mock MCP
  server and an end-to-end proxy test.
- **Docs**: `docs/RECEIPTS.md` (receipt format and verification),
  `docs/POLICY.md` (policy schema and the starter policy), `RELEASING.md`, and
  CI.
- Apache-2.0, with `NOTICE`, `CITATION.cff` and `.zenodo.json` for archiving
  and citation.

---

## A note on tags

**0.1.1 was published to npm but never tagged in git.** Only `v0.1.0` exists.
The comparison link for 0.1.1 below therefore points at a commit range rather
than a tag, because there is no tag to point at.

This matters beyond tidiness: `.github/workflows/release.yml` triggers on `v*`
tags, so from now on an untagged publish cannot happen through CI — but it also
means the tag history has a hole where a release actually shipped. Creating
`v0.1.1` retroactively at `01c5e00` would close it. That is a tagging action and
is deliberately left to the repository owner.

[Unreleased]: https://github.com/11-11AI/execution-governance/compare/v0.1.2...main
[0.1.2]: https://github.com/11-11AI/execution-governance/compare/01c5e00...v0.1.2
[0.1.1]: https://github.com/11-11AI/execution-governance/compare/v0.1.0...01c5e00
[0.1.0]: https://github.com/11-11AI/execution-governance/releases/tag/v0.1.0
