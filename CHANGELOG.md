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

### Changed

- Documentation only. Nothing in `dist` has changed since 0.1.1, so a release
  cut from here would be identical in behaviour to 0.1.1.

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

[Unreleased]: https://github.com/11-11AI/execution-governance/compare/01c5e00...main
[0.1.1]: https://github.com/11-11AI/execution-governance/compare/v0.1.0...01c5e00
[0.1.0]: https://github.com/11-11AI/execution-governance/releases/tag/v0.1.0
