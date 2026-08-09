<p align="center">
  <img src="https://11aiblockchain.com/npm-banner.png" alt="11/11 AI — Execution Governance" width="480" />
</p>

# @11ai/mcp-gate

[![npm version](https://img.shields.io/npm/v/@11ai/mcp-gate.svg)](https://www.npmjs.com/package/@11ai/mcp-gate)
[![npm downloads](https://img.shields.io/npm/dm/@11ai/mcp-gate.svg)](https://www.npmjs.com/package/@11ai/mcp-gate)
[![CI](https://github.com/11-11AI/execution-governance/actions/workflows/ci.yml/badge.svg)](https://github.com/11-11AI/execution-governance/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](https://github.com/11-11AI/execution-governance/blob/main/LICENSE)

**A firewall for MCP tool calls. Add one line to your config — no code changes.**

`mcp-gate` is a fail-closed stdio proxy that sits between any MCP client
(Claude Desktop, Claude Code, Cursor, anything) and any MCP server. Every
`tools/call` is checked against your policy before it's forwarded. Denied
calls never reach the server — the client gets a JSON-RPC error and a
signed receipt records the attempt.

No API key. No network. No telemetry.

## One-line install

Wrap any MCP server by changing its command in your client config:

**Before**

```json
{
  "command": "node",
  "args": ["their-server.js"]
}
```

**After**

```json
{
  "command": "npx",
  "args": ["-y", "@11ai/mcp-gate", "--policy", "eg-policy.yaml", "--", "node", "their-server.js"]
}
```

That's it. `initialize`, `tools/list`, resources, and notifications pass
through untouched. Only `tools/call` is gated.

## Why you want this

MCP servers run with your credentials and your filesystem. A
prompt-injected agent can call any tool the server exposes — exfiltrate
secrets, POST data to attacker URLs, delete files. Reviewing logs
afterward doesn't undo it.

`mcp-gate` decides **before** the call runs:

- **Deny by policy** — block outbound calls carrying secret material,
  writes outside allowed paths, dangerous shell commands, whatever your
  policy says.
- **Fail-closed** — engine error, timeout, malformed policy? The call is
  denied. There is no fail-open path.
- **Signed receipts** — every allow and every deny is Ed25519-signed,
  SHA3-512 hashed, and chained. Verify the file offline with `eg-verify`,
  no access to the machine required.

## What a denial looks like

The client receives a JSON-RPC error instead of a tool result, and the
receipt log records:

```json
{
  "tool": "http.post",
  "decision": "deny",
  "reason": "exfiltration: outbound call carrying secret material",
  "policyVersion": "starter-1",
  "sig": "…"
}
```

## Policy

Start from the canonical starter policy and edit YAML — allow/deny rules
per tool, argument matching, path and URL constraints. Full schema:
[docs/POLICY.md](https://github.com/11-11AI/execution-governance/blob/main/docs/POLICY.md).

## CLI reference

```
mcp-gate --policy <file> [options] -- <server-command> [args...]
```

| Flag                | Purpose                                                                                                                           |
| ------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| `--policy <path>`   | Policy file. Required unless `EG_CONTROL_PLANE_URL` is set. Malformed policy = every call denied.                                 |
| `--receipts <path>` | Append signed receipts here (default `./eg-receipts.jsonl`).                                                                      |
| `--key <path>`      | Ed25519 seed for a stable signing key. Without it a key is generated per run and receipts are not verifiable across restarts.     |
| `--timeout <ms>`    | Policy evaluation timeout. A timeout is a deny.                                                                                   |
| `--name <name>`     | Tool namespace prefix. Defaults to a name derived from the wrapped command. See the warning below — this affects policy matching. |
| `-h`, `--help`      | Show usage and exit 0.                                                                                                            |
| `--`                | Everything after is the wrapped server command, verbatim.                                                                         |

> **Set `--key` before you rely on the receipts.** Without it, a new signing
> key is generated per run and receipts cannot be verified across restarts.
> Each run's receipts still verify against that run's own key, so nothing looks
> broken — the failure only appears later, when you try to verify an older file
> and no longer have the key it was signed with. The gate warns on startup when
> it generates an ephemeral key.

> **`--name` is part of what your policy matches on.** Tool calls are evaluated
> as `<name>.<tool>`, so a rule written for `their-server.http_post` stops
> matching if the prefix changes. The default is derived from the wrapped
> command, which means editing the command in your client config can change the
> prefix as a side effect — and a rule that no longer matches is a rule that no
> longer denies. Set `--name` explicitly and the prefix stops depending on how
> the server happens to be launched.

Exit behavior: if the wrapped server exits, the gate exits with the same
code. If the gate cannot start (bad policy, missing binary), it exits
nonzero and **no server starts** — fail-closed extends to process
lifecycle.

## Works with

- **Claude Desktop / Claude Code** — wrap any server in
  `claude_desktop_config.json` or `.mcp.json`
- **Cursor, Windsurf, any MCP client** — anything that launches stdio MCP
  servers
- **Any MCP server** — filesystem, GitHub, databases, browsers; the gate
  is server-agnostic

## Versioning

Semver, tracks `@11ai/execution-governance` minors. The receipt format is
versioned independently; old receipt files stay verifiable.

## The @11ai packages

| Package                                                                                  | What it is                                       |
| ---------------------------------------------------------------------------------------- | ------------------------------------------------ |
| [`@11ai/execution-governance`](https://www.npmjs.com/package/@11ai/execution-governance) | SDK: gate any function call, not just MCP.       |
| [`@11ai/mcp-gate`](https://www.npmjs.com/package/@11ai/mcp-gate)                         | This package.                                    |
| `@11ai/identity-oidc` _(coming)_                                                         | OIDC-verified principals bound to every receipt. |
| `execution-governance` on PyPI _(coming)_                                                | Python SDK, cross-verifiable receipts.           |

## Part of Execution Governance

Built on
[`@11ai/execution-governance`](https://www.npmjs.com/package/@11ai/execution-governance)
— the SDK for gating any function call (not just MCP) with the same policy
engine and receipt chain. Try the prompt-injection demo:

```bash
git clone https://github.com/11-11AI/execution-governance && cd execution-governance
npm install && npm run demo
```

## License

Apache-2.0. Fully functional locally — no account, no hosted dependency.
See [LICENSE](https://github.com/11-11AI/execution-governance/blob/main/LICENSE).
