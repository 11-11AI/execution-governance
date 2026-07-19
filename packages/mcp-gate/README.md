# @11ai/mcp-gate

A fail-closed stdio MCP proxy. It sits between an MCP client and an MCP server, evaluates every tool call against an Execution Governance policy, and denies before the call reaches the server. Every decision produces a signed receipt.

Request, Verify, Allow or Deny, Execute, Proof.

## One line to gate an existing server

Change the server command in your MCP client config to wrap it:

```json
{
  "command": "npx",
  "args": ["-y", "@11ai/mcp-gate", "--policy", "eg-policy.yaml", "--", "node", "their-server.js"]
}
```

The proxy spawns the wrapped server, forwards `initialize`, `tools/list`, resources, and notifications untouched, and gates `tools/call`. A denied call is answered to the client with a JSON-RPC error and is never forwarded to the server.

## Flags

- `--policy <path>`: policy file, required unless `EG_CONTROL_PLANE_URL` is set.
- `--receipts <path>`: where receipts are written. Default `./eg-receipts.jsonl`.
- `--key <path>`: Ed25519 seed file, base64url or hex, for a stable signing key.
- `--timeout <ms>`: decision timeout. A timeout is a deny.
- `--name <serverName>`: tool namespace prefix. Default derived from the command.

## Fail-closed

If the policy is malformed the proxy exits before starting the server. If the gate throws while making a decision, the proxy exits rather than pass traffic ungated. A denied tool call is never forwarded.

## License

Apache-2.0. See NOTICE.
