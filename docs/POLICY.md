# Policy

The local policy engine is deny by default. A request that matches no allow rule is denied. Rules match on tool name (glob), arg content (regex), and named action classes.

## Structure

```yaml
version: "your-policy-1"

actionClasses:
  <className>:
    tools: [<glob>, ...] # optional, matches the tool name
    argsPattern: "<regex>" # optional, matches the JSON string of args

rules:
  - class: <className> # match a named class, or
    tool: <glob> # match a tool glob, or
    argsPattern: "<regex>" # add a regex filter
    effect: allow | deny
    reason: "<short reason>" # optional
```

Rules are evaluated in order. The first matching rule wins. If no rule matches, the request is denied.

## Globs

Tool globs are matched case-insensitively. `*` matches any characters within one dot separated segment. `**` matches across segments.

- `http.*` matches `http.post` but not `http.v2.post`.
- `*.delete` matches `fs.delete`.
- `**.delete` matches `db.v2.delete`.

## Regex

`argsPattern` is a regular expression matched, case-insensitively, against `JSON.stringify(args)`. Write patterns in single quoted YAML so backslashes stay literal, for example `'\.env'`.

## Action classes

Action classes name a category of risky behavior, so rules read clearly. A class matches when the tool matches one of its globs and, if present, the args match its `argsPattern`. Suggested classes:

- `irreversible`: deletes, drops, destructive shell.
- `exfiltration`: outbound calls carrying secret material.
- `spend`: charges, transfers, purchases.
- `identity-change`: role grants, key additions, new users.

## Starter policy

This is the canonical starter policy, also used by the tests and examples. It denies the four risky classes and allows a small set of safe reads.

```yaml
version: "starter-1"

actionClasses:
  exfiltration:
    tools:
      [
        "http.post",
        "http.put",
        "http.patch",
        "https.post",
        "https.put",
        "*.upload",
        "*.send",
        "email.send",
        "webhook.*",
      ]
    argsPattern: '(secret|api[_-]?key|password|passwd|token|credential|\.env|private[_-]?key|BEGIN [A-Z ]*PRIVATE KEY|authorization:|aws_access|ssh-rsa)'
  irreversible:
    tools:
      [
        "fs.delete",
        "fs.rmdir",
        "shell.exec",
        "shell.*",
        "*.delete",
        "*.destroy",
        "*.drop",
        "db.drop*",
      ]
  spend:
    tools:
      ["payments.*", "*.charge", "*.transfer", "*.pay", "*.purchase", "stripe.*", "wallet.send"]
  identity-change:
    tools:
      [
        "iam.*",
        "auth.*",
        "*.setrole",
        "*.set_role",
        "*.addkey",
        "*.add_key",
        "*.grant",
        "*.createuser",
      ]

rules:
  - class: exfiltration
    effect: deny
    reason: "exfiltration: outbound call carrying secret material"
  - class: irreversible
    effect: deny
    reason: "irreversible action denied by default"
  - class: spend
    effect: deny
    reason: "spend action denied by default"
  - class: identity-change
    effect: deny
    reason: "identity change denied by default"
  - tool: "fs.read"
    effect: allow
    reason: "reads are allowed"
  - tool: "http.get"
    effect: allow
    reason: "safe GET allowed"
  - tool: "log.*"
    effect: allow
    reason: "logging allowed"
```

## Remote engine

If `EG_CONTROL_PLANE_URL` is set, the gate can use the remote engine instead. It POSTs the request there with a bearer token from `EG_API_KEY`. A timeout, a non-200, or a malformed response all resolve to deny. The server side is out of scope for this package.

## Validate a policy before you ship it

```bash
npx @11ai/mcp-gate --validate --policy eg-policy.yaml
```

Exits 0 and prints the policy version, or exits 1 and names the fault. It starts
no server and writes no receipts, so it is safe in CI.

This runs the engine's own parser, which is why it is the check worth gating on.
It catches things a schema cannot: a rule naming an `actionClass` that was never
declared, and an `argsPattern` that is not a compilable regex. Both produce a
policy that loads as valid-looking YAML and then denies everything, which is
indistinguishable at a glance from a very strict policy.

## JSON Schema

[`schemas/eg-policy.schema.json`](../schemas/eg-policy.schema.json) describes the
policy shape for editor completion and for CI on non-JavaScript toolchains.

**It is the weaker check.** It cannot express the two rules above. Use it for
authoring; use `--validate` for gating. A test in this repository asserts the
schema and the engine accept the same set of keys, so the two cannot drift apart
silently.

### A YAML trap worth knowing

Write `argsPattern` values in **single quotes**. YAML processes escape sequences
inside double quotes but not inside single quotes, so `"\.env"` and `'\.env'` are
different patterns. A formatter that requotes your file can therefore change what
a rule matches without changing anything you would notice in review.

## Starter policies

| Policy                                                                            | For                                                                          |
| --------------------------------------------------------------------------------- | ---------------------------------------------------------------------------- |
| [`tests/fixtures/starter-policy.yaml`](../tests/fixtures/starter-policy.yaml)     | general: exfiltration, irreversible actions, spend, identity change          |
| [`examples/policies/browser-agent.yaml`](../examples/policies/browser-agent.yaml) | an agent driving a browser, where injected page text is the normal condition |
| [`examples/policies/finance-agent.yaml`](../examples/policies/finance-agent.yaml) | an agent with access to money movement                                       |
| [`examples/git-hook/eg-policy.yaml`](../examples/git-hook/eg-policy.yaml)         | a coding agent with push access                                              |

Each is deny-by-default, and each is covered by tests asserting it denies what
its comments claim rather than merely parsing.
