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
