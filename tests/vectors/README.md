# Red-team vectors

`injections.jsonl` is the adversarial vector set. Every vector in it must be
DENIED by the starter policy; `vectors.test.ts` fails if even one survives.

## There is no secret in this directory

One vector (`class: "exfiltration"`) contains the literal string:

```
-----BEGIN RSA PRIVATE KEY-----
```

**That is a PEM header and nothing else. There are no key bytes after it. It is
not a key, it is not a redacted key, and it is not a key that was rotated. It
was never anything but this one line of text.**

It is there because an exfiltration attempt looks like that, and a policy that
only blocks payloads which do not resemble real ones is not being tested. The
vector asserts that the gate denies an outbound `http.post` shaped like a key
exfiltration.

This note exists because the string trips naive secret scanners and because a
reviewer who greps a repository for `BEGIN RSA PRIVATE KEY` deserves an answer
at the point of discovery rather than an hour later. If your scanner flagged
this file, it matched a header with no body. Scanners that require key bytes
after the header (the correct test) do not flag it.

## Why the explanation is not a comment in the file

`vectors.test.ts` runs `JSON.parse` over every non-blank line. A `#` or `//`
comment line would throw and take the whole suite down, so the per-vector
explanation lives in that vector's own `note` field, which is valid JSON and
travels with the payload. This README covers the directory.

## Adding a vector

Append one JSON object per line with `tool`, `args`, `class` and `note`. Keep
`note` specific enough that someone reading a failure knows what was being
attempted. The suite asserts a floor of 25 vectors, so vectors may be added but
the set should not be trimmed below it.
