#!/usr/bin/env bash
# Assert that an ALREADY-INSTALLED @11ai/execution-governance behaves.
#
# Run from a directory where the package is installed, however it got there:
# coldstart.yml installs it from the registry with `npm install`, and the
# post-publish job does the same against @latest. Both call this, so the
# assertions cannot drift apart between them.
#
# THREE OUTCOMES, KEPT DISTINCT.
#   exit 0  the checks ran and held
#   exit 1  the checks ran and did not hold
#   exit 3  the checks COULD NOT RUN (nothing installed, no bin shim)
# A check that could not run must never report a pass. Callers must treat 3 as
# red, and the log line says which of the two reds it was.
set -euo pipefail

PKG="node_modules/@11ai/execution-governance"
BIN="node_modules/.bin"

die_unmeasurable() { echo "COULD NOT RUN: $1"; exit 3; }
fail()             { echo "FAIL: $1"; exit 1; }

[ -d "$PKG" ] || die_unmeasurable "$PKG is not installed in $(pwd)"
for b in eg-demo eg-verify eg-conform; do
  [ -x "$BIN/$b" ] || die_unmeasurable "$BIN/$b is missing or not executable"
done

# Absolute, because the demo runs in a scratch directory that has no
# node_modules of its own; npx there would find nothing.
ABS_BIN="$(cd "$BIN" && pwd)"
VERSION="$(node -p "require('./$PKG/package.json').version")"
echo "verifying installed @11ai/execution-governance@$VERSION"

# --- the package must not depend on itself ---------------------------------
# Read from the INSTALLED manifest, which for a registry install is the
# published manifest. This is the assertion 0.4.0 needed and did not have.
node -e '
  const m = require("./node_modules/@11ai/execution-governance/package.json");
  const fields = ["dependencies", "peerDependencies", "optionalDependencies"];
  const bad = fields.filter((f) => m[f] && Object.prototype.hasOwnProperty.call(m[f], m.name));
  if (bad.length) {
    console.error(`FAIL: published ${m.name}@${m.version} lists itself in: ${bad.join(", ")}`);
    process.exit(1);
  }
  console.log("ok: published manifest does not list the package as its own dependency");
'

# --- and no copy of it may be nested inside it -----------------------------
# The shape is the smell whatever caused it. `npm install` resolves a
# self-dependency by nesting a stale release here, silently, and every other
# assertion still passes with it present. No exact package count is asserted:
# that number moves for reasons that are not bugs.
if [ -e "$PKG/node_modules/@11ai/execution-governance" ]; then
  echo "  outer: $VERSION"
  echo "  inner: $(node -p "require('./$PKG/node_modules/@11ai/execution-governance/package.json').version")"
  fail "a second copy of the package is nested inside it"
fi
echo "ok: no copy of the package is nested inside itself"

# --- eg-demo: real decisions, both directions, and a real key --------------
WORK="$(mktemp -d)"
DEMO="$WORK/demo.txt"
( cd "$WORK" && "$ABS_BIN/eg-demo" ) > "$DEMO" 2>&1 || { cat "$DEMO"; fail "eg-demo exited non-zero"; }
grep -q 'ALLOW' "$DEMO" || fail "eg-demo printed no ALLOW"
grep -q 'DENY'  "$DEMO" || fail "eg-demo printed no DENY"
# Parse the key out of what it printed rather than hardcoding one: if the demo
# stops printing a usable key, that IS the bug, and a hardcoded key would hide it.
KEY="$(grep -o -- '--pubkey [A-Za-z0-9_-]\{43\}' "$DEMO" | head -1 | awk '{print $2}')"
[ -n "$KEY" ] || fail "eg-demo printed no public key that could be parsed"
[ -s "$WORK/eg-receipts.jsonl" ] || fail "eg-demo wrote no receipts"
echo "ok: eg-demo produced an ALLOW, a DENY and a public key"

R="$WORK/eg-receipts.jsonl"

# --- eg-verify agrees ------------------------------------------------------
# Assert on the reported result, not only the exit code: an exit code alone
# cannot tell "verified" from a future change that stops treating a break as a
# failure.
VOUT="$("$ABS_BIN/eg-verify" --receipts "$R" --pubkey "$KEY")" || fail "eg-verify exited non-zero on its own demo receipts"
echo "$VOUT" | grep -q "RESULT: VERIFIED" || fail "eg-verify did not report VERIFIED"
echo "ok: eg-verify reports VERIFIED"

# --- eg-conform agrees, with zero failed rules -----------------------------
COUT="$("$ABS_BIN/eg-conform" "$R" --key "$KEY" --json)" || fail "eg-conform exited non-zero on its own demo receipts"
node -e '
  const r = JSON.parse(process.argv[1]);
  if (!r.ok) { console.error("FAIL: eg-conform did not report ok"); process.exit(1); }
  if (r.failed !== 0) { console.error(`FAIL: eg-conform reported ${r.failed} failed rule(s)`); process.exit(1); }
  if (r.passed < 1) { console.error("FAIL: eg-conform reported no passing rules"); process.exit(1); }
  console.log(`ok: eg-conform CONFORMANT, ${r.passed} rules passed, 0 failed`);
' "$COUT"

# --- THE NEGATIVE. This is the one that matters. ---------------------------
#
# A conformance checker is only proven by what it refuses. Give it a valid,
# well-formed Ed25519 public key that did not sign these receipts.
#
# Assert on the RULE OUTCOME, not the exit code. In 0.4.0 eg-conform skipped
# every receipt whose kid it held no key for and then reported every rule
# passing -- it exited 0, so an exit-code assertion would have called that
# green. The distinction that catches it is fail versus not_applicable on the
# signature rule.
OTHER="$(node -e '
  const { generateKeyPairSync } = require("node:crypto");
  const { publicKey } = generateKeyPairSync("ed25519");
  process.stdout.write(Buffer.from(publicKey.export({ format: "jwk" }).x, "base64url").toString("base64url"));
')"
set +e
NOUT="$("$ABS_BIN/eg-conform" "$R" --key "$OTHER" --json)"
NCODE=$?
set -e
[ "$NCODE" -eq 1 ] || fail "eg-conform exited $NCODE for a key that did not sign these receipts; expected 1"
node -e '
  const r = JSON.parse(process.argv[1]);
  if (r.ok) { console.error("FAIL: eg-conform reported CONFORMANT for a key that did not sign"); process.exit(1); }
  const sig = r.findings.filter((f) => f.rule === "R11");
  if (sig.length === 0) { console.error("FAIL: the signature rule R11 was not reported at all"); process.exit(1); }
  const worst = sig.some((f) => f.status === "fail") ? "fail"
    : sig.every((f) => f.status === "not_applicable") ? "not_applicable" : "pass";
  if (worst !== "fail") {
    console.error(`FAIL: signature rule R11 reported "${worst}" for a key that did not sign these receipts.`);
    console.error("  A rule that could not be checked must not be reported as anything but a failure");
    console.error("  here: the caller supplied the keys and is asking whether these receipts verify.");
    console.error("  This is the 0.4.0 behaviour, and it exited 0 while reporting every rule passing.");
    process.exit(1);
  }
  console.log("ok: a non-signing key is refused, and R11 is reported failed rather than skipped");
' "$NOUT"

rm -rf "$WORK"
echo "installed package verified: @11ai/execution-governance@$VERSION"
