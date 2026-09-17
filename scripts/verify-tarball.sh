#!/usr/bin/env bash
# Pack both packages, install them into a throwaway project, and run the quickstart.
#
# This job tests the ARTIFACT, not the workspace. The workspace resolves local
# source; a user resolves a tarball. Only one of those ever reaches anybody.
#
# No network calls are added here beyond the dependency install npm already
# does. The offline claim is the product, and a suite that needs the network to
# test an offline tool has given the claim away. Every assertion below reads
# files on disk.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
npm run build
OUT="$(mktemp -d)"
GATE_TGZ="$(cd "$OUT" && npm pack "$ROOT/packages/gate" --silent)"
MCP_TGZ="$(cd "$OUT" && npm pack "$ROOT/packages/mcp-gate" --silent)"

# --- A package must not depend on itself -----------------------------------
#
# 0.4.0 declared "@11ai/execution-governance": "^0.3.0" in its own dependencies.
# npm cannot satisfy that from the package itself, so every consumer install
# fetched 0.3.0 and nested it inside 0.4.0: two copies of the signing and
# verification code in one tree, the inner one stale. It reached the registry
# because nothing ever looked at the tarball's own manifest.
#
# This reads the manifest out of the packed tarball rather than out of the
# source tree, because the tarball is what ships.
for TGZ in "$GATE_TGZ" "$MCP_TGZ"; do
  MANIFEST="$(tar -xzOf "$OUT/$TGZ" package/package.json)"
  node --input-type=module -e '
    const m = JSON.parse(process.argv[1]);
    const fields = ["dependencies", "peerDependencies", "optionalDependencies"];
    const bad = fields.filter((f) => m[f] && Object.hasOwn(m[f], m.name));
    if (bad.length > 0) {
      console.error(`FAIL: ${m.name}@${m.version} lists itself in: ${bad.join(", ")}`);
      for (const f of bad) console.error(`  ${f}.${m.name} = ${m[f][m.name]}`);
      console.error("  A package cannot satisfy a dependency on itself. npm resolves it by");
      console.error("  fetching an older release from the registry and nesting it inside this");
      console.error("  one, so every consumer install carries two copies of this code.");
      process.exit(1);
    }
    console.log(`ok: ${m.name}@${m.version} does not depend on itself`);
  ' "$MANIFEST"
done

APP="$(mktemp -d)"
cd "$APP"
npm init -y >/dev/null
npm install "$OUT/$GATE_TGZ" "$OUT/$MCP_TGZ" --silent

# --- Nothing nested inside the package itself ------------------------------
#
# The shape is the smell, whatever caused it. An exact total package count is
# deliberately NOT asserted: that number moves for reasons that are not bugs,
# and a check that cries wolf gets deleted.
for SCOPE in execution-governance mcp-gate; do
  NESTED="node_modules/@11ai/$SCOPE/node_modules/@11ai/$SCOPE"
  if [ -e "$NESTED" ]; then
    echo "FAIL: a second copy of @11ai/$SCOPE is nested inside itself"
    echo "  at $NESTED"
    echo "  version out: $(node -p "require('./node_modules/@11ai/$SCOPE/package.json').version")"
    echo "  version in:  $(node -p "require('./$NESTED/package.json').version")"
    exit 1
  fi
done
echo "ok: no copy of either package is nested inside itself"

cp "$ROOT/examples/quickstart/eg-policy.yaml" .
cp "$ROOT/examples/quickstart/quickstart.mjs" .
node quickstart.mjs

# --- and every bin, against the artifact, BEFORE it can be published --------
#
# The same assertions post-publish.yml runs against @latest, run here against
# the candidate. Running them only after publication would mean the first
# genuine test of a release happened once it was already irreversible.
#
# No network: the package is installed from the local tarball above, and every
# assertion in the script reads files or runs a bin. The offline claim is the
# product.
set +e
bash "$ROOT/scripts/verify-installed-package.sh"
code=$?
set -e
case "$code" in
  0) ;;
  3) echo "COULD NOT RUN: the bin assertions never executed. That is not a pass."; exit 1 ;;
  *) echo "FAIL: the packed artifact did not hold (exit $code)"; exit 1 ;;
esac

echo "tarball install verified: quickstart and all three bins ran from packed tarballs"
