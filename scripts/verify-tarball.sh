#!/usr/bin/env bash
# Pack both packages, install them into a throwaway project, and run the quickstart.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
npm run build
OUT="$(mktemp -d)"
GATE_TGZ="$(cd "$OUT" && npm pack "$ROOT/packages/gate" --silent)"
MCP_TGZ="$(cd "$OUT" && npm pack "$ROOT/packages/mcp-gate" --silent)"
APP="$(mktemp -d)"
cd "$APP"
npm init -y >/dev/null
npm install "$OUT/$GATE_TGZ" "$OUT/$MCP_TGZ" --silent
cp "$ROOT/examples/quickstart/eg-policy.yaml" .
cp "$ROOT/examples/quickstart/quickstart.mjs" .
node quickstart.mjs
echo "tarball install verified: quickstart ran from packed tarballs"
