# Quickstart

Install to first deny receipt in under 5 minutes.

## From an empty project (recommended)

This uses the published package. `quickstart.mjs` and `eg-policy.yaml` are in this
directory of the repository; copy them, or fetch them directly:

```bash
mkdir eg-quickstart && cd eg-quickstart
npm init -y && npm pkg set type=module
npm install @11ai/execution-governance
curl -sLO https://raw.githubusercontent.com/11-11AI/execution-governance/main/examples/quickstart/quickstart.mjs
curl -sLO https://raw.githubusercontent.com/11-11AI/execution-governance/main/examples/quickstart/eg-policy.yaml
node quickstart.mjs
```

`npm pkg set type=module` matters: `quickstart.mjs` uses ESM imports.

## From a clone of this repository

This directory is an npm **workspace**, so `npm install @11ai/execution-governance`
here symlinks the local `packages/gate` instead of fetching the published package.
That local package must be built first, or the import fails with
`ERR_MODULE_NOT_FOUND`:

```bash
git clone https://github.com/11-11AI/execution-governance
cd execution-governance
npm install
npm run build          # required: the workspace link points at unbuilt source
cd examples/quickstart
node quickstart.mjs
```

With the starter policy `eg-policy.yaml`, `quickstart.mjs` tries a secret-bearing outbound POST. The gate denies it before `fetch` runs and prints the receipt:

```
denied: exfiltration: outbound call carrying secret material
receipt: 019...
```

Every decision, allow or deny, appends a signed receipt to `./eg-receipts.jsonl`. Verify it yourself:

```
eg-verify --receipts eg-receipts.jsonl --pubkey <printed public key>
```
