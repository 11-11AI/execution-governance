# Quickstart

Install to first deny receipt, and then verify that receipt yourself, in under
5 minutes.

## From an empty project (recommended)

This uses the published package. `quickstart.mjs` and `eg-policy.yaml` are in this
directory of the repository; copy them, or fetch them directly:

```bash
mkdir eg-quickstart && cd eg-quickstart
npm init -y && npm pkg set type=module
npm install @11ai/execution-governance
curl -sLO https://raw.githubusercontent.com/11-11AI/execution-governance/main/examples/quickstart/quickstart.mjs
curl -sLO https://raw.githubusercontent.com/11-11AI/execution-governance/main/examples/quickstart/eg-policy.yaml
node quickstart.mjs --key ./eg-signing.key --receipts ./eg-receipts.jsonl
```

`npm pkg set type=module` matters: `quickstart.mjs` uses ESM imports.

With the starter policy `eg-policy.yaml`, `quickstart.mjs` tries a secret-bearing
outbound POST. The gate denies it before `fetch` runs and prints the receipt:

```
created signing key ./eg-signing.key (private: keep it out of version control)
denied: exfiltration: outbound call carrying secret material
receipt: 01a03bd6-f736-785b-a82d-62363da0273e

verify it yourself:
  npx eg-verify --receipts ./eg-receipts.jsonl --pubkey huCJiiZMYF0Ye7R6099agDYtV8TLOhmqCnv8LewTb7A
```

## Verify it yourself

Run the command the script printed. The public key is yours, so it will not be
the one above:

```bash
npx eg-verify --receipts ./eg-receipts.jsonl --pubkey huCJiiZMYF0Ye7R6099agDYtV8TLOhmqCnv8LewTb7A
```

```
  eg-verify: ./eg-receipts.jsonl
  receipts: 1, allows: 0, denies: 1
  RESULT: VERIFIED
```

`eg-verify` recomputes every hash, checks every signature, and walks the chain.
It exits 0 on `VERIFIED` and 1 on `FAILED`, so it is usable in a script.

## The two flags

```
--key <path>       Ed25519 signing seed, base64url. Created on the first run.
--receipts <path>  Where receipts are appended. Default ./eg-receipts.jsonl.
```

Both are optional and both default to what is shown above. They are on the
command line here because **the key is what makes the receipt worth anything.**
Without a stable key the SDK generates one per run, warns, and throws it away;
the receipts still look fine and can never be verified again, including by you a
minute later. The same flags, and the same key file format, are what
[`@11ai/mcp-gate`](../../packages/mcp-gate/README.md) takes.

Keep `eg-signing.key` private. It is the signing key: anyone holding it can
forge receipts that verify. The repository `.gitignore` already excludes `*.key`.

Run the quickstart again and the second receipt chains onto the first, so
`eg-verify` reports `receipts: 2` and still `VERIFIED`. A custom `--receipts`
path must be a fresh file: the SDK continues an existing chain only for its own
default sink, so pointing a new run at another file that already has receipts in
it would start again at genesis and break the chain. The script checks for this
and stops rather than write a file that cannot verify.

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
node quickstart.mjs --key ./eg-signing.key --receipts ./eg-receipts.jsonl
```

Every decision, allow or deny, appends a signed receipt. Nothing in this
quickstart touches the network: the POST is denied before `fetch` is called.
