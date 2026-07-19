# Quickstart

Install to first deny receipt in under 5 minutes.

```
npm install @11ai/execution-governance
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
