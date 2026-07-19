// @11ai/execution-governance
// Pre-execution authorization for AI agent tool calls: allow or deny before
// execution, fail-closed, with a signed receipt for every decision.

export * from "./types.js";
export { createGate } from "./gate.js";
export { LocalPolicyEngine } from "./engines/local.js";
export { RemotePolicyEngine, type RemotePolicyEngineOptions } from "./engines/remote.js";
export { verifyReceiptFile } from "./verify.js";
export { generateSigningKey, publicKeyBytes, fingerprint, toB64u, fromB64u } from "./crypto.js";
export { jcs } from "./jcs.js";
