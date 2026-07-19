import type { Receipt, DecisionValue } from "./types.js";
import { jcs } from "./jcs.js";
import { sha3Bytes, sha3Hex, sign, toB64u, uuidv7 } from "./crypto.js";

export interface ReceiptDraft {
  sessionId: string;
  agentId?: string;
  tool: string;
  argsHash: string;
  decision: DecisionValue;
  reason: string;
  policyVersion: string;
  parentReceiptId?: string;
}

// Build and sign a receipt chained to prevReceiptHash. The signature covers the
// sha3-512 of the canonical receipt without the sig field.
export function buildReceipt(
  draft: ReceiptDraft,
  prevReceiptHash: string,
  kid: string,
  seed: Uint8Array,
): Receipt {
  const unsigned: Omit<Receipt, "sig"> = {
    receiptId: uuidv7(),
    ts: new Date().toISOString(),
    sessionId: draft.sessionId,
    ...(draft.agentId !== undefined ? { agentId: draft.agentId } : {}),
    tool: draft.tool,
    argsHash: draft.argsHash,
    decision: draft.decision,
    reason: draft.reason,
    policyVersion: draft.policyVersion,
    ...(draft.parentReceiptId !== undefined ? { parentReceiptId: draft.parentReceiptId } : {}),
    prevReceiptHash,
    kid,
  };
  const sig = toB64u(sign(seed, sha3Bytes(jcs(unsigned))));
  return { ...unsigned, sig };
}

// The chain hash of a full receipt, including its signature.
export function receiptHash(r: Receipt): string {
  return sha3Hex(jcs(r));
}
