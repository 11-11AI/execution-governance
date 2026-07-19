// Public types for the authorization gate. The interface is deliberately small.
// The policy decision is delegated to a PolicyEngine, which is the boundary
// behind which any advanced engine stays hidden. This package ships only a
// local YAML engine and a remote HTTP hook.

export type DecisionValue = "allow" | "deny";

/** What an agent wants to do, evaluated before it runs. */
export interface ActionRequest {
  sessionId: string;
  agentId?: string;
  /** Namespaced tool name, for example "fs.write", "http.post", "shell.exec". */
  tool: string;
  /** Action arguments. Hashed into the receipt, never stored raw in the receipt. */
  args: unknown;
  context?: Record<string, string>;
  /** Chain linkage for absorbing deny: the receipt this call depends on. */
  parentReceiptId?: string;
}

/** The immutable, signed record of one decision. */
export interface Receipt {
  receiptId: string; // uuidv7
  ts: string; // ISO 8601 UTC
  sessionId: string;
  agentId?: string;
  tool: string;
  argsHash: string; // sha3-512 hex of the canonical args
  decision: DecisionValue;
  reason: string;
  policyVersion: string;
  parentReceiptId?: string;
  prevReceiptHash: string; // sha3-512 hex of the previous receipt in this sink, "genesis" if first
  kid: string; // sha3-512 fingerprint of the public key, first 16 hex chars
  sig: string; // base64url Ed25519 over sha3-512 of the canonical receipt without sig
}

export interface Decision {
  decision: DecisionValue;
  reason: string;
  policyVersion: string;
  receipt: Receipt;
}

export interface PolicyEngineResult {
  decision: DecisionValue;
  reason: string;
  policyVersion: string;
}

/** The hiding boundary. Implementations decide allow or deny. */
export interface PolicyEngine {
  evaluate(req: ActionRequest): Promise<PolicyEngineResult>;
  version(): string;
}

export interface GateOptions {
  /** A PolicyEngine instance, or a path to a policy.yaml for the built-in local engine. */
  policy: PolicyEngine | string;
  /** Ed25519 private key seed, 32 bytes. If omitted, an ephemeral key is generated and a warning is printed. */
  signingKey?: Uint8Array;
  /** Where receipts go. Default appends JSONL to ./eg-receipts.jsonl. */
  receiptSink?: (r: Receipt) => void | Promise<void>;
  /** Decision timeout in milliseconds. Default 2000. A timeout is a deny. */
  decisionTimeoutMs?: number;
}

export interface ReceiptBreak {
  line: number;
  issue: string;
}

export interface VerifyReport {
  ok: boolean;
  total: number;
  allows: number;
  denies: number;
  breaks: ReceiptBreak[];
}

export interface Gate {
  /** Evaluate and sign a receipt. Does not execute anything. */
  authorize(req: ActionRequest): Promise<Decision>;
  /** Authorize, then run fn only on allow. Throws DeniedError on deny. */
  govern<T>(req: ActionRequest, fn: () => Promise<T>): Promise<T>;
  /** Recompute hashes, verify signatures and the chain of a receipt file. */
  verifyReceipts(path: string): Promise<VerifyReport>;
  /** The gate public key, base64url encoded. */
  publicKey(): string;
}

/** Thrown by govern() when a request is denied. Carries the signed decision. */
export class DeniedError extends Error {
  readonly decision: Decision;
  constructor(decision: Decision) {
    super(`Denied by Execution Governance policy: ${decision.reason}`);
    this.name = "DeniedError";
    this.decision = decision;
  }
}
