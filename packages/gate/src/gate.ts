import { appendFileSync, existsSync, readFileSync } from "node:fs";
import type {
  ActionRequest,
  Decision,
  DecisionValue,
  Gate,
  GateOptions,
  PolicyEngine,
  Receipt,
  VerifyReport,
} from "./types.js";
import { DeniedError } from "./types.js";
import { fingerprint, generateSigningKey, publicKeyBytes, sha3Hex, toB64u } from "./crypto.js";
import { jcs } from "./jcs.js";
import { buildReceipt, receiptHash } from "./receipt.js";
import { verifyReceiptFile } from "./verify.js";
import { LocalPolicyEngine } from "./engines/local.js";

const DEFAULT_SINK_PATH = "./eg-receipts.jsonl";
const DEFAULT_TIMEOUT_MS = 2000;

function withTimeout<T>(p: Promise<T>, ms: number): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`decision timeout after ${ms}ms`)), ms);
    p.then(
      (v) => {
        clearTimeout(timer);
        resolve(v);
      },
      (e) => {
        clearTimeout(timer);
        reject(e);
      },
    );
  });
}

interface ChainNode {
  denied: boolean;
  parent?: string;
}

class GateImpl implements Gate {
  private readonly engine: PolicyEngine;
  private readonly seed: Uint8Array;
  private readonly pub: Uint8Array;
  private readonly kid: string;
  private readonly timeoutMs: number;
  private readonly sink: (r: Receipt) => void | Promise<void>;
  private chainHead: string | null = null;
  private readonly index = new Map<string, ChainNode>();

  constructor(options: GateOptions) {
    // Engine: a supplied instance, or the local engine from a policy path.
    // A malformed policy throws here, so the gate is never silently permissive.
    this.engine =
      typeof options.policy === "string" ? new LocalPolicyEngine(options.policy) : options.policy;

    if (options.signingKey) {
      this.seed = options.signingKey;
    } else {
      this.seed = generateSigningKey();
      console.warn(
        "eg: no signingKey provided, generated an ephemeral key. Receipts will not be verifiable across restarts. Provide options.signingKey for a stable key.",
      );
    }
    this.pub = publicKeyBytes(this.seed);
    this.kid = fingerprint(this.pub);
    this.timeoutMs = options.decisionTimeoutMs ?? DEFAULT_TIMEOUT_MS;

    if (options.receiptSink) {
      this.sink = options.receiptSink;
    } else {
      // Default sink appends JSONL. Continue the existing chain if the file exists.
      this.sink = (r: Receipt) => appendFileSync(DEFAULT_SINK_PATH, JSON.stringify(r) + "\n");
      if (existsSync(DEFAULT_SINK_PATH)) {
        this.chainHead = this.readChainHead(DEFAULT_SINK_PATH);
      }
    }
  }

  private readChainHead(path: string): string {
    // Fail closed: if an existing receipt file cannot be parsed, refuse to start.
    const lines = readFileSync(path, "utf8")
      .split("\n")
      .map((l) => l.trim())
      .filter((l) => l.length > 0);
    if (lines.length === 0) return "genesis";
    const last = lines[lines.length - 1]!;
    let r: Receipt;
    try {
      r = JSON.parse(last) as Receipt;
    } catch (e) {
      throw new Error(
        `fail-closed: existing receipt file is unreadable at the last line: ${(e as Error).message}`,
      );
    }
    return receiptHash(r);
  }

  private ancestorDenied(parentId: string): string | null {
    let cur: string | undefined = parentId;
    const seen = new Set<string>();
    while (cur && !seen.has(cur)) {
      seen.add(cur);
      const node = this.index.get(cur);
      if (!node) break; // unknown ancestor, cannot confirm a denial
      if (node.denied) return cur;
      cur = node.parent;
    }
    return null;
  }

  async authorize(req: ActionRequest): Promise<Decision> {
    let decision: DecisionValue;
    let reason: string;
    let policyVersion: string;

    // 1. Absorbing deny: if any ancestor in this chain was denied, deny without
    //    calling the engine. A new receipt is still written for this call.
    const absorbedFrom = req.parentReceiptId ? this.ancestorDenied(req.parentReceiptId) : null;
    if (absorbedFrom) {
      decision = "deny";
      reason = `absorbing-deny: upstream denial ${absorbedFrom}`;
      policyVersion = this.safeVersion();
    } else {
      // 2. Evaluate with a timeout. Any error, timeout, or malformed decision is DENY.
      try {
        const res = await withTimeout(this.engine.evaluate(req), this.timeoutMs);
        if (res.decision !== "allow" && res.decision !== "deny") {
          decision = "deny";
          reason = "fail-closed: engine returned a malformed decision";
          policyVersion =
            typeof res.policyVersion === "string" ? res.policyVersion : this.safeVersion();
        } else {
          decision = res.decision;
          reason = res.reason;
          policyVersion = res.policyVersion;
        }
      } catch (e) {
        decision = "deny";
        reason = `fail-closed: ${(e as Error).message}`;
        policyVersion = this.safeVersion();
      }
    }

    // 3. Build and sign the receipt, chained to the current head.
    const argsHash = sha3Hex(this.canonicalArgs(req.args));
    const prev = this.chainHead ?? "genesis";
    const receipt = buildReceipt(
      {
        sessionId: req.sessionId,
        agentId: req.agentId,
        tool: req.tool,
        argsHash,
        decision,
        reason,
        policyVersion,
        parentReceiptId: req.parentReceiptId,
      },
      prev,
      this.kid,
      this.seed,
    );

    // 4. Persist. If proof cannot be recorded, fail closed by throwing, so that
    //    govern() never runs the action. The chain head is not advanced on failure.
    try {
      await this.sink(receipt);
    } catch (e) {
      throw new Error(`fail-closed: cannot persist receipt: ${(e as Error).message}`);
    }
    this.chainHead = receiptHash(receipt);
    this.index.set(receipt.receiptId, { denied: decision === "deny", parent: req.parentReceiptId });

    return { decision, reason, policyVersion, receipt };
  }

  async govern<T>(req: ActionRequest, fn: () => Promise<T>): Promise<T> {
    const decision = await this.authorize(req);
    if (decision.decision !== "allow") throw new DeniedError(decision);
    return fn();
  }

  async verifyReceipts(path: string): Promise<VerifyReport> {
    return verifyReceiptFile(path, this.pub);
  }

  publicKey(): string {
    return toB64u(this.pub);
  }

  private safeVersion(): string {
    try {
      return this.engine.version();
    } catch {
      return "unknown";
    }
  }

  private canonicalArgs(args: unknown): string {
    try {
      return jcs(args ?? null);
    } catch {
      // Non canonicalizable args still get a stable hash input rather than throwing.
      return JSON.stringify(String(args));
    }
  }
}

export function createGate(options: GateOptions): Gate {
  return new GateImpl(options);
}
