import type { ActionRequest, PolicyEngine, PolicyEngineResult } from "../types.js";
import { defaultJwksUrl, verifySignedDecision, type SignedDecisionEnvelope } from "./jwks.js";

// Remote policy engine. POSTs the request to EG_CONTROL_PLANE_URL with a bearer
// token from EG_API_KEY. This is the hook for an out of process engine. Timeout,
// non-200, or a malformed response all resolve to DENY. There is no fail-open path.

export interface RemotePolicyEngineOptions {
  url: string;
  apiKey: string;
  timeoutMs?: number;
  fetchImpl?: typeof fetch;
  /**
   * Where the engine publishes its Ed25519 public keys.
   * Defaults to the control-plane origin + `/.well-known/jwks.json`.
   */
  jwksUrl?: string;
  /**
   * Require every decision to carry a signature that verifies against the JWKS.
   *
   * DEFAULTS TO TRUE, and that default is the point of this class. Without it,
   * an allow is only as trustworthy as whoever can answer the URL. Setting it
   * to false restores that: the engine will then believe any well-formed JSON
   * from anything that responds.
   */
  requireSignature?: boolean;
}

export class RemotePolicyEngine implements PolicyEngine {
  private readonly url: string;
  private readonly apiKey: string;
  private readonly timeoutMs: number;
  private readonly fetchImpl: typeof fetch;
  private readonly jwksUrl: string;
  private readonly requireSignature: boolean;

  constructor(opts: RemotePolicyEngineOptions) {
    if (!opts.url) throw new Error("RemotePolicyEngine requires a url (EG_CONTROL_PLANE_URL)");
    this.url = opts.url;
    this.apiKey = opts.apiKey;
    this.timeoutMs = opts.timeoutMs ?? 2000;
    this.fetchImpl = opts.fetchImpl ?? fetch;
    this.requireSignature = opts.requireSignature ?? true;
    this.jwksUrl = opts.jwksUrl ?? defaultJwksUrl(opts.url);
  }

  /** Build a RemotePolicyEngine from EG_CONTROL_PLANE_URL and EG_API_KEY. */
  static fromEnv(env: NodeJS.ProcessEnv = process.env, timeoutMs?: number): RemotePolicyEngine {
    return new RemotePolicyEngine({
      url: env.EG_CONTROL_PLANE_URL ?? "",
      apiKey: env.EG_API_KEY ?? "",
      timeoutMs,
      ...(env.EG_JWKS_URL ? { jwksUrl: env.EG_JWKS_URL } : {}),
      // Opting out is possible, but it has to be typed out in full. A one
      // character value like "0" should not be what disables signature
      // verification on an authorization path.
      ...(env.EG_REQUIRE_SIGNATURE === "false" ? { requireSignature: false } : {}),
    });
  }

  version(): string {
    return "remote";
  }

  async evaluate(req: ActionRequest): Promise<PolicyEngineResult> {
    let res: Response;
    try {
      res = await this.fetchImpl(this.url, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          ...(this.apiKey ? { authorization: `Bearer ${this.apiKey}` } : {}),
        },
        body: JSON.stringify(req),
        signal: AbortSignal.timeout(this.timeoutMs),
      });
    } catch (e) {
      return {
        decision: "deny",
        reason: `fail-closed: remote engine unreachable: ${(e as Error).message}`,
        policyVersion: "remote",
      };
    }

    if (!res.ok) {
      return {
        decision: "deny",
        reason: `fail-closed: remote engine returned HTTP ${res.status}`,
        policyVersion: "remote",
      };
    }

    let data: unknown;
    try {
      data = await res.json();
    } catch {
      return {
        decision: "deny",
        reason: "fail-closed: remote engine returned a non-JSON body",
        policyVersion: "remote",
      };
    }

    const d = data as Record<string, unknown> | null;
    if (!d || (d.decision !== "allow" && d.decision !== "deny")) {
      return {
        decision: "deny",
        reason: "fail-closed: remote engine returned a malformed decision",
        policyVersion: "remote",
      };
    }
    // Signature check LAST, after the body has parsed into a decision, so that
    // a verification failure is reported as a verification failure rather than
    // as a malformed body. The distinction matters when debugging: "malformed"
    // sends you to the server's serialiser, "unverified" sends you to the keys.
    //
    // This gate applies to an allow AND to a deny. An unsigned deny is not
    // dangerous, but accepting it teaches the deployment that unsigned
    // decisions are normal, and the next one may not be a deny.
    if (this.requireSignature) {
      const ok = await verifySignedDecision(d as SignedDecisionEnvelope, {
        jwksUrl: this.jwksUrl,
        fetchImpl: this.fetchImpl,
        timeoutMs: this.timeoutMs,
      });
      if (!ok) {
        return {
          decision: "deny",
          reason:
            "fail-closed: remote decision did not verify against the engine's JWKS " +
            `(${this.jwksUrl})`,
          policyVersion: "remote",
        };
      }
    }

    return {
      decision: d.decision,
      reason: typeof d.reason === "string" ? d.reason : "remote decision",
      policyVersion: typeof d.policyVersion === "string" ? d.policyVersion : "remote",
    };
  }
}
