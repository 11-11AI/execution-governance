import type { ActionRequest, PolicyEngine, PolicyEngineResult } from "../types.js";

// Remote policy engine. POSTs the request to EG_CONTROL_PLANE_URL with a bearer
// token from EG_API_KEY. This is the hook for an out of process engine. Timeout,
// non-200, or a malformed response all resolve to DENY. There is no fail-open path.

export interface RemotePolicyEngineOptions {
  url: string;
  apiKey: string;
  timeoutMs?: number;
  fetchImpl?: typeof fetch;
}

export class RemotePolicyEngine implements PolicyEngine {
  private readonly url: string;
  private readonly apiKey: string;
  private readonly timeoutMs: number;
  private readonly fetchImpl: typeof fetch;

  constructor(opts: RemotePolicyEngineOptions) {
    if (!opts.url) throw new Error("RemotePolicyEngine requires a url (EG_CONTROL_PLANE_URL)");
    this.url = opts.url;
    this.apiKey = opts.apiKey;
    this.timeoutMs = opts.timeoutMs ?? 2000;
    this.fetchImpl = opts.fetchImpl ?? fetch;
  }

  /** Build a RemotePolicyEngine from EG_CONTROL_PLANE_URL and EG_API_KEY. */
  static fromEnv(env: NodeJS.ProcessEnv = process.env, timeoutMs?: number): RemotePolicyEngine {
    return new RemotePolicyEngine({
      url: env.EG_CONTROL_PLANE_URL ?? "",
      apiKey: env.EG_API_KEY ?? "",
      timeoutMs,
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
      return { decision: "deny", reason: `fail-closed: remote engine unreachable: ${(e as Error).message}`, policyVersion: "remote" };
    }

    if (!res.ok) {
      return { decision: "deny", reason: `fail-closed: remote engine returned HTTP ${res.status}`, policyVersion: "remote" };
    }

    let data: unknown;
    try {
      data = await res.json();
    } catch {
      return { decision: "deny", reason: "fail-closed: remote engine returned a non-JSON body", policyVersion: "remote" };
    }

    const d = data as Record<string, unknown> | null;
    if (!d || (d.decision !== "allow" && d.decision !== "deny")) {
      return { decision: "deny", reason: "fail-closed: remote engine returned a malformed decision", policyVersion: "remote" };
    }
    return {
      decision: d.decision,
      reason: typeof d.reason === "string" ? d.reason : "remote decision",
      policyVersion: typeof d.policyVersion === "string" ? d.policyVersion : "remote",
    };
  }
}
