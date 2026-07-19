import type { ActionRequest, Gate } from "@11ai/execution-governance";

// The proxy core, decoupled from real stdio so it can be unit tested. It reads
// line delimited JSON-RPC messages from the client, gates tools/call requests,
// and forwards everything else unchanged. If the gate itself throws, onFatal is
// called: the CLI exits rather than pass traffic ungated.

export interface ProxyIO {
  /** Write one line to the wrapped server stdin. */
  toServer(line: string): void;
  /** Write one line to the client stdout. */
  toClient(line: string): void;
  /** The gate crashed. Abort rather than run ungated. */
  onFatal(err: Error): void;
}

interface JsonRpcMessage {
  jsonrpc?: string;
  id?: string | number | null;
  method?: string;
  params?: { name?: string; arguments?: unknown; [k: string]: unknown };
}

export class GateProxy {
  constructor(
    private readonly gate: Gate,
    private readonly serverName: string,
    private readonly sessionId: string,
    private readonly io: ProxyIO,
  ) {}

  /** Handle a raw line from the client. May forward to the server or deny to the client. */
  async handleClientLine(line: string): Promise<void> {
    if (line.trim().length === 0) return; // ignore blank keepalive lines

    let msg: JsonRpcMessage;
    try {
      msg = JSON.parse(line) as JsonRpcMessage;
    } catch {
      // Not JSON we understand. Pass it through unchanged.
      this.io.toServer(line);
      return;
    }

    // Only tools/call requests are gated. Everything else passes through.
    if (msg.method !== "tools/call" || msg.id === undefined || msg.id === null) {
      this.io.toServer(line);
      return;
    }

    const params = msg.params ?? {};
    const toolName = String(params.name ?? "");
    const req: ActionRequest = {
      sessionId: this.sessionId,
      tool: `${this.serverName}.${toolName}`,
      args: params.arguments ?? {},
    };

    let decision;
    try {
      decision = await this.gate.authorize(req);
    } catch (e) {
      // The gate crashed. Fail closed by aborting the proxy.
      this.io.onFatal(e as Error);
      return;
    }

    if (decision.decision === "deny") {
      // Respond to the client with a JSON-RPC error. Do not forward to the server.
      this.io.toClient(
        JSON.stringify({
          jsonrpc: "2.0",
          id: msg.id,
          error: {
            code: -32001,
            message: `Denied by Execution Governance policy: ${decision.reason}. Receipt ${decision.receipt.receiptId}.`,
          },
        }),
      );
      return;
    }

    // Allowed. Forward the original request unchanged.
    this.io.toServer(line);
  }

  /** Handle a raw line from the server. Forward to the client unchanged. */
  handleServerLine(line: string): void {
    if (line.length === 0) return;
    this.io.toClient(line);
  }
}

/** Split a byte or string stream into newline delimited lines. */
export function makeLineHandler(onLine: (line: string) => void): (chunk: Buffer | string) => void {
  let buffer = "";
  return (chunk: Buffer | string) => {
    buffer += chunk.toString();
    let idx: number;
    while ((idx = buffer.indexOf("\n")) >= 0) {
      const line = buffer.slice(0, idx);
      buffer = buffer.slice(idx + 1);
      onLine(line);
    }
  };
}

/** Derive a short server name from the wrapped command for tool namespacing. */
export function deriveServerName(wrapped: string[], override?: string): string {
  if (override && override.length > 0) return override;
  for (const token of wrapped) {
    if (/\.(mjs|cjs|js|ts|py)$/.test(token)) {
      const base = token.split(/[\\/]/).pop() ?? token;
      return base.replace(/\.(mjs|cjs|js|ts|py)$/, "");
    }
  }
  const first = wrapped[0] ?? "server";
  return first.split(/[\\/]/).pop() ?? first;
}
