// @11ai/mcp-gate
// A stdio MCP proxy that gates tools/call requests through Execution Governance.
// Fail-closed: a denied call is not forwarded, and a gate crash exits the proxy.

export { GateProxy, makeLineHandler, deriveServerName, type ProxyIO } from "./proxy.js";
