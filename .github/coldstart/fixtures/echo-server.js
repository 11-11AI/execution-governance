#!/usr/bin/env node
// A tiny stdio MCP server for the cold-start smoke test. Exposes read_file and
// http_post. When http_post actually runs it appends to ECHO_SIDE_EFFECT, so the
// driver can prove a denied call never reached the server, rather than only
// proving the client was told "denied".
import { appendFileSync } from "node:fs";
import { createInterface } from "node:readline";

const sideEffect = process.env.ECHO_SIDE_EFFECT;
const send = (o) => process.stdout.write(JSON.stringify(o) + "\n");

createInterface({ input: process.stdin }).on("line", (line) => {
  if (!line.trim()) return;
  let m;
  try {
    m = JSON.parse(line);
  } catch {
    return;
  }

  if (m.method === "initialize") {
    send({
      jsonrpc: "2.0",
      id: m.id,
      result: {
        protocolVersion: "2024-11-05",
        capabilities: { tools: {} },
        serverInfo: { name: "echo-server", version: "0.0.0" },
      },
    });
    return;
  }

  if (m.method === "tools/list") {
    send({
      jsonrpc: "2.0",
      id: m.id,
      result: { tools: [{ name: "read_file" }, { name: "http_post" }] },
    });
    return;
  }

  if (m.method === "tools/call") {
    const name = m.params && m.params.name;
    if (name === "read_file") {
      send({
        jsonrpc: "2.0",
        id: m.id,
        result: { content: [{ type: "text", text: "file contents" }] },
      });
      return;
    }
    if (name === "http_post") {
      // Reaching this line at all is a failure of the gate, and the file is how
      // the driver finds out.
      if (sideEffect) appendFileSync(sideEffect, "http_post executed on server\n");
      send({ jsonrpc: "2.0", id: m.id, result: { content: [{ type: "text", text: "posted" }] } });
      return;
    }
    send({ jsonrpc: "2.0", id: m.id, error: { code: -32601, message: "unknown tool" } });
  }
});
