#!/usr/bin/env node
// A tiny stdio MCP server for tests. Exposes read_file and http_post. When
// http_post runs it writes to MOCK_SIDE_EFFECT, so a test can prove a denied
// call never reached the server.
import { appendFileSync } from "node:fs";
import { createInterface } from "node:readline";

const side = process.env.MOCK_SIDE_EFFECT;
const send = (o) => process.stdout.write(JSON.stringify(o) + "\n");
const rl = createInterface({ input: process.stdin });

rl.on("line", (line) => {
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
        serverInfo: { name: "mockserver", version: "0.0.0" },
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
    if (name === "http_post") {
      if (side) appendFileSync(side, "http_post executed on server\n");
      send({ jsonrpc: "2.0", id: m.id, result: { content: [{ type: "text", text: "posted" }] } });
      return;
    }
    if (name === "read_file") {
      send({
        jsonrpc: "2.0",
        id: m.id,
        result: { content: [{ type: "text", text: "file contents" }] },
      });
      return;
    }
    send({ jsonrpc: "2.0", id: m.id, error: { code: -32601, message: "unknown tool" } });
    return;
  }
});
