#!/usr/bin/env node
// verify-migration/fake-server.mjs — 容器内假防火墙 + 假 LLM 服务（自包含增强版）
// 新增能力（其余行为与原版一致）:
//   fw-mode = "tool-block" → 仅当 validate 请求 body.source 为 tool_call/skill 时 block，其余 pass
//   llm-script = "toolcall-once" → 首次 chat/completions 返回 exec tool_call，之后返回普通文本
//     （用于工具防护场景：LLM 发起一次工具调用被阻断后，第二轮正常收尾，避免无限循环）

import http from "node:http";
import fs from "node:fs";
import path from "node:path";

const args = process.argv.slice(2);
function argOf(name, def) {
  const i = args.indexOf(name);
  return i >= 0 && args[i + 1] ? args[i + 1] : def;
}
const FW_PORT = parseInt(argOf("--firewall-port", "9820"), 10);
const LLM_PORT = parseInt(argOf("--llm-port", "9821"), 10);
const STATE_DIR = argOf("--dir", "/logs/fake");
const FW_LOG = path.join(STATE_DIR, "fw-requests.jsonl");
const LLM_LOG = path.join(STATE_DIR, "llm-requests.jsonl");
const FW_MODE_FILE = path.join(STATE_DIR, "fw-mode");
const LLM_SCRIPT_FILE = path.join(STATE_DIR, "llm-script");

fs.mkdirSync(STATE_DIR, { recursive: true });

let toolcallOnceUsed = false;

function append(file, obj) {
  fs.appendFileSync(file, JSON.stringify(obj) + "\n");
}
function readMode() {
  try {
    return fs.readFileSync(FW_MODE_FILE, "utf8").trim() || "pass";
  } catch {
    return "pass";
  }
}
function readScript() {
  try {
    return fs.readFileSync(LLM_SCRIPT_FILE, "utf8").trim() || "text";
  } catch {
    return "text";
  }
}
function countLines(file) {
  try {
    return fs.readFileSync(file, "utf8").split("\n").filter((l) => l.trim()).length;
  } catch {
    return 0;
  }
}
function readBody(req) {
  return new Promise((resolve) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
  });
}
function safeJson(s) {
  try { return JSON.parse(s); } catch { return s; }
}

// ---------------- 假防火墙 ----------------
const fwServer = http.createServer(async (req, res) => {
  const url = req.url || "";
  if (req.method === "GET" && url === "/__reset") {
    try { fs.writeFileSync(FW_LOG, ""); } catch {}
    res.writeHead(200); res.end('{"ok":true}');
    return;
  }
  if (req.method === "GET" && url === "/__count") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ fw: countLines(FW_LOG), llm: countLines(LLM_LOG) }));
    return;
  }
  const body = await readBody(req);
  append(FW_LOG, { ts: Date.now(), method: req.method, path: url, headers: req.headers, body: body ? safeJson(body) : null });

  const p = url.split("?")[0];
  if (req.method === "POST" && p === "/api/firewall/openclaw/validate") {
    const mode = readMode();
    const parsed = body ? safeJson(body) : {};
    let blocked = mode === "block";
    if (mode === "tool-block") {
      blocked = !!parsed && (parsed.source === "tool_call" || parsed.source === "skill");
    }
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({
      code: 200,
      data: {
        action: blocked ? "block" : "pass",
        result: blocked ? "block" : "pass",
        risk_level: blocked ? 3 : 0,
        violation_reason: blocked ? "mig-test-block" : "",
        hit_rules: blocked ? [{ rule_name: "mig-test-rule", rule_desc: "migration synthetic rule" }] : [],
      },
    }));
    return;
  }
  if (req.method === "POST" && p === "/api/firewall/openclaw/device/register") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ code: 200, data: { registered: true } }));
    return;
  }
  res.writeHead(404, { "Content-Type": "application/json" });
  res.end('{"code":404,"message":"not found (verify-migration fake firewall)"}');
});

// ---------------- 假 LLM ----------------
function chatCompletionBody(script) {
  if (script === "toolcall" || (script === "toolcall-once" && !toolcallOnceUsed)) {
    toolcallOnceUsed = true;
    return {
      id: "chatcmpl-mig-toolcall",
      object: "chat.completion",
      created: Math.floor(Date.now() / 1000),
      model: "fake-model",
      choices: [{
        index: 0,
        message: {
          role: "assistant",
          content: null,
          tool_calls: [{
            id: "call_mig_1",
            type: "function",
            function: {
              name: "exec",
              arguments: JSON.stringify({ command: ["bash", "-c", "touch /tmp/aw-tool-ran"] }),
            },
          }],
        },
        finish_reason: "tool_calls",
      }],
      usage: { prompt_tokens: 10, completion_tokens: 10, total_tokens: 20 },
    };
  }
  return {
    id: "chatcmpl-mig-text",
    object: "chat.completion",
    created: Math.floor(Date.now() / 1000),
    model: "fake-model",
    choices: [{
      index: 0,
      message: { role: "assistant", content: "AUTOWATCH-FAKE-REPLY" },
      finish_reason: "stop",
    }],
    usage: { prompt_tokens: 10, completion_tokens: 10, total_tokens: 20 },
  };
}

const llmServer = http.createServer(async (req, res) => {
  const url = req.url || "";
  if (req.method === "GET" && url === "/__reset") {
    try { fs.writeFileSync(LLM_LOG, ""); } catch {}
    res.writeHead(200); res.end('{"ok":true}');
    return;
  }
  if (req.method === "GET" && url === "/__count") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ fw: countLines(FW_LOG), llm: countLines(LLM_LOG) }));
    return;
  }
  const body = await readBody(req);
  append(LLM_LOG, { ts: Date.now(), method: req.method, path: url, headers: req.headers, body: body ? safeJson(body) : null });

  if (req.method === "GET" && url.includes("/models")) {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ object: "list", data: [{ id: "fake-model", object: "model", owned_by: "verify-migration" }] }));
    return;
  }
  if (req.method === "POST" && url.includes("/chat/completions")) {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(chatCompletionBody(readScript())));
    return;
  }
  res.writeHead(404, { "Content-Type": "application/json" });
  res.end('{"error":{"message":"not found (verify-migration fake llm)"}}');
});

fwServer.listen(FW_PORT, "127.0.0.1", () => console.log(`[fake] firewall on 127.0.0.1:${FW_PORT}`));
llmServer.listen(LLM_PORT, "127.0.0.1", () => console.log(`[fake] llm on 127.0.0.1:${LLM_PORT}`));
console.log(`[fake] state dir: ${STATE_DIR}`);

function shutdown() { process.exit(0); }
process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
