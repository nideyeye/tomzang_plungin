#!/usr/bin/env node
// verify-migration/hook-smoke.mjs — M3: 工具防护钩子确定性断言（含会话贯通验证）
// 用法: node hook-smoke.mjs <pluginDir> <防火墙baseURL> <authKey> <fwModeFile> <fwLogJsonl>
// 前置: 假防火墙 fw-mode 由本脚本设置为 "tool-block"（仅拦 tool_call/skill）
import { createRequire } from "node:module";
import fs from "node:fs";
import path from "node:path";

const pluginDir = process.argv[2];
const firewallUrl = process.argv[3];
const authKey = process.argv[4] || "test-auth-key";
const modeFile = process.argv[5];
const fwLog = process.argv[6] || "/logs/fake/fw-requests.jsonl";

if (!pluginDir || !firewallUrl) {
  console.error("usage: hook-smoke.mjs <pluginDir> <firewallUrl> [authKey] [modeFile] [fwLog]");
  process.exit(2);
}
if (modeFile) {
  try { fs.writeFileSync(modeFile, "tool-block"); } catch {}
}

const require = createRequire(import.meta.url);
const plugin = require(path.join(pluginDir, "index.js"));

const handlers = {};
const api = {
  logger: console,
  runtime: {
    config: {
      current: () => ({
        plugins: {
          entries: {
            tomzang_plungin: { config: { firewallUrl, authKey, debug: "true" } },
          },
        },
      }),
    },
  },
  on: (name, fn) => { handlers[name] = fn; },
};
plugin.register(api);

const before = handlers["before_tool_call"];
const after = handlers["after_tool_call"];
if (typeof before !== "function" || typeof after !== "function") {
  console.log("MIG_TEST M3-register FAIL before/after_tool_call 未注册");
  process.exit(1);
}
console.log("MIG_TEST M3-register PASS register() + before/after_tool_call 注册成功");

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let failed = 0;
const ok = (id, m) => console.log(`MIG_TEST ${id} PASS ${m}`);
const bad = (id, m) => { failed++; console.log(`MIG_TEST ${id} FAIL ${m}`); };

const SESS = "mig-m3";
const RUN = "mig-m3-run"; // 插件侧会拼 "run-" + runId
function readFw() {
  try {
    return fs.readFileSync(fwLog, "utf8").split("\n").filter((l) => l.trim()).map((l) => JSON.parse(l));
  } catch {
    return [];
  }
}
const validates = (rows) => rows.filter((e) => (e.path || "").split("?")[0] === "/api/firewall/openclaw/validate");

// 用例 1: before_tool_call exec + tool-block → 拦截 + 审计带真实 session/trace
{
  const len0 = validates(readFw()).length;
  const ev = { toolName: "exec", params: { command: ["bash", "-c", "touch /tmp/aw-tool-ran"] } };
  const ctx = { toolName: "exec", sessionId: SESS, runId: RUN, toolCallId: "tc-mig-3" };
  const res = await before(ev, ctx);
  await sleep(600);
  if (res && res.block === true) {
    ok("M3-tool-block", `before_tool_call 返回 block（blockReason=${String(res.blockReason).slice(0, 24)}...）`);
  } else {
    bad("M3-tool-block", `期望 block:true 实际 ${JSON.stringify(res)}`);
  }
  const v = validates(readFw()).slice(len0).find((e) => e.body?.source === "tool_call");
  if (v && v.body.session_id === SESS && v.body.trace_id === "run-" + RUN) {
    ok("M3-tool-reported", `tool_call 审计带真实会话（session_id=${v.body.session_id}, trace_id=${v.body.trace_id}）——阶段0修复生效`);
  } else {
    bad("M3-tool-reported", `tool_call 审计异常: ${JSON.stringify(v?.body || null).slice(0, 140)}`);
  }
  const did = v?.body?.device_id || "";
  if (/^[0-9a-f]{64}$/.test(did)) {
    ok("M3-device", `tool_call 审计 device_id=64hex（${did.slice(0, 12)}...）`);
  } else {
    bad("M3-device", `device_id 非法: "${did}"`);
  }
}

// 用例 2: 白名单 web_search → 放行且不触发防火墙
{
  const len0 = readFw().length;
  const res = await before({ toolName: "web_search", params: { query: "mig bypass test" } }, { toolName: "web_search", sessionId: SESS });
  await sleep(400);
  const grown = readFw().length - len0;
  if (res === undefined && grown === 0) {
    ok("M3-whitelist", "web_search 白名单放行且未触发防火墙");
  } else {
    bad("M3-whitelist", `res=${JSON.stringify(res)} 防火墙新增 ${grown} 条（可能被网关心跳干扰，重跑确认）`);
  }
}

// 用例 3: after_tool_call 结果审计带会话
{
  const len0 = validates(readFw()).length;
  const ctx2 = { toolName: "exec", sessionId: SESS, runId: RUN, toolCallId: "tc-mig-3b", result: "MIG-M3-RESULT demo output" };
  await after(ctx2);
  await sleep(600);
  const v = validates(readFw()).slice(len0).find((e) => e.body?.source === "tool_result");
  if (v && v.body.session_id === SESS && String(v.body.content?.response || "").includes("MIG-M3-RESULT")) {
    ok("M3-tool-result", `tool_result 审计带会话（session_id=${v.body.session_id}, trace_id=${v.body.trace_id}）`);
  } else {
    bad("M3-tool-result", `tool_result 审计异常: ${JSON.stringify(v?.body || null).slice(0, 160)}`);
  }
}

console.log(`MIG_RESULT M3 ${failed === 0 ? "PASS" : `FAIL(${failed})`}`);
process.exit(failed === 0 ? 0 : 1);
