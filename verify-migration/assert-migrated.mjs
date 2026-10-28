#!/usr/bin/env node
// assert-migrated.mjs — 迁移插件端到端断言（M0/M1/M2/M4；M3 由 hook-smoke.mjs 自行断言）
// 参数:
//   <installFwJsonl>
//   <m1FwJsonl> <m1AgentJson> <m1AgentErr> <m1LlmCount>
//   <m2FwJsonl> <m2AgentJson> <m2AgentErr> <m2LlmCount>
import fs from "node:fs";

const a = process.argv.slice(2);
function readJsonl(p) {
  try {
    return fs.readFileSync(p, "utf8").split("\n").filter((l) => l.trim()).map((l) => JSON.parse(l));
  } catch {
    return [];
  }
}
function readText(p) {
  try { return fs.readFileSync(p, "utf8"); } catch { return ""; }
}
const ok = (id, msg) => console.log(`MIG_TEST ${id} PASS ${msg}`);
const bad = (id, msg) => { failed++; console.log(`MIG_TEST ${id} FAIL ${msg}`); };
const soft = (id, msg) => console.log(`MIG_TEST ${id} WARN ${msg}（软断言不计失败）`);
let failed = 0;

const installFw = readJsonl(a[0]);
const validates = (rows) => rows.filter((e) => (e.path || "").split("?")[0] === "/api/firewall/openclaw/validate");

// ---------- M0: 安装链路 + 设备注册 ----------
{
  const reg = installFw.filter((e) => (e.path || "").includes("/device/register"));
  if (reg.length >= 1) {
    const did = reg[0].body && reg[0].body.device_id;
    if (/^[0-9a-f]{64}$/.test(did || "")) {
      const pv = reg[0].body.plugin_version ? String(reg[0].body.plugin_version) : "";
      ok("M0-device-register", `设备注册请求存在 device_id=${did.slice(0, 12)}... plugin_version=${pv}`);
    } else {
      bad("M0-device-register", `device/register 存在但 device_id 非法: "${did}"`);
    }
  } else {
    bad("M0-device-register", `未见 device/register 请求（install 阶段共 ${installFw.length} 条请求）`);
  }
}

// ---------- M1: 聚合 + 去重 ----------
{
  const fw = validates(readJsonl(a[1]));
  const out = readText(a[2]) + "\n" + readText(a[3]);
  const llm = parseInt(a[4], 10);
  const MARK = "MIG-M1";
  const withMark = fw.filter((e) => JSON.stringify(e.body?.content || {}).includes(MARK));
  const inHits = withMark.filter((e) => e.body?.stage === "input");
  const outHits = withMark.filter((e) => e.body?.stage === "output");

  if (inHits.length === 1) {
    const b = inHits[0].body;
    if (b.session_id === "mig-m1") {
      if (/^run-/.test(b.trace_id || "")) {
        ok("M1-input", `input 审计恰好 1 条且来自官方钩子通道（session_id=mig-m1, trace_id=${b.trace_id.slice(0, 26)}..., device_id=${String(b.device_id || "").slice(0, 12)}...）`);
      } else {
        ok("M1-input", `input 审计恰好 1 条，session_id=mig-m1，trace=${b.trace_id}（非 run- 前缀，走了 fetch 兜底）`);
      }
    } else {
      bad("M1-input", `input 审计 1 条但 session_id="${b.session_id}"（期望 mig-m1）`);
    }
  } else if (inHits.length === 0) {
    bad("M1-input", `无含 ${MARK} 的 input 审计（validate 共 ${fw.length} 条）`);
  } else {
    bad("M1-input", `含 ${MARK} 的 input 审计有 ${inHits.length} 条（去重失效）`);
  }

  if (outHits.length === 1) {
    const b = outHits[0].body;
    if (b.session_id === "mig-m1") {
      const sameRun = inHits.length === 1 && inHits[0].body.trace_id === b.trace_id;
      ok("M1-output", `output 审计恰好 1 条且 session_id=mig-m1${sameRun ? "，trace_id 与 input 相同（同回合配对成立）" : `，trace_id=${b.trace_id}`}`);
    } else {
      bad("M1-output", `output 审计 1 条但 session_id="${b.session_id}"（期望 mig-m1）`);
    }
  } else if (outHits.length === 0) {
    bad("M1-output", `无含 ${MARK} 的 output 审计`);
  } else {
    bad("M1-output", `含 ${MARK} 的 output 审计有 ${outHits.length} 条（去重失效）`);
  }

  if (llm >= 1) {
    ok("M1-llm", `假 LLM 收到 ${llm} 次调用（透传正常）`);
  } else {
    bad("M1-llm", `假 LLM 调用数 ${llm}，应 ≥1`);
  }

  if (out.includes("AUTOWATCH-FAKE-REPLY")) {
    ok("M1-reply", "agent 回复含假 LLM 文本");
  } else {
    soft("M1-reply", "agent 输出未见 AUTOWATCH-FAKE-REPLY");
  }
}

// ---------- M2: 输入截断 ----------
{
  const fw = validates(readJsonl(a[5]));
  const out = readText(a[6]) + "\n" + readText(a[7]);
  const llm = parseInt(a[8], 10);
  const MARK = "MIG-M2";
  const inHits = fw.filter((e) => e.body?.stage === "input" && JSON.stringify(e.body?.content || {}).includes(MARK));
  const outHits = fw.filter((e) => e.body?.stage === "output");

  if (inHits.length === 1 && inHits[0].body.session_id === "mig-m2") {
    ok("M2-input-reported", `input 审计 1 条且 session_id=mig-m2（官方输入门上报，trace_id=${inHits[0].body.trace_id?.slice(0, 26)}...）`);
  } else {
    bad("M2-input-reported", `input 审计异常: ${inHits.length} 条，session_id=${inHits[0]?.body?.session_id}`);
  }

  if (llm === 0) {
    ok("M2-no-llm", "假 LLM 零调用（输入在模型前被截断）");
  } else {
    bad("M2-no-llm", `假 LLM 被调用 ${llm} 次，截断未生效`);
  }

  if (outHits.length === 0) {
    ok("M2-no-output-audit", "无 output 审计（回合未到输出阶段）");
  } else {
    soft("M2-no-output-audit", `出现 ${outHits.length} 条 output 审计`);
  }

  if (out.includes("无法执行该请求")) {
    ok("M2-block-tip", "用户可见 blockTip 出现在 agent 输出");
  } else {
    soft("M2-block-tip", "agent 输出未见 blockTip 文本");
  }
}

// ---------- M4: 设备一致性（网关侧三个阶段的 validate device_id 一致） ----------
{
  const phases = [
    ["install", validates(installFw)],
    ["m1", validates(readJsonl(a[1]))],
    ["m2", validates(readJsonl(a[5]))],
  ];
  const ids = new Set();
  let total = 0;
  for (const [, rows] of phases) {
    for (const r of rows) {
      const d = r.body?.device_id;
      if (d) { ids.add(d); total++; }
    }
  }
  if (total > 0 && ids.size === 1) {
    const [id] = ids;
    if (/^[0-9a-f]{64}$/.test(id)) {
      ok("M4-device-consistency", `网关侧全部 ${total} 条 validate 的 device_id 一致（${id.slice(0, 12)}...，64hex）`);
    } else {
      bad("M4-device-consistency", `device_id 唯一但格式非法: "${id}"`);
    }
  } else {
    bad("M4-device-consistency", `device_id 出现 ${ids.size} 个不同值（${total} 条请求）`);
  }
}

console.log(`MIG_RESULT assert ${failed === 0 ? "PASS" : `FAIL(${failed})`}`);
process.exit(failed === 0 ? 0 : 1);
