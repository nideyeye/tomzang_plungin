#!/usr/bin/env node
// assert-gate.mjs — 官方钩子行为断言
// 参数（三组场景，各 4 个）:
//   <eventsJsonl> <agentJson> <agentErr> <llmCount>   ×3 (T-A 观测 / T-B 截断 / T-C 代答)
import fs from "node:fs";

const args = process.argv.slice(2);
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
function eventsOf(i) { return readJsonl(args[i * 4]); }
function agentOut(i) { return readText(args[i * 4 + 1]) + "\n" + readText(args[i * 4 + 2]); }
function llmCount(i) { return parseInt(args[i * 4 + 3], 10); }

let failed = 0;
const ok = (id, msg) => console.log(`GP_TEST ${id} PASS ${msg}`);
const bad = (id, msg) => { failed++; console.log(`GP_TEST ${id} FAIL ${msg}`); };
const soft = (id, msg) => console.log(`GP_TEST ${id} WARN ${msg}（软断言不计失败）`);

// ---------- T-A 观测 ----------
{
  const ev = eventsOf(0);
  const out = agentOut(0);
  const llm = llmCount(0);
  const li = ev.find((e) => e.kind === "llm_input" && (e.prompt || "").includes("GP-TA"));
  const lo = ev.find((e) => e.kind === "llm_output");

  if (li) {
    if (li.sessionId && li.runId) {
      ok("TA-llm-input", `llm_input 触发且带 sessionId=${li.sessionId} runId=${String(li.runId).slice(0, 18)}... provider=${li.provider}/${li.model} history=${li.historyCount}`);
    } else {
      bad("TA-llm-input", `llm_input 触发但缺 sessionId/runId: ${JSON.stringify(li).slice(0, 200)}`);
    }
  } else {
    bad("TA-llm-input", `llm_input 未触发（事件 ${ev.length} 条，kinds=${ev.map((e) => e.kind).join(",") || "无"}）`);
  }

  if (lo) {
    if (lo.sessionId && lo.sessionId === (li && li.sessionId)) {
      ok("TA-llm-output", `llm_output 触发，sessionId 与 llm_input 一致（可聚合同一会话） assistant=${JSON.stringify(lo.assistantTexts)}`);
    } else {
      bad("TA-llm-output", `llm_output sessionId 缺失或不一致: input=${li && li.sessionId} output=${lo.sessionId}`);
    }
  } else {
    bad("TA-llm-output", `llm_output 未触发（事件 kinds=${ev.map((e) => e.kind).join(",") || "无"}）`);
  }

  if (llm >= 1) {
    ok("TA-llm-called", `假 LLM 收到 ${llm} 次真实调用（观测场景应有模型调用）`);
  } else {
    bad("TA-llm-called", `假 LLM 调用数为 ${llm}，正常场景应 ≥1`);
  }

  if (out.includes("AUTOWATCH-FAKE-REPLY")) {
    ok("TA-reply", "agent 回复含假 LLM 文本（端到端透传正常）");
  } else {
    soft("TA-reply", "agent 输出未见 AUTOWATCH-FAKE-REPLY");
  }

  const fin = ev.find((e) => e.kind === "before_agent_finalize");
  if (fin) {
    ok("TA-finalize", `before_agent_finalize 触发（输出侧官方门可用）last=${JSON.stringify(fin.lastAssistantMessage).slice(0, 80)}`);
  } else {
    soft("TA-finalize", "before_agent_finalize 未触发");
  }
}

// ---------- T-B 截断 ----------
{
  const ev = eventsOf(1);
  const out = agentOut(1);
  const llm = llmCount(1);
  const bar = ev.find((e) => e.kind === "before_agent_run");
  const decision = ev.find((e) => e.kind === "DECISION" && e.hook === "before_agent_run" && e.outcome === "block");
  const liLeak = ev.find((e) => e.kind === "llm_input");

  if (bar) {
    ok("TB-gate-fired", `before_agent_run 触发（prompt 前缀=${JSON.stringify((bar.prompt || "").slice(0, 40))}）`);
  } else {
    bad("TB-gate-fired", `before_agent_run 未触发（事件 kinds=${ev.map((e) => e.kind).join(",") || "无"}）`);
  }

  if (decision) {
    ok("TB-gate-decision", "before_agent_run 返回了 block 决策");
  } else {
    bad("TB-gate-decision", "未见 block 决策（插件返回值未被接受或未触发）");
  }

  if (llm === 0) {
    ok("TB-no-llm", "假 LLM 零调用（输入在模型前被截断）");
  } else {
    bad("TB-no-llm", `假 LLM 被调用 ${llm} 次，截断未生效`);
  }

  if (liLeak) {
    bad("TB-no-llm-input", `截断后仍出现 llm_input（${JSON.stringify(liLeak.prompt || "").slice(0, 60)}）`);
  } else {
    ok("TB-no-llm-input", "截断后无 llm_input 事件");
  }

  if (out.includes("已被 before_agent_run 拦截")) {
    ok("TB-block-message", "用户可见 block message 出现在 agent 输出中");
  } else {
    soft("TB-block-message", "agent 输出未见 block message（CLI 输出面可能不含）");
  }
}

// ---------- T-C 代答 ----------
{
  const ev = eventsOf(2);
  const out = agentOut(2);
  const llm = llmCount(2);
  const barReply = ev.find((e) => e.kind === "before_agent_reply");
  const decision = ev.find((e) => e.kind === "DECISION" && e.hook === "before_agent_reply" && e.outcome === "handled");
  const runLeak = ev.find((e) => e.kind === "before_agent_run");

  if (barReply) {
    ok("TC-reply-hook-fired", `before_agent_reply 触发（cleanedBody=${JSON.stringify((barReply.cleanedBody || "").slice(0, 40))}）`);
  } else {
    bad("TC-reply-hook-fired", `before_agent_reply 未触发（事件 kinds=${ev.map((e) => e.kind).join(",") || "无"}）`);
  }

  if (decision) {
    ok("TC-handled-decision", "before_agent_reply 返回了 handled 决策");
  } else {
    bad("TC-handled-decision", "未见 handled 决策");
  }

  if (llm === 0) {
    ok("TC-no-llm", "假 LLM 零调用（代答未经过模型）");
  } else {
    bad("TC-no-llm", `假 LLM 被调用 ${llm} 次，代答未生效`);
  }

  if (runLeak) {
    soft("TC-agent-run", "代答后仍出现 before_agent_run（handled 可能不短路 agent run）");
  } else {
    ok("TC-no-agent-run", "代答后无 before_agent_run（回合被短路）");
  }

  if (out.includes("[gate-probe] 代答")) {
    ok("TC-answer-text", "代答文本出现在 agent 输出中");
  } else {
    soft("TC-answer-text", "agent 输出未见代答文本（CLI 输出面可能不含）");
  }
}

console.log(`GP_RESULT assert ${failed === 0 ? "PASS" : `FAIL(${failed})`}`);
process.exit(failed === 0 ? 0 : 1);
