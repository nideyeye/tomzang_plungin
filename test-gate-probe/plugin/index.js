// gate-probe — OpenClaw 官方钩子行为探针（research-audit 分支专用）
// 目的：在真实 openclaw 运行时里验证：
//   1. before_agent_run 返回 block 能否截断回合（输入门）
//   2. before_agent_reply 返回 handled+reply 能否代答（免模型回复）
//   3. llm_input / llm_output 是否触发、是否带 sessionId/runId（观测 + 会话聚合）
// 每个钩子触发都追加一行 JSON 到 GATE_PROBE_LOG（默认 /logs/gate-probe-events.jsonl），
// 同时带 [gate-probe] 前缀打 console 日志，便于在 gateway stdout 中定位。
// 触发词：
//   提示词含 "GATE_BLOCK"   → before_agent_run 返回 block
//   提示词含 "GATE_ANSWER"  → before_agent_reply 返回 handled（代答）

var fs = require("fs");

var EVENT_LOG = process.env.GATE_PROBE_LOG || "/logs/gate-probe-events.jsonl";

function emit(ev) {
  ev.t = new Date().toISOString();
  try {
    fs.appendFileSync(EVENT_LOG, JSON.stringify(ev) + "\n");
  } catch (e) {
    // /logs 不可写时仅依赖 console 日志
  }
  console.log("[gate-probe] " + ev.kind + " " + JSON.stringify(ev));
}

function snippet(v, n) {
  var s = v === undefined || v === null ? "" : String(v);
  return s.length > n ? s.slice(0, n) + "..." : s;
}

var plugin = {
  name: "gate-probe",
  register: function (api) {
    console.log("[gate-probe] register() called, event log: " + EVENT_LOG);
    emit({ kind: "register" });

    // ─── 输入门：before_agent_run ───
    api.on("before_agent_run", async function (event, ctx) {
      emit({
        kind: "before_agent_run",
        prompt: snippet(event.prompt, 160),
        messagesCount: Array.isArray(event.messages) ? event.messages.length : null,
        ctxSessionId: ctx.sessionId || null,
        ctxSessionKey: ctx.sessionKey || null,
        ctxAgentId: ctx.agentId || null
      });
      if (String(event.prompt || "").indexOf("GATE_BLOCK") !== -1) {
        emit({ kind: "DECISION", hook: "before_agent_run", outcome: "block" });
        return {
          outcome: "block",
          reason: "gate-probe-block",
          message: "[gate-probe] 输入已被 before_agent_run 拦截（官方 Gate 截断）"
        };
      }
    });

    // ─── 代答门：before_agent_reply ───
    api.on("before_agent_reply", async function (event, ctx) {
      var body = String(event.cleanedBody || "");
      emit({
        kind: "before_agent_reply",
        cleanedBody: snippet(body, 160),
        ctxSessionId: ctx.sessionId || null,
        ctxSessionKey: ctx.sessionKey || null
      });
      if (body.indexOf("GATE_ANSWER") !== -1) {
        emit({ kind: "DECISION", hook: "before_agent_reply", outcome: "handled" });
        return {
          handled: true,
          reply: { text: "[gate-probe] 代答：本回复由插件直接提供，未调用模型" },
          reason: "gate-probe-answer"
        };
      }
    });

    // ─── 观测：llm_input / llm_output ───
    api.on("llm_input", async function (event, ctx) {
      emit({
        kind: "llm_input",
        sessionId: event.sessionId || null,
        runId: event.runId || null,
        provider: event.provider || null,
        model: event.model || null,
        prompt: snippet(event.prompt, 160),
        historyCount: Array.isArray(event.historyMessages) ? event.historyMessages.length : null,
        hasSystemPrompt: !!event.systemPrompt
      });
    });

    api.on("llm_output", async function (event, ctx) {
      emit({
        kind: "llm_output",
        sessionId: event.sessionId || null,
        runId: event.runId || null,
        provider: event.provider || null,
        model: event.model || null,
        assistantTexts: (event.assistantTexts || []).map(function (t) {
          return snippet(t, 100);
        })
      });
    });

    // ─── 辅助观测：终结前 / 会话生命周期 ───
    api.on("before_agent_finalize", async function (event, ctx) {
      emit({
        kind: "before_agent_finalize",
        sessionId: event.sessionId || null,
        lastAssistantMessage: snippet(event.lastAssistantMessage, 160)
      });
    });

    api.on("session_start", async function (event, ctx) {
      emit({ kind: "session_start", ctxSessionKey: ctx.sessionKey || null });
    });

    api.on("session_end", async function (event, ctx) {
      emit({ kind: "session_end", ctxSessionKey: ctx.sessionKey || null });
    });
  }
};

module.exports = plugin;
