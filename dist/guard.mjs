#!/usr/bin/env node
/**
 * guard.mjs — WorkBuddy 防火墙插件的 hook 入口
 *
 * 用法：  node guard.mjs <mode>
 *   mode = session | input | tool | tool_result | output
 *   省略 mode 时按 stdin 里的 hook_event_name 自动推断
 *
 * 输入：stdin 一个 JSON（Claude Code / WorkBuddy hook 标准输入）
 * 输出：
 *   放行  → exit 0，stdout 空
 *   确认  → exit 0，stdout { hookSpecificOutput.permissionDecision: "ask" }   （仅 PreToolUse）
 *   阻断  → exit 2，stdout { decision: "block" } / { permissionDecision: "deny" }
 *
 * 全程 fail-open：任何异常都 exit 0 放行。
 */

import fs from 'node:fs';
import {
  loadConfig, validateConfig, callFirewallApi, logInfo, logDebug, preview,
  pluginRoot, shouldMaskOutput,
} from './firewall.mjs';
import {
  stripMetadataPrefix, contentToText, shouldSkipFirewall,
  isSkillFilePath, expandHome, stringifyParams,
  lastAssistantTextFromTranscript,
} from './extract.mjs';

const MAX_AUDIT_CHARS = 20000;   // 单次送审内容上限，避免把整个大文件丢给后端
const REASON_MAX = 256;
// --explain：只打印「这份输入会被抽成什么文本去送审」，不调后端。排误判用。
const EXPLAIN = process.argv.includes('--explain');

function explain(label, text) {
  process.stderr.write(`[explain] ${label} → ${text.length} chars\n---8<---\n${text}\n--->8---\n`);
}

// ───────── stdin ─────────

async function readStdin() {
  try {
    const chunks = [];
    for await (const chunk of process.stdin) chunks.push(chunk);
    const raw = Buffer.concat(chunks).toString('utf8').trim();
    if (!raw) return {};
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === 'object' ? parsed : {};
  } catch (e) {
    logInfo('guard', 'stdin_parse_failed', String((e && e.message) || e));
    return {};
  }
}

// ───────── 出口协议 ─────────

function allow(config, category, action, data) {
  logDebug(config, category, action, data);
  process.exit(0);
}

/** UserPromptSubmit / Stop 阶段阻断 */
function blockPrompt(reason) {
  process.stderr.write(reason + '\n');
  process.stdout.write(JSON.stringify({ decision: 'block', reason }));
  process.exit(2);
}

/** PreToolUse 阶段阻断（与内置 subscription-gate 插件同构） */
function denyTool(reason) {
  process.stderr.write(reason + '\n');
  process.stdout.write(JSON.stringify({
    continue: false,
    stopReason: reason,
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: 'deny',
      permissionDecisionReason: reason,
    },
  }));
  process.exit(2);
}

/** PreToolUse 阶段二次确认 */
function askTool(reason) {
  process.stdout.write(JSON.stringify({
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: 'ask',
      permissionDecisionReason: reason.slice(0, REASON_MAX),
    },
  }));
  process.exit(0);
}

/**
 * Stop 阶段的 reason 是喂给「模型」的（UserPromptSubmit 的 reason 才是喂给用户的），
 * 所以这里必须给可执行的指令，而不是那句面向用户的 blockTip ——
 * 否则模型拿到「抱歉我无法执行该请求」只会原地打转。
 */
function stopBlockReason(fw) {
  const why = fw.violationReason ? `（判定：${fw.violationReason}）` : '';
  const rules = (fw.hitRules || [])
    .map((r) => (r && typeof r === 'object' ? (r.rule_name || r.rule_code) : String(r)))
    .filter(Boolean)
    .slice(0, 3)
    .join('、');
  return `你上一条回复被内容安全组件拦截${why}${rules ? `，命中规则：${rules}` : ''}。`
    + '请重新组织回答，移除其中的敏感信息后再次输出；不要向用户复述被拦截的内容，也不要提及本次拦截。';
}

function truncate(text, max = MAX_AUDIT_CHARS) {
  if (typeof text !== 'string') return '';
  return text.length > max ? text.slice(0, max) : text;
}

function buildReason(prefix, detail, violationReason) {
  let reason = prefix;
  if (detail) reason += `\n参数: ${detail.slice(0, 100)}${detail.length > 100 ? '…' : ''}`;
  if (violationReason) reason += `\n\n风险提示: ${violationReason}`;
  return reason.length > REASON_MAX ? reason.slice(0, REASON_MAX - 3) + '…' : reason;
}

// ───────── 模式：session ─────────

function handleSession(input, config) {
  logInfo('session', input.hook_event_name || 'session', {
    sessionId: input.session_id || '-',
    source: input.source || '-',
    cwd: input.cwd || '-',
  });
  allow(config, 'session', 'logged', { event: input.hook_event_name });
}

// ───────── 模式：input（UserPromptSubmit）─────────

async function handleInput(input, config) {
  const raw = contentToText(input.prompt ?? input.user_prompt ?? '');
  const prompt = truncate(stripMetadataPrefix(raw));

  if (!prompt) {
    return allow(config, 'input', 'skipped_empty', { rawLength: raw.length });
  }
  if (shouldSkipFirewall(prompt)) {
    return allow(config, 'input', 'skipped_builtin_or_internal', { preview: preview(prompt, 80) });
  }

  if (EXPLAIN) { explain('input/prompt', prompt); return allow(config, 'input', 'explain', {}); }

  const fw = await callFirewallApi(config, {
    prompt,
    sessionId: input.session_id || '',
    stage: 'input',
    source: 'text',
  });

  if (fw.error) {
    // fail-open：后端不可达 / 超时，放行
    return allow(config, 'input', 'fail_open', { error: fw.error });
  }

  if (fw.result === 'block') {
    logInfo('input', 'blocked', {
      sessionId: input.session_id || '-',
      riskLevel: fw.riskLevel,
      hitRules: fw.hitRules,
      violationReason: fw.violationReason,
      preview: preview(prompt),
    });
    return blockPrompt(config.blockTip);
  }

  // 输入脱敏：hook 无法改写用户原始 prompt，按配置决定「仅记录」还是「阻断」
  if (fw.maskedContent && fw.maskedContent.prompt && fw.maskedContent.prompt !== prompt) {
    logInfo('input', 'masked_detected', {
      hitRules: fw.hitRules,
      originalPreview: preview(prompt),
      maskedPreview: preview(fw.maskedContent.prompt),
      behavior: config.onMaskedInput,
    });
    if (config.onMaskedInput === 'block') {
      return blockPrompt(config.blockTip);
    }
  }

  return allow(config, 'input', 'passed', { riskLevel: fw.riskLevel, action: fw.action });
}

// ───────── 模式：tool（PreToolUse）─────────

async function handleTool(input, config) {
  const toolName = input.tool_name || input.toolName || '';
  const params = input.tool_input ?? input.toolInput ?? input.params ?? {};

  if (config.toolWhitelist.includes(toolName)) {
    return allow(config, 'tool', 'skipped_whitelist', { toolName });
  }

  // ── skill 正文审计（与 tool_call 互斥：命中 skill 就不走普通 tool_call）──
  const skillPath = findSkillPath(params);
  if (skillPath) {
    let content = '';
    try {
      content = fs.readFileSync(expandHome(skillPath), 'utf8');
    } catch (e) {
      logInfo('skill', 'read_failed', { skillPath, error: String((e && e.message) || e) });
    }
    if (content) {
      const payload = JSON.stringify([{ path: 'SKILL.md', content: truncate(content) }]);
      const fw = await callFirewallApi(config, {
        prompt: payload,
        sessionId: input.session_id || '',
        stage: 'input',
        source: 'skill',
      });
      if (fw.action === 'block' || fw.error || (fw.action && fw.action !== 'pass')) {
        logInfo('skill', 'alert', {
          toolName, skillPath,
          action: fw.action, riskLevel: fw.riskLevel,
          violationReason: fw.violationReason, error: fw.error || undefined,
        });
      } else {
        logDebug(config, 'skill', 'checked', { toolName, skillPath, action: fw.action || '(empty)' });
      }
      if (fw.action === 'block') return denyTool(config.blockTip);
      if (!fw.error && fw.action && fw.action !== 'pass') {
        return askTool(buildReason(`读取 skill: ${skillPath}`, '', fw.violationReason));
      }
      return allow(config, 'skill', 'passed', { skillPath, action: fw.action || '(empty)' });
    }
    // 读不到正文 → fail-open，落到下面普通 tool_call 审计
  }

  const paramsText = truncate(stringifyParams(params));
  const fw = await callFirewallApi(config, {
    prompt: paramsText,
    sessionId: input.session_id || '',
    stage: 'input',
    source: 'tool_call',
  });

  // 放行不落盘，避免日志里堆满每次工具调用的原文；只有异常/告警才留痕
  if (fw.error || fw.action === 'block' || (fw.action && fw.action !== 'pass')) {
    logInfo('tool', 'alert', {
      toolName,
      action: fw.action, riskLevel: fw.riskLevel,
      violationReason: fw.violationReason, error: fw.error || undefined,
      paramsPreview: preview(paramsText, 300),
    });
  } else {
    logDebug(config, 'tool', 'checked', { toolName, action: fw.action || '(empty)' });
  }

  if (fw.error) return allow(config, 'tool', 'fail_open', { toolName, error: fw.error });
  if (fw.action === 'block') return denyTool(config.blockTip);
  if (!fw.action || fw.action === 'pass') return allow(config, 'tool', 'passed', { toolName });

  // review / warn 等 → 二次确认
  return askTool(buildReason(`执行工具: ${toolName}`, paramsText, fw.violationReason));
}

function findSkillPath(params) {
  const candidates = [params.file_path, params.path, params.file, params.skill, params.notebook_path];
  for (const c of candidates) {
    if (typeof c === 'string' && isSkillFilePath(c)) return c;
  }
  return null;
}

// ───────── 模式：tool_result（PostToolUse）─────────

async function handleToolResult(input, config) {
  if (!config.auditToolResult) return allow(config, 'tool_result', 'disabled', {});

  const toolName = input.tool_name || input.toolName || '';
  if (config.toolWhitelist.includes(toolName)) {
    return allow(config, 'tool_result', 'skipped_whitelist', { toolName });
  }

  const commandText = truncate(stringifyParams(input.tool_input ?? input.toolInput ?? {}));
  let resultText = '';
  const resp = input.tool_response ?? input.toolResponse ?? input.result;
  if (resp !== undefined && resp !== null) {
    resultText = typeof resp === 'string' ? resp : stringifyParams(resp);
    // 常见形态：{ stdout, stderr, ... }
    if (typeof resp === 'object' && (resp.stdout || resp.stderr)) {
      resultText = [resp.stdout, resp.stderr, resp.content].filter(Boolean).join('\n');
    }
  }
  resultText = truncate(resultText);

  if (!commandText && !resultText) {
    return allow(config, 'tool_result', 'skipped_empty', { toolName });
  }

  const fw = await callFirewallApi(config, {
    prompt: commandText,
    response: resultText,
    sessionId: input.session_id || '',
    stage: 'output',
    source: 'tool_result',
  });

  // 结果已经产生，无法真正拦截：命中 block 只告警，由后端留存审计记录
  if (fw.action === 'block') {
    logInfo('tool_result', 'blocked_alert', {
      toolName,
      riskLevel: fw.riskLevel,
      violationReason: fw.violationReason,
      hitRules: fw.hitRules,
      resultPreview: preview(resultText, 300),
    });
  } else if (shouldMaskOutput(fw)) {
    logInfo('tool_result', 'masked_detected', {
      toolName,
      hitRules: fw.hitRules,
      originalPreview: preview(resultText, 300),
      maskedPreview: preview(fw.maskedContent.response, 300),
    });
  } else {
    logDebug(config, 'tool_result', 'passed', { toolName });
  }

  return allow(config, 'tool_result', 'done', { toolName, action: fw.action || '(empty)' });
}

// ───────── 模式：output（Stop）─────────

async function handleOutput(input, config) {
  if (!config.auditOutput) return allow(config, 'output', 'disabled', {});
  // 已经因阻断重入过一次，避免死循环
  if (input.stop_hook_active === true) {
    return allow(config, 'output', 'skipped_stop_hook_active', {});
  }

  const text = truncate(stripMetadataPrefix(
    lastAssistantTextFromTranscript(input.transcript_path || ''),
  ));
  if (!text) return allow(config, 'output', 'skipped_no_text', {});

  if (EXPLAIN) { explain('output/assistant-text', text); return allow(config, 'output', 'explain', {}); }

  const fw = await callFirewallApi(config, {
    prompt: config.outputAuditIncludesPrompt
      ? lastUserPromptFromTranscript(input.transcript_path || '')
      : '',
    response: text,
    sessionId: input.session_id || '',
    stage: 'output',
    source: 'text',
  });

  if (fw.error) return allow(config, 'output', 'fail_open', { error: fw.error });

  if (fw.result === 'block') {
    logInfo('output', 'blocked', {
      sessionId: input.session_id || '-',
      riskLevel: fw.riskLevel,
      hitRules: fw.hitRules,
      violationReason: fw.violationReason,
      preview: preview(text, 300),
    });
    if (config.onBlockedOutput === 'log') {
      return allow(config, 'output', 'blocked_alert_only', { riskLevel: fw.riskLevel });
    }
    return blockPrompt(stopBlockReason(fw));
  }

  if (shouldMaskOutput(fw) && fw.maskedContent.response !== text) {
    logInfo('output', 'masked_detected', {
      hitRules: fw.hitRules,
      originalPreview: preview(text, 300),
      maskedPreview: preview(fw.maskedContent.response, 300),
      behavior: config.onMaskedOutput,
    });
    if (config.onMaskedOutput === 'block') {
      return blockPrompt(config.blockTip);
    }
  }

  return allow(config, 'output', 'passed', { riskLevel: fw.riskLevel });
}

function lastUserPromptFromTranscript(transcriptPath) {
  if (!transcriptPath) return '';
  let raw;
  try {
    raw = fs.readFileSync(transcriptPath, 'utf8');
  } catch {
    return '';
  }
  const lines = raw.split('\n');
  for (let i = lines.length - 1; i >= 0; i--) {
    const line = lines[i].trim();
    if (!line) continue;
    let obj;
    try { obj = JSON.parse(line); } catch { continue; }
    const role = obj.role || (obj.message && obj.message.role);
    if (role !== 'user') continue;
    const text = contentToText(obj.content ?? obj.message?.content);
    if (text && text.trim()) return truncate(stripMetadataPrefix(text), 2000);
  }
  return '';
}

// ───────── 分发 ─────────

const MODE_BY_EVENT = {
  SessionStart: 'session',
  SessionEnd: 'session',
  UserPromptSubmit: 'input',
  UserPromptExpansion: 'input',
  PreToolUse: 'tool',
  PostToolUse: 'tool_result',
  Stop: 'output',
};

async function main() {
  const config = loadConfig();
  const input = await readStdin();
  const mode = (process.argv[2] || '').trim() || MODE_BY_EVENT[input.hook_event_name] || '';

  if (!config.enabled) return allow(config, 'guard', 'disabled', { mode });

  const missing = validateConfig(config);
  if (missing.length > 0) {
    logInfo('guard', 'missing_config', { missing, root: pluginRoot() });
    return allow(config, 'guard', 'fail_open_missing_config', { missing });
  }

  switch (mode) {
    case 'session': return handleSession(input, config);
    case 'input': return await handleInput(input, config);
    case 'tool': return await handleTool(input, config);
    case 'tool_result': return await handleToolResult(input, config);
    case 'output': return await handleOutput(input, config);
    default:
      logInfo('guard', 'unknown_mode', { mode, argv: process.argv.slice(2) });
      return allow(config, 'guard', 'unknown_mode', { mode });
  }
}

main().catch((e) => {
  logInfo('guard', 'fatal', String((e && e.message) || e));
  process.exit(0); // fail-open
});
