/**
 * extract.mjs — 内容提取与噪声剥离
 *
 * 移植自 OpenClaw 插件 `tomzang_plungin`：
 *   - 注入标签剥离（relevant-memories / inherited-rules / derived-focus / self-improvement-reminder）
 *   - 元数据前缀剥离（System: / Conversation info / Sender / 飞书 message_id / 时间戳）
 *   - 内置命令与系统内部请求跳过
 */

import os from 'node:os';
import { statSync, openSync, readSync, closeSync } from 'node:fs';

export const INJECTED_TAG_PATTERNS = [
  /<relevant-memories>[\s\S]*?<\/relevant-memories>/g,
  /<inherited-rules>[\s\S]*?<\/inherited-rules>/g,
  /<derived-focus>[\s\S]*?<\/derived-focus>/g,
  /<self-improvement-reminder>[\s\S]*?<\/self-improvement-reminder>/g,
  /<system-reminder>[\s\S]*?<\/system-reminder>/g,
];

export const BUILT_IN_COMMANDS = [
  '/new', '/reset', '/help', '/clear', '/config', '/exit', '/quit',
  '/sessions', '/models', '/providers', '/agent', '/session', '/continue',
  '/version', '/debug', '/verbose', '/compact', '/model', '/permissions',
];

export const SYSTEM_INTERNAL_PATTERNS = [
  /A new session was started via \/new/i,
  /A new session was started via \/reset/i,
  /Based on this conversation, generate a short/i,
  /generate a short \d+-\d+ word filename slug/i,
  /session was started via \//i,
  /session was reset/i,
];

/** 移除提示器注入的标签及其内部内容（非贪婪 + 全局） */
export function stripInjectedTags(text) {
  if (!text || typeof text !== 'string') return text || '';
  let out = text;
  for (const re of INJECTED_TAG_PATTERNS) out = out.replace(re, '');
  return out.replace(/\n{3,}/g, '\n\n');
}

/** 去掉 control-ui / openclaw 可能附加的时间戳前缀 */
export function stripTimestampPrefix(text) {
  return text.replace(/^\[.*?\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}(?::\d{2})?\s+(?:GMT|UTC)[^\]]*\]\s*/, '');
}

function stripMetadataPrefixRaw(text) {
  if (!text || typeof text !== 'string') return text || '';

  // 运行时上下文行（"Runtime: agent=..."）在多个分支会提前返回，入口统一移除
  text = text.replace(/\n\s*Runtime: agent=[^\n]*/g, '\n');

  const lastFence = text.lastIndexOf('```');
  if (lastFence !== -1) {
    let afterFence = text.substring(lastFence + 3).replace(/^\s*\n*/, '');
    if (afterFence.length > 0) {
      const feishuInAfterFence = afterFence.match(/^\[message_id:\s*[^\]]+\]\s*([a-z]+_\w+):\s*/);
      if (feishuInAfterFence) {
        const contentAfterUserId = afterFence.substring(feishuInAfterFence[0].length);
        const stripped = contentAfterUserId.replace(/^\s+/, '').replace(/\s+$/, '');
        if (stripped.length > 0) return stripTimestampPrefix(stripped).trim();
      }
      return stripTimestampPrefix(afterFence).trim();
    }
  }

  const feishuMatch = text.match(/^\[message_id:\s*[^\]]+\]\s*([a-z]+_\w+):\s*/m);
  if (feishuMatch) {
    const afterUserId = text.substring(feishuMatch[0].length);
    const stripped = afterUserId.replace(/^\s+/, '').replace(/\s+$/, '');
    if (stripped.length > 0) return stripTimestampPrefix(stripped).trim();
  }

  const parts = text.split(/\n\n/);
  while (parts.length > 1 && /^Runtime: /.test(parts[parts.length - 1].trim())) parts.pop();
  const lastPart = parts[parts.length - 1];
  if (lastPart && lastPart.trim().length > 0) return stripTimestampPrefix(lastPart).trim();

  return text.trim();
}

/** 完整剥离：元数据前缀 + 注入标签 */
export function stripMetadataPrefix(text) {
  return stripInjectedTags(stripMetadataPrefixRaw(text)).trim();
}

/**
 * 从 content 数组（Anthropic 格式）拼接 text 片段。
 *
 * 关键：只取 type === 'text' 的块。tool_use / tool_result / thinking 一律跳过。
 * 早期版本在没有 .text 时兜底 JSON.stringify(整个数组)，会把工具回显（日志、
 * 文件内容、命令输出）整包塞进送审文本 —— 上一轮 Stop 被误判就是这么来的：
 * 助手那条消息里只有 tool_result，兜底把含 PII 的日志原文序列化后送审，直接被判 block。
 */
export function extractTextFromContentArray(contentArray) {
  if (!Array.isArray(contentArray)) {
    return typeof contentArray === 'string' ? contentArray : '';
  }
  const texts = [];
  for (const item of contentArray) {
    if (!item || typeof item !== 'object') continue;
    if (item.type && item.type !== 'text') continue;
    if (typeof item.text === 'string') texts.push(item.text);
  }
  return texts.join('\n');
}

/** 任意 content 形态 → 纯文本 */
export function contentToText(content) {
  if (content === null || content === undefined) return '';
  if (typeof content === 'string') return content;
  if (Array.isArray(content)) return extractTextFromContentArray(content);
  if (typeof content === 'object') {
    if (content.type && content.type !== 'text') return '';   // tool_use / tool_result / thinking
    if (typeof content.text === 'string') return content.text;
    if (Array.isArray(content.content)) return extractTextFromContentArray(content.content);
    return '';
  }
  return String(content);
}

export function isBuiltInCommand(text) {
  if (!text || typeof text !== 'string') return false;
  const trimmed = text.trim();
  if (trimmed.length <= 1 || trimmed[0] !== '/') return false;
  const command = trimmed.split(/\s+/)[0];
  return BUILT_IN_COMMANDS.includes(command);
}

export function isSystemInternalRequest(text) {
  if (!text || typeof text !== 'string') return false;
  return SYSTEM_INTERNAL_PATTERNS.some((re) => re.test(text));
}

export function shouldSkipFirewall(text) {
  return isBuiltInCommand(text) || isSystemInternalRequest(text);
}

// ───────── SKILL.md 审计辅助 ─────────

export function isSkillFilePath(filePath) {
  if (!filePath || typeof filePath !== 'string') return false;
  return /\/SKILL\.md$/i.test(filePath.replace(/\\/g, '/'));
}

export function expandHome(filePath) {
  if (!filePath || typeof filePath !== 'string') return filePath;
  if (filePath === '~') return os.homedir();
  if (filePath.startsWith('~/') || filePath.startsWith('~\\')) {
    return os.homedir() + filePath.slice(1);
  }
  return filePath;
}

// ───────── 工具参数序列化 ─────────

export function stringifyParams(params) {
  if (params === undefined || params === null) return '';
  if (typeof params === 'string') return params;
  try {
    return JSON.stringify(params) || '';
  } catch {
    return '';
  }
}

// ───────── 转录文件（transcript）解析 ─────────

/** 从 jsonl 转录文件中取出最后一条 assistant 文本 */
export function lastAssistantTextFromTranscript(transcriptPath, maxBytes = 512 * 1024) {
  if (!transcriptPath) return '';
  let raw;
  let start = 0;
  try {
    const { size } = statSync(transcriptPath);
    const fd = openSync(transcriptPath, 'r');
    start = Math.max(0, size - maxBytes);
    const buf = Buffer.alloc(size - start);
    readSync(fd, buf, 0, buf.length, start);
    closeSync(fd);
    raw = buf.toString('utf8');
  } catch {
    return '';
  }

  const lines = raw.split('\n');
  if (start > 0) lines.shift(); // 半行丢弃

  for (let i = lines.length - 1; i >= 0; i--) {
    const line = lines[i].trim();
    if (!line) continue;
    let obj;
    try { obj = JSON.parse(line); } catch { continue; }
    if (!obj) continue;

    const role = obj.role || (obj.message && obj.message.role);
    if (role !== 'assistant') continue;
    if (obj.type === 'summary') continue;

    const text = contentToText(obj.content ?? obj.message?.content);
    const cleaned = stripInjectedTags(text).trim();
    if (cleaned) return cleaned;
  }
  return '';
}
