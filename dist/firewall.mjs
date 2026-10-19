/**
 * firewall.mjs — 审计后端客户端 / 配置 / 日志 / 设备指纹
 *
 * 逻辑移植自 OpenClaw 插件 `tomzang_plungin`（v2026-10-02），
 * 去掉了 undici / fetch 拦截层（WorkBuddy 无该扩展点），
 * 改为由 hooks（UserPromptSubmit / PreToolUse / PostToolUse / Stop）驱动。
 *
 * 设计原则（与原插件一致）：fail-open —— 任何异常都放行，只记日志，绝不阻断正常会话。
 */

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { execSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

export const PLUGIN_ID = 'wb-firewall-guard';
export const PLUGIN_VERSION = 'v1.0.0';
export const LOG_PREFIX = '[wb-firewall-guard]';
export const FIREWALL_API_PATH = '/api/firewall/openclaw/validate';

export const DEFAULT_BLOCK_MESSAGE = '当前请求包含敏感关键字，已被安全组件拦截';
export const DEFAULT_BLOCK_TIP =
  '抱歉，我无法执行该请求。作为智能助手，我会在我的设定范围内提供帮助。如果你有合法的需求，请正常描述，我会尽力协助。';
const DEFAULT_TIMEOUT_MS = 3000;

// ───────── 路径 ─────────

const __dirname = path.dirname(fileURLToPath(import.meta.url));

/** 插件根目录：环境变量优先（install.sh 会写入绝对路径），否则按模块位置推导 */
export function pluginRoot() {
  return (process.env.WB_FIREWALL_ROOT || '').trim() || path.resolve(__dirname, '..');
}

// ───────── 配置 ─────────

function boolFrom(value, fallback = false) {
  if (typeof value === 'boolean') return value;
  if (typeof value === 'string') return value.trim().toLowerCase() === 'true';
  return fallback;
}

export function buildFullFirewallUrl(host) {
  if (!host) return '';
  return String(host).trim().replace(/\/+$/, '') + FIREWALL_API_PATH;
}

export function resolveConfig(raw = {}) {
  const timeout = Number.isFinite(Number(raw.timeout)) && Number(raw.timeout) > 0
    ? Math.floor(Number(raw.timeout))
    : DEFAULT_TIMEOUT_MS;

  const blockTip = typeof raw.blockTip === 'string' && raw.blockTip.trim() !== ''
    ? raw.blockTip.trim()
    : DEFAULT_BLOCK_TIP;

  return {
    enabled: boolFrom(raw.enabled, true),
    firewallUrl: buildFullFirewallUrl(raw.firewallUrl),
    authKey: typeof raw.authKey === 'string' ? raw.authKey.trim() : '',
    blockMessage: typeof raw.blockMessage === 'string' && raw.blockMessage.trim() !== ''
      ? raw.blockMessage.trim()
      : DEFAULT_BLOCK_MESSAGE,
    blockTip,
    debug: boolFrom(raw.debug, false),
    timeout,
    toolWhitelist: Array.isArray(raw.toolWhitelist) ? raw.toolWhitelist.map(String) : [],
    auditToolResult: boolFrom(raw.auditToolResult, true),
    auditOutput: boolFrom(raw.auditOutput, true),
    onMaskedInput: raw.onMaskedInput === 'block' ? 'block' : 'log',
    onMaskedOutput: raw.onMaskedOutput === 'block' ? 'block' : 'log',
    // Stop 阶段命中 block 时：block = 打回让模型重答一次（第二次靠 stop_hook_active 放行，防死循环）
    //                        log   = 只告警不打断
    onBlockedOutput: raw.onBlockedOutput === 'log' ? 'log' : 'block',
    // Stop 阶段是否把「用户提问」也一起送审。
    // 默认 false：只审模型自己说的话。否则用户贴了密钥/敏感材料时，
    // 模型一句无辜的回复也会被连带判 block —— 上一轮误伤就是这么来的。
    outputAuditIncludesPrompt: boolFrom(raw.outputAuditIncludesPrompt, false),
  };
}

/** config.json + 环境变量覆盖（环境变量优先级更高，方便临时调试） */
export function loadConfig() {
  const root = pluginRoot();
  let raw = {};
  try {
    raw = JSON.parse(fs.readFileSync(path.join(root, 'config.json'), 'utf8'));
  } catch {
    raw = {};
  }
  if (process.env.WB_FIREWALL_URL) raw.firewallUrl = process.env.WB_FIREWALL_URL;
  if (process.env.WB_FIREWALL_AUTH_KEY) raw.authKey = process.env.WB_FIREWALL_AUTH_KEY;
  if (process.env.WB_FIREWALL_DEBUG) raw.debug = process.env.WB_FIREWALL_DEBUG;
  if (process.env.WB_FIREWALL_TIMEOUT) raw.timeout = process.env.WB_FIREWALL_TIMEOUT;
  if (process.env.WB_FIREWALL_ENABLED) raw.enabled = process.env.WB_FIREWALL_ENABLED;
  return resolveConfig(raw);
}

export function validateConfig(config) {
  const missing = [];
  if (!config.firewallUrl) missing.push('firewallUrl');
  if (!config.authKey) missing.push('authKey');
  return missing;
}

// ───────── 日志 ─────────

let logFileReady = false;

function logPath() {
  return path.join(pluginRoot(), 'logs', 'guard.log');
}

function writeLog(line) {
  try {
    const file = logPath();
    if (!logFileReady) {
      fs.mkdirSync(path.dirname(file), { recursive: true });
      logFileReady = true;
    }
    fs.appendFileSync(file, line + '\n');
  } catch {
    /* 日志写不进去也不能影响主流程 */
  }
}

function formatMessage(category, action, data) {
  const head = `${LOG_PREFIX} [${new Date().toISOString()}] [${category}] [${action}]`;
  if (data === undefined) return head;
  return `${head} ${typeof data === 'string' ? data : JSON.stringify(data)}`;
}

export function logInfo(category, action, data) {
  const line = formatMessage(category, action, data);
  writeLog(line);
  if (process.env.WB_FIREWALL_STDERR === '1') process.stderr.write(line + '\n');
}
export const logWarn = logInfo;
export const logError = logInfo;

export function logDebug(config, category, action, data) {
  if (!config || !config.debug) return;
  logInfo(category, action, data);
}

// ───────── 设备标识 ─────────
// 硬件指纹在进程存活期间不变，缓存避免每次校验都 execSync（macOS system_profiler 单次可达秒级）

let cachedDeviceId = null;

export function getDeviceId() {
  if (cachedDeviceId) return cachedDeviceId;

  const hardwareIds = [];
  const platform = os.platform();
  const execOptions = { encoding: 'utf-8', stdio: ['ignore', 'pipe', 'ignore'] };

  try {
    let cpuInfo = '';
    if (platform === 'linux') {
      try { cpuInfo = execSync("cat /proc/cpuinfo | grep 'processor\\|model name' | head -1", execOptions).trim(); } catch { cpuInfo = ''; }
    } else if (platform === 'darwin') {
      try { cpuInfo = execSync('sysctl -n machdep.cpu.brand_string', execOptions).trim(); } catch { cpuInfo = ''; }
    } else if (platform === 'win32') {
      try { cpuInfo = execSync('wmic cpu get ProcessorId /value', execOptions).trim().replace(/ProcessorId=/, '').replace(/\r?\n/g, ''); } catch { cpuInfo = ''; }
    }
    if (cpuInfo) hardwareIds.push(cpuInfo);

    let boardInfo = '';
    if (platform === 'linux') {
      try { boardInfo = execSync("dmidecode -s baseboard-serial-number 2>/dev/null || cat /sys/class/dmi/id/board_serial 2>/dev/null || echo ''", { shell: true, ...execOptions }).trim(); } catch { boardInfo = ''; }
    } else if (platform === 'darwin') {
      try { boardInfo = execSync("system_profiler SPHardwareDataType | grep 'Serial Number' | awk '{print $3}'", execOptions).trim(); } catch { boardInfo = ''; }
    } else if (platform === 'win32') {
      try { boardInfo = execSync('wmic baseboard get SerialNumber /value', execOptions).trim().replace(/SerialNumber=/, '').replace(/\r?\n/g, ''); } catch { boardInfo = ''; }
    }
    if (boardInfo) hardwareIds.push(boardInfo);

    let diskInfo = '';
    if (platform === 'linux') {
      try { diskInfo = execSync("lsblk -d -o name,serial | head -2 | tail -1 | awk '{print $2}'", execOptions).trim(); } catch { diskInfo = ''; }
    } else if (platform === 'darwin') {
      try { diskInfo = execSync("diskutil info / | grep 'Disk UUID' | awk '{print $3}'", execOptions).trim(); } catch { diskInfo = ''; }
    } else if (platform === 'win32') {
      try { diskInfo = execSync('wmic diskdrive get SerialNumber /value', execOptions).trim().replace(/SerialNumber=/, '').replace(/\r?\n/g, ''); } catch { diskInfo = ''; }
    }
    if (diskInfo) hardwareIds.push(diskInfo);

    let macInfo = '';
    const networkInterfaces = os.networkInterfaces();
    for (const iface of Object.keys(networkInterfaces)) {
      if (iface === 'lo' || iface.includes('Loopback')) continue;
      for (const addr of networkInterfaces[iface] || []) {
        if (addr.family === 'IPv4' && !addr.internal) {
          macInfo = addr.mac;
          break;
        }
      }
      if (macInfo) break;
    }
    if (macInfo) hardwareIds.push(macInfo);

    if (hardwareIds.length === 0) {
      hardwareIds.push(os.hostname(), platform, os.arch(), os.release());
    }

    cachedDeviceId = crypto.createHash('sha256').update(hardwareIds.join('|')).digest('hex');
    return cachedDeviceId;
  } catch {
    cachedDeviceId = crypto
      .createHash('sha256')
      .update(`${os.hostname()}|${os.platform()}|${os.arch()}|${os.release()}`)
      .digest('hex');
    return cachedDeviceId;
  }
}

// ───────── 防火墙 API ─────────

let firewallCallId = 0;

/**
 * 调用审计后端。返回结构：
 * { action, result, riskLevel, violationReason, hitRules, maskedContent, error? }
 * 任何失败都返回 { action: 'pass', result: 'pass', error } —— fail-open
 */
export async function callFirewallApi(config, options) {
  const {
    prompt = '',
    response = '',
    sessionId = '',
    stage = 'input',
    source = 'text',
    contentType = 'text',
  } = options || {};

  const callId = ++firewallCallId;
  const traceId = `trace-${Date.now()}-${callId}`;

  const requestBody = {
    auth_key: config.authKey,
    session_id: sessionId || 'session-workbuddy',
    trace_id: traceId,
    stage,
    source,
    source_user: (() => {
      const v = process.env.GROUP_CHAT_ALLOWED_SENDERS ?? process.env.USER ?? '';
      return typeof v === 'string' || typeof v === 'number' ? String(v) : '';
    })(),
    device_id: getDeviceId(),
    content_type: contentType,
    content: { prompt, response, image: '' },
  };

  logDebug(config, 'firewall', 'api_request', {
    callId, stage, source, url: config.firewallUrl,
    promptPreview: preview(prompt),
    responsePreview: preview(response),
  });

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), config.timeout);

  try {
    const startedAt = Date.now();
    const resp = await fetch(config.firewallUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(requestBody),
      signal: controller.signal,
    });
    const durationMs = Date.now() - startedAt;

    if (!resp.ok) {
      logWarn('firewall', 'api_error', { callId, status: resp.status, durationMs });
      return { action: 'pass', result: 'pass', riskLevel: 0, violationReason: '', hitRules: [], maskedContent: null, error: `API returned status ${resp.status}` };
    }

    const result = await resp.json();
    logDebug(config, 'firewall', 'api_raw_response', { callId, durationMs, responseBody: result });

    if (!result || result.code !== 200 || !result.data) {
      logWarn('firewall', 'unexpected_response', { callId, durationMs, body: result });
      return { action: 'pass', result: 'pass', riskLevel: 0, violationReason: '', hitRules: [], maskedContent: null, error: 'Unexpected response format' };
    }

    const data = result.data;
    let maskedContent = null;
    if (data.masked_content && typeof data.masked_content === 'object') {
      maskedContent = {
        prompt: data.masked_content.prompt || '',
        response: data.masked_content.response || '',
        image: data.masked_content.image || '',
      };
    }

    logDebug(config, 'firewall', 'api_response', {
      callId, stage, source,
      action: data.action, result: data.result,
      riskLevel: data.risk_level, violationReason: data.violation_reason,
      hitRules: data.hit_rules, hasMaskedContent: !!maskedContent, durationMs,
    });

    return {
      action: data.action || '',
      result: data.result || '',
      riskLevel: data.risk_level || 0,
      violationReason: data.violation_reason || '',
      hitRules: data.hit_rules || [],
      maskedContent,
    };
  } catch (e) {
    logError('firewall', 'api_call_failed', {
      callId,
      url: config.firewallUrl,
      stage,
      errorMessage: String((e && e.message) || e),
      errorType: (e && e.constructor && e.constructor.name) || 'Unknown',
    });
    return { action: 'pass', result: 'pass', riskLevel: 0, violationReason: '', hitRules: [], maskedContent: null, error: String((e && e.message) || e) };
  } finally {
    clearTimeout(timer);
  }
}

/** 后端返回脱敏内容且 response/prompt 非空 → 需要做替换 */
export function shouldMaskOutput(fwResult) {
  return !!(
    fwResult.maskedContent &&
    typeof fwResult.maskedContent.response === 'string' &&
    fwResult.maskedContent.response.length > 0
  );
}

export function preview(text, max = 500) {
  if (typeof text !== 'string') return '';
  return text.length > max ? `${text.slice(0, max)}…` : text;
}
