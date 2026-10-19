#!/usr/bin/env node
/**
 * install-helper.mjs — wb-firewall-guard 的跨平台安装内核
 *
 * install.sh（macOS / Linux）与 install.ps1（Windows）都只做「解析参数 + 找 node」，
 * 真正的部署 / 写配置 / 挂钩子 / 设备注册全部收敛在这里，保证两端行为完全一致。
 *
 * 子命令：
 *   deploy   --source <包目录>  --target <安装目录>      复制插件文件（旧目录自动备份，只留最近 3 份）
 *   config   --target <安装目录> [--url] [--key] [--debug] [--tip] [--timeout]
 *   hooks    --target <安装目录> [--settings <path>] [--remove]   挂 / 摘 user settings 钩子
 *   register --target <安装目录> --url <base> --key <key>         设备注册（device_id 与插件同源）
 *   verify   --target <安装目录> [--settings <path>]              校验钩子是否挂好
 *   uninstall --target <安装目录> [--settings <path>] [--purge]    摘钩子并（可选）清理目录
 *
 * 退出码：0 成功；2 部署/写文件失败；3 设备注册失败；4 校验失败
 */

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { getDeviceId, PLUGIN_VERSION } from './firewall.mjs';

const PLUGIN_ID = 'wb-firewall-guard';
const LOG_PREFIX = '[wb-firewall-guard]';
const KEEP_BACKUPS = 3;

const __dirname = path.dirname(fileURLToPath(import.meta.url));

function log(tag, msg) {
  process.stdout.write(`${LOG_PREFIX} [${new Date().toISOString()}] [${tag}] ${msg}\n`);
}
function fail(tag, msg, code = 2) {
  process.stderr.write(`${LOG_PREFIX} [${tag}] [ERROR] ${msg}\n`);
  process.exit(code);
}

// ───────── 参数 ─────────

function parseArgs(argv) {
  const out = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--') continue;
    if (a.startsWith('--')) {
      const body = a.slice(2);
      if (body.includes('=')) {
        const [k, ...rest] = body.split('=');
        out[k] = rest.join('=');
      } else {
        out[body] = argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[++i] : 'true';
      }
    } else {
      out._.push(a);
    }
  }
  return out;
}

/** node ≥18：依赖原生 fetch（firewall.mjs 直接用全局 fetch） */
function checkNode() {
  const major = Number(process.versions.node.split('.')[0]);
  if (major < 18) fail('node', `需要 Node.js ≥ 18，当前 ${process.version}`, 2);
  return major;
}

function defaultTarget() {
  return path.join(os.homedir(), '.workbuddy', 'plugins', PLUGIN_ID);
}
function defaultSettings() {
  return path.join(os.homedir(), '.workbuddy', 'settings.json');
}
function stamp() {
  const d = new Date();
  const p = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}-${p(d.getHours())}${p(d.getMinutes())}${p(d.getSeconds())}`;
}

function readJson(file, fallback) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return fallback;
  }
}
function writeJson(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify(value, null, 2) + '\n');
}

/** 备份并只保留最近 KEEP_BACKUPS 份（避免重装几次后垃圾堆积） */
function rotateBackups(dir, base) {
  try {
    const entries = fs
      .readdirSync(dir)
      .filter((n) => n.startsWith(`${base}.bak-`))
      .sort();
    while (entries.length > KEEP_BACKUPS) {
      const oldest = entries.shift();
      fs.rmSync(path.join(dir, oldest), { recursive: true, force: true });
      log('backup', `清理过期备份: ${oldest}`);
    }
  } catch {
    /* 清理失败不影响主流程 */
  }
}

function backupPath(p) {
  const dir = path.dirname(p);
  const base = path.basename(p);
  const dst = path.join(dir, `${base}.bak-${stamp()}`);
  fs.cpSync(p, dst, { recursive: true });
  rotateBackups(dir, base);
  return dst;
}

// ───────── deploy ─────────

function cmdDeploy(args) {
  checkNode();
  const source = path.resolve(args.source || path.resolve(__dirname, '..'));
  const target = path.resolve(args.target || defaultTarget());
  log('deploy', `源目录: ${source}`);
  log('deploy', `目标目录: ${target}`);

  if (source === target) {
    log('deploy', '源目录与目标目录相同，跳过复制（就地安装）');
    return;
  }

  if (fs.existsSync(target)) {
    const bak = backupPath(target);
    fs.rmSync(target, { recursive: true, force: true });
    log('deploy', `已备份旧版本 → ${bak}`);
  }

  fs.mkdirSync(target, { recursive: true });
  for (const rel of ['.codebuddy-plugin', 'hooks', 'dist']) {
    const from = path.join(source, rel);
    if (fs.existsSync(from)) {
      fs.cpSync(from, path.join(target, rel), { recursive: true });
    }
  }
  fs.mkdirSync(path.join(target, 'logs'), { recursive: true });

  // config.json：目标已有就保留（重装不丢配置），否则用包里的模板
  const cfgTarget = path.join(target, 'config.json');
  if (!fs.existsSync(cfgTarget)) {
    const tpl = path.join(source, 'config.example.json');
    if (fs.existsSync(tpl)) fs.copyFileSync(tpl, cfgTarget);
    else writeJson(cfgTarget, {});
    log('deploy', '已从模板生成 config.json');
  } else {
    log('deploy', '保留已有 config.json');
  }
  log('deploy', '插件文件部署完成');
}

// ───────── config ─────────

function boolArg(v) {
  if (v === undefined || v === null) return undefined;
  if (typeof v === 'boolean') return v;
  const s = String(v).trim().toLowerCase();
  if (s === 'true' || s === '1' || s === 'yes') return true;
  if (s === 'false' || s === '0' || s === 'no') return false;
  return undefined;
}

function cmdConfig(args) {
  const target = path.resolve(args.target || defaultTarget());
  const file = path.join(target, 'config.json');
  const cfg = readJson(file, {});
  if (!fs.existsSync(file)) fs.mkdirSync(target, { recursive: true });

  if (args.url) cfg.firewallUrl = String(args.url).trim().replace(/\/+$/, '');
  if (args.key) cfg.authKey = String(args.key).trim();
  if (args.tip) cfg.blockTip = String(args.tip).trim();
  if (args.message) cfg.blockMessage = String(args.message).trim();
  if (args.timeout && Number.isFinite(Number(args.timeout))) cfg.timeout = Math.floor(Number(args.timeout));
  const dbg = boolArg(args.debug);
  if (dbg !== undefined) cfg.debug = dbg;
  cfg.enabled = true;

  writeJson(file, cfg);
  log('config', `已写入 ${file}`);
  log('config', `firewallUrl=${cfg.firewallUrl || '(空)'} debug=${cfg.debug === true}`);
  if (!cfg.firewallUrl || !cfg.authKey) {
    process.stderr.write(`${LOG_PREFIX} [config] [WARN] firewallUrl / authKey 不完整，插件会 fail-open 放行\n`);
  }
}

// ───────── hooks ─────────

const HOOK_SPEC = {
  SessionStart: ['session', 10],
  UserPromptSubmit: ['input', 15],
  PreToolUse: ['tool', 15],
  PostToolUse: ['tool_result', 15],
  Stop: ['output', 20],
  SessionEnd: ['session', 10],
};

function hookCommand(root, nodeBin, mode) {
  const entry = path.join(root, 'dist', 'guard.mjs');
  // 不加环境变量前缀：guard.mjs 会按自身位置推导插件根（pluginRoot()），
  // 这样 Windows 的 cmd / PowerShell 下都能原样执行。
  return `"${nodeBin}" "${entry}" ${mode}`;
}

/**
 * 判断一条 hook command 是不是本插件的。
 * 两个判据取其一：命令里出现插件 id，或出现本次的安装目录
 * （自定义 --target 时路径里可能不含插件 id，只看插件名会漏判，导致无法幂等清理）。
 */
function normPath(p) {
  return String(p || '').replace(/\\/g, '/').toLowerCase();
}
function isOurHook(command, target) {
  const c = normPath(command);
  return c.includes(PLUGIN_ID) || (target ? c.includes(normPath(target)) : false);
}

function writeHooks(args, remove) {
  const target = path.resolve(args.target || defaultTarget());
  const settingsPath = path.resolve(args.settings || defaultSettings());
  const nodeBin = process.execPath;

  let settings = {};
  if (fs.existsSync(settingsPath)) {
    const raw = fs.readFileSync(settingsPath, 'utf8').trim();
    settings = raw ? readJson(settingsPath, null) : {};
    if (settings === null || typeof settings !== 'object' || Array.isArray(settings)) {
      fail('hooks', `${settingsPath} 不是合法的 JSON 对象，已中止（未做任何修改）`, 2);
    }
    const bak = backupPath(settingsPath);
    log('hooks', `已备份配置 → ${bak}`);
  } else {
    log('hooks', `${settingsPath} 不存在，将新建`);
  }

  settings.hooks = settings.hooks || {};

  // 幂等：先摘掉本插件的旧条目（按 command 是否含插件 id 判断）
  for (const [event, groups] of Object.entries(settings.hooks)) {
    if (!Array.isArray(groups)) continue;
    const kept = groups
      .map((g) => ({
        ...g,
        hooks: (g.hooks || []).filter((h) => !isOurHook(h.command, target)),
      }))
      .filter((g) => (g.hooks || []).length > 0);
    if (kept.length > 0) settings.hooks[event] = kept;
    else delete settings.hooks[event];
  }

  if (remove) {
    writeJson(settingsPath, settings);
    log('hooks', '已移除全部 wb-firewall-guard 钩子');
    return;
  }

  for (const [event, [mode, timeout]] of Object.entries(HOOK_SPEC)) {
    settings.hooks[event] = [
      ...(settings.hooks[event] || []),
      { hooks: [{ type: 'command', command: hookCommand(target, nodeBin, mode), timeout }] },
    ];
  }

  writeJson(settingsPath, settings);
  log('hooks', `已挂载 ${Object.keys(HOOK_SPEC).length} 个事件: ${Object.keys(HOOK_SPEC).join(', ')}`);
  log('hooks', `node = ${nodeBin}`);
}

function cmdHooks(args) {
  checkNode();
  writeHooks(args, args.remove === 'true');
}

// ───────── register ─────────

function platformName() {
  switch (os.platform()) {
    case 'darwin': return 'mac';
    case 'win32': return 'windows';
    case 'linux': return 'linux';
    default: return 'unknown';
  }
}

function osString() {
  const p = os.platform();
  try {
    if (p === 'darwin') {
      const name = execSync('sw_vers -productName', { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
      const ver = execSync('sw_vers -productVersion', { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
      return `${name} ${ver}`;
    }
    if (p === 'linux') {
      const rel = fs.readFileSync('/etc/os-release', 'utf8');
      const m = rel.match(/^PRETTY_NAME="?([^"\n]+)"?/m);
      return m ? m[1] : `Linux ${os.release()}`;
    }
    if (p === 'win32') {
      const cap = execSync('(Get-CimInstance Win32_OperatingSystem).Caption', {
        shell: 'powershell.exe', encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'],
      }).trim();
      return cap || `Windows ${os.release()}`;
    }
  } catch {
    /* 取不到就用兜底值 */
  }
  return `${os.type()} ${os.release()}`;
}

function localIp() {
  for (const iface of Object.values(os.networkInterfaces())) {
    for (const addr of iface || []) {
      if (addr.family === 'IPv4' && !addr.internal) return addr.address;
    }
  }
  return '127.0.0.1';
}

async function cmdRegister(args) {
  checkNode();
  const base = String(args.url || '').trim().replace(/\/+$/, '');
  const key = String(args.key || '').trim();
  if (!base || !key) fail('register', '缺少 --url 或 --key', 3);

  const registerUrl = `${base}/api/firewall/openclaw/device/register`;
  const deviceId = getDeviceId(); // 与插件运行时同源，保证同一个 device_id

  const body = {
    auth_key: key,
    device_id: deviceId,
    ip: localIp(),
    os: osString(),
    platform: platformName(),
    app_version: process.env.WB_APP_VERSION || 'unknown',
    app_typ: 'workbuddy',
    plugin_version: PLUGIN_VERSION,
  };

  log('register', `设备: platform=${body.platform} os=${body.os} ip=${body.ip}`);
  log('register', `device_id = ${deviceId}`);

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 10000);
  try {
    const resp = await fetch(registerUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      signal: controller.signal,
    });
    const text = await resp.text();
    if (!resp.ok) fail('register', `HTTP ${resp.status}: ${text.slice(0, 300)}`, 3);
    log('register', `设备注册成功: ${text.slice(0, 300)}`);
  } catch (e) {
    fail('register', `调用失败 ${registerUrl} — ${String((e && e.message) || e)}`, 3);
  } finally {
    clearTimeout(timer);
  }
}

// ───────── verify / uninstall ─────────

function cmdVerify(args) {
  const target = path.resolve(args.target || defaultTarget());
  const settingsPath = path.resolve(args.settings || defaultSettings());
  const settings = readJson(settingsPath, {});
  const hooks = settings.hooks || {};
  const missing = Object.keys(HOOK_SPEC).filter((event) =>
    !(hooks[event] || []).some((g) => (g.hooks || []).some((h) => isOurHook(h.command, target))),
  );
  const checks = [
    ['插件目录', fs.existsSync(path.join(target, 'dist', 'guard.mjs'))],
    ['config.json', fs.existsSync(path.join(target, 'config.json'))],
    ['settings.json 钩子', missing.length === 0],
  ];
  for (const [name, ok] of checks) log('verify', `${ok ? 'OK  ' : 'FAIL'} ${name}`);
  if (missing.length > 0) log('verify', `缺失事件: ${missing.join(', ')}`);
  if (checks.some(([, ok]) => !ok)) process.exit(4);
  log('verify', '全部检查通过');
}

function cmdUninstall(args) {
  checkNode();
  writeHooks(args, true);
  if (args.purge === 'true') {
    const target = path.resolve(args.target || defaultTarget());
    if (fs.existsSync(target)) {
      const bak = backupPath(target);
      fs.rmSync(target, { recursive: true, force: true });
      log('uninstall', `插件目录已移除（备份 → ${bak}）`);
    }
  } else {
    log('uninstall', '保留插件目录与 config.json；加 --purge 可一并删除');
  }
}

// ───────── 分发 ─────────

const args = parseArgs(process.argv.slice(2));
const cmd = (args._[0] || '').toLowerCase();

switch (cmd) {
  case 'deploy': cmdDeploy(args); break;
  case 'config': cmdConfig(args); break;
  case 'hooks': cmdHooks(args); break;
  case 'register': cmdRegister(args).catch((e) => fail('register', String((e && e.message) || e), 3)); break;
  case 'verify': cmdVerify(args); break;
  case 'uninstall': cmdUninstall(args); break;
  default:
    process.stderr.write(
      `用法: install-helper.mjs <deploy|config|hooks|register|verify|uninstall> [--target <dir>] [--settings <file>] [...]\n`,
    );
    process.exit(1);
}
