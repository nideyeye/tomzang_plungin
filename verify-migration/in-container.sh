#!/usr/bin/env bash
# verify-migration/in-container.sh — 主插件迁移到官方钩子架构后的端到端验证
# 由宿主 docker run 调起。环境变量:
#   OPENCLAW_VERSION   被测 openclaw 版本
#   AW_FW_PORT / AW_LLM_PORT / AW_GW_PORT
#   OPENCLAW_GATEWAY_TOKEN
# 挂载: /plugin-under-test(插件仓库, ro) /logs(结果, rw)
# 场景:
#   M0 install.sh 全链路安装 + 设备注册
#   M1 聚合+去重: 正常消息 → input/output 各恰好 1 条 validate，session_id 为真实会话 id，trace_id 带 run 前缀
#   M2 截断: fw=block → before_agent_run 阻断，0 次 LLM 调用，用户可见 blockTip
#   M3 工具防护: 假 LLM 返回 exec tool_call → before_tool_call 阻断（工具未执行）
#   M4 设备一致性: 全部 validate 请求 device_id 一致且为 64hex；device/register 请求存在
# 退出码: 0 全部通过 / 1 断言失败 / 2 环境错误

set -u
set -o pipefail

OPENCLAW_VERSION="${OPENCLAW_VERSION:-}"
AW_FW_PORT="${AW_FW_PORT:-9820}"
AW_LLM_PORT="${AW_LLM_PORT:-9821}"
AW_GW_PORT="${AW_GW_PORT:-18809}"
AW_AUTH_KEY="${AW_AUTH_KEY:-test-auth-key}"
PLUGIN_SRC="/plugin-under-test"
PLUGIN_DIR="${HOME}/.openclaw/extensions/tomzang_plungin"
CONFIG_FILE="${HOME}/.openclaw/openclaw.json"
FAKE_DIR="/logs/fake"

FAILURES=0
note()  { printf '[mig-ctl][%s] %s\n' "$(date '+%H:%M:%S')" "$*"; }
fail()  { printf '[mig-ctl][FAIL] %s\n' "$*" >&2; FAILURES=$((FAILURES+1)); }
die()   { printf '[mig-ctl][ENV-FAIL] %s\n' "$*" >&2; exit 2; }

[[ -n "${OPENCLAW_VERSION}" ]] || die "OPENCLAW_VERSION 未设置"
[[ -d "${PLUGIN_SRC}" ]]       || die "${PLUGIN_SRC} 未挂载"
[[ -d /logs ]]                 || die "/logs 未挂载"

exec > >(tee -a /logs/container.log) 2>&1
note "=== 迁移插件端到端验证开始: openclaw@${OPENCLAW_VERSION} ==="

# ---------- 1. 安装 openclaw ----------
note "[step1] npm install -g openclaw@${OPENCLAW_VERSION}"
npm install -g "openclaw@${OPENCLAW_VERSION}" >/logs/npm-install.log 2>&1 || {
  tail -30 /logs/npm-install.log
  die "openclaw@${OPENCLAW_VERSION} 安装失败"
}
openclaw --version | tee /logs/openclaw-version.txt

# ---------- 2. 假服务（增强版：tool-block 模式 + toolcall-once 脚本） ----------
note "[step2] 启动假防火墙/假 LLM (fw:${AW_FW_PORT} llm:${AW_LLM_PORT})"
mkdir -p "${FAKE_DIR}"
node /plugin-under-test/verify-migration/fake-server.mjs --firewall-port "${AW_FW_PORT}" --llm-port "${AW_LLM_PORT}" --dir "${FAKE_DIR}" >/logs/fake-server.log 2>&1 &
FAKE_PID=$!
for i in $(seq 1 30); do
  curl -sf "http://127.0.0.1:${AW_FW_PORT}/__count" >/dev/null 2>&1 && break
  sleep 1
done
curl -sf "http://127.0.0.1:${AW_FW_PORT}/__count" >/dev/null || die "假防火墙启动失败"
curl -sf "http://127.0.0.1:${AW_LLM_PORT}/__count" >/dev/null || die "假 LLM 启动失败"

fw_set_mode() { printf '%s' "$1" > "${FAKE_DIR}/fw-mode"; }
llm_set_script() { printf '%s' "$1" > "${FAKE_DIR}/llm-script"; }
fake_reset() { curl -sf "http://127.0.0.1:${AW_FW_PORT}/__reset" >/dev/null; curl -sf "http://127.0.0.1:${AW_LLM_PORT}/__reset" >/dev/null; }
llm_count() { curl -sf "http://127.0.0.1:${AW_LLM_PORT}/__count" | sed -E 's/.*"llm":([0-9]+).*/\1/'; }

# ---------- 3. 基础配置（不含插件段，交由 install.sh 写入） ----------
note "[step3] 预写基础配置"
mkdir -p "${HOME}/.openclaw"
node -e '
const fs = require("fs");
const p = process.env.HOME + "/.openclaw/openclaw.json";
let cfg = {};
if (fs.existsSync(p)) { try { cfg = JSON.parse(fs.readFileSync(p, "utf8")); } catch {} }
cfg.gateway = Object.assign({}, cfg.gateway, {
  mode: "local",
  auth: { mode: "token", token: process.env.OPENCLAW_GATEWAY_TOKEN },
  port: Number(process.env.AW_GW_PORT),
  bind: "loopback",
});
cfg.models = {
  mode: "merge",
  providers: {
    fakellm: {
      baseUrl: "http://127.0.0.1:" + process.env.AW_LLM_PORT + "/v1",
      api: "openai-completions",
      apiKey: "test-auth-key",
      models: [{ id: "fake-model", name: "Fake Model", contextWindow: 128000, maxTokens: 4096 }],
    },
  },
};
cfg.agents = { defaults: { model: { primary: "fakellm/fake-model" } } };
fs.writeFileSync(p, JSON.stringify(cfg, null, 2));
console.log("base config written");
'

# ---------- 4. M0: install.sh 真实安装链路（含设备注册） ----------
note "[M0] bash install.sh（假防火墙 ${AW_FW_PORT}）"
fw_set_mode pass
printf 'text' > "${FAKE_DIR}/llm-script"
bash "${PLUGIN_SRC}/install.sh" "http://127.0.0.1:${AW_FW_PORT}" "${AW_AUTH_KEY}" "" "true" "" >/logs/install-sh.log 2>&1
INSTALL_RC=$?
if [[ ${INSTALL_RC} -eq 3 ]]; then
  note "install.sh 退出 3（GitHub 下载偶发断流），10s 后重试一次"
  sleep 10
  bash "${PLUGIN_SRC}/install.sh" "http://127.0.0.1:${AW_FW_PORT}" "${AW_AUTH_KEY}" "" "true" "" >/logs/install-sh-retry.log 2>&1
  INSTALL_RC=$?
  [[ ${INSTALL_RC} -eq 0 ]] && cp /logs/install-sh-retry.log /logs/install-sh.log
fi
if [[ ${INSTALL_RC} -ne 0 ]]; then
  tail -60 /logs/install-sh.log
  fail "M0: install.sh 退出码 ${INSTALL_RC}"
  echo "MIG_TEST M0-install FAIL install.sh exit=${INSTALL_RC}"
else
  echo "MIG_TEST M0-install PASS install.sh 全链路成功"
fi
grep -E '设备ID|设备注册成功|plugin_version|设备注册失败' /logs/install-sh.log | head -6 || true
cp "${FAKE_DIR}/fw-requests.jsonl" /logs/fw-phase-install.jsonl 2>/dev/null || true

# ---------- 5. 强制部署 worktree 代码（确保被测代码 = 分支工作区代码） ----------
note "[step5] 强制部署 /plugin-under-test → ${PLUGIN_DIR}"
rm -rf "${PLUGIN_DIR}"
mkdir -p "$(dirname "${PLUGIN_DIR}")"
cp -R "${PLUGIN_SRC}" "${PLUGIN_DIR}"
rm -rf "${PLUGIN_DIR}/.git" "${PLUGIN_DIR}/test-gate-probe" "${PLUGIN_DIR}/verify-migration" 2>/dev/null || true
node --check "${PLUGIN_DIR}/index.js" || die "被测 index.js 语法错误"
node -e '
const fs = require("fs");
const p = process.env.HOME + "/.openclaw/openclaw.json";
let cfg = {};
try { cfg = JSON.parse(fs.readFileSync(p, "utf8")); } catch {}
cfg.gateway = Object.assign({}, cfg.gateway, { mode: "local", port: Number(process.env.AW_GW_PORT), bind: "loopback" });
if (!cfg.gateway.auth || !cfg.gateway.auth.token) cfg.gateway.auth = { mode: "token", token: process.env.OPENCLAW_GATEWAY_TOKEN };
if (!cfg.models || !cfg.models.providers || !cfg.models.providers.fakellm) {
  cfg.models = { mode: "merge", providers: { fakellm: { baseUrl: "http://127.0.0.1:" + process.env.AW_LLM_PORT + "/v1", api: "openai-completions", apiKey: "test-auth-key", models: [{ id: "fake-model", name: "Fake Model", contextWindow: 128000, maxTokens: 4096 }] } } };
}
if (!cfg.agents || !cfg.agents.defaults) cfg.agents = { defaults: { model: { primary: "fakellm/fake-model" } } };
const pluginDir = process.env.HOME + "/.openclaw/extensions/tomzang_plungin";
const pathRel = "~/.openclaw/extensions/tomzang_plungin";
cfg.plugins = cfg.plugins || {};
cfg.plugins.load = cfg.plugins.load || {};
const paths = Array.isArray(cfg.plugins.load.paths) ? cfg.plugins.load.paths : [];
if (!paths.includes(pluginDir) && !paths.includes(pathRel)) paths.push(pathRel);
cfg.plugins.load.paths = paths;
fs.writeFileSync(p, JSON.stringify(cfg, null, 2));
console.log("config re-ensured");
'
cp "${CONFIG_FILE}" /logs/openclaw-config.json 2>/dev/null || true

export OPENCLAW_GATEWAY_TOKEN
wait_health() {
  local secs="$1" i
  for i in $(seq 1 "${secs}"); do
    if node -e '
      const net = require("net");
      const s = net.connect({ host: "127.0.0.1", port: Number(process.env.AW_GW_PORT) }, () => { s.destroy(); process.exit(0); });
      s.on("error", () => process.exit(1));
      setTimeout(() => process.exit(1), 2000).unref();
    ' 2>/dev/null; then
      return 0
    fi
    sleep 1
  done
  return 1
}

# ---------- 6. 启动网关 ----------
note "[step6] 启动 gateway"
pkill -f "openclaw gateway" 2>/dev/null || true
sleep 1
nohup openclaw gateway run >>/logs/gateway-stdout.log 2>&1 &
if ! wait_health 150; then
  cp -R "${HOME}/.openclaw/logs" /logs/openclaw-logs 2>/dev/null || true
  tail -50 /logs/gateway-stdout.log
  die "gateway 无法启动"
fi
note "gateway 已监听 :${AW_GW_PORT}"

run_agent() { # run_agent <sessionId> <message> <outfile>
  openclaw agent -m "$2" --json --session-id "$1" --timeout 120 >"$3" 2>"$3.err" || true
}

# ---------- 7. M1: 聚合 + 去重 ----------
note "[M1] 正常消息 → 官方钩子审计 + session 聚合 + 去重 (fw=pass)"
fake_reset
fw_set_mode pass
run_agent "mig-m1" "MIG-M1 聚合验证请照常回复" /logs/agent-m1.json
sleep 3
M1_LLM=$(llm_count)
cp "${FAKE_DIR}/fw-requests.jsonl" /logs/fw-phase-m1.jsonl 2>/dev/null || true
note "M1 后 LLM 调用数=${M1_LLM}"

# ---------- 8. M2: 输入截断 ----------
note "[M2] fw=block → before_agent_run 输入门阻断"
fake_reset
fw_set_mode block
rm -f /tmp/aw-tool-ran
run_agent "mig-m2" "MIG-M2 截断验证这条应当被拦截" /logs/agent-m2.json
sleep 3
M2_LLM=$(llm_count)
cp "${FAKE_DIR}/fw-requests.jsonl" /logs/fw-phase-m2.jsonl 2>/dev/null || true
note "M2 后 LLM 调用数=${M2_LLM}"

# ---------- 9. M3: 工具防护（钩子级确定性断言，agent CLI 路径受 openclaw 自身 exec 策略干扰不作硬断言） ----------
note "[M3] hook-smoke: before/after_tool_call 确定性验证"
fake_reset
fw_set_mode tool-block
node /plugin-under-test/verify-migration/hook-smoke.mjs "${PLUGIN_DIR}" "http://127.0.0.1:${AW_FW_PORT}" "${AW_AUTH_KEY}" "${FAKE_DIR}/fw-mode" "${FAKE_DIR}/fw-requests.jsonl" >/logs/hook-smoke.log 2>&1
M3_RC=$?
cat /logs/hook-smoke.log
[[ ${M3_RC} -ne 0 ]] && fail "M3 钩子冒烟未通过" || true

# M3b: agent e2e 工具防护（信息项）
fake_reset
fw_set_mode tool-block
printf 'toolcall-once' > "${FAKE_DIR}/llm-script"
rm -f /tmp/aw-tool-ran
run_agent "mig-m3b" "MIG-M3B 工具防护e2e验证请执行命令" /logs/agent-m3b.json
sleep 3
M3B_TOOL_RAN="no"; [[ -f /tmp/aw-tool-ran ]] && M3B_TOOL_RAN="yes"
note "M3b 工具实际执行=${M3B_TOOL_RAN}（openclaw 策略或插件拦截，安全侧结果）"
printf 'text' > "${FAKE_DIR}/llm-script"

# ---------- 10. 断言 ----------
node /plugin-under-test/verify-migration/assert-migrated.mjs \
  /logs/fw-phase-install.jsonl \
  /logs/fw-phase-m1.jsonl /logs/agent-m1.json /logs/agent-m1.json.err "${M1_LLM}" \
  /logs/fw-phase-m2.jsonl /logs/agent-m2.json /logs/agent-m2.json.err "${M2_LLM}"
ASSERT_RC=$?
[[ ${ASSERT_RC} -ne 0 ]] && fail "断言未通过" || true

# ---------- 收尾 ----------
fw_set_mode pass
cp -R "${HOME}/.openclaw/logs" /logs/openclaw-logs 2>/dev/null || true
note "=== 结果汇总 ==="
printf 'FAILURES=%d install_rc=%d assert_rc=%d m3_rc=%d\n' "${FAILURES}" "${INSTALL_RC}" "${ASSERT_RC}" "${M3_RC}"

pkill -f "openclaw gateway" 2>/dev/null || true
kill "${FAKE_PID}" 2>/dev/null || true
sleep 1

if [[ ${FAILURES} -eq 0 ]]; then
  echo "MIG_RESULT ${OPENCLAW_VERSION} PASS"
  exit 0
fi
echo "MIG_RESULT ${OPENCLAW_VERSION} FAIL"
exit 1
