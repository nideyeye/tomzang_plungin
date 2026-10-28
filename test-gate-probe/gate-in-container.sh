#!/usr/bin/env bash
# gate-in-container.sh — 官方钩子行为实测编排（research-audit 分支）
# 由宿主通过 docker run 调起，环境变量:
#   OPENCLAW_VERSION   被测 openclaw 版本
#   AW_FW_PORT / AW_LLM_PORT / AW_GW_PORT  本地服务端口
#   OPENCLAW_GATEWAY_TOKEN  网关令牌
# 挂载: /plugin-src(插件仓库, ro) /logs(结果, rw)
# 场景:
#   T-A 观测: 正常消息 → llm_input/llm_output 触发且带 sessionId，LLM 真实调用
#   T-B 截断: GATE_BLOCK → before_agent_run block，用户可见 message，0 次 LLM 调用
#   T-C 代答: GATE_ANSWER → before_agent_reply handled，0 次 LLM 调用
# 退出码: 0 全部通过 / 1 断言失败 / 2 环境错误

set -u
set -o pipefail

OPENCLAW_VERSION="${OPENCLAW_VERSION:-}"
AW_FW_PORT="${AW_FW_PORT:-9820}"
AW_LLM_PORT="${AW_LLM_PORT:-9821}"
AW_GW_PORT="${AW_GW_PORT:-18809}"
PLUGIN_SRC="/plugin-src"
PLUGIN_STAGING="${PLUGIN_SRC}/test-gate-probe/plugin"
PLUGIN_DIR="${HOME}/.openclaw/extensions/gate-probe"
FAKE_DIR="/logs/fake"

export GATE_PROBE_LOG="/logs/gate-probe-events.jsonl"
EVENTS_LOG="${GATE_PROBE_LOG}"

FAILURES=0
note()  { printf '[gate-ctl][%s] %s\n' "$(date '+%H:%M:%S')" "$*"; }
fail()  { printf '[gate-ctl][FAIL] %s\n' "$*" >&2; FAILURES=$((FAILURES+1)); }
die()   { printf '[gate-ctl][ENV-FAIL] %s\n' "$*" >&2; exit 2; }

[[ -n "${OPENCLAW_VERSION}" ]] || die "OPENCLAW_VERSION 未设置"
[[ -d "${PLUGIN_STAGING}" ]]  || die "${PLUGIN_STAGING} 未挂载"
[[ -d /logs ]]                || die "/logs 未挂载"

exec > >(tee -a /logs/container.log) 2>&1
note "=== gate-probe 官方钩子实测开始: openclaw@${OPENCLAW_VERSION} ==="

# ---------- 1. 安装 openclaw ----------
note "[step1] npm install -g openclaw@${OPENCLAW_VERSION}"
npm install -g "openclaw@${OPENCLAW_VERSION}" >/logs/npm-install.log 2>&1 || {
  tail -30 /logs/npm-install.log
  die "openclaw@${OPENCLAW_VERSION} 安装失败"
}
openclaw --version | tee /logs/openclaw-version.txt

# ---------- 2. 起假服务（本测试只用假 LLM；假防火墙顺带起但不消费） ----------
note "[step2] 启动假 LLM (port ${AW_LLM_PORT})"
mkdir -p "${FAKE_DIR}"
node /plugin-src/verify-migration/fake-server.mjs --firewall-port "${AW_FW_PORT}" --llm-port "${AW_LLM_PORT}" --dir "${FAKE_DIR}" >/logs/fake-server.log 2>&1 &
FAKE_PID=$!
for i in $(seq 1 30); do
  curl -sf "http://127.0.0.1:${AW_LLM_PORT}/__count" >/dev/null 2>&1 && break
  sleep 1
done
curl -sf "http://127.0.0.1:${AW_LLM_PORT}/__count" >/dev/null || die "假 LLM 启动失败"
printf 'text' > "${FAKE_DIR}/llm-script"

# ---------- 3. 部署探针插件 + 写配置 ----------
note "[step3] 部署 gate-probe → ${PLUGIN_DIR}"
rm -rf "${PLUGIN_DIR}"
mkdir -p "$(dirname "${PLUGIN_DIR}")"
cp -R "${PLUGIN_STAGING}" "${PLUGIN_DIR}"
node --check "${PLUGIN_DIR}/index.js" || die "探针插件语法错误"

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
const pluginDir = process.env.HOME + "/.openclaw/extensions/gate-probe";
const pathRel = "~/.openclaw/extensions/gate-probe";
cfg.plugins = cfg.plugins || {};
cfg.plugins.load = cfg.plugins.load || {};
const paths = Array.isArray(cfg.plugins.load.paths) ? cfg.plugins.load.paths : [];
if (!paths.includes(pluginDir) && !paths.includes(pathRel)) paths.push(pathRel);
cfg.plugins.load.paths = paths;
// 允许清单：外部插件不在 plugins.allow 中会被拒绝加载（install.sh 同款机制）
cfg.plugins.allow = Array.isArray(cfg.plugins.allow) ? cfg.plugins.allow : [];
if (!cfg.plugins.allow.includes("gate-probe")) cfg.plugins.allow.push("gate-probe");
// 内容型钩子权限门（llm_input/llm_output/before_agent_reply 需要）
cfg.plugins.entries = Object.assign({}, cfg.plugins.entries, {
  "gate-probe": { hooks: { allowConversationAccess: true } },
});
fs.writeFileSync(p, JSON.stringify(cfg, null, 2));
console.log("config written");
'
cp "${HOME}/.openclaw/openclaw.json" /logs/openclaw-config.json

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

# ---------- 4. 启动网关 ----------
note "[step4] 启动 gateway"
pkill -f "openclaw gateway" 2>/dev/null || true
sleep 1
nohup openclaw gateway run >>/logs/gateway-stdout.log 2>&1 &
if ! wait_health 150; then
  cp -R "${HOME}/.openclaw/logs" /logs/openclaw-logs 2>/dev/null || true
  tail -50 /logs/gateway-stdout.log
  die "gateway 无法启动"
fi
note "gateway 已监听 :${AW_GW_PORT}"
openclaw health >/logs/gateway-health.json 2>&1 || true

llm_count() { curl -sf "http://127.0.0.1:${AW_LLM_PORT}/__count" | sed -E 's/.*"llm":([0-9]+).*/\1/'; }

# 等探针插件被懒加载（首个 agent 请求后才预热；预热后事件文件会出现 register 行）
wait_plugin_loaded() {
  local i
  for i in $(seq 1 20); do
    if [[ -f "${EVENTS_LOG}" ]] && grep -q '"kind":"register"' "${EVENTS_LOG}" 2>/dev/null; then return 0; fi
    sleep 1
  done
  return 1
}

run_agent() { # run_agent <sessionId> <message> <outfile>
  openclaw agent -m "$2" --json --session-id "$1" --timeout 120 >"$3" 2>"$3.err" || true
}

# ---------- 预热（插件懒加载：首个请求触发加载，预热后才对 T-A 断言） ----------
note "[warmup] 预热请求（触发插件加载，不参与断言）"
curl -sf "http://127.0.0.1:${AW_LLM_PORT}/__reset" >/dev/null
rm -f "${EVENTS_LOG}"
run_agent "gp-warm" "GP-WARMUP 预热请求" /logs/agent-warm.json
sleep 2
if wait_plugin_loaded; then
  note "预热完成，gate-probe 已加载"
else
  note "预热后仍未加载（后续断言将揭示问题）"
fi

# ---------- T-A 观测 ----------
note "[T-A] 正常消息 → llm_input/llm_output 触发 + sessionId"
curl -sf "http://127.0.0.1:${AW_LLM_PORT}/__reset" >/dev/null
rm -f "${EVENTS_LOG}"
run_agent "gp-ta" "GP-TA 正常请求，请照常回复" /logs/agent-ta.json
sleep 2
wait_plugin_loaded || note "T-A: 未见 register 事件（插件可能未加载）"
TA_LLM_COUNT=$(llm_count)
cp "${EVENTS_LOG}" /logs/events-ta.jsonl 2>/dev/null || true
note "T-A 后 LLM 调用数=${TA_LLM_COUNT}"

# ---------- T-B 截断 ----------
note "[T-B] GATE_BLOCK → before_agent_run block"
curl -sf "http://127.0.0.1:${AW_LLM_PORT}/__reset" >/dev/null
rm -f "${EVENTS_LOG}"
run_agent "gp-tb" "GP-TB GATE_BLOCK 这条消息应当被截断" /logs/agent-tb.json
sleep 2
TB_LLM_COUNT=$(llm_count)
cp "${EVENTS_LOG}" /logs/events-tb.jsonl 2>/dev/null || true
note "T-B 后 LLM 调用数=${TB_LLM_COUNT}"

# ---------- T-C 代答 ----------
note "[T-C] GATE_ANSWER → before_agent_reply handled"
curl -sf "http://127.0.0.1:${AW_LLM_PORT}/__reset" >/dev/null
rm -f "${EVENTS_LOG}"
run_agent "gp-tc" "GP-TC GATE_ANSWER 这条消息应当被代答" /logs/agent-tc.json
sleep 2
TC_LLM_COUNT=$(llm_count)
cp "${EVENTS_LOG}" /logs/events-tc.jsonl 2>/dev/null || true
note "T-C 后 LLM 调用数=${TC_LLM_COUNT}"

# ---------- 5. 断言 ----------
node /plugin-src/test-gate-probe/assert-gate.mjs \
  /logs/events-ta.jsonl /logs/agent-ta.json /logs/agent-ta.json.err "${TA_LLM_COUNT}" \
  /logs/events-tb.jsonl /logs/agent-tb.json /logs/agent-tb.json.err "${TB_LLM_COUNT}" \
  /logs/events-tc.jsonl /logs/agent-tc.json /logs/agent-tc.json.err "${TC_LLM_COUNT}"
ASSERT_RC=$?
[[ ${ASSERT_RC} -ne 0 ]] && fail "断言未通过" || true

# ---------- 收尾 ----------
cp -R "${HOME}/.openclaw/logs" /logs/openclaw-logs 2>/dev/null || true
note "=== 结果汇总 ==="
printf 'FAILURES=%d assert_rc=%d\n' "${FAILURES}" "${ASSERT_RC}"

pkill -f "openclaw gateway" 2>/dev/null || true
kill "${FAKE_PID}" 2>/dev/null || true
sleep 1

if [[ ${FAILURES} -eq 0 ]]; then
  echo "GP_RESULT ${OPENCLAW_VERSION} PASS"
  exit 0
fi
echo "GP_RESULT ${OPENCLAW_VERSION} FAIL"
exit 1
