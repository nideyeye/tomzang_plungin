#!/usr/bin/env bash
# ============================================================
#  wb-firewall-guard 一键安装（macOS / Linux）
#
#  做了什么：
#    0. 检测安装包完整性：不完整（例如只下载了本脚本一个文件）时自动从 GitHub 下载整包解压后继续
#    1. 部署插件到 ~/.workbuddy/plugins/wb-firewall-guard（旧版本自动备份，只留最近 3 份）
#    2. 写入 config.json（firewallUrl / authKey / debug / blockTip …）
#    3. 备份 ~/.workbuddy/settings.json 并把 6 个钩子合并进去（幂等，重复执行不会堆积）
#    4. 向防火墙后端注册本机设备（device_id 与插件运行时同源）
#    5. 校验钩子已生效
#
#  用法：
#    ./install.sh <firewallUrl> <authKey>           # 后端地址与密钥必传（位置参数，与 tomzang_plungin 一致）
#    ./install.sh <url> <key> true "自定义拦截提示"
#    ./install.sh --url <url> --key <key> --debug true --skip-register
#    单文件也能装（脚本会自动从 GitHub 下载整包，多源重试）：
#    curl -fsSL <脚本下载地址>/install.sh -o install.sh && chmod +x install.sh && ./install.sh <url> <key>
#
#  环境变量（优先级低于命令行参数）：WB_FIREWALL_URL / WB_FIREWALL_AUTH_KEY
#  WB_FIREWALL_PKG_URL 可覆盖整包下载地址（设置后只走这一个地址；默认依次尝试 GitHub 直连 + 国内加速镜像）
# ============================================================

set -uo pipefail

PLUGIN_ID="wb-firewall-guard"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# 引导下载：脚本旁边没有 dist/ 时按顺序尝试这些下载源（GitHub 直连优先，失败自动换国内可达的加速镜像）
# WB_FIREWALL_PKG_URL 可整体覆盖（设置后只走这一个地址，调试/镜像用）
PKG_BASE="https://github.com/nideyeye/tomzang_plungin/archive/refs/heads/workbuddy.tar.gz"
DEFAULT_PKG_URLS=("${PKG_BASE}" "https://ghproxy.net/${PKG_BASE}" "https://gh-proxy.com/${PKG_BASE}")
if [[ -n "${WB_FIREWALL_PKG_URL:-}" ]]; then
  PACKAGE_URLS=("${WB_FIREWALL_PKG_URL}")
else
  PACKAGE_URLS=("${DEFAULT_PKG_URLS[@]}")
fi
PKG_DIR="${SCRIPT_DIR}/wb-firewall-guard-pkg"
ROOT=""   # 安装包根目录：脚本所在目录本身，或引导下载的解压目录，由完整性检测决定
TARGET="${HOME}/.workbuddy/plugins/${PLUGIN_ID}"
SETTINGS="${HOME}/.workbuddy/settings.json"

# -------- 日志 --------
log()  { printf '[%s] [INFO]  %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*"; }
warn() { printf '[%s] [WARN]  %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >&2; }
err()  { printf '[%s] [ERROR] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >&2; }

# -------- 安装包完整性：单文件运行时自动从 GitHub 引导下载整包 --------
pkg_complete() {
  [[ -f "$1/dist/install-helper.mjs" && -f "$1/dist/guard.mjs" \
     && -f "$1/dist/firewall.mjs" && -f "$1/dist/extract.mjs" \
     && -f "$1/config.example.json" ]]
}

bootstrap_package() {
  local archive url
  archive="$(mktemp "${TMPDIR:-/tmp}/wbfg-pkg.XXXXXX")" || return 1
  if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
    err "未找到 curl / wget，无法下载安装包"
    rm -f "${archive}"
    return 1
  fi
  for url in "${PACKAGE_URLS[@]}"; do
    log "安装包不完整，正在下载整包: ${url}"
    if command -v curl >/dev/null 2>&1; then
      curl -fsSL --connect-timeout 15 --max-time 300 "${url}" -o "${archive}" && break
    else
      wget -q --timeout=30 "${url}" -O "${archive}" && break
    fi
    warn "该下载源失败，换下一个源重试"
  done
  if [[ ! -s "${archive}" ]]; then
    err "所有下载源均失败（共 ${#PACKAGE_URLS[@]} 个）"
    rm -f "${archive}"
    return 1
  fi
  # 下载成功后才清掉旧缓存目录，下载失败时旧包还在，可作离线兜底
  rm -rf "${PKG_DIR}"
  mkdir -p "${PKG_DIR}" || { rm -f "${archive}"; return 1; }
  if ! tar xzf "${archive}" -C "${PKG_DIR}"; then
    err "解压安装包失败"
    rm -f "${archive}"
    return 1
  fi
  rm -f "${archive}"
  return 0
}

usage() {
  cat <<EOF
用法: $0 [firewallUrl authKey [debug] [blockTip]]
      $0 [--url <url>] [--key <key>] [--debug true|false] [--tip <文案>]
         [--target <安装目录>] [--settings <settings.json>] [--skip-register]

参数:
  firewallUrl   防火墙后端地址（必填，包内 config.example.json 只是占位符模板）
  authKey       防火墙认证密钥（必填，也可用环境变量 WB_FIREWALL_AUTH_KEY 传入）
  debug         是否开启调试日志 true/false（默认 false）
  blockTip      拦截时展示给用户的提示文案（默认内置文案）
  --skip-register  跳过设备注册（后端无 register 接口或离线安装时用）

示例:
  $0 http://\${防火墙服务地址}/ \${页面上生成的 key}
  $0 --url http://\${防火墙服务地址} --key \${页面上生成的 key}
EOF
}

# -------- 参数 --------
POSITIONAL=()
FIREWALL_URL=""
AUTH_KEY=""
DEBUG_FLAG=""
BLOCK_TIP=""
SKIP_REGISTER=0
CUSTOM_TARGET=""
CUSTOM_SETTINGS=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --url) FIREWALL_URL="${2:-}"; shift 2 ;;
    --key|--auth-key) AUTH_KEY="${2:-}"; shift 2 ;;
    --debug) DEBUG_FLAG="${2:-}"; shift 2 ;;
    --tip|--block-tip) BLOCK_TIP="${2:-}"; shift 2 ;;
    --target) CUSTOM_TARGET="${2:-}"; shift 2 ;;
    --settings) CUSTOM_SETTINGS="${2:-}"; shift 2 ;;
    --skip-register) SKIP_REGISTER=1; shift ;;
    --*) warn "未知参数: $1"; usage; exit 1 ;;
    *) POSITIONAL+=("$1"); shift ;;
  esac
done

if [[ ${#POSITIONAL[@]} -ge 1 ]]; then FIREWALL_URL="${POSITIONAL[0]}"; fi
if [[ ${#POSITIONAL[@]} -ge 2 ]]; then AUTH_KEY="${POSITIONAL[1]}"; fi
if [[ ${#POSITIONAL[@]} -ge 3 ]]; then DEBUG_FLAG="${POSITIONAL[2]}"; fi
if [[ ${#POSITIONAL[@]} -ge 4 ]]; then BLOCK_TIP="${POSITIONAL[3]}"; fi

# -------- 依赖：node --------
NODE_BIN="$(command -v node 2>/dev/null || true)"
if [[ -z "${NODE_BIN}" ]]; then
  for candidate in /opt/homebrew/bin/node /usr/local/bin/node /usr/bin/node \
                   "${HOME}/.nvm/versions/node/current/bin/node" \
                   "${HOME}/.volta/bin/node" "${HOME}/.fnm/current/bin/node"; do
    if [[ -x "${candidate}" ]]; then NODE_BIN="${candidate}"; break; fi
  done
fi
if [[ -z "${NODE_BIN}" ]]; then
  err "未找到 node（需要 ≥ 18）。请先安装 Node.js: https://nodejs.org/"
  err "macOS 也可: brew install node"
  exit 2
fi
log "node = ${NODE_BIN} ($("${NODE_BIN}" --version 2>/dev/null))"
log "安装脚本版本: v3 (2026-10-19)"

# -------- 解析安装包根目录：完整则就地安装，否则引导下载 --------
if pkg_complete "${SCRIPT_DIR}"; then
  ROOT="${SCRIPT_DIR}"
else
  BOOTSTRAP_OK=1
  bootstrap_package || BOOTSTRAP_OK=0
  if pkg_complete "${PKG_DIR}"; then
    ROOT="${PKG_DIR}"
  else
    # GitHub 归档会多一层 <repo>-<branch> 目录
    for d in "${PKG_DIR}"/*/; do
      if pkg_complete "${d}"; then ROOT="${d%/}"; break; fi
    done
  fi
  if [[ -z "${ROOT}" ]]; then
    err "无法获得完整安装包：当前目录不完整，所有下载源均失败，且本地无可用缓存"
    exit 2
  fi
  [[ "${BOOTSTRAP_OK}" -eq 1 ]] || warn "下载失败，改用本地已缓存的安装包: ${ROOT}"
fi
HELPER="${ROOT}/dist/install-helper.mjs"
log "安装包目录: ${ROOT}"

if [[ ! -f "${HELPER}" ]]; then
  err "找不到安装内核: ${HELPER}（安装包不完整）"
  exit 2
fi

# -------- 默认值：命令行参数 > 环境变量 > 包内 config.example.json --------
read_default() {
  "${NODE_BIN}" -e '
    const fs = require("fs");
    try {
      const c = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
      process.stdout.write(String(c[process.argv[2]] || ""));
    } catch (e) { process.stdout.write(""); }
  ' "$@" 2>/dev/null || true
}

# 环境变量优先于包内模板（模板里是 ${...} 占位符，不换掉会被下面的校验拦下）
if [[ -z "${FIREWALL_URL}" && -n "${WB_FIREWALL_URL:-}" ]]; then
  FIREWALL_URL="${WB_FIREWALL_URL}"; log "firewallUrl 取自环境变量 WB_FIREWALL_URL"
fi
if [[ -z "${AUTH_KEY}" && -n "${WB_FIREWALL_AUTH_KEY:-}" ]]; then
  AUTH_KEY="${WB_FIREWALL_AUTH_KEY}"; log "authKey 取自环境变量 WB_FIREWALL_AUTH_KEY"
fi
if [[ -z "${FIREWALL_URL}" ]]; then
  FIREWALL_URL="$(read_default "${ROOT}/config.example.json" firewallUrl)"
fi
if [[ -z "${AUTH_KEY}" ]]; then
  AUTH_KEY="$(read_default "${ROOT}/config.example.json" authKey)"
fi
if [[ -z "${DEBUG_FLAG}" ]]; then DEBUG_FLAG="false"; fi

# -------- 校验：空值或未替换的 ${...} 占位符一律拒绝，逼使用者在命令行填真实值 --------
is_unfilled() {
  [[ -z "${1:-}" || "${1}" == *'${'* ]]
}
if is_unfilled "${FIREWALL_URL}" || is_unfilled "${AUTH_KEY}"; then
  err "firewallUrl / authKey 未填写，或仍是占位符（包内 config.example.json 只是模板）。"
  err "请在命令行传入真实值，例如："
  err "  $0 http://<防火墙服务地址> <页面上生成的key>"
  err "  $0 --url http://<防火墙服务地址> --key <页面上生成的key>"
  exit 2
fi

TARGET_ARGS=()
[[ -n "${CUSTOM_TARGET}" ]] && TARGET_ARGS=(--target "${CUSTOM_TARGET}")
SETTINGS_ARGS=()
[[ -n "${CUSTOM_SETTINGS}" ]] && SETTINGS_ARGS=(--settings "${CUSTOM_SETTINGS}")
if [[ -n "${CUSTOM_TARGET}" ]]; then TARGET="${CUSTOM_TARGET}"; fi
if [[ -n "${CUSTOM_SETTINGS}" ]]; then SETTINGS="${CUSTOM_SETTINGS}"; fi

log "安装目录: ${TARGET}"
log "配置文件: ${SETTINGS}"

# -------- Step 1: 部署 --------
log "Step 1/5  部署插件文件"
if ! "${NODE_BIN}" "${HELPER}" deploy --source "${ROOT}" --target "${TARGET}"; then
  err "部署插件文件失败"
  exit 2
fi

# -------- Step 2: 写配置 --------
log "Step 2/5  写入 config.json"
CONFIG_ARGS=(--url "${FIREWALL_URL}" --key "${AUTH_KEY}" --debug "${DEBUG_FLAG}")
[[ -n "${BLOCK_TIP}" ]] && CONFIG_ARGS+=(--tip "${BLOCK_TIP}")
if ! "${NODE_BIN}" "${HELPER}" config --target "${TARGET}" "${CONFIG_ARGS[@]}"; then
  err "写入 config.json 失败"
  exit 2
fi

# -------- Step 3: 挂钩子 --------
log "Step 3/5  挂载 WorkBuddy 钩子"
if ! "${NODE_BIN}" "${HELPER}" hooks --target "${TARGET}" --settings "${SETTINGS}"; then
  err "挂载钩子失败"
  exit 2
fi

# -------- Step 4: 设备注册 --------
if [[ "${SKIP_REGISTER}" -eq 1 ]]; then
  log "Step 4/5  跳过设备注册（--skip-register）"
else
  log "Step 4/5  向防火墙后端注册设备"
  if ! "${NODE_BIN}" "${HELPER}" register --url "${FIREWALL_URL}" --key "${AUTH_KEY}"; then
    err "设备注册失败。插件已安装但后端可能拒绝该设备的审计请求。"
    err "可加 --skip-register 强制安装；或恢复备份后排查网络/密钥。"
    err "配置文件备份目录: $(dirname "${SETTINGS}")"
    exit 3
  fi
fi

# -------- Step 5: 校验 --------
log "Step 5/5  校验安装结果"
if ! "${NODE_BIN}" "${HELPER}" verify --target "${TARGET}" --settings "${SETTINGS}"; then
  err "校验未通过"
  exit 4
fi

cat <<EOF

────────────────────────────────────────────
安装完成。

  插件目录  ${TARGET}
  配置文件  ${SETTINGS}
  日志      ${TARGET}/logs/guard.log

生效方式：完全退出并重启 WorkBuddy 会话（钩子只在会话启动时加载）。

其它命令：
  卸载    bash ${ROOT}/uninstall.sh
  自检    cat '{"prompt":"hello"}' | "${NODE_BIN}" "${TARGET}/dist/guard.mjs" input
  排误判  "${NODE_BIN}" "${TARGET}/dist/guard.mjs" output --explain < case.json
────────────────────────────────────────────
EOF
