set -euo pipefail

# -------- 常量 --------
PLUGIN_ID="tomzang_plungin"
CLAWHUB_REF="clawhub:${PLUGIN_ID}"
PLUGIN_DIR="${HOME}/.openclaw/extensions/${PLUGIN_ID}"
CONFIG_FILE="${HOME}/.openclaw/openclaw.json"
GITHUB_REPO="nideyeye/${PLUGIN_ID}"
GITHUB_API_LATEST="https://api.github.com/repos/${GITHUB_REPO}/releases/latest"
GITHUB_PAGE="https://github.com/${GITHUB_REPO}"
# 可选: 通过环境变量 GITHUB_TOKEN 提升 API 速率限制
GITHUB_TOKEN="${GITHUB_TOKEN:-}"
TMP_DIR="$(mktemp -d -t ${PLUGIN_ID}.XXXXXX)"

# -------- 工具函数 --------
log()  { printf '[%s] [INFO]  %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*"; }
warn() { printf '[%s] [WARN]  %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >&2; }
err()  { printf '[%s] [ERROR] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >&2; }

cleanup() { rm -rf "${TMP_DIR}" 2>/dev/null || true; }
trap cleanup EXIT

usage() {
  cat <<EOF
用法: $0 <firewallUrl> <authKey> [blockMessage] [debug]

参数:
  firewallUrl   防火墙 API 地址 (必填, 对应 openclaw.plugin.json 中的 firewallUrl)
  authKey       防火墙 API 认证密钥 (必填, 对应 openclaw.plugin.json 中的 authKey)
  blockMessage  自定义拦截提示语 (可选)
  debug         是否开启调试日志 true/false (可选, 默认 false)

示例:
  $0 http://127.0.0.1:8080/api/firewall/openclaw/validate my-auth-key
EOF
}

# -------- 参数校验 --------
if [[ $# -lt 2 ]]; then
  usage
  exit 1
fi

FIREWALL_URL="$1"
AUTH_KEY="$2"
BLOCK_MESSAGE="${3:-}"
DEBUG_FLAG="${4:-false}"

# 归一化 debug 取值
if [[ "${DEBUG_FLAG}" == "true" ]]; then
  DEBUG_VAL="true"
else
  DEBUG_VAL="false"
fi

# -------- 依赖检查 --------
need_cmd() {
  command -v "$1" >/dev/null 2>&1 || { err "缺少依赖命令: $1, 请先安装"; exit 2; }
}

HAS_OPENCLAW=0
if command -v openclaw >/dev/null 2>&1; then
  HAS_OPENCLAW=1
fi

# -------- 方式 1: 通过 openclaw CLI 安装 --------
install_via_openclaw() {
  if [[ "${HAS_OPENCLAW}" -ne 1 ]]; then
    warn "未检测到 openclaw 命令, 跳过 CLI 安装"
    return 1
  fi
  log "尝试通过 openclaw CLI 安装: openclaw plugins install ${CLAWHUB_REF}"
  if openclaw plugins install "${CLAWHUB_REF}"; then
    log "openclaw CLI 安装成功"
    return 0
  fi
  warn "openclaw CLI 安装失败"
  return 1
}

# -------- 方式 1 的配置: 通过 openclaw CLI 写配置 --------
config_via_openclaw() {
  if [[ "${HAS_OPENCLAW}" -ne 1 ]]; then
    return 1
  fi
  log "尝试通过 openclaw CLI 写入配置"

  local ok=1
  # 依次设置必填/可选项, 任一失败即视为 CLI 配置不可用
  if ! openclaw plugins config "${PLUGIN_ID}" "firewallUrl=${FIREWALL_URL}" >/dev/null 2>&1; then
    ok=0
  fi
  if [[ "${ok}" -eq 1 ]] && \
     ! openclaw plugins config "${PLUGIN_ID}" "authKey=${AUTH_KEY}" >/dev/null 2>&1; then
    ok=0
  fi
  if [[ "${ok}" -eq 1 && -n "${BLOCK_MESSAGE}" ]] && \
     ! openclaw plugins config "${PLUGIN_ID}" "blockMessage=${BLOCK_MESSAGE}" >/dev/null 2>&1; then
    ok=0
  fi
  if [[ "${ok}" -eq 1 ]] && \
     ! openclaw plugins config "${PLUGIN_ID}" "debug=${DEBUG_VAL}" >/dev/null 2>&1; then
    ok=0
  fi

  if [[ "${ok}" -eq 1 ]]; then
    # 尝试启用 / 加入 allowlist (CLI 子命令命名因版本而异, 失败均不影响主流程)
    openclaw plugins enable "${PLUGIN_ID}" >/dev/null 2>&1 || true
    openclaw plugins allow  "${PLUGIN_ID}" >/dev/null 2>&1 || true
    openclaw plugins allowlist add "${PLUGIN_ID}" >/dev/null 2>&1 || true
    log "openclaw CLI 配置写入成功"
    return 0
  fi
  warn "openclaw CLI 配置写入失败, 将回退为直接写 ${CONFIG_FILE}"
  return 1
}

# -------- 校验插件是否已进入 allowlist; 未进入则返回 1 --------
verify_in_allowlist() {
  if ! command -v node >/dev/null 2>&1; then
    # 没有 node 无法解析, 默认认为需要补写
    return 1
  fi
  PLUGIN_ID="${PLUGIN_ID}" CONFIG_FILE="${CONFIG_FILE}" node -e '
    const fs = require("fs");
    const p = process.env.CONFIG_FILE;
    if (!fs.existsSync(p)) process.exit(1);
    let cfg;
    try { cfg = JSON.parse(fs.readFileSync(p, "utf8")); } catch (e) { process.exit(1); }
    const allow = cfg && cfg.plugins && Array.isArray(cfg.plugins.allow) ? cfg.plugins.allow : [];
    process.exit(allow.includes(process.env.PLUGIN_ID) ? 0 : 1);
  ' >/dev/null 2>&1
}

# -------- 方式 2: 从 GitHub Release 下载并手动部署 --------
# 解析最新 release 的下载 URL 与 tag, 写入 stdout 两行: <tag> <url>
# 优先使用 release 资产 (asset), 回退到 release 源码 tarball
resolve_latest_release() {
  need_cmd curl
  local headers=(-H 'Accept: application/vnd.github+json' -H 'User-Agent: tomzang_plungin-installer')
  if [[ -n "${GITHUB_TOKEN}" ]]; then
    headers+=(-H "Authorization: Bearer ${GITHUB_TOKEN}")
  fi

  local body
  if ! body="$(curl -fsSL --connect-timeout 10 --max-time 60 \
                  "${headers[@]}" "${GITHUB_API_LATEST}")"; then
    err "调用 GitHub API 失败: ${GITHUB_API_LATEST}"
    return 1
  fi

  local tag="" url=""
  if command -v node >/dev/null 2>&1; then
    # 使用 node 严谨解析 JSON: 优先 .tar.gz/.tgz/.zip 资产, 否则用 tarball_url
    read -r tag url < <(BODY="${body}" node -e '
      const r = JSON.parse(process.env.BODY);
      const tag = r.tag_name || "";
      let url = "";
      const assets = Array.isArray(r.assets) ? r.assets : [];
      const pick = assets.find(a => /\.(tar\.gz|tgz)$/i.test(a.name))
                || assets.find(a => /\.zip$/i.test(a.name));
      if (pick) url = pick.browser_download_url;
      else if (r.tarball_url) url = r.tarball_url;
      console.log(tag + " " + url);
    ' 2>/dev/null) || true
  else
    # 退化: 使用 grep/sed 抓取字段, 容忍度有限但能覆盖 GitHub 标准响应
    tag="$(printf '%s' "${body}" | grep -m1 '"tag_name"' \
            | sed -E 's/.*"tag_name"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/')"
    url="$(printf '%s' "${body}" | grep -m1 '"browser_download_url"' \
            | grep -Eo 'https://[^"]+\.(tar\.gz|tgz|zip)' | head -n 1)"
    if [[ -z "${url}" ]]; then
      url="$(printf '%s' "${body}" | grep -m1 '"tarball_url"' \
              | sed -E 's/.*"tarball_url"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/')"
    fi
  fi

  if [[ -z "${url}" ]]; then
    err "未能从 GitHub Release 中解析出下载地址 (仓库可能尚未发布 release)"
    return 1
  fi

  printf '%s %s\n' "${tag:-unknown}" "${url}"
}

download_from_github() {
  local dst="$1"
  need_cmd curl
  need_cmd tar

  local resolved tag url ext archive
  if ! resolved="$(resolve_latest_release)"; then
    return 1
  fi
  tag="${resolved%% *}"
  url="${resolved#* }"
  log "GitHub 最新 release: ${tag}"
  log "下载地址: ${url}"

  case "${url}" in
    *.zip) ext="zip" ;;
    *)     ext="tar.gz" ;;
  esac
  archive="${dst}/release.${ext}"

  local dl_args=(-fsSL --connect-timeout 10 --max-time 300 -o "${archive}")
  if [[ -n "${GITHUB_TOKEN}" ]]; then
    dl_args+=(-H "Authorization: Bearer ${GITHUB_TOKEN}")
  fi
  if ! curl "${dl_args[@]}" "${url}"; then
    err "下载 release 失败: ${url}"
    return 1
  fi

  mkdir -p "${dst}/extracted"
  if [[ "${ext}" == "zip" ]]; then
    need_cmd unzip
    if ! unzip -q "${archive}" -d "${dst}/extracted"; then
      err "解压 zip 失败: ${archive}"
      return 1
    fi
  else
    if ! tar -xzf "${archive}" -C "${dst}/extracted"; then
      err "解压 tar.gz 失败: ${archive}"
      return 1
    fi
  fi
  log "GitHub release 下载并解压完成"
  return 0
}

locate_plugin_root() {
  local base="$1"
  local candidate
  candidate="$(find "${base}" -maxdepth 4 -type f -name 'openclaw.plugin.json' 2>/dev/null | head -n 1)"
  if [[ -z "${candidate}" ]]; then
    err "解压后未找到 openclaw.plugin.json, 安装包格式异常"
    return 1
  fi
  dirname "${candidate}"
}

install_via_github() {
  if ! download_from_github "${TMP_DIR}"; then
    return 1
  fi
  local src_root
  src_root="$(locate_plugin_root "${TMP_DIR}/extracted")" || return 1
  log "插件源目录: ${src_root}"

  # 备份已存在的插件目录
  if [[ -d "${PLUGIN_DIR}" ]]; then
    local ts backup
    ts="$(date '+%Y%m%d_%H%M%S')"
    backup="${PLUGIN_DIR}.bak.${ts}"
    mv "${PLUGIN_DIR}" "${backup}"
    log "已备份原插件目录到: ${backup}"
  fi

  mkdir -p "${PLUGIN_DIR}"
  cp -R "${src_root}/." "${PLUGIN_DIR}/"
  log "插件文件已部署到: ${PLUGIN_DIR}"
  return 0
}

# -------- 方式 2 的配置: 直接写 openclaw.json (带备份) --------
write_config_file() {
  local cfg_dir
  cfg_dir="$(dirname "${CONFIG_FILE}")"
  mkdir -p "${cfg_dir}"

  if [[ -f "${CONFIG_FILE}" ]]; then
    local ts backup
    ts="$(date '+%Y%m%d_%H%M%S')"
    backup="${CONFIG_FILE}.bak.${ts}"
    cp "${CONFIG_FILE}" "${backup}"
    log "已备份原配置到: ${backup}"
  fi

  if command -v node >/dev/null 2>&1; then
    FIREWALL_URL="${FIREWALL_URL}" \
    AUTH_KEY="${AUTH_KEY}" \
    BLOCK_MESSAGE="${BLOCK_MESSAGE}" \
    DEBUG_VAL="${DEBUG_VAL}" \
    PLUGIN_ID="${PLUGIN_ID}" \
    PLUGIN_DIR="${PLUGIN_DIR}" \
    CONFIG_FILE="${CONFIG_FILE}" \
    node -e '
      const fs = require("fs");
      const path = process.env.CONFIG_FILE;
      const pid = process.env.PLUGIN_ID;
      const pluginDir = process.env.PLUGIN_DIR;
      // 写入配置时使用 ~ 形式, 与现有配置保持一致
      const home = process.env.HOME || "";
      const pathRel = home && pluginDir.startsWith(home) ? "~" + pluginDir.slice(home.length) : pluginDir;

      let cfg = {};
      if (fs.existsSync(path)) {
        try { cfg = JSON.parse(fs.readFileSync(path, "utf8")); } catch (e) { cfg = {}; }
      }
      cfg.plugins = cfg.plugins || {};

      // 1. 写入 entries 配置
      cfg.plugins.entries = cfg.plugins.entries || {};
      const entry = cfg.plugins.entries[pid] || {};
      entry.enabled = true;
      entry.config = entry.config || {};
      entry.config.firewallUrl = process.env.FIREWALL_URL;
      entry.config.authKey = process.env.AUTH_KEY;
      if (process.env.BLOCK_MESSAGE && process.env.BLOCK_MESSAGE.length > 0) {
        entry.config.blockMessage = process.env.BLOCK_MESSAGE;
      }
      entry.config.debug = process.env.DEBUG_VAL === "true";
      cfg.plugins.entries[pid] = entry;

      // 2. 写入 allowlist (plugins.allow), 这是消除 "not in allowlist" 警告的关键
      cfg.plugins.allow = Array.isArray(cfg.plugins.allow) ? cfg.plugins.allow : [];
      if (!cfg.plugins.allow.includes(pid)) {
        cfg.plugins.allow.push(pid);
      }

      // 3. 写入 load.paths, 让 OpenClaw 能扫描到该插件目录
      cfg.plugins.load = cfg.plugins.load || {};
      cfg.plugins.load.paths = Array.isArray(cfg.plugins.load.paths) ? cfg.plugins.load.paths : [];
      if (!cfg.plugins.load.paths.includes(pathRel) &&
          !cfg.plugins.load.paths.includes(pluginDir)) {
        cfg.plugins.load.paths.push(pathRel);
      }

      fs.writeFileSync(path, JSON.stringify(cfg, null, 2));
    '
    log "已写入配置: ${CONFIG_FILE} (含 entries / allow / load.paths)"
  else
    warn "未检测到 node, 无法自动合并 JSON 配置, 请手动在 ${CONFIG_FILE} 中添加如下配置:"
    cat <<EOF
{
  "plugins": {
    "allow": ["${PLUGIN_ID}"],
    "load": {
      "paths": ["~/.openclaw/extensions/${PLUGIN_ID}"]
    },
    "entries": {
      "${PLUGIN_ID}": {
        "enabled": true,
        "config": {
          "firewallUrl": "${FIREWALL_URL}",
          "authKey": "${AUTH_KEY}"$( [[ -n "${BLOCK_MESSAGE}" ]] && printf ',\n          "blockMessage": "%s"' "${BLOCK_MESSAGE}" ),
          "debug": ${DEBUG_VAL}
        }
      }
    }
  }
}
EOF
  fi
}

# -------- 主流程 --------
main() {
  log "开始安装 ${PLUGIN_ID}"
  log "目标目录: ${PLUGIN_DIR}"

  local install_ok=0
  local config_done_by_cli=0

  # Step 1: 优先使用 openclaw CLI 安装
  if install_via_openclaw; then
    install_ok=1
    # 安装成功后, 继续尝试用 CLI 完成配置
    if config_via_openclaw; then
      config_done_by_cli=1
    fi
  fi

  # Step 2: CLI 路径失败则回退到 GitHub
  if [[ "${install_ok}" -ne 1 ]]; then
    warn "openclaw CLI 安装不可用, 回退到 GitHub 方案"
    if ! install_via_github; then
      err "所有安装渠道均失败, 安装中止"
      exit 3
    fi
    install_ok=1
  fi

  # Step 3: 若 CLI 未能完成配置, 直接写配置文件
  if [[ "${config_done_by_cli}" -ne 1 ]]; then
    write_config_file
  fi

  # Step 4: 兜底校验, 确保插件已加入 allowlist (避免 "not in allowlist" 警告导致禁用)
  if ! verify_in_allowlist; then
    warn "插件尚未出现在 plugins.allow 中, 进行兜底补写"
    write_config_file
  fi

  log "${PLUGIN_ID} 安装完成, 请运行: openclaw gateway restart 以使配置生效"
}

main "$@"
