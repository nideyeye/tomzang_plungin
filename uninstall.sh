#!/usr/bin/env bash
# ============================================================
#  wb-firewall-guard 卸载（macOS / Linux）
#
#  默认只摘掉 ~/.workbuddy/settings.json 里的钩子，保留插件目录与 config.json
#  （方便改配置后直接重装）。加 --purge 会连插件目录一起移除（先备份）。
# ============================================================

set -uo pipefail

PLUGIN_ID="wb-firewall-guard"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HELPER="${ROOT}/dist/install-helper.mjs"
TARGET="${HOME}/.workbuddy/plugins/${PLUGIN_ID}"
SETTINGS="${HOME}/.workbuddy/settings.json"
PURGE=0

log()  { printf '[%s] [INFO]  %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*"; }
err()  { printf '[%s] [ERROR] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >&2; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --purge) PURGE=1; shift ;;
    --target) TARGET="$2"; shift 2 ;;
    --settings) SETTINGS="$2"; shift 2 ;;
    -h|--help) sed -n '2,10p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) err "未知参数: $1"; exit 1 ;;
  esac
done

NODE_BIN="$(command -v node 2>/dev/null || true)"
if [[ -z "${NODE_BIN}" ]]; then
  for candidate in /opt/homebrew/bin/node /usr/local/bin/node /usr/bin/node; do
    [[ -x "${candidate}" ]] && { NODE_BIN="${candidate}"; break; }
  done
fi
if [[ -z "${NODE_BIN}" ]]; then
  err "未找到 node，无法卸载"
  exit 2
fi

ARGS=(--target "${TARGET}" --settings "${SETTINGS}")
[[ "${PURGE}" -eq 1 ]] && ARGS+=(--purge true)

log "卸载目录: ${TARGET}"
if ! "${NODE_BIN}" "${HELPER}" uninstall "${ARGS[@]}"; then
  err "卸载失败"
  exit 2
fi

log "卸载完成。重启 WorkBuddy 会话后生效。"
log "重装： bash ${ROOT}/install.sh"
