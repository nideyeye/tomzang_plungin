#!/usr/bin/env bash

# OpenCode 插件安装脚本 (Unix-like: Linux, macOS)
# Windows 用户请使用 install.ps1
# 支持在线安装和离线安装，可自定义配置

set -euo pipefail

# 远程仓库配置
REPO_URL="https://raw.githubusercontent.com/nideyeye/tomzang_plungin"
REPO_BRANCH="${REPO_BRANCH:-open-code}"  # 可通过环境变量覆盖

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 打印函数
info() { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# 获取脚本所在目录
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLUGIN_FILE="${SCRIPT_DIR}/index.js"

# OpenCode 配置路径
OPENCODE_CONFIG_DIR="${HOME}/.config/opencode"
OPENCODE_CONFIG_FILE="${OPENCODE_CONFIG_DIR}/opencode.json"
OPENCODE_PLUGINS_DIR="${OPENCODE_CONFIG_DIR}/plugins"

# 默认配置
INSTALL_MODE="global"  # 使用全局安装模式
FIREWALL_URL=""
AUTH_KEY=""
BLOCK_MESSAGE="当前请求包含敏感信息，已被安全组件拦截"
FIREWALL_TIMEOUT=3000
DEBUG=false
PROJECT_DIR="${PWD}"
SKIP_VALIDATION=false

# Shell 配置文件路径
SHELL_CONFIG_FILE=""

# 显示帮助信息
show_help() {
    cat << EOF
OpenCode 插件离线安装脚本

用法: $0 [选项] [firewall-url] [auth-key]

选项:
    -m, --mode <MODE>          安装模式: project (项目级) 或 global (全局级) [默认: global]
    -p, --project-dir <PATH>  项目目录 [默认: 当前目录]
    -u, --firewall-url <URL>   防火墙服务地址
    -a, --auth-key <KEY>       认证密钥
    -b, --block-message <MSG>  拦截提示消息
    -t, --timeout <MS>         超时时间(毫秒) [默认: 3000]
    -d, --debug                启用调试模式
    -s, --skip-validation      跳过配置验证
    -h, --help                 显示此帮助信息

位置参数:
    firewall-url              防火墙服务地址 (等同于 -u/--firewall-url)
    auth-key                  认证密钥 (等同于 -a/--auth-key)

交互式模式 (不带参数运行):
    脚本将提示输入所有必要配置

说明:
    插件通过环境变量进行配置，安装后会自动添加到您的 shell 配置文件中。
    安装完成后请运行 'source ~/.zshrc' 或重启终端使环境变量生效。

示例:
    # 交互式安装
    $0

    # 快速安装 (位置参数: firewall-url auth-key)
    $0 http://firewall-url auth-key

    # 全局安装（默认模式）
    $0 -u "http://localhost:8080" -a "your-key"

    # 项目级安装
    $0 -m project -p /path/to/project -u "http://localhost:8080" -a "your-key"

    # 一键安装命令
    curl -fsSL https://raw.githubusercontent.com/nideyeye/tomzang_plungin/open-code/install.sh | bash -s -- http://firewall-url auth-key

EOF
}

# 下载远程文件
download_file() {
    local url="$1"
    local dest="$2"
    local max_retries=3
    local retry=0

    while [[ $retry -lt $max_retries ]]; do
        if curl -fsSL "${url}" -o "${dest}"; then
            return 0
        fi
        ((retry++))
        if [[ $retry -lt $max_retries ]]; then
            warn "下载失败，重试 ($retry/$max_retries)..."
            sleep 1
        fi
    done

    error "无法下载文件: ${url}"
}

# 检查必要的文件
check_files() {
    info "检查必要文件..."

    # 检查是否需要远程下载
    if [[ ! -f "${PLUGIN_FILE}" ]]; then
        warn "本地插件文件不存在，尝试从远程下载..."

        # 创建临时目录
        TEMP_DIR=$(mktemp -d)
        info "创建临时目录: ${TEMP_DIR}"

        # 下载插件文件
        info "下载插件文件..."
        download_file "${REPO_URL}/${REPO_BRANCH}/index.js" "${TEMP_DIR}/index.js"

        # 更新文件路径
        PLUGIN_FILE="${TEMP_DIR}/index.js"

        success "远程文件下载完成"
    fi

    if [[ ! -f "${PLUGIN_FILE}" ]]; then
        error "插件文件不存在: ${PLUGIN_FILE}"
    fi

    success "必要文件检查通过"
}

# 验证 URL 格式
validate_url() {
    local url="$1"
    if [[ ! "${url}" =~ ^https?:// ]]; then
        error "无效的 URL 格式: ${url}"
    fi
}

# 验证配置
validate_config() {
    if [[ "${SKIP_VALIDATION}" == true ]]; then
        warn "跳过配置验证"
        return
    fi

    info "验证配置..."

    if [[ -z "${FIREWALL_URL}" ]]; then
        warn "未配置 firewallUrl，插件将仅运行在日志模式（无安全检测）"
    else
        validate_url "${FIREWALL_URL}"
    fi

    if [[ -z "${AUTH_KEY}" ]]; then
        warn "未配置 authKey，插件将仅运行在日志模式（无安全检测）"
    fi

    if [[ -z "${FIREWALL_URL}" ]] || [[ -z "${AUTH_KEY}" ]]; then
        warn "如需启用防火墙功能，请配置 firewallUrl 和 authKey"
    fi

    success "配置验证通过"
}

# 读取用户输入
read_input() {
    local prompt="$1"
    local var_name="$2"
    local default_value="${3:-}"
    local is_secret="${4:-false}"

    if [[ -n "${default_value}" ]]; then
        prompt="${prompt} [默认: ${default_value}]"
    fi

    if [[ "${is_secret}" == true ]]; then
        read -s -p "$(echo -e "${YELLOW}${prompt}: ${NC}")" "$var_name"
        echo
    else
        read -p "$(echo -e "${YELLOW}${prompt}: ${NC}")" "$var_name"
    fi

    # 如果用户没有输入，使用默认值
    if [[ -z "${!var_name}" ]] && [[ -n "${default_value}" ]]; then
        export "$var_name"="${default_value}"
    fi
}

# 交互式配置
interactive_config() {
    echo
    info "开始交互式配置..."
    echo

    # 选择安装模式
    echo "请选择安装模式:"
    echo "  1) 项目级 (仅在当前项目中启用)"
    echo "  2) 全局级 (在所有项目中启用)"
    read_input "选择 [1/2]" mode_choice "1"
    case "${mode_choice}" in
        1) INSTALL_MODE="project" ;;
        2) INSTALL_MODE="global" ;;
        *) error "无效选择" ;;
    esac

    # 如果是项目级，询问项目目录
    if [[ "${INSTALL_MODE}" == "project" ]]; then
        read_input "项目目录" project_dir_input "${PROJECT_DIR}"
        PROJECT_DIR="${project_dir_input}"
    fi

    echo
    info "配置防火墙参数 (留空则仅运行在日志模式)"
    echo

    read_input "防火墙服务 URL (如 http://localhost:8080/api/firewall/openclaw/validate)" firewall_url_input
    FIREWALL_URL="${firewall_url_input}"

    if [[ -n "${FIREWALL_URL}" ]]; then
        read_input "认证密钥" auth_key_input "" true
        AUTH_KEY="${auth_key_input}"

        read_input "拦截提示消息" block_message_input "${BLOCK_MESSAGE}"
        BLOCK_MESSAGE="${block_message_input}"

        read_input "超时时间 (毫秒)" timeout_input "${FIREWALL_TIMEOUT}"
        FIREWALL_TIMEOUT="${timeout_input}"

        read_input "启用调试模式? (y/n)" debug_input "n"
        if [[ "${debug_input}" =~ ^[Yy]$ ]]; then
            DEBUG=true
        fi
    fi
}

# 清理临时文件
cleanup() {
    if [[ -n "${TEMP_DIR:-}" ]] && [[ -d "${TEMP_DIR}" ]]; then
        rm -rf "${TEMP_DIR}"
        info "已清理临时文件"
    fi
}

# 设置退出时清理
trap cleanup EXIT INT TERM

# 创建项目级安装（使用 .opencode/plugins 目录）
install_project() {
    local project_dir="$1"
    local plugin_path="${PLUGIN_FILE}"
    local need_copy_files=false

    info "安装到项目: ${project_dir}"

    # 检查项目目录是否存在
    if [[ ! -d "${project_dir}" ]]; then
        error "项目目录不存在: ${project_dir}"
    fi

    # 如果使用临时文件，复制到项目目录
    if [[ -n "${TEMP_DIR:-}" ]] && [[ "${PLUGIN_FILE}" == "${TEMP_DIR}"/* ]]; then
        need_copy_files=true
        local target_plugin_dir="${project_dir}/.opencode/plugins/tomzang_plungin"
        mkdir -p "${target_plugin_dir}"

        info "复制插件文件到 ${target_plugin_dir}"
        cp "${PLUGIN_FILE}" "${target_plugin_dir}/index.js"

        plugin_path="${target_plugin_dir}/index.js"
    fi

    # 添加环境变量到 shell 配置文件
    add_env_vars_to_shell

    success "项目级安装完成"
    if [[ "${need_copy_files}" == true ]]; then
        info "插件文件已复制到: ${plugin_path}"
    fi
    info "环境变量已添加到: ${SHELL_CONFIG_FILE}"
    warn "请运行 'source ${SHELL_CONFIG_FILE}' 或重启终端以使环境变量生效"
}

# 创建全局级安装
install_global() {
    info "安装到全局: ${OPENCODE_PLUGINS_DIR}"

    # 创建必要的目录
    mkdir -p "${OPENCODE_PLUGINS_DIR}"

    # 复制插件文件
    local target_plugin_dir="${OPENCODE_PLUGINS_DIR}/tomzang_plungin"
    mkdir -p "${target_plugin_dir}"

    info "复制插件文件到 ${target_plugin_dir}"
    cp "${PLUGIN_FILE}" "${target_plugin_dir}/index.js"

    # 添加环境变量到 shell 配置文件
    add_env_vars_to_shell

    success "全局级安装完成"
    info "插件目录: ${target_plugin_dir}"
    info "环境变量已添加到: ${SHELL_CONFIG_FILE}"
    warn "请运行 'source ${SHELL_CONFIG_FILE}' 或重启终端以使环境变量生效"
}

# 显示手动配置指南（已废弃，保留以备兼容）
show_manual_config() {
    local plugin_path="$1"

    cat << EOF

请在 opencode.json 中添加以下配置:

{
  "plugin": [
    {
      "package": "${plugin_path}",
      "options": {
        "firewallUrl": "${FIREWALL_URL}",
        "authKey": "${AUTH_KEY}",
        "blockMessage": "${BLOCK_MESSAGE}",
        "firewallTimeout": ${FIREWALL_TIMEOUT},
        "debug": ${DEBUG}
      }
    }
  ]
}

EOF
}

# 检测 shell 配置文件
detect_shell_config() {
    # 检测当前使用的 shell
    local current_shell="${SHELL##*/}"

    case "${current_shell}" in
        zsh)
            SHELL_CONFIG_FILE="${HOME}/.zshrc"
            ;;
        bash)
            SHELL_CONFIG_FILE="${HOME}/.bashrc"
            ;;
        *)
            # 默认使用 .zshrc（ macOS 默认）
            SHELL_CONFIG_FILE="${HOME}/.zshrc"
            warn "未识别的 shell '${current_shell}'，默认使用 ${SHELL_CONFIG_FILE}"
            ;;
    esac
}

# 添加环境变量到 shell 配置文件
add_env_vars_to_shell() {
    detect_shell_config

    # 检查配置文件是否存在
    if [[ ! -f "${SHELL_CONFIG_FILE}" ]]; then
        warn "Shell 配置文件不存在: ${SHELL_CONFIG_FILE}"
        read -p "是否创建该文件? (y/n): " create_file
        if [[ "${create_file}" =~ ^[Yy]$ ]]; then
            touch "${SHELL_CONFIG_FILE}"
            success "已创建: ${SHELL_CONFIG_FILE}"
        else
            error "取消安装"
        fi
    fi

    # 检查是否已经配置过
    if grep -q "TOMZANG_FIREWALL_URL" "${SHELL_CONFIG_FILE}" 2>/dev/null; then
        warn "检测到已存在的 TomZang 插件配置"
        read -p "是否覆盖现有配置? (y/n): " overwrite
        if [[ !"${overwrite}" =~ ^[Yy]$ ]]; then
            info "跳过环境变量配置"
            return
        fi

        # 删除旧的配置
        # 删除从 "# TomZang Firewall Plugin 开始" 到 "# TomZang Firewall Plugin 结束" 的所有行
        sed -i.tmp '/# TomZang Firewall Plugin 开始/,/# TomZang Firewall Plugin 结束/d' "${SHELL_CONFIG_FILE}"
        rm -f "${SHELL_CONFIG_FILE}.tmp"
    fi

    # 添加环境变量配置
    cat >> "${SHELL_CONFIG_FILE}" << EOF

# TomZang Firewall Plugin 开始
export TOMZANG_FIREWALL_URL="${FIREWALL_URL}"
export TOMZANG_AUTH_KEY="${AUTH_KEY}"
export TOMZANG_BLOCK_MESSAGE="${BLOCK_MESSAGE}"
export TOMZANG_FIREWALL_TIMEOUT="${FIREWALL_TIMEOUT}"
export TOMZANG_DEBUG="${DEBUG}"
# TomZang Firewall Plugin 结束
EOF

    success "环境变量已添加到 ${SHELL_CONFIG_FILE}"
}

# 显示配置摘要
show_summary() {
    echo
    info "配置摘要:"
    echo "  安装模式: ${INSTALL_MODE}"
    if [[ "${INSTALL_MODE}" == "project" ]]; then
        echo "  项目目录: ${PROJECT_DIR}"
    fi
    echo "  防火墙 URL: ${FIREWALL_URL:-<未配置，仅日志模式>}"
    echo "  认证密钥: ${AUTH_KEY:+<已设置>}"
    echo "  拦截消息: ${BLOCK_MESSAGE}"
    echo "  超时时间: ${FIREWALL_TIMEOUT}ms"
    echo "  调试模式: ${DEBUG}"
    echo "  Shell 配置文件: ${SHELL_CONFIG_FILE:-<自动检测>}"
    echo
}

# 解析命令行参数
parse_args() {
    # 处理位置参数 (第一个非选项参数作为 firewall-url，第二个作为 auth-key)
    local positional_args=()

    while [[ $# -gt 0 ]]; do
        case $1 in
            -m|--mode)
                INSTALL_MODE="$2"
                shift 2
                ;;
            -p|--project-dir)
                PROJECT_DIR="$2"
                shift 2
                ;;
            -u|--firewall-url)
                FIREWALL_URL="$2"
                shift 2
                ;;
            -a|--auth-key)
                AUTH_KEY="$2"
                shift 2
                ;;
            -b|--block-message)
                BLOCK_MESSAGE="$2"
                shift 2
                ;;
            -t|--timeout)
                FIREWALL_TIMEOUT="$2"
                shift 2
                ;;
            -d|--debug)
                DEBUG=true
                shift
                ;;
            -s|--skip-validation)
                SKIP_VALIDATION=true
                shift
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            -*)
                error "未知选项: $1"
                ;;
            *)
                # 收集位置参数
                positional_args+=("$1")
                shift
                ;;
        esac
    done

    # 处理位置参数: firewall-url auth-key
    if [[ ${#positional_args[@]} -gt 0 ]]; then
        FIREWALL_URL="${positional_args[0]}"
    fi
    if [[ ${#positional_args[@]} -gt 1 ]]; then
        AUTH_KEY="${positional_args[1]}"
    fi
}

# 主函数
main() {
    echo
    echo "=========================================="
    echo "  OpenCode 插件离线安装脚本"
    echo "  TomZang Firewall Plugin v1.0.0"
    echo "=========================================="
    echo

    # 解析命令行参数
    parse_args "$@"

    # 如果没有提供任何参数（包括位置参数），进入交互式模式
    if [[ $# -eq 0 ]]; then
        interactive_config
    fi

    # 验证安装模式
    if [[ "${INSTALL_MODE}" != "project" ]] && [[ "${INSTALL_MODE}" != "global" ]]; then
        error "无效的安装模式: ${INSTALL_MODE} (必须是 project 或 global)"
    fi

    # 显示配置摘要
    show_summary

    # 检查必要文件
    check_files

    # 验证配置
    validate_config

    # 执行安装
    if [[ "${INSTALL_MODE}" == "project" ]]; then
        install_project "${PROJECT_DIR}"
    else
        install_global
    fi

    echo
    success "安装完成！"
    info "插件已安装到: ${OPENCODE_PLUGINS_DIR}/tomzang_plungin"
    info "环境变量已添加到: ${SHELL_CONFIG_FILE}"
    warn "请运行以下命令使环境变量生效："
    warn "  source ${SHELL_CONFIG_FILE}"
    warn "或重启终端"
    echo
}

# 运行主函数
main "$@"
