#!/usr/bin/env bash

# OpenCode V2 插件配置测试脚本
# V2 安装不写 opencode.json：插件经 plugins 目录自动发现，配置在插件同目录 config.json

echo "=========================================="
echo "  OpenCode V2 插件配置测试"
echo "=========================================="
echo

# 1. 检查插件部署（全局级优先，项目级兜底）
GLOBAL_PLUGIN_DIR="$HOME/.config/opencode/plugins/tomzang_plungin"
PROJECT_PLUGIN_DIR=".opencode/plugins/tomzang_plungin"

PLUGIN_DIR=""
if [[ -f "$GLOBAL_PLUGIN_DIR/index.js" ]]; then
    PLUGIN_DIR="$GLOBAL_PLUGIN_DIR"
    echo "1. 检测到全局级安装: $PLUGIN_DIR"
elif [[ -f "$PROJECT_PLUGIN_DIR/index.js" ]]; then
    PLUGIN_DIR="$PROJECT_PLUGIN_DIR"
    echo "1. 检测到项目级安装: $PLUGIN_DIR"
else
    echo "1. ❌ 未找到插件部署"
    echo "   全局级: $GLOBAL_PLUGIN_DIR/index.js"
    echo "   项目级: $PROJECT_PLUGIN_DIR/index.js"
    echo "   请先运行 install.sh / install.ps1，或参考 README 手动安装"
    exit 1
fi
echo

# 2. 解析插件配置文件
CONFIG_FILE="$PLUGIN_DIR/config.json"
echo "2. 解析插件配置: $CONFIG_FILE"
if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "   ❌ 配置文件不存在（插件将以仅日志模式运行，无安全检测）"
    exit 1
fi
if ! jq empty "$CONFIG_FILE" 2>/dev/null; then
    echo "   ❌ 配置文件不是合法 JSON"
    exit 1
fi
echo "   ✅ 配置文件存在且为合法 JSON"
jq -r 'to_entries | .[] | "   \(.key): \(if .key == "authKey" and (.value | length > 0) then "<已设置>" else .value end)"' "$CONFIG_FILE"

FIREWALL_URL=$(jq -r '.firewallUrl // empty' "$CONFIG_FILE")
AUTH_KEY=$(jq -r '.authKey // empty' "$CONFIG_FILE")
DEBUG=$(jq -r '.debug // false' "$CONFIG_FILE")
LOG_FILE=$(jq -r '.logFile // empty' "$CONFIG_FILE")
echo

# 3. 检查插件文件
echo "3. 检查插件文件"
if node --check "$PLUGIN_DIR/index.js" 2>/dev/null; then
    echo "   ✅ index.js 语法检查通过: $PLUGIN_DIR/index.js"
else
    echo "   ❌ index.js 缺失或语法错误"
    exit 1
fi
echo

# 4. 测试防火墙 API
echo "4. 测试防火墙 API 连接"
if [[ -n "$FIREWALL_URL" && -n "$AUTH_KEY" ]]; then
    API_URL="${FIREWALL_URL%/}/api/firewall/openclaw/validate"
    echo "   API URL: $API_URL"

    RESPONSE=$(curl -s -w "%{http_code}" -X POST "$API_URL" \
        -H "Content-Type: application/json" \
        -H "APIKey: admin" \
        -d "{
            \"auth_key\": \"$AUTH_KEY\",
            \"session_id\": \"test-session\",
            \"trace_id\": \"test-trace\",
            \"stage\": \"input\",
            \"source_app\": \"opencode\",
            \"source\": \"text\",
            \"content_type\": \"text\",
            \"content\": {\"prompt\": \"test\", \"response\": \"\"}
        }" 2>/dev/null)

    HTTP_CODE="${RESPONSE: -3}"
    BODY="${RESPONSE%???}"

    if [[ "$HTTP_CODE" == "200" ]]; then
        echo "   ✅ API 连接成功 (HTTP $HTTP_CODE)"
        echo "   响应结果: $(echo "$BODY" | jq -r '.data.result // empty')"
    else
        echo "   ❌ API 连接失败 (HTTP $HTTP_CODE)"
        echo "   响应: $BODY"
    fi
else
    echo "   ⚠️  未配置 firewallUrl 或 authKey（插件仅记录日志，不进行安全检测）"
fi
echo

# 5. 检查日志文件
echo "5. 检查日志文件"
if [[ -n "$LOG_FILE" ]]; then
    echo "   日志文件路径: $LOG_FILE"
    if [[ -f "$LOG_FILE" ]]; then
        echo "   ✅ 日志文件存在"
        echo "   文件大小: $(wc -c < "$LOG_FILE") bytes"
        echo "   最后 5 行日志:"
        tail -5 "$LOG_FILE" | sed 's/^/   /'
    else
        echo "   ⚠️  日志文件不存在（将在首次使用时创建）"
    fi
else
    echo "   ⚠️  未配置日志文件（建议在 config.json 中设置 logFile 便于排查）"
fi
echo

echo "测试完成！"
echo
echo "建议："
echo "- 如果 API 连接失败，请检查防火墙服务是否运行"
echo "- OpenCode V2 无需在 opencode.json 中声明本插件（自动发现），声明本地路径反而会安装失败"
echo "- 重启 OpenCode 以加载最新配置"
