#!/usr/bin/env bash

# OpenCode 插件配置测试脚本

echo "=========================================="
echo "  OpenCode 插件配置测试"
echo "=========================================="
echo

# 1. 检查配置文件
CONFIG_FILE="$HOME/.config/opencode/opencode.json"
echo "1. 检查配置文件: $CONFIG_FILE"
if [[ -f "$CONFIG_FILE" ]]; then
    echo "   ✅ 配置文件存在"
else
    echo "   ❌ 配置文件不存在"
    exit 1
fi
echo

# 2. 解析配置
echo "2. 解析插件配置"
PLUGIN_CONFIG=$(cat "$CONFIG_FILE" | jq '.plugin[] | select(.[0] | contains("tomzang_plungin"))')
if [[ -n "$PLUGIN_CONFIG" ]]; then
    echo "   ✅ 找到插件配置"

    PLUGIN_PATH=$(echo "$PLUGIN_CONFIG" | jq -r '.[0]')
    echo "   插件路径: $PLUGIN_PATH"

    OPTIONS=$(echo "$PLUGIN_CONFIG" | jq '.[1]')
    echo "   配置选项:"
    echo "$OPTIONS" | jq -r 'to_entries | .[] | "   \(.key): \(.value)"'

    FIREWALL_URL=$(echo "$OPTIONS" | jq -r '.firewallUrl // empty')
    AUTH_KEY=$(echo "$OPTIONS" | jq -r '.authKey // empty')
    DEBUG=$(echo "$OPTIONS" | jq -r '.debug // false')
    LOG_FILE=$(echo "$OPTIONS" | jq -r '.logFile // empty')
else
    echo "   ❌ 未找到插件配置"
    exit 1
fi
echo

# 3. 检查插件文件
echo "3. 检查插件文件"
if [[ -f "$PLUGIN_PATH" ]]; then
    echo "   ✅ 插件文件存在: $PLUGIN_PATH"
else
    echo "   ❌ 插件文件不存在: $PLUGIN_PATH"
    exit 1
fi
echo

# 4. 测试防火墙 API
echo "4. 测试防火墙 API 连接"
if [[ -n "$FIREWALL_URL" && -n "$AUTH_KEY" ]]; then
    API_URL="${FIREWALL_URL}api/firewall/openclaw/validate"
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
        echo "   响应时间: $(echo "$BODY" | jq -r '.data.response_time // empty')ms"
    else
        echo "   ❌ API 连接失败 (HTTP $HTTP_CODE)"
        echo "   响应: $BODY"
    fi
else
    echo "   ⚠️  未配置防火墙 URL 或 authKey"
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
    echo "   ⚠️  未配置日志文件"
fi
echo

# 6. 显示当前日志（如果存在）
if [[ -n "$LOG_FILE" && -f "$LOG_FILE" ]]; then
    echo "6. 完整日志内容:"
    echo "=========================================="
    cat "$LOG_FILE" | sed 's/^/| /'
    echo "=========================================="
    echo
fi

echo "测试完成！"
echo
echo "建议："
echo "- 如果 API 连接失败，请检查防火墙服务是否运行"
echo "- 查看日志文件: tail -f $LOG_FILE"
echo "- 重启 OpenCode 以加载最新配置"
