# tomzang_plungin

OpenCode 插件 — 记录用户输入和工具调用日志，并集成 OpenClaw ToolGuard 防火墙进行安全审计。

## 功能

- 捕获用户发送的每条消息，输出 `[USER]` 日志
- 捕获所有工具调用（bash、file_read、file_edit、glob 等），输出 `[TOOL:名称]` 日志和参数摘要
- 捕获工具执行结果，输出 `[TOOL_RESULT:名称]` 日志
- 集成防火墙 API，对用户输入、工具调用和工具结果进行安全检测
- 检测到违规内容时拦截请求，向用户展示拦截原因
- 插件加载/卸载时打印状态

## 安装

### 方式一：项目内使用

将此仓库 clone 到本地，在 `opencode.json` 中注册并配置：

```json
{
  "plugin": [
    {
      "package": "./path/to/tomzang_plungin/index.js",
      "options": {
        "firewallUrl": "http://your-host:port/api/firewall/openclaw/validate",
        "authKey": "your-auth-key",
        "blockMessage": "当前请求包含敏感信息，已被安全组件拦截",
        "firewallTimeout": 3000,
        "debug": false
      }
    }
  ]
}
```

### 方式二：全局使用

复制 `index.js` 到 `~/.config/opencode/plugins/` 目录下，然后在 `~/.config/opencode/opencode.json` 中配置 options。

## 配置项

| 配置项 | 类型 | 必填 | 默认值 | 说明 |
|--------|------|------|--------|------|
| `firewallUrl` | string | **是** | - | 防火墙审计接口地址 |
| `authKey` | string | **是** | - | 调用接口的认证密钥 |
| `blockMessage` | string | 否 | `当前请求包含敏感信息，已被安全组件拦截` | 拦截时的默认提示语 |
| `firewallTimeout` | number | 否 | `3000` | 防火墙 API 超时时间（毫秒），超时则跳过本次审计 |
| `debug` | boolean | 否 | `false` | 开启后打印所有请求/响应日志 |

> `firewallUrl` 和 `authKey` 未配置时，插件仅记录日志，不进行安全检测。

## 日志格式

**正常日志：**
```
[tomzang_plungin] 已加载 | 项目: xxx | 目录: /path | 防火墙: 已启用
[2026/7/16 14:30:00] [USER] 你好，请帮我看看这个项目
[2026/7/16 14:30:02] [TOOL:bash] command=ls -la
[2026/7/16 14:30:03] [TOOL_RESULT:bash] total 48 drwxr-xr-x ...
```

**拦截日志：**
```
[2026/7/16 14:30:00] [BLOCK] 用户输入被拦截: Shell命令链
[2026/7/16 14:30:02] [BLOCK] 工具调用被拦截: bash - Shell命令链
[2026/7/16 14:30:05] [BLOCK] 工具结果被拦截: read_file - 敏感内容
```

**debug 日志（debug=true 时）：**
```
[tomzang_plungin] [DEBUG] 请求防火墙 source=text session_id=xxx
[tomzang_plungin] [DEBUG] 防火墙响应 result=block action=block risk_level=3
[tomzang_plungin] [DEBUG] 防火墙 API 超时(3000ms)，跳过本次审计
```

## 拦截行为

**用户输入被拦截时：**
- 消息替换为拦截提示（含违规原因和命中规则）
- 本次对话终止，消息不发送到 LLM

**工具调用被拦截时：**
- 工具不执行
- 向用户展示拦截原因

**工具结果被拦截时：**
- 工具输出替换为拦截提示
- 向用户展示拦截原因

**拦截提示格式：**
```
当前请求包含敏感信息，已被安全组件拦截

拦截原因: Shell命令链

命中规则: G.1 - Shell命令链 - 检测到Shell命令链攻击
```

## 实现逻辑

插件基于 OpenCode V1 Plugin API，使用以下 hooks：

| Hook | 触发时机 | 用途 |
|------|---------|------|
| `chat.message` | 用户发送消息时 | 提取文本 → 日志 → 防火墙审计 → 拦截或放行 |
| `tool.execute.before` | 工具执行前 | 获取工具名和参数 → 日志 → 防火墙审计 → 拦截或放行 |
| `tool.execute.after` | 工具执行后 | 获取工具结果 → 日志 → 防火墙审计 → 替换结果或放行 |
| `dispose` | 插件卸载时 | 打印卸载消息 |

**数据流：**
```
用户输入 → chat.message hook
  ├─ 打印 [USER] 日志
  ├─ 防火墙 API (source=text, stage=input)
  │   ├─ pass → 放行，消息发送到 LLM
  │   └─ block → 替换消息内容 + 抛出 Error 终止对话
  └─ 防火墙调用失败 → 打印 WARN，放行

工具调用 → tool.execute.before hook
  ├─ 打印 [TOOL:name] 日志
  ├─ 防火墙 API (source=tool_call, stage=input)
  │   ├─ pass → 放行，工具正常执行
  │   └─ block → 返回 { block: true, blockReason } 阻止执行
  └─ 防火墙调用失败 → 打印 WARN，放行

工具结果 → tool.execute.after hook
  ├─ 打印 [TOOL_RESULT:name] 日志
  ├─ 防火墙 API (source=tool_result, stage=output)
  │   ├─ pass → 放行，结果返回给 LLM
  │   └─ block → 替换工具输出为拦截提示
  └─ 防火墙调用失败 → 打印 WARN，放行
```

## 防火墙 API

插件调用 `POST /api/firewall/openclaw/validate`，请求格式：

```json
{
  "auth_key": "<authKey>",
  "session_id": "<sessionID>",
  "trace_id": "<traceID>",
  "stage": "input | output",
  "source": "text | tool_call | tool_result",
  "content_type": "text",
  "content": {
    "prompt": "<用户输入或工具名>",
    "response": "<工具参数或工具返回结果>"
  }
}
```

**审计路由：**

| source | stage | prompt | 走的模块 |
|--------|-------|--------|---------|
| `text` | `input` | 用户消息文本 | 全链路（内容合规 + 敏感内容 + 提示词攻击） |
| `tool_call` | `input` | 工具名 | ToolGuard（检查工具调用参数） |
| `tool_result` | `output` | 工具名 | ToolGuard（检查工具返回结果） |

响应中 `data.result` 取值：`pass`（放行）、`block`（拦截）、`confirm`（二次确认）。

## 技术细节

- 纯 ES Module JavaScript，无构建步骤
- 日志默认关闭，仅在 `debug=true` 时打印
- 防火墙 API 超时（默认 3 秒）自动跳过审计，不影响正常使用
- 防火墙调用失败时自动降级为仅日志模式，不影响正常使用
- 参数摘要截断至 200 字符，用户消息截断至 500 字符
