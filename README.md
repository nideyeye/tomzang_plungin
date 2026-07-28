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

### 快速安装（推荐）

#### Linux / macOS

```bash
curl -fsSL https://raw.githubusercontent.com/nideyeye/tomzang_plungin/open-code/install.sh | bash -s -- <firewall-url> <auth-key>
```

#### Windows (PowerShell 7+)

```powershell
irm https://raw.githubusercontent.com/nideyeye/tomzang_plungin/open-code/install.ps1 | iex -- <firewall-url> <auth-key>
```

### 详细安装方式

#### Linux / macOS

使用 `install.sh` 脚本：

```bash
# 一键安装
curl -fsSL https://raw.githubusercontent.com/nideyeye/tomzang_plungin/open-code/install.sh | bash -s -- http://firewall-url auth-key

# 或下载后执行
curl -fsSL https://raw.githubusercontent.com/nideyeye/tomzang_plungin/open-code/install.sh -o install.sh
chmod +x install.sh
./install.sh http://firewall-url auth-key

# 交互式安装
./install.sh

# 全局安装
./install.sh -m global http://firewall-url auth-key

# 查看帮助
./install.sh --help
```

#### Windows (PowerShell)

使用 `install.ps1` 脚本：

```powershell
# 一键安装
irm https://raw.githubusercontent.com/nideyeye/tomzang_plungin/open-code/install.ps1 | iex -- http://firewall-url auth-key

# 或下载后执行
irm https://raw.githubusercontent.com/nideyeye/tomzang_plungin/open-code/install.ps1 -OutFile install.ps1
.\install.ps1 http://firewall-url auth-key

# 全局安装
.\install.ps1 -Mode global http://firewall-url auth-key

# 查看帮助
.\install.ps1 -Help
```

### 安装脚本选项

| Bash 选项 | PowerShell 选项 | 说明 |
|-----------|----------------|------|
| `-m, --mode` | `-Mode` | 安装模式: `project` (项目级) 或 `global` (全局级) |
| `-p, --project-dir` | `-ProjectDir` | 项目目录路径 |
| `-u, --firewall-url` | `-FirewallUrl` | 防火墙服务地址 |
| `-a, --auth-key` | `-AuthKey` | 认证密钥 |
| `-b, --block-message` | `-BlockMessage` | 拦截提示消息 |
| `-t, --timeout` | `-FirewallTimeout` | 超时时间(毫秒) |
| `-d, --debug` | `-Debug` | 启用调试模式 |
| `-s, --skip-validation` | `-SkipValidation` | 跳过配置验证 |
| `-h, --help` | `-Help` | 显示帮助信息 |

### 手动安装

#### 项目级安装

克隆仓库并在项目的 `opencode.json` 中配置：

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

#### 全局安装

复制 `index.js` 到 `~/.config/opencode/plugins/tomzang_plungin/` 目录下，然后在 `~/.config/opencode/opencode.json` 中配置：

```json
{
  "plugin": [
    {
      "package": "~/.config/opencode/plugins/tomzang_plungin/index.js",
      "options": {
        "firewallUrl": "http://your-host:port/api/firewall/openclaw/validate",
        "authKey": "your-auth-key"
      }
    }
  ]
}
```

### 卸载插件

编辑对应的 `opencode.json` 文件，删除插件配置条目：

```bash
# 项目级
vim opencode.json
rm -rf .opencode-plugins/tomzang_plungin

# 全局级
vim ~/.config/opencode/opencode.json
rm -rf ~/.config/opencode/plugins/tomzang_plungin
```

## 配置项

| 配置项 | 类型 | 必填 | 默认值 | 说明 |
|--------|------|------|--------|------|
| `firewallUrl` | string | **是** | - | 防火墙审计接口地址 |
| `authKey` | string | **是** | - | 调用接口的认证密钥 |
| `blockMessage` | string | 否 | `当前请求包含敏感信息，已被安全组件拦截` | 拦截时的默认提示语 |
| `firewallTimeout` | number | 否 | `3000` | 防火墙 API 超时时间（毫秒），超时则跳过本次审计 |
| `debug` | boolean | 否 | `false` | 开启后打印所有请求/响应日志 |
| `logFile` | string | 否 | - | 日志文件路径，如 `/tmp/opencode-firewall.log` |

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

正常请求：
```
[tomzang_plungin] [DEBUG] ===== 防火墙请求 =====
[tomzang_plungin] [DEBUG] URL: http://localhost:8080/api/firewall/openclaw/validate
[tomzang_plungin] [DEBUG] 超时: 3000ms
[tomzang_plungin] [DEBUG] source=text session_id=sess-xxx trace_id=xxx
[tomzang_plungin] [DEBUG] 请求体: {
  "auth_key": "your-key",
  "session_id": "sess-xxx",
  "trace_id": "xxx",
  "stage": "input",
  "source_app": "opencode",
  "source": "text",
  "content_type": "text",
  "content": {
    "prompt": "用户输入内容",
    "response": ""
  }
}
[tomzang_plungin] [DEBUG] ===== 防火墙响应 =====
[tomzang_plungin] [DEBUG] 状态码: 200
[tomzang_plungin] [DEBUG] 响应体: { "data": { "result": "pass", ... } }
[tomzang_plungin] [DEBUG] result=pass action=allow risk_level=0
```

超时时：
```
[tomzang_plungin] [DEBUG] ===== 防火墙超时 =====
[tomzang_plungin] [DEBUG] 超时时间: 3000ms
[tomzang_plungin] [DEBUG] 请求URL: http://localhost:8080/api/firewall/openclaw/validate
[tomzang_plungin] [DEBUG] 请求体: { ... }
[tomzang_plungin] [DEBUG] 跳过本次审计，放行请求
```

错误时：
```
[tomzang_plungin] [DEBUG] ===== 防火墙调用错误 =====
[tomzang_plungin] [DEBUG] 错误类型: TypeError
[tomzang_plungin] [DEBUG] 错误信息: Failed to fetch
[tomzang_plungin] [DEBUG] 请求URL: http://localhost:8080/api/firewall/openclaw/validate
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

## 测试

插件包含测试脚本用于验证配置和功能。

### 运行配置测试

```bash
./tests/test-config.sh
```

测试脚本会检查：
- 配置文件是否存在
- 插件配置是否正确
- 防火墙 API 连接是否正常
- 日志文件状态

### 查看日志

```bash
# 实时查看日志
tail -f /tmp/opencode-firewall.log

# 查看拦截日志
grep "BLOCK" /tmp/opencode-firewall.log

# 查看会话终止日志
grep "ABORT" /tmp/opencode-firewall.log
```

### 测试场景

1. **基本连接测试**：运行 `./tests/test-config.sh`
2. **拦截功能测试**：输入敏感内容，查看日志中的 `[BLOCK]` 和 `[ABORT]` 记录
3. **工具拦截测试**：执行敏感命令，查看工具调用拦截日志

更多测试细节请查看 [tests/README.md](tests/README.md)。
