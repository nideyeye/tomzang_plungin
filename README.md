# tomzang_plungin

OpenClaw 安全内容检测插件，通过防火墙 API 对用户输入进行实时安全检测和拦截。

## 主要功能

- **实时内容检测**：拦截所有 LLM 请求，提取用户输入内容，调用防火墙 API 进行安全检测
- **工具调用审计**：在工具调用执行前（`before_tool_call`）对工具名称和参数进行安全检测
- **智能拦截**：检测到敏感内容时，自动构造合规的拦截响应（支持 SSE 流式和非流式），阻止请求到达 LLM
- **内置命令跳过**：自动跳过以 `/` 开头的内置命令和系统内部操作（如 `/reset`、摘要生成等），避免误检
- **命中规则展示**：拦截时以 Markdown 表格形式展示命中的安全规则（rule_code、rule_name、description）

## 工作原理

```
用户输入 → fetch 拦截 → 提取用户 prompt → 防火墙 API 检测
  ├─ 安全 → 正常转发请求到 LLM
  └─ 不安全 → 构造拦截响应返回给客户端

工具调用 → before_tool_call → 防火墙 API 检测
  ├─ 安全 → 正常执行工具
  └─ 不安全 → 返回 block 拦截
```

## 配置项

在 `~/.openclaw/openclaw.json` 的 `plugins.entries.tomzang_plungin.config` 中配置：

```json
{
  "firewallUrl": "http://your-firewall-host:port/api/firewall/openclaw/validate",
  "authKey": "your-auth-key",
  "blockMessage": "自定义拦截提示语",
  "debug": false
}
```

### 配置说明

| 配置项 | 类型 | 必填 | 默认值 | 说明 |
|--------|------|------|--------|------|
| `firewallUrl` | string | **是** | 无 | 防火墙 API 地址，用于内容安全检测 |
| `authKey` | string | **是** | 无 | 防火墙 API 认证密钥 |
| `blockMessage` | string | 否 | `当前请求包含敏感关键字，已被安全组件拦截` | 自定义拦截提示语（当无命中规则时显示） |
| `debug` | boolean | 否 | `false` | 是否启用调试模式，开启后会输出详细日志 |

> **重要**：`firewallUrl` 和 `authKey` 为必填项。如果未配置，插件将在启动时上报错误，并跳过所有防火墙检测功能（仅保留基本的生命周期钩子日志记录）。

## 防火墙 API 接口

插件调用防火墙 API 时发送如下格式的 POST 请求：

```json
{
  "auth_key": "配置中的 authKey",
  "session_id": "会话标识",
  "trace_id": "追踪ID",
  "stage": "input",
  "content_type": "text",
  "content": {
    "prompt": "待检测的用户输入内容",
    "response": "",
    "image": ""
  }
}
```

当返回结果中 `result` 为 `"block"` 时，插件将拦截该请求。

## 安装

将插件目录放置在 `~/.openclaw/extensions/tomzang_plungin/` 下，确保包含以下文件：

- `index.js` — 插件主逻辑
- `openclaw.plugin.json` — 插件元数据
- `package.json` — 包配置

## 日志

插件通过 OpenClaw 的日志系统输出日志，所有日志以 `[tomzang_plungin]` 为前缀。开启 `debug: true` 可以查看详细的请求/响应信息，用于排查问题。
