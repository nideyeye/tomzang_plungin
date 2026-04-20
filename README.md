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

### 方式一：使用安装脚本（推荐）

仓库根目录提供了 `install.sh`，会自动下载并部署插件，写入 `~/.openclaw/openclaw.json` 中的 `plugins.entries.tomzang_plungin.config`。

```bash
./install.sh <firewallUrl> <authKey> [blockMessage] [debug]
```

参数说明：

| 位置参数 | 必填 | 对应配置项 | 说明 |
|----------|------|------------|------|
| `firewallUrl` | 是 | `firewallUrl` | 防火墙 API 地址 |
| `authKey` | 是 | `authKey` | 防火墙 API 认证密钥 |
| `blockMessage` | 否 | `blockMessage` | 自定义拦截提示语 |
| `debug` | 否 | `debug` | 是否开启调试日志，`true`/`false` |

示例：

```bash
./install.sh http://127.0.0.1:8080/api/firewall/openclaw/validate my-auth-key
```

安装与配置策略（按优先级，前者失败自动回退）：

1. **CLI 优先**：调用 `openclaw plugins install clawhub:tomzang_plungin` 完成安装，并使用 `openclaw plugins config tomzang_plungin key=value` 写入全部配置项，最后尝试 `openclaw plugins enable tomzang_plungin`。
2. **GitHub Release 回退**：当本机未安装 `openclaw` CLI 或 CLI 执行失败时，调用 GitHub API `GET /repos/nideyeye/tomzang_plungin/releases/latest` 解析最新 release，优先下载其中的 `.tar.gz` / `.tgz` / `.zip` 资产；若 release 没有资产则回退到 release 的源码 `tarball_url`（绑定在 release 对应 tag 上）。**不再使用 `main` 分支打包**。解压后部署到 `~/.openclaw/extensions/tomzang_plungin/`。可通过环境变量 `GITHUB_TOKEN` 提升 API 速率限制（私仓必填）。
3. **配置回退**：当 CLI 配置失败（或走的是 GitHub 分支）时，直接合并写入 `~/.openclaw/openclaw.json`，同时维护以下三处，确保插件不会因不在允许列表而被禁用：
   - `plugins.entries.tomzang_plungin`：写入 `enabled: true` 与配置项；
   - `plugins.allow`：将 `tomzang_plungin` 加入 allowlist（消除 `not in allowlist` 警告的关键）；
   - `plugins.load.paths`：将 `~/.openclaw/extensions/tomzang_plungin` 加入扫描路径。
4. **allowlist 兜底**：写入完成后会再次校验 `plugins.allow`，若插件仍未出现在其中，将再次执行直接写入流程进行兜底。
5. **自动备份**：已存在的插件目录与 `openclaw.json` 会先被备份为 `.bak.YYYYMMDD_HHMMSS` 后缀文件。
6. **生效方式**：完成后执行 `openclaw gateway restart` 重启网关使配置生效。

依赖：`curl`、`tar`（GitHub 回退时使用）；建议安装 `node`（用于回退路径合并 JSON；缺失时脚本会输出需手动追加的 JSON 片段）。如果已安装 `openclaw` CLI，则通常无需额外依赖。

### 方式二：手动安装

将插件目录放置在 `~/.openclaw/extensions/tomzang_plungin/` 下，确保包含以下文件：

- `index.js` — 插件主逻辑
- `openclaw.plugin.json` — 插件元数据
- `package.json` — 包配置

## 日志

插件通过 OpenClaw 的日志系统输出日志，所有日志以 `[tomzang_plungin]` 为前缀。开启 `debug: true` 可以查看详细的请求/响应信息，用于排查问题。
