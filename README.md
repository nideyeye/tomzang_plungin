# wb-firewall-guard

WorkBuddy 内容安全审计插件：把**用户输入、工具调用、工具结果、模型输出**四个通道的内容送到防火墙后端做判定，命中则拦截 / 二次确认 / 记录告警。

逻辑移植自 OpenClaw 安全插件 `tomzang_plungin`（v2026-10-02），安装流程沿用该仓库的
`install.sh` 设计（参数解析 → 部署 → 写配置 → 注册设备 → 校验 → 自动备份），
并补齐了 Windows 端：`install.bat` 双击即可，PowerShell 与 bash 两端复用同一个安装内核
`dist/install-helper.mjs`，行为完全一致。

```
用户输入 ──▶ UserPromptSubmit ──┐
工具调用 ──▶ PreToolUse ────────┤
工具结果 ──▶ PostToolUse ───────┼──▶ 防火墙后端 ──▶ block / ask / mask / pass
模型输出 ──▶ Stop ─────────────┘
```

- 阻断提问 / 阻断收尾 → `exit 2` + `decision:"block"`
- 拒绝工具调用 → `exit 2` + `permissionDecision:"deny"`
- 需二次确认 → `exit 0` + `permissionDecision:"ask"`
- 全程 **fail-open**：后端不可达、超时、脚本报错一律放行，只写日志

---

## 一键安装

脚本会先检测所在目录的安装包完整性：只下载了单个 install 脚本也没关系，会自动从 GitHub 拉取整包解压到脚本旁的 `wb-firewall-guard-pkg/` 再继续（下载失败时回退本地缓存；`WB_FIREWALL_PKG_URL` 可覆盖整包地址）。

### macOS / Linux（单文件一键）

```bash
curl -fsSL https://raw.githubusercontent.com/nideyeye/tomzang_plungin/workbuddy/install.sh -o install.sh && chmod +x install.sh && ./install.sh http://${防火墙服务地址}/ ${页面上生成的 key}
```

或从完整包安装：

```bash
cd ~/Downloads/wb-firewall-guard
chmod +x install.sh uninstall.sh
./install.sh http://${防火墙服务地址}/ ${页面上生成的 key}
```

### Windows（单文件一键）

```powershell
irm https://raw.githubusercontent.com/nideyeye/tomzang_plungin/workbuddy/install.ps1 -OutFile install.ps1; powershell -ExecutionPolicy Bypass -File .\install.ps1 -FirewallUrl http://${防火墙服务地址}/ -AuthKey ${页面上生成的 key}
```

双击 **`install.bat`**（完整包内）会转调 `install.ps1`（无参时同样会被校验拦下并提示填地址与密钥），或：

```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps1 -FirewallUrl http://${防火墙服务地址}/ -AuthKey ${页面上生成的 key}
```

前置依赖只有一个：**Node.js ≥ 18**（脚本找不到 node 会直接报错并给出安装指引）。

---

## 参数

| 参数（sh / ps1） | 必填 | 默认 | 说明 |
|---|---|---|---|
| `<firewallUrl>` / `-FirewallUrl` | 否* | 包内 `config.example.json` | 防火墙后端地址，如 `http://${防火墙服务地址}/` |
| `<authKey>` / `-AuthKey` | 否* | 包内 `config.example.json` | 64 位认证密钥 |
| `<debug>` / `-DebugLog` | 否 | `false` | `true` 时把每次送审详情写入日志 |
| `<blockTip>` / `-BlockTip` | 否 | 内置文案 | 拦截时展示给用户的提示 |
| `--target` / `-Target` | 否 | `~/.workbuddy/plugins/wb-firewall-guard` | 插件安装目录 |
| `--settings` / `-Settings` | 否 | `~/.workbuddy/settings.json` | WorkBuddy 用户配置 |
| `--skip-register` / `-SkipRegister` | 否 | 关 | 跳过设备注册（后端无 register 接口 / 离线安装时用） |

\* `config.example.json` 已是 `${...}` 占位符模板：无参安装会检测到占位符直接报错退出（exit 2），必须在命令行传入真实值。本地内网批量安装可先把真实值写进 `config.example.json` 再无参运行。
取值顺序：命令行参数 > 环境变量 `WB_FIREWALL_URL` / `WB_FIREWALL_AUTH_KEY` > `config.example.json`。另有 `WB_FIREWALL_PKG_URL` 覆盖引导下载的整包地址（默认 GitHub workbuddy 分支归档）。

---

## 安装做了什么

| 步骤 | 动作 |
|---|---|
| 0 | 检测安装包完整性（`dist/` + `config.example.json`），不完整时自动从 GitHub 下载整包解压到脚本旁的 `wb-firewall-guard-pkg/`，下载失败回退本地缓存 |
| 1 | 部署插件到 `~/.workbuddy/plugins/wb-firewall-guard`，旧版本先备份（`.bak-<时间戳>`，自动只留最近 3 份） |
| 2 | 合并写入 `config.json`（保留已有键，重装不丢配置） |
| 3 | 备份 `settings.json`，把 6 个钩子合并进 `hooks` 字段；按 command 里的插件名去重，**重复安装不会堆积** |
| 4 | 向 `<firewallUrl>/api/firewall/openclaw/device/register` 注册本机（`device_id` 与插件运行时同源，取的是同一个硬件指纹函数） |
| 5 | 校验插件目录 / config / 钩子三处是否就位，任一缺失退出码 4 |

退出码：`0` 成功 · `2` 部署或写文件失败 · `3` 设备注册失败 · `4` 校验未通过。
配置文件备份路径会在失败时打印，可用 `cp <备份> <原文件>` 还原。

**生效方式**：完全退出并重启 WorkBuddy 会话（钩子只在会话启动时加载）。

---

## 目录

| 路径 | 作用 |
|---|---|
| `install.sh` / `install.ps1` / `install.bat` | 一键安装（bat = 双击入口，转调 ps1） |
| `uninstall.sh` / `uninstall.ps1` / `uninstall.bat` | 一键卸载（默认保留插件目录，`--purge` / `-Purge` 连目录一起删） |
| `dist/guard.mjs` | 钩子入口：`session / input / tool / tool_result / output`，支持 `--explain` 排误判 |
| `dist/firewall.mjs` | 配置、设备指纹、审计 API 客户端、日志（fail-open） |
| `dist/extract.mjs` | 元数据剥离、SKILL.md 识别、转录解析 |
| `dist/install-helper.mjs` | 跨平台安装内核（deploy / config / hooks / register / verify / uninstall） |
| `.codebuddy-plugin/plugin.json` + `hooks/hooks.json` | 插件清单，走插件市场分发时用（脚本安装走 user settings，不依赖它） |
| `config.example.json` | 配置模板，安装时生成 `config.json` |

---

## 配置项（`config.json`）

| 键 | 默认 | 说明 |
|---|---|---|
| `firewallUrl` / `authKey` | —（模板为占位符） | 后端地址与密钥，安装时必填 |
| `timeout` | `3000` | 单次送审超时（ms），超时即放行 |
| `debug` | `false` | 调试日志 |
| `enabled` | `true` | 总开关 |
| `toolWhitelist` | `WebSearch/WebFetch/Glob/Grep/TodoWrite/Task*` | 跳过送审的工具（**Read 不放行**，否则 SKILL.md 正文审计会被跳过） |
| `onMaskedInput` / `onMaskedOutput` | `log` | 命中脱敏时仅记录（`log`）还是阻断（`block`） |
| `onBlockedOutput` | `block` | Stop 判 block 时打回让模型重答一次（`block`）还是只告警（`log`） |
| `outputAuditIncludesPrompt` | `false` | Stop 阶段是否连用户提问一起送审。默认只审模型自己说的话 |
| `blockTip` / `blockMessage` | 内置文案 | 拦截提示 |

---

## 自检与排误判

```bash
NODE=node
TARGET="$HOME/.workbuddy/plugins/wb-firewall-guard"

# 冒烟：一条正常输入应当放行（exit 0）
echo '{"prompt":"hello"}' | "$NODE" "$TARGET/dist/guard.mjs" input

# 只打印「这份输入会被抽成什么文本去送审」，不调后端
"$NODE" "$TARGET/dist/guard.mjs" output --explain < case.json
"$NODE" "$TARGET/dist/guard.mjs" input  --explain < case.json
```

**抽文本规则（关键）**：只取 `type === 'text'` 的内容块，`tool_use` / `tool_result` / `thinking`
一律丢弃。否则工具回显（日志、文件内容、命令输出）会被整包序列化进送审文本，模型一句正常的话
也会被连带判 block —— 首次接生产就踩过这个坑。

**死循环防护**：Stop 被阻会后模型重答，第二次 Stop 携带 `stop_hook_active: true`，插件直接放行，最多打回一次。

日志：`~/.workbuddy/plugins/wb-firewall-guard/logs/guard.log`

---

## 分发方式二：插件市场（可选）

本包自带的 `.codebuddy-plugin/plugin.json` + `hooks/hooks.json` 可以直接作为 WorkBuddy 本地插件分发，
钩子命令用的是 `${CODEBUDDY_PLUGIN_ROOT}` 变量，无需安装脚本介入：

```json
{ "type": "command", "command": "node \"${CODEBUDDY_PLUGIN_ROOT}/dist/guard.mjs\" input", "timeout": 15 }
```

两种方式的差别只在「谁负责把命令写进配置」，插件逻辑与配置格式完全一致。

---

## 后端接口契约

```http
POST /api/firewall/openclaw/validate
{ "auth_key":"...", "session_id":"...", "trace_id":"...", "stage":"input|output",
  "source":"text|tool_call|tool_result|skill", "device_id":"...",
  "content": { "prompt":"...", "response":"...", "image":"" } }

200 { "code":200, "data":{ "action":"pass|review|block", "result":"pass|block",
      "risk_level":0-3, "violation_reason":"", "hit_rules":[],
      "masked_content": { "prompt":"", "response":"", "image":"" } } }
```

设备注册：`POST /api/firewall/openclaw/device/register`
（`auth_key` / `device_id` / `ip` / `os` / `platform` / `app_version` / `app_typ` / `plugin_version`）。

---

## 常见问题

| 现象 | 处理 |
|---|---|
| 装完没效果 | 钩子只在会话启动加载，**完全退出 WorkBuddy 再重开** |
| 提示未找到 node | 装 Node.js ≥ 18 后重跑；脚本已覆盖 Homebrew / nvm / volta / fnm / Program Files 常见路径 |
| 设备注册失败（exit 3） | 检查后端地址与密钥；离线或后端无该接口用 `--skip-register` |
| 想还原配置 | `~/.workbuddy/settings.json.bak-<时间戳>`，直接覆盖回去 |
| 正常回复被误拦 | 用 `output --explain` 看送审文本是否混入了工具回显；必要时把 `onBlockedOutput` 改为 `log` |
| 后端不可用 | 插件 fail-open 全放行，不影响使用，只在日志留 error |
