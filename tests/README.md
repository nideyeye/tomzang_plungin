# OpenCode V2 插件测试目录

此目录包含与插件测试相关的脚本和文件。V2 安装经插件目录自动发现（`~/.config/opencode/plugins/` 或项目级 `.opencode/plugins/`），**不写 `opencode.json`**。

## 测试脚本

### test-config.sh
配置验证和 API 连接测试脚本。

**功能：**
- 检查插件部署（全局级 / 项目级自动发现目录）
- 解析插件同目录的 `config.json`（authKey 输出做掩码处理）
- `node --check` 校验 index.js 语法
- 测试防火墙 API 连接
- 检查日志文件

**使用方法：**
```bash
./tests/test-config.sh
```

## 日志文件

建议在 `config.json` 中配置 `logFile`（如 `/tmp/opencode-firewall.log`），日志双通道独立于 `debug` 开关写入。

**查看日志：**
```bash
# 实时查看
tail -f /tmp/opencode-firewall.log

# 搜索拦截日志
grep "BLOCK" /tmp/opencode-firewall.log
grep "ABORT" /tmp/opencode-firewall.log
```

> 注意：OpenCode V2 的插件在 server 进程内运行，终端 console 输出可能不可见，排查问题以 `logFile` 文件为准。

## 测试场景

### 1. 基本连接测试
```bash
./tests/test-config.sh
```

### 2. 拦截功能测试
1. 清空日志：`echo '' > /tmp/opencode-firewall.log`
2. 在 OpenCode 中输入应该被拦截的内容
3. 查看日志中是否有：
   - `[BLOCK] 用户输入被拦截`
   - `[BLOCK] 风险等级: X`
   - `[BLOCK] 命中规则: [...]`
   - `[BLOCK] 已在发送前替换被拦截用户输入`
   - `[TOAST-SKIP] 🚨 内容被拦截`（V2 无 TUI 通知通道，降级日志，信息量与 V1 Toast 对齐）

### 3. 工具拦截测试
在 OpenCode 中执行应该被拦截的工具命令，查看日志：
- `[BLOCK] 工具调用被拦截`
- `[BLOCK] 工具结果被拦截`
- `[ABORT] 会话已中止`

## 预期日志格式

### 插件加载日志
```
[tomzang_plungin] ===== 插件加载（OpenCode V2）=====
[tomzang_plungin] 项目: my-project
[tomzang_plungin] 目录: /path/to/project
[tomzang_plungin] 防火墙: 已启用
[tomzang_plungin] Toast: 不可用（V2 服务器插件无 TUI 通知通道，拦截通知降级为日志）
[tomzang_plungin] Debug: true
[tomzang_plungin] 日志文件: /tmp/opencode-firewall.log
[tomzang_plungin] 版本: v2026-xx-xx
[tomzang_plungin] ===================
```

### 拦截日志
```
[2026/11/24 10:56:26] [BLOCK] 用户输入被拦截: 违规原因
[2026/11/24 10:56:26] [BLOCK] 风险等级: 3
[2026/11/24 10:56:26] [BLOCK] 命中规则: [...]
[2026/11/24 10:56:26] [BLOCK] 已在发送前替换被拦截用户输入
[2026/11/24 10:56:26] [BLOCK] Interrupt 请求已发送（异步执行中）
[2026/11/24 10:56:26] [ABORT] 会话已中止
```

## 问题排查

### 插件未加载
1. 检查插件目录：`~/.config/opencode/plugins/tomzang_plungin/`（直属子目录才会被自动发现）
2. **不要**在 `opencode.json` 的 `plugins` 里声明本地路径——V2 会将其当作 npm 包安装而失败
3. 重启 OpenCode

### API 连接失败
1. 运行测试脚本：`./tests/test-config.sh`
2. 检查防火墙服务是否运行
3. 检查网络连接

### 日志文件不存在
1. 检查 `config.json` 中 `logFile` 是否设置
2. 确保目录有写入权限
3. 触发一次请求后日志文件会自动创建
