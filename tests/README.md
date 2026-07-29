# OpenCode 插件测试目录

此目录包含所有与插件测试相关的脚本和文件。

## 测试脚本

### test-config.sh
配置验证和 API 连接测试脚本。

**功能：**
- 检查配置文件是否存在
- 解析插件配置
- 验证插件文件
- 测试防火墙 API 连接
- 检查日志文件
- 显示当前日志内容

**使用方法：**
```bash
./tests/test-config.sh
```

**运行测试脚本：**
```bash
# 从项目根目录
./tests/test-config.sh

# 或进入 tests 目录
cd tests && ./test-config.sh
```

## 日志文件

默认日志文件位置：`/tmp/opencode-firewall.log`

**查看日志：**
```bash
# 实时查看
tail -f /tmp/opencode-firewall.log

# 查看最近 50 行
tail -50 /tmp/opencode-firewall.log

# 搜索拦截日志
grep "BLOCK" /tmp/opencode-firewall.log
grep "ABORT" /tmp/opencode-firewall.log

# 搜索错误
grep "ERROR" /tmp/opencode-firewall.log
```

**清空日志：**
```bash
echo '' > /tmp/opencode-firewall.log
```

## 测试场景

### 1. 基本连接测试
```bash
./tests/test-config.sh
```

### 2. 拦截功能测试
1. 清空日志：`echo '' > /tmp/opencode-firewall.log`
2. 启动日志监控：`tail -f /tmp/opencode-firewall.log`
3. 在 OpenCode 中输入应该被拦截的内容
4. 查看日志中是否有：
   - `[BLOCK] 用户输入被拦截`
   - `[BLOCK] 风险等级: X`
   - `[BLOCK] 命中规则: [...]`
   - `[ABORT] 会话已中止`

### 3. 工具拦截测试
在 OpenCode 中执行应该被拦截的工具命令，查看日志：
- `[BLOCK] 工具调用被拦截`
- `[BLOCK] 工具结果被拦截`

## 预期日志格式

### 插件加载日志
```
[tomzang_plungin] ===== 插件加载 =====
[tomzang_plungin] 项目: xxx
[tomzang_plungin] 目录: /path/to/project
[tomzang_plungin] 防火墙: 已启用
[tomzang_plungin] Toast: 可用
[tomzang_plungin] Debug: true
[tomzang_plungin] 日志文件: /tmp/opencode-firewall.log
[tomzang_plungin] ===================
```

### 拦截日志
```
[2026/7/28 10:56:26] [BLOCK] 用户输入被拦截: 违规原因
[2026/7/28 10:56:26] [BLOCK] 风险等级: 3
[2026/7/28 10:56:26] [BLOCK] 命中规则: [...]
[2026/7/28 10:56:26] [BLOCK] hasClient=true session_id=xxx
[2026/7/28 10:56:26] [BLOCK] 正在调用 client.session.abort...
[2026/7/28 10:56:26] [ABORT] 会话已中止
```

## 问题排查

### 插件未加载
1. 检查配置文件路径：`~/.config/opencode/opencode.json`
2. 检查插件文件路径是否正确
3. 重启 OpenCode

### API 连接失败
1. 运行测试脚本：`./tests/test-config.sh`
2. 检查防火墙服务是否运行
3. 检查网络连接

### 日志文件不存在
1. 检查配置中 `logFile` 是否设置
2. 确保目录有写入权限
3. 触发一次请求后日志文件会自动创建
