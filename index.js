var DEFAULT_BLOCK_MESSAGE = "当前请求包含敏感信息，已被安全组件拦截";

function ts() {
  return new Date().toLocaleString("zh-CN", { hour12: false });
}

// 获取设备唯一标识
async function getDeviceId() {
  var os = require("os");
  var crypto = require("crypto");
  var exec = require("child_process").exec;

  var hardwareInfo = [];

  // 1. 获取 CPU 信息
  try {
    var cpuModel = os.cpus()[0].model;
    hardwareInfo.push("cpu:" + cpuModel);
  } catch (_) {}

  // 2. 获取 MAC 地址（首张非内部网卡）
  try {
    var networkInterfaces = os.networkInterfaces();
    var macAddress = null;
    var interfaceNames = Object.keys(networkInterfaces);
    for (var i = 0; i < interfaceNames.length; i++) {
      var iface = networkInterfaces[interfaceNames[i]];
      if (iface && iface.length > 0) {
        // 跳过内部/虚拟网卡
        if (interfaceNames[i].indexOf("lo") !== 0 &&
            interfaceNames[i].indexOf("veth") !== 0 &&
            interfaceNames[i].indexOf("docker") !== 0) {
          macAddress = iface[0].mac;
          break;
        }
      }
    }
    if (macAddress && macAddress !== "00:00:00:00:00:00") {
      hardwareInfo.push("mac:" + macAddress);
    }
  } catch (_) {}

  // 3. 获取主机名
  try {
    var hostname = os.hostname();
    hardwareInfo.push("hostname:" + hostname);
  } catch (_) {}

  // 4. 获取系统特定硬件信息
  var platform = os.platform();
  var systemInfo = "";

  if (platform === "darwin") {
    // macOS
    try {
      // 获取硬件 UUID
      var hwUuid = await new Promise(function(resolve) {
        exec("ioreg -rd1 -c IOPlatformExpertDevice | grep IOPlatformUUID", function(error, stdout) {
          if (stdout && stdout.match(/"IOPlatformUUID" = "([^"]+)"/)) {
            resolve(stdout.match(/"IOPlatformUUID" = "([^"]+)"/)[1]);
          } else {
            resolve("");
          }
        });
      });
      if (hwUuid) systemInfo += hwUuid;
    } catch (_) {}

    try {
      // 获取磁盘序列号（启动盘）
      var diskSerial = await new Promise(function(resolve) {
        exec("diskutil info / | grep 'Volume UUID'", function(error, stdout) {
          if (stdout && stdout.match(/Volume UUID:\s*([A-F0-9-]+)/i)) {
            resolve(stdout.match(/Volume UUID:\s*([A-F0-9-]+)/i)[1]);
          } else {
            resolve("");
          }
        });
      });
      if (diskSerial) systemInfo += diskSerial;
    } catch (_) {}
  } else if (platform === "linux") {
    // Linux
    try {
      // 读取 machine-id
      var fs = require("fs");
      var machineIdPath = "/etc/machine-id";
      if (fs.existsSync(machineIdPath)) {
        var machineId = fs.readFileSync(machineIdPath, "utf8").trim();
        systemInfo += machineId;
      }
    } catch (_) {}

    try {
      // 尝试读取 DMI 产品 UUID
      var dmiUuid = await new Promise(function(resolve) {
        exec("cat /sys/class/dmi/id/product_uuid 2>/dev/null", function(error, stdout) {
          resolve(stdout ? stdout.trim() : "");
        });
      });
      if (dmiUuid) systemInfo += dmiUuid;
    } catch (_) {}
  } else if (platform === "win32") {
    // Windows
    try {
      // 获取主板序列号
      var boardSerial = await new Promise(function(resolve) {
        exec("wmic baseboard get serialnumber", function(error, stdout) {
          if (stdout) {
            var lines = stdout.split("\n");
            for (var i = 0; i < lines.length; i++) {
              var line = lines[i].trim();
              if (line && line !== "SerialNumber") {
                resolve(line);
                return;
              }
            }
          }
          resolve("");
        });
      });
      if (boardSerial) systemInfo += boardSerial;
    } catch (_) {}

    try {
      // 获取 CPU ID
      var cpuId = await new Promise(function(resolve) {
        exec("wmic cpu get processorid", function(error, stdout) {
          if (stdout) {
            var lines = stdout.split("\n");
            for (var i = 0; i < lines.length; i++) {
              var line = lines[i].trim();
              if (line && line !== "ProcessorId") {
                resolve(line);
                return;
              }
            }
          }
          resolve("");
        });
      });
      if (cpuId) systemInfo += cpuId;
    } catch (_) {}
  }

  if (systemInfo) {
    hardwareInfo.push("system:" + systemInfo);
  }

  // 如果没有获取到任何信息，使用备用方案
  if (hardwareInfo.length === 0) {
    var fallbackInfo = "os:" + platform + ";arch:" + os.arch() + ";cpus:" + os.cpus().length;
    hardwareInfo.push(fallbackInfo);
  }

  // 拼接所有信息
  var combined = hardwareInfo.join("|");

  // 计算 SHA256 hash
  var hash = crypto.createHash("sha256").update(combined).digest("hex");

  return hash;
}

function summarizeArgs(args) {
  if (!args || typeof args !== "object") return String(args || "");
  return Object.entries(args)
    .map(function ([k, v]) {
      var display =
        typeof v === "string"
          ? v.length > 200
            ? v.slice(0, 200) + "..."
            : v
          : JSON.stringify(v);
      return k + "=" + display;
    })
    .join(" ");
}

function buildToolCommand(tool, args) {
  if (!args) return tool;

  switch (tool) {
    case "read":
      return "read " + (args.filePath || args.path || "");
    case "bash":
      return "bash " + (args.command || "");
    case "glob":
      return "glob " + (args.pattern || "");
    case "grep":
      return (
        "grep " + (args.pattern || "") + " " + (args.path || args.include || "")
      );
    case "edit":
      return "edit " + (args.filePath || "");
    case "write":
      return "write " + (args.filePath || "");
    default:
      return tool + " " + JSON.stringify(args);
  }
}

function buildHitRulesText(hitRules) {
  if (!Array.isArray(hitRules) || hitRules.length === 0) return "";
  var lines = [];
  for (var i = 0; i < hitRules.length; i++) {
    var rule = hitRules[i];
    lines.push(
      "命中规则: " +
        (rule.rule_code || "-") +
        " - " +
        (rule.rule_name || "-") +
        " - " +
        (rule.description || "-")
    );
  }
  return lines.join("\n");
}

function buildBlockResponse(fwData, defaultMsg) {
  var reason = fwData.violation_reason || "";
  var hitRulesText = buildHitRulesText(fwData.hit_rules);
  var msg = defaultMsg;
  if (reason) msg += "\n\n拦截原因: " + reason;
  if (hitRulesText) msg += "\n\n" + hitRulesText;
  return msg;
}

function getRiskEmoji(riskLevel) {
  if (riskLevel >= 3) return "🔴";
  if (riskLevel === 2) return "🟠";
  if (riskLevel === 1) return "🟡";
  return "⚪";
}

function formatHitRulesForToast(hitRules) {
  if (!Array.isArray(hitRules) || hitRules.length === 0) return "无详细规则信息";

  var lines = [];
  for (var i = 0; i < hitRules.length; i++) {
    var rule = hitRules[i];
    var emoji = getRiskEmoji(rule.risk_level || 0);
    lines.push(
      (rule.rule_code || "-") +
        " | " +
        (rule.rule_name || "-") +
        " | " +
        emoji +
        " " +
        (rule.risk_level || 0) +
        " | " +
        (rule.description || "-") +
        (rule.aia_name ? " | " + rule.aia_name : "")
    );
  }
  return lines.join("\n");
}

function generateId() {
  return (
    "sess-" +
    Date.now().toString(36) +
    "-" +
    Math.random().toString(36).slice(2, 8)
  );
}

async function callFirewallApi(config, prompt, response, source, sessionId, deviceId) {
  var url = config.firewallUrl.replace(/\/+$/, "") + "/api/firewall/openclaw/validate";
  var body = {
    auth_key: config.authKey,
    session_id: sessionId || generateId(),
    trace_id: generateId(),
    stage: source === "tool_result" ? "output" : "input",
    source_app: "opencode",
    source: source,
    content_type: "text",
    content: {
      prompt: prompt,
      response: response || "",
    },
  };

  // 添加 device_id
  if (deviceId) {
    body.device_id = deviceId;
  }

  if (config.debug) {
    console.log(
      "[tomzang_plungin] [DEBUG] ===== 防火墙请求 ====="
    );
    console.log(
      "[tomzang_plungin] [DEBUG] URL: " + url
    );
    console.log(
      "[tomzang_plungin] [DEBUG] 超时: " + config.firewallTimeout + "ms"
    );
    console.log(
      "[tomzang_plungin] [DEBUG] source=" +
        source +
        " session_id=" +
        body.session_id +
        " trace_id=" +
        body.trace_id
    );
    console.log(
      "[tomzang_plungin] [DEBUG] 请求体: " + JSON.stringify(body, null, 2)
    );
  }

  // 写入文件日志
  writeLog(
    config.logFile,
    "===== 防火墙请求 =====\nURL: " + url + "\n超时: " + config.firewallTimeout + "ms\n" +
    "source: " + source + " | session_id: " + body.session_id + " | trace_id: " + body.trace_id + "\n" +
    "请求体: " + JSON.stringify(body, null, 2)
  );

  var controller = new AbortController();
  var timeoutId = setTimeout(function () {
    controller.abort();
  }, config.firewallTimeout);

  try {
    var resp = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "APIKey": "admin"
      },
      body: JSON.stringify(body),
      signal: controller.signal,
    });
    clearTimeout(timeoutId);

    if (!resp.ok) {
      var errText = "";
      try {
        errText = await resp.text();
      } catch (_) {}
      throw new Error(
        "防火墙 API 返回 " + resp.status + ": " + errText.slice(0, 200)
      );
    }

    var json = await resp.json();

    if (config.debug) {
      console.log(
        "[tomzang_plungin] [DEBUG] ===== 防火墙响应 ====="
      );
      console.log(
        "[tomzang_plungin] [DEBUG] 状态码: " + resp.status
      );
      console.log(
        "[tomzang_plungin] [DEBUG] 响应体: " + JSON.stringify(json, null, 2)
      );
      console.log(
        "[tomzang_plungin] [DEBUG] result=" +
          (json.data && json.data.result) +
          " action=" +
          (json.data && json.data.action) +
          " risk_level=" +
          (json.data && json.data.risk_level)
      );
    }

    // 写入文件日志
    writeLog(
      config.logFile,
      "===== 防火墙响应 =====\n状态码: " + resp.status + "\n" +
      "响应体: " + JSON.stringify(json, null, 2) + "\n" +
      "result: " + (json.data && json.data.result) + " | action: " + (json.data && json.data.action) + " | risk_level: " + (json.data && json.data.risk_level)
    );

    return json.data || {};
  } catch (e) {
    clearTimeout(timeoutId);
    if (e.name === "AbortError") {
      if (config.debug) {
        console.log(
          "[tomzang_plungin] [DEBUG] ===== 防火墙超时 ====="
        );
        console.log(
          "[tomzang_plungin] [DEBUG] 超时时间: " + config.firewallTimeout + "ms"
        );
        console.log(
          "[tomzang_plungin] [DEBUG] 请求URL: " + url
        );
        console.log(
          "[tomzang_plungin] [DEBUG] 请求体: " + JSON.stringify(body, null, 2)
        );
        console.log(
          "[tomzang_plungin] [DEBUG] 跳过本次审计，放行请求"
        );
      }
      // 写入文件日志
      writeLog(
        config.logFile,
        "===== 防火墙超时 =====\n超时时间: " + config.firewallTimeout + "ms\n" +
        "请求URL: " + url + "\n" +
        "请求体: " + JSON.stringify(body, null, 2) + "\n" +
        "跳过本次审计，放行请求"
      );
      return { result: "pass" };
    }
    // 其他错误
    if (config.debug) {
      console.log(
        "[tomzang_plungin] [DEBUG] ===== 防火墙调用错误 ====="
      );
      console.log(
        "[tomzang_plungin] [DEBUG] 错误类型: " + e.name
      );
      console.log(
        "[tomzang_plungin] [DEBUG] 错误信息: " + (e.message || e)
      );
      console.log(
        "[tomzang_plungin] [DEBUG] 请求URL: " + url
      );
    }
    // 写入文件日志
    writeLog(
      config.logFile,
      "===== 防火墙调用错误 =====\n错误类型: " + e.name + "\n" +
      "错误信息: " + (e.message || e) + "\n" +
      "请求URL: " + url
    );
    throw e;
  }
}

// 新增：格式化命中规则表头
var HIT_RULES_HEADER = "规则代码 | 规则名称 | 风险等级 | 描述 | AIA分类";

// 新增：写入日志到文件
async function writeLog(logFilePath, message) {
  if (!logFilePath) return;
  try {
    var timestamp = new Date().toLocaleString("zh-CN", { hour12: false });
    var logMessage = "[" + timestamp + "] " + message + "\n";
    // 使用 Bun 的 file API
    var file = Bun.file(logFilePath);
    var existingContent = "";
    try {
      existingContent = await file.text();
    } catch (_) {
      existingContent = "";
    }
    await Bun.write(logFilePath, existingContent + logMessage);
  } catch (e) {
    // 静默失败，避免影响主流程
    console.error("[tomzang_plungin] 写入日志失败: " + (e.message || e));
  }
}

// 读取配置文件（从插件所在目录读取）
async function readConfigFile() {
  // 获取插件所在目录的 config.json
  // 插件目录通常在: ~/.config/opencode/plugins/tomzang_plungin/
  // 或者项目级: <project>/.opencode/plugins/tomzang_plungin/
  var importMetaUrl = import.meta.url;
  var pluginDir = importMetaUrl.slice(0, importMetaUrl.lastIndexOf("/"));
  var configPath = pluginDir + "/config.json";

  try {
    var file = Bun.file(configPath);
    var text = await file.text();
    return JSON.parse(text);
  } catch (_) {
    return null;
  }
}

export default async function TomzangPlungin({ project, directory, client }) {
  // 优先级: 配置文件 > 环境变量 > 默认值
  var fileConfig = await readConfigFile();
  var config = {
    firewallUrl: (fileConfig && fileConfig.firewallUrl) || process.env.TOMZANG_FIREWALL_URL || "",
    authKey: (fileConfig && fileConfig.authKey) || process.env.TOMZANG_AUTH_KEY || "",
    blockMessage: (fileConfig && fileConfig.blockMessage) || process.env.TOMZANG_BLOCK_MESSAGE || DEFAULT_BLOCK_MESSAGE,
    firewallTimeout: parseInt((fileConfig && fileConfig.firewallTimeout) || process.env.TOMZANG_FIREWALL_TIMEOUT || "3000", 10),
    debug: (fileConfig && fileConfig.debug) || process.env.TOMZANG_DEBUG === "true",
    logFile: (fileConfig && fileConfig.logFile) || process.env.TOMZANG_LOG_FILE || "",
  };

  // 获取设备唯一标识
  var deviceId = await getDeviceId();

  var hasFirewall = !!(config.firewallUrl && config.authKey);
  var hasClient = !!(client && client.tui && client.tui.showToast);

  function log() {
    if (!config.debug) return;
    console.log.apply(console, arguments);
    // 同时写入文件
    var msg = Array.from(arguments).join(" ");
    writeLog(config.logFile, msg);
  }

  // 强制写入日志（不受 debug 控制）
  function logForce() {
    console.log.apply(console, arguments);
    var msg = Array.from(arguments).join(" ");
    writeLog(config.logFile, msg);
  }

  function logToFile(message) {
    if (config.logFile) {
      writeLog(config.logFile, message);
    }
  }

  // 插件加载日志
  logForce(
    "[tomzang_plungin] ===== 插件加载 ====="
  );
  logForce(
    "[tomzang_plungin] 项目: " +
      (project && project.id ? project.id : "unknown")
  );
  logForce(
    "[tomzang_plungin] 目录: " + directory
  );
  logForce(
    "[tomzang_plungin] 防火墙: " +
      (hasFirewall ? "已启用" : "未配置")
  );
  logForce(
    "[tomzang_plungin] Toast: " +
      (hasClient ? "可用" : "不可用")
  );
  logForce(
    "[tomzang_plungin] Debug: " + config.debug
  );
  logForce(
    "[tomzang_plungin] 日志文件: " + (config.logFile || "未配置")
  );
  if (hasFirewall) {
    logForce(
      "[tomzang_plungin] 防火墙URL: " + config.firewallUrl
    );
    logForce(
      "[tomzang_plungin] 超时时间: " + config.firewallTimeout + "ms"
    );
  }
  logForce(
    "[tomzang_plungin] ===================="
  );

  if (!hasFirewall) {
    logForce(
      "[tomzang_plungin] 未配置 firewallUrl 或 authKey，防火墙检测已禁用"
    );
  }

  // 新增：显示拦截 Toast 的函数
  async function showBlockToast(fwData, source) {
    if (!hasClient) {
      log("[tomzang_plungin] client 不可用，无法显示 Toast");
      return;
    }

    try {
      var hitRulesText = formatHitRulesForToast(fwData.hit_rules);
      var reason = fwData.violation_reason || "未知原因";
      var riskLevel = fwData.risk_level || 0;
      var emoji = getRiskEmoji(riskLevel);

      var message =
        "🚨 内容被拦截\n\n" +
        "原因: " +
        reason +
        "\n" +
        "风险等级: " +
        emoji +
        " " +
        riskLevel +
        "\n\n" +
        HIT_RULES_HEADER +
        "\n" +
        hitRulesText;

      await client.tui.showToast({
        body: {
          message: message,
          variant: "error",
        },
      });

      log(
        "[" +
          ts() +
          "] [TOAST] 已显示拦截通知 source=" +
          source +
          " risk=" +
          riskLevel
      );
    } catch (e) {
      log(
        "[tomzang_plungin] [WARN] 显示 Toast 失败: " +
          (e.message || e)
      );
    }
  }

  return {
    "chat.message": async function (input, output) {
      var text = output.parts
        .filter(function (p) {
          return p.type === "text";
        })
        .map(function (p) {
          return p.text;
        })
        .join("\n");
      text = text.replace(/<system-reminder>[\s\S]*?<\/system-reminder>/g, "").trim();
      if (!text) return;

      log("[" + ts() + "] [USER] " + text.slice(0, 500));

      if (!hasFirewall) return;

      try {
        var fwData = await callFirewallApi(
          config,
          text,
          "",
          "text",
          input.sessionID,
          deviceId
        );
        if (fwData.result === "block") {
          logForce(
            "[" + ts() + "] [BLOCK] 用户输入被拦截: " + (fwData.violation_reason || "")
          );
          logForce(
            "[" + ts() + "] [BLOCK] 风险等级: " + (fwData.risk_level || 0)
          );
          logForce(
            "[" + ts() + "] [BLOCK] 命中规则: " + JSON.stringify(fwData.hit_rules || [])
          );

          // 显示 Toast
          await showBlockToast(fwData, "用户输入");

          // 终止对话：用 synthetic 消息替换用户原始内容
          // 这样用户内容不会发送给 LLM，LLM 会响应拦截说明
          var blockMsg = buildBlockResponse(fwData, config.blockMessage);
          var firstPart = output.parts[0] || {};
          output.parts.length = 0;
          output.parts.push({
            ...firstPart,
            type: "text",
            text: blockMsg,
            synthetic: true,
          });

          logForce(
            "[" + ts() + "] [BLOCK] 已替换用户消息为拦截说明"
          );

          // 异步尝试中止会话（不阻塞主流程）
          // 注意：根据已知问题，abort 可能不会立即生效或会卡住
          // 因此我们异步调用，避免阻塞用户界面
          if (hasClient && input.sessionID) {
            client.session.abort({ path: { id: input.sessionID } })
              .then(function () {
                logForce(
                  "[" + ts() + "] [ABORT] 会话已中止"
                );
              })
              .catch(function (e) {
                logForce(
                  "[" + ts() + "] [WARN] Abort 异步失败: " + (e.message || e)
                );
              });
            logForce(
              "[" + ts() + "] [BLOCK] Abort 请求已发送（异步执行中）"
            );
          }
          return;
        }
      } catch (e) {
        if (e.message && e.message.indexOf("防火墙") === -1) {
          log(
            "[" + ts() + "] [BLOCK] " + e.message.slice(0, 200)
          );
          throw e;
        }
        log(
          "[" +
            ts() +
            "] [WARN] 防火墙调用失败: " +
            (e.message || e)
        );
      }
    },

    "tool.execute.before": async function (input, output) {
      var argsSummary = summarizeArgs(output.args);
      log(
        "[" + ts() + "] [TOOL:" + input.tool + "] " + argsSummary
      );

      if (!hasFirewall) return;

      var toolCommand = buildToolCommand(input.tool, output.args);
      try {
        var fwData = await callFirewallApi(
          config,
          toolCommand,
          "",
          "tool_call",
          input.sessionID,
          deviceId
        );
        if (fwData.result === "block") {
          var blockMsg = buildBlockResponse(fwData, config.blockMessage);
          logForce(
            "[" +
              ts() +
              "] [BLOCK] 工具调用被拦截: " +
              input.tool +
              " - " +
              (fwData.violation_reason || "")
          );
          logForce(
            "[" + ts() + "] [BLOCK] 风险等级: " + (fwData.risk_level || 0)
          );
          logForce(
            "[" + ts() + "] [BLOCK] 命中规则: " + JSON.stringify(fwData.hit_rules || [])
          );

          // 显示 Toast
          await showBlockToast(fwData, "工具调用: " + input.tool);

          // 终止对话：返回 block 标记
          // 注意：需要先返回 block，然后再异步尝试 abort
          // 延迟执行 abort 以确保 block 先生效
          if (hasClient && input.sessionID) {
            setTimeout(function() {
              client.session.abort({ path: { id: input.sessionID } })
                .then(function () {
                  logForce(
                    "[" + ts() + "] [ABORT] 会话已中止"
                  );
                })
                .catch(function (e) {
                  logForce(
                    "[" + ts() + "] [WARN] Abort 异步失败: " + (e.message || e)
                  );
                });
              logForce(
                "[" + ts() + "] [BLOCK] Abort 请求已发送（异步执行中）"
              );
            }, 100);
          }

          return { block: true, blockReason: blockMsg };
        }
      } catch (e) {
        log(
          "[" +
            ts() +
            "] [WARN] 防火墙调用失败: " +
            (e.message || e)
        );
      }
    },

    "tool.execute.after": async function (input, output) {
      var resultPreview = (output.output || "").slice(0, 500);
      log(
        "[" + ts() + "] [TOOL_RESULT:" + input.tool + "] " + resultPreview
      );

      if (!hasFirewall) return;

      var toolCommand = buildToolCommand(input.tool, null);
      try {
        var fwData = await callFirewallApi(
          config,
          toolCommand,
          output.output || "",
          "tool_result",
          input.sessionID,
          deviceId
        );
        if (fwData.result === "block") {
          var blockMsg = buildBlockResponse(fwData, config.blockMessage);
          logForce(
            "[" +
              ts() +
              "] [BLOCK] 工具结果被拦截: " +
              input.tool +
              " - " +
              (fwData.violation_reason || "")
          );
          logForce(
            "[" + ts() + "] [BLOCK] 风险等级: " + (fwData.risk_level || 0)
          );
          logForce(
            "[" + ts() + "] [BLOCK] 命中规则: " + JSON.stringify(fwData.hit_rules || [])
          );

          // 显示 Toast
          await showBlockToast(fwData, "工具结果: " + input.tool);

          // 终止对话：替换输出
          output.output = blockMsg;

          // 异步尝试中止会话（不阻塞主流程）
          if (hasClient && input.sessionID) {
            setTimeout(function() {
              client.session.abort({ path: { id: input.sessionID } })
                .then(function () {
                  logForce(
                    "[" + ts() + "] [ABORT] 会话已中止"
                  );
                })
                .catch(function (e) {
                  logForce(
                    "[" + ts() + "] [WARN] Abort 异步失败: " + (e.message || e)
                  );
                });
              logForce(
                "[" + ts() + "] [BLOCK] Abort 请求已发送（异步执行中）"
              );
            }, 100);
          }
          logForce(
            "[" + ts() + "] [BLOCK] 已替换工具输出为拦截消息"
          );
        }
      } catch (e) {
        log(
          "[" +
            ts() +
            "] [WARN] 防火墙调用失败: " +
            (e.message || e)
        );
      }
    },

    dispose: async function () {
      log("[tomzang_plungin] 已卸载");
    },
  };
}
