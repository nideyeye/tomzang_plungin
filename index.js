var DEFAULT_BLOCK_MESSAGE = "当前请求包含敏感信息，已被安全组件拦截";

function ts() {
  return new Date().toLocaleString("zh-CN", { hour12: false });
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

async function callFirewallApi(config, prompt, response, source, sessionId) {
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

  if (config.debug) {
    console.log(
      "[tomzang_plungin] [DEBUG] 请求防火墙 source=" +
        source +
        " session_id=" +
        body.session_id
    );
  }

  var controller = new AbortController();
  var timeoutId = setTimeout(function () {
    controller.abort();
  }, config.firewallTimeout);

  try {
    var resp = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json" 
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
        "[tomzang_plungin] [DEBUG] 防火墙响应 result=" +
          (json.data && json.data.result) +
          " action=" +
          (json.data && json.data.action) +
          " risk_level=" +
          (json.data && json.data.risk_level)
      );
    }

    return json.data || {};
  } catch (e) {
    clearTimeout(timeoutId);
    if (e.name === "AbortError") {
      if (config.debug) {
        console.log(
          "[tomzang_plungin] [DEBUG] 防火墙 API 超时(" +
            config.firewallTimeout +
            "ms)，跳过本次审计"
        );
      }
      return { result: "pass" };
    }
    throw e;
  }
}

// 新增：格式化命中规则表头
var HIT_RULES_HEADER = "规则代码 | 规则名称 | 风险等级 | 描述 | AIA分类";

export default async function TomzangPlungin({ project, directory, client }, options) {
  var config = {
    firewallUrl: (options && options.firewallUrl) || "",
    authKey: (options && options.authKey) || "",
    blockMessage: (options && options.blockMessage) || DEFAULT_BLOCK_MESSAGE,
    firewallTimeout: (options && options.firewallTimeout) || 3000,
    debug: !!(options && options.debug),
  };

  var hasFirewall = !!(config.firewallUrl && config.authKey);
  var hasClient = !!(client && client.tui && client.tui.showToast);

  function log() {
    if (!config.debug) return;
    console.log.apply(console, arguments);
  }

  log(
    "[tomzang_plungin] 已加载 | 项目: " +
      (project && project.id ? project.id : "unknown") +
      " | 目录: " +
      directory +
      " | 防火墙: " +
      (hasFirewall ? "已启用" : "未配置") +
      " | Toast: " +
      (hasClient ? "可用" : "不可用")
  );

  if (!hasFirewall) {
    log(
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
          input.sessionID
        );
        if (fwData.result === "block") {
          log(
            "[" + ts() + "] [BLOCK] 用户输入被拦截: " + (fwData.violation_reason || "")
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

          // 尝试中止当前生成（作为额外保险）
          if (hasClient && input.sessionID) {
            try {
              await client.session.abort({ path: { id: input.sessionID } });
              log("[" + ts() + "] [ABORT] 会话已中止");
            } catch (e) {
              log("[" + ts() + "] [WARN] 中止会话失败: " + (e.message || e));
            }
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
          input.sessionID
        );
        if (fwData.result === "block") {
          var blockMsg = buildBlockResponse(fwData, config.blockMessage);
          log(
            "[" +
              ts() +
              "] [BLOCK] 工具调用被拦截: " +
              input.tool +
              " - " +
              (fwData.violation_reason || "")
          );

          // 显示 Toast
          await showBlockToast(fwData, "工具调用: " + input.tool);

          // 终止对话：返回 block 标记
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
          input.sessionID
        );
        if (fwData.result === "block") {
          var blockMsg = buildBlockResponse(fwData, config.blockMessage);
          log(
            "[" +
              ts() +
              "] [BLOCK] 工具结果被拦截: " +
              input.tool +
              " - " +
              (fwData.violation_reason || "")
          );

          // 显示 Toast
          await showBlockToast(fwData, "工具结果: " + input.tool);

          // 终止对话：替换输出
          output.output = blockMsg;
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
