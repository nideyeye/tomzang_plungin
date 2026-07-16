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

  var resp = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });

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
}

export default async function TomzangPlungin({ project, directory }, options) {
  var config = {
    firewallUrl: (options && options.firewallUrl) || "",
    authKey: (options && options.authKey) || "",
    blockMessage: (options && options.blockMessage) || DEFAULT_BLOCK_MESSAGE,
    debug: !!(options && options.debug),
  };

  var hasFirewall = !!(config.firewallUrl && config.authKey);

  console.log(
    "[tomzang_plungin] 已加载 | 项目: " +
      (project && project.id ? project.id : "unknown") +
      " | 目录: " +
      directory +
      " | 防火墙: " +
      (hasFirewall ? "已启用" : "未配置")
  );

  if (!hasFirewall) {
    console.log(
      "[tomzang_plungin] 未配置 firewallUrl 或 authKey，防火墙检测已禁用"
    );
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

      console.log("[" + ts() + "] [USER] " + text.slice(0, 500));

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
          var blockMsg = buildBlockResponse(fwData, config.blockMessage);
          console.log(
            "[" + ts() + "] [BLOCK] 用户输入被拦截: " + (fwData.violation_reason || "")
          );
          output.parts = [{ type: "text", text: blockMsg }];
          throw new Error(blockMsg);
        }
      } catch (e) {
        if (e.message && e.message.indexOf("防火墙") === -1) {
          console.log(
            "[" + ts() + "] [BLOCK] " + e.message.slice(0, 200)
          );
          throw e;
        }
        console.log(
          "[" +
            ts() +
            "] [WARN] 防火墙调用失败: " +
            (e.message || e)
        );
      }
    },

    "tool.execute.before": async function (input, output) {
      var argsSummary = summarizeArgs(output.args);
      console.log(
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
          console.log(
            "[" +
              ts() +
              "] [BLOCK] 工具调用被拦截: " +
              input.tool +
              " - " +
              (fwData.violation_reason || "")
          );
          return { block: true, blockReason: blockMsg };
        }
      } catch (e) {
        console.log(
          "[" +
            ts() +
            "] [WARN] 防火墙调用失败: " +
            (e.message || e)
        );
      }
    },

    "tool.execute.after": async function (input, output) {
      var resultPreview = (output.output || "").slice(0, 500);
      console.log(
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
          console.log(
            "[" +
              ts() +
              "] [BLOCK] 工具结果被拦截: " +
              input.tool +
              " - " +
              (fwData.violation_reason || "")
          );
          output.output = blockMsg;
        }
      } catch (e) {
        console.log(
          "[" +
            ts() +
            "] [WARN] 防火墙调用失败: " +
            (e.message || e)
        );
      }
    },

    dispose: async function () {
      console.log("[tomzang_plungin] 已卸载");
    },
  };
}
