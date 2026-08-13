// ─── 配置解析 ───

var PLUGIN_VERSION = "v2026-08-11";
var fs = require("fs");
var os = require("os");
var DEFAULT_BLOCK_MESSAGE = "当前请求包含敏感关键字，已被安全组件拦截";
var DEFAULT_TIMEOUT_MS = 3000;  // 默认防火墙 API 超时时间 3 秒
var FIREWALL_API_PATH = "/api/firewall/openclaw/validate";

function buildFullFirewallUrl(host) {
  if (!host) return "";
  var base = host.trim().replace(/\/+$/, "");
  return base + FIREWALL_API_PATH;
}

function resolveConfig(rawConfig) {
  var cfg = rawConfig ?? {};
  // 解析 timeout，必须是正整数
  var timeout = DEFAULT_TIMEOUT_MS;
  if (typeof cfg.timeout === "number" && cfg.timeout > 0) {
    timeout = Math.floor(cfg.timeout);
  }
  // 解析 debug，支持 boolean 和 string 类型（"true"/"false"）
  var debug = false;
  if (typeof cfg.debug === "boolean") {
    debug = cfg.debug;
  } else if (typeof cfg.debug === "string") {
    var trimmed = cfg.debug.trim().toLowerCase();
    debug = trimmed === "true";
  }
  return {
    firewallUrl: buildFullFirewallUrl(cfg.firewallUrl),
    authKey: typeof cfg.authKey === "string" && cfg.authKey.trim() !== ""
      ? cfg.authKey.trim()
      : "",
    blockMessage: typeof cfg.blockMessage === "string" && cfg.blockMessage.trim() !== ""
      ? cfg.blockMessage.trim()
      : DEFAULT_BLOCK_MESSAGE,
    debug: debug,
    timeout: timeout,
    undiciPath: typeof cfg.undiciPath === "string" && cfg.undiciPath.trim() !== ""
      ? cfg.undiciPath.trim()
      : ""
  };
}

// 检查必要配置是否完整
function validateConfig(config) {
  var missing = [];
  if (!config.firewallUrl) missing.push("firewallUrl");
  if (!config.authKey) missing.push("authKey");
  return missing;
}

// ─── 日志 ───

var LOG_PREFIX = "[tomzang_plungin]";
var currentLogger = null;
var debugMode = false;

function formatMessage(category, action, data) {
  var prefix = LOG_PREFIX + " [" + category + "] [" + action + "]";
  if (data !== undefined) {
    var dataStr = typeof data === "string" ? data : JSON.stringify(data);
    return prefix + " " + dataStr;
  }
  return prefix;
}

function logInfo(category, action, data) {
  if (currentLogger && currentLogger.info) {
    currentLogger.info(formatMessage(category, action, data));
  }
}

function logWarn(category, action, data) {
  if (currentLogger && currentLogger.warn) {
    currentLogger.warn(formatMessage(category, action, data));
  }
}

function logError(category, action, data) {
  if (currentLogger && currentLogger.error) {
    currentLogger.error(formatMessage(category, action, data));
  }
}

function logDebug(category, action, data) {
  if (!debugMode) return;
  if (currentLogger && currentLogger.info) {
    currentLogger.info(formatMessage(category, action, data));
  }
}

// ─── 防火墙API调用 ───

var firewallCallId = 0;

async function callFirewallApi(fetchFn, config, prompt, response, sessionId, stage, source) {
  var callId = ++firewallCallId;
  var traceId = "trace-" + Date.now() + "-" + callId;
  var requestBody = {
    auth_key: config.authKey,
    session_id: sessionId || "session-openclaw",
    trace_id: traceId,
    stage: stage || "input",
    source: source || "user_prompt",
    source_user: (function () {
      var v = process.env.GROUP_CHAT_ALLOWED_SENDERS;
      return (typeof v === "string" || typeof v === "number") ? String(v) : "";
    })(),
    content_type: "text",
    content: {
      prompt: prompt || "",
      response: response || "",
      image: ""
    }
  };

  logDebug("firewall", "api_request", {
    callId: callId,
    stage: stage,
    url: config.firewallUrl,
    requestBody: requestBody,
    promptPreview: prompt || "",
    responsePreview: response ? response.slice(0, BODY_PREVIEW_MAX_LENGTH) : ""
  });

  try {
    var startTime = Date.now();
    // 创建超时控制器（兼容 fetch 和 undici.fetch）
    var controller = new AbortController();
    var timeoutId = setTimeout(function () {
      controller.abort();
    }, config.timeout);

    var resp;
    try {
      resp = await fetchFn(config.firewallUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(requestBody),
        signal: controller.signal
      });
    } finally {
      clearTimeout(timeoutId);
    }

    var durationMs = Date.now() - startTime;

    if (!resp.ok) {
      logWarn("firewall", "api_error", { callId: callId, status: resp.status, durationMs: durationMs });
      // 接口调用失败时放行，避免阻断正常请求
      return { action: "pass", error: "API returned status " + resp.status };
    }

    var result = await resp.json();

    logDebug("firewall", "api_raw_response", {
      callId: callId,
      url: config.firewallUrl,
      responseBody: result,
      durationMs: durationMs
    });

    if (result && result.code === 200 && result.data) {
      var data = result.data;

      // 提取 masked_content（脱敏内容）
      var maskedContent = null;
      if (data.masked_content && typeof data.masked_content === "object") {
        maskedContent = {
          prompt: data.masked_content.prompt || "",
          response: data.masked_content.response || "",
          image: data.masked_content.image || ""
        };
      }

      logDebug("firewall", "api_response", {
        callId: callId,
        stage: stage,
        action: data.action,
        result: data.result,
        riskLevel: data.risk_level,
        violationReason: data.violation_reason,
        hitRules: data.hit_rules,
        hasMaskedContent: !!maskedContent,
        durationMs: durationMs
      });
      return {
        action: data.action,
        result: data.result || "",
        riskLevel: data.risk_level || 0,
        violationReason: data.violation_reason || "",
        hitRules: data.hit_rules || [],
        maskedContent: maskedContent
      };
    }

    logWarn("firewall", "unexpected_response", { callId: callId, durationMs: durationMs });
    // 响应格式异常时放行
    return { action: "pass", error: "Unexpected response format" };
  } catch (e) {
    // 详细记录错误信息用于诊断
    var errorDetails = {
      callId: callId,
      url: config.firewallUrl,
      stage: stage,
      errorMessage: String(e && e.message || e),
      errorType: e && e.constructor ? e.constructor.name : "Unknown",
      errorCode: e && e.code ? String(e.code) : undefined,
      errorCause: e && e.cause ? String(e.cause.message || e.cause) : undefined
    };

    // 如果有堆栈信息，记录前几行
    if (e && e.stack) {
      errorDetails.stackPreview = String(e.stack).split('\n').slice(0, 3).join('\n');
    }

    // 尝试提取更多 undici 特定的错误信息
    if (e && typeof e === 'object') {
      var keys = Object.keys(e);
      errorDetails.errorKeys = keys;
      // 记录一些可能包含关键信息的字段
      if (e.statusCode) errorDetails.statusCode = e.statusCode;
      if (e.status) errorDetails.status = e.status;
      if (e.reason) errorDetails.reason = e.reason;
    }

    logError("firewall", "api_call_failed", errorDetails);
    // 接口异常时放行，避免阻断正常请求
    return { action: "pass", result: "pass", error: String(e && e.message || e) };
  }
}

// ─── 用户输入提取 ───
function extractLastUserPrompt(reqBodyText) {
  if (!reqBodyText) return "";
  try {
    var obj = JSON.parse(reqBodyText);
    if (obj && Array.isArray(obj.messages)) {
      logDebug("extract", "messages_structure", {
        messagesCount: obj.messages.length,
        messagesPreview: obj.messages.map(function (m, idx) {
          return { idx: idx, role: m.role, contentType: typeof m.content, hasContent: !!m.content };
        })
      });

      // 首先收集所有 user 消息的详细信息
      var userMessages = [];
      for (var i = obj.messages.length - 1; i >= 0; i--) {
        var msg = obj.messages[i];
        if (msg.role === "user" && msg.content) {
          var raw = typeof msg.content === "string"
            ? msg.content
            : extractTextFromContentArray(msg.content);
          var stripped = stripMetadataPrefix(raw);
          userMessages.push({
            idx: i,
            rawLength: raw ? raw.length : 0,
            rawPreview: raw ? raw.slice(0, 500) : "",
            stripped: stripped,
            strippedLength: stripped ? stripped.length : 0
          });
        }
      }

      logDebug("extract", "all_user_messages", {
        count: userMessages.length,
        messages: userMessages
      });

      // 从后往前找，优先选择包含真实用户输入的消息
      // 策略：跳过以 "Sender (untrusted metadata):" 或 "Conversation info (untrusted metadata):" 开头的消息
      for (var j = 0; j < userMessages.length; j++) {
        var userInfo = userMessages[j];
        var content = userInfo.stripped;

        // 检查是否是元数据块（以特定前缀开头）
        var isMetadata = content.indexOf("Sender (untrusted metadata):") === 0 ||
                         content.indexOf("Conversation info (untrusted metadata):") === 0 ||
                         content.indexOf("System:") === 0;

        if (isMetadata) {
          logDebug("extract", "skipped_metadata_block", {
            idx: userInfo.idx,
            strippedLength: userInfo.strippedLength,
            reason: "content starts with metadata prefix",
            preview: content.slice(0, 100)
          });
          continue;
        }

        // 如果不是元数据且有内容，选择这条消息
        if (userInfo.strippedLength > 0) {
          logDebug("extract", "selected_user_message", {
            idx: userInfo.idx,
            originalLength: userInfo.rawLength,
            strippedLength: userInfo.strippedLength,
            preview: userInfo.stripped.slice(0, 200)
          });
          return userInfo.stripped;
        }
      }

      // 如果所有 user 消息都很短，返回最后一条
      if (userMessages.length > 0) {
        logDebug("extract", "using_last_user_message", {
          idx: userMessages[0].idx,
          content: userMessages[0].stripped
        });
        return userMessages[0].stripped;
      }

      logDebug("extract", "no_user_message_found", { messagesCount: obj.messages.length });
      return "";
    }
    logDebug("extract", "not_messages_array", { bodyPreview: reqBodyText.slice(0, 500) });
    return reqBodyText.slice(0, 2000);
  } catch (e) {
    logDebug("extract", "parse_error", { error: String(e), bodyPreview: reqBodyText.slice(0, 500) });
    return reqBodyText.slice(0, 2000);
  }
}

/**
 * 从飞书适配器的 content 数组中拼接所有 text 片段
 * content 形如: [{\"type\":\"text\",\"text\":\"...\"},{\"type\":\"text\",\"text\":\"...\"}]
 */
function extractTextFromContentArray(contentArray) {
  if (!Array.isArray(contentArray)) {
    return typeof contentArray === "string" ? contentArray : JSON.stringify(contentArray);
  }
  var texts = [];
  for (var i = 0; i < contentArray.length; i++) {
    var item = contentArray[i];
    if (item && typeof item.text === "string") {
      texts.push(item.text);
    }
  }
  return texts.join("\n") || JSON.stringify(contentArray);
}

// 提示器注入的标签，连同内部内容一并移除（非贪婪，匹配所有出现）
// 这些标签由渲染层注入，不属于用户真实输入，送审计前需要剥离
var INJECTED_TAG_PATTERNS = [
  /<relevant-memories>[\s\S]*?<\/relevant-memories>/g,
  /<inherited-rules>[\s\S]*?<\/inherited-rules>/g,
  /<derived-focus>[\s\S]*?<\/derived-focus>/g,
  /<self-improvement-reminder>[\s\S]*?<\/self-improvement-reminder>/g
];

/**
 * 移除提示器注入的四类标签及其内部内容
 * 非贪婪 + 全局匹配：删除每种标签的所有出现，安全处理多次/相邻/混合出现
 * 仅处理标准闭合标签 <tag>...</tag>，不处理自闭合或未闭合变体
 */
function stripInjectedTags(text) {
  if (!text || typeof text !== "string") return text || "";
  for (var i = 0; i < INJECTED_TAG_PATTERNS.length; i++) {
    text = text.replace(INJECTED_TAG_PATTERNS[i], "");
  }
  // 合并因删标签而残留的多余空行，避免大段空白
  return text.replace(/\n{3,}/g, "\n\n");
}

/**
 * 去除系统前缀 / 元数据块，提取末尾真正的用户输入
 *
 * 已知的噪声结构（按出现顺序）：
 *   1. System: [...] Feishu[...] DM | ...\n\n
 *   2. Conversation info (untrusted metadata):\n```json\n{...}\n```\n\n
 *   3. Sender (untrusted metadata):\n```json\n{...}\n```\n\n
 *   4. 飞书消息格式：
 *      [message_id: om_xxx]
 *      ou_xxx: 实际消息内容
 *
 * 策略：先处理飞书格式，再找最后一个 ``` 代码块结束标记后面的内容；
 *       再去掉可能的时间戳行前缀 [Mon 2026-04-20 18:08 GMT+8]；
 *       最后统一剥离提示器注入的标签（stripInjectedTags）
 */
function stripMetadataPrefix(text) {
  return stripInjectedTags(stripMetadataPrefixRaw(text)).trim();
}

// 原有的元数据 / 前缀剥离逻辑（不含注入标签处理）
function stripMetadataPrefixRaw(text) {
  if (!text || typeof text !== "string") return text || "";

  // 找最后一个 ``` 标记的位置（元数据代码块的结束）
  var lastFence = text.lastIndexOf("```");
  if (lastFence !== -1) {
    // 取 ``` 之后的内容
    var afterFence = text.substring(lastFence + 3);
    // 去掉开头的空白换行
    afterFence = afterFence.replace(/^\s*\n*/, "");
    if (afterFence.length > 0) {
      // 在 ``` 之后的文本中继续处理飞书格式
      var feishuInAfterFence = afterFence.match(/^\[message_id:\s*[^\]]+\]\s*([a-z]+_\w+):\s*/);
      if (feishuInAfterFence) {
        // 提取用户 ID 后面的内容
        var contentAfterUserId = afterFence.substring(feishuInAfterFence[0].length);
        var stripped = contentAfterUserId.replace(/^\s+/, "").replace(/\s+$/, "");
        if (stripped.length > 0) {
          logDebug("extract", "feishu_format_after_fence_stripped", {
            userId: feishuInAfterFence[1],
            originalLength: text.length,
            strippedLength: stripped.length,
            preview: stripped.slice(0, 100)
          });
          return stripTimestampPrefix(stripped).trim();
        }
      }
      return stripTimestampPrefix(afterFence).trim();
    }
    // 如果 ``` 后面没内容，回退到原文
  }

  // 处理飞书消息格式：[message_id: xxx]\nou_xxx: 实际内容
  // 只在没有 ``` 代码块时尝试，避免把元数据代码块之前的内容也匹配进去
  var feishuPattern = /^\[message_id:\s*[^\]]+\]\s*([a-z]+_\w+):\s*/m;
  var feishuMatch = text.match(feishuPattern);
  if (feishuMatch) {
    // 提取用户 ID 后面的内容
    var afterUserId = text.substring(feishuMatch[0].length);
    // 去除可能的多余空格和换行
    var stripped = afterUserId.replace(/^\s+/, "").replace(/\s+$/, "");
    if (stripped.length > 0) {
      logDebug("extract", "feishu_format_stripped", {
        userId: feishuMatch[1],
        originalLength: text.length,
        strippedLength: stripped.length,
        preview: stripped.slice(0, 100)
      });
      return stripTimestampPrefix(stripped).trim();
    }
  }

  // 没有 ``` 代码块且没有飞书格式的情况：尝试按 \n\n 分割，取最后一段
  var parts = text.split(/\n\n/);
  var lastPart = parts[parts.length - 1];
  if (lastPart && lastPart.trim().length > 0) {
    return stripTimestampPrefix(lastPart).trim();
  }

  return text.trim();
}

/**
 * 去掉 control-ui 自带聊天可能附加的时间戳前缀
 * 例如: "[Mon 2026-04-20 18:08 GMT+8] 打开浏览器" → "打开浏览器"
 */
function stripTimestampPrefix(text) {
  // 匹配 [Mon 2026-04-20 18:08 GMT+8] 或 [2026-04-20 18:08:22 GMT+8] 等格式
  return text.replace(/^\[.*?\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}(?::\d{2})?\s+GMT[^\]]*\]\s*/, "");
}


// OpenClaw 内置命令白名单（只对这些命令跳过审计）
var BUILT_IN_COMMANDS = [
  "/new",
  "/reset",
  "/help",
  "/clear",
  "/config",
  "/exit",
  "/quit",
  "/sessions",
  "/models",
  "/providers",
  "/agent",
  "/session",
  "/continue",
  "/version",
  "/debug",
  "/verbose"
];

// 判断是否为内置命令（仅对白名单中的命令跳过审计）
function isBuiltInCommand(text) {
  if (!text || typeof text !== "string") return false;
  var trimmed = text.trim();

  // 必须以 / 开头且长度大于1
  if (trimmed.length <= 1 || trimmed[0] !== "/") return false;

  // 提取命令部分（处理带参数的情况，如 /config set key=value）
  var parts = trimmed.split(/\s+/);
  var command = parts[0];

  // 检查是否在白名单中
  for (var i = 0; i < BUILT_IN_COMMANDS.length; i++) {
    if (command === BUILT_IN_COMMANDS[i]) {
      return true;
    }
  }

  // 不在白名单中的 / 开头文本仍然需要审计
  return false;
}

// 判断是否为系统内部操作触发的请求（无需防火墙检测）
// 包括：内置命令触发的会话初始化消息、系统自动生成的摘要/文件名请求等
var SYSTEM_INTERNAL_PATTERNS = [
  /A new session was started via \/new/i,
  /A new session was started via \/reset/i,
  /Based on this conversation, generate a short/i,
  /generate a short \d+-\d+ word filename slug/i,
  /session was started via \//i,
  /session was reset/i
];

function isSystemInternalRequest(text) {
  if (!text || typeof text !== "string") return false;
  for (var i = 0; i < SYSTEM_INTERNAL_PATTERNS.length; i++) {
    if (SYSTEM_INTERNAL_PATTERNS[i].test(text)) return true;
  }
  return false;
}

// 综合判断：是否应该跳过防火墙检测（内置命令或系统内部操作）
function shouldSkipFirewall(text) {
  return isBuiltInCommand(text) || isSystemInternalRequest(text);
}

// ─── Skill 审计辅助函数 ───

// 判断路径是否指向 SKILL.md（仅看文件名，不限制所在目录）
function isSkillFilePath(filePath) {
  if (!filePath || typeof filePath !== "string") return false;
  var normalized = filePath.replace(/\\/g, "/");
  return /\/SKILL\.md$/i.test(normalized);
}

// 展开路径开头的 ~ 为用户家目录（fs 不会自动展开）
function expandHome(filePath) {
  if (!filePath || typeof filePath !== "string") return filePath;
  if (filePath === "~") return os.homedir();
  if (filePath.indexOf("~/") === 0 || filePath.indexOf("~\\") === 0) {
    return os.homedir() + filePath.slice(1);
  }
  return filePath;
}

// 读取 SKILL.md 正文，失败返回空字符串（遵循 fail-open）
function readSkillContent(filePath) {
  try {
    return fs.readFileSync(expandHome(filePath), "utf8");
  } catch (e) {
    logWarn("skill", "read_skill_failed", { filePath: filePath, error: String(e && e.message || e) });
    return "";
  }
}

// 从 tool call 参数中提取 SKILL.md 文件路径（若该调用是在读取 skill 正文）
// 兼容 Read 工具（file_path / path）与 Skill 工具（skill / file / file_path / path）
// 兼容 params 为对象或 JSON 字符串两种形态
function extractSkillFilePath(event) {
  if (!event || !event.params) return null;
  var params = event.params;
  var candidates = [];
  if (typeof params === "string") {
    try {
      var p = JSON.parse(params);
      if (p && typeof p === "object") {
        candidates.push(p.file_path, p.path, p.file, p.skill);
      } else {
        candidates.push(params);
      }
    } catch (e) {
      candidates.push(params);
    }
  } else {
    candidates.push(params.file_path, params.path, params.file, params.skill);
  }
  for (var i = 0; i < candidates.length; i++) {
    if (candidates[i] && isSkillFilePath(String(candidates[i]))) {
      return String(candidates[i]);
    }
  }
  return null;
}

// ─── Fetch 工具函数 ───

function getUrlFromFetchArgs(input) {
  if (typeof input === "string") return input;
  if (input instanceof URL) return input.toString();
  if (input instanceof Request) return input.url;
  return String(input);
}

function getMethodFromFetchArgs(input, init) {
  var m = (init && init.method) || (input instanceof Request ? input.method : "GET") || "GET";
  return String(m).toUpperCase();
}

async function getRequestBodyText(input, init) {
  if (input instanceof Request) {
    try { return await input.clone().text(); } catch { return ""; }
  }
  return (init && typeof init.body === "string") ? init.body : "";
}

function headersInitToRecord(headersInit) {
  var out = {};
  if (!headersInit) return out;
  try {
    if (headersInit instanceof Headers) {
      headersInit.forEach(function (v, k) { out[k] = v; });
    } else if (Array.isArray(headersInit)) {
      for (var i = 0; i < headersInit.length; i++) {
        out[String(headersInit[i][0])] = String(headersInit[i][1]);
      }
    } else {
      for (var k in headersInit) { out[k] = String(headersInit[k]); }
    }
  } catch {}
  return out;
}

function getMergedRequestHeaders(input, init) {
  var initHeaders = headersInitToRecord(init && init.headers);
  var inputHeaders = input instanceof Request ? headersInitToRecord(input.headers) : {};
  var merged = {};
  for (var k in inputHeaders) merged[k] = inputHeaders[k];
  for (var k2 in initHeaders) merged[k2] = initHeaders[k2];
  return merged;
}

function headersToRecord(headers) {
  var out = {};
  try { headers.forEach(function (v, k) { out[k] = v; }); } catch {}
  return out;
}

// ─── 拦截提示语生成 ───

// 从防火墙返回的 hit_rules 中提取详细信息，生成 markdown 表格
function buildBlockMessageFromHitRules(hitRules) {
  if (!Array.isArray(hitRules) || hitRules.length === 0) {
    return DEFAULT_BLOCK_MESSAGE;
  }
  var lines = [
    "**⛔ 当前请求已被安全组件拦截，命中以下规则：**",
    "",
    "| 规则代码 | 规则名称 | 风险等级 | 描述 | AIA分类 |",
    "| --- | --- | ---: | --- | --- |"
  ];
  for (var i = 0; i < hitRules.length; i++) {
    var rule = hitRules[i];
    var code = rule.rule_code || "-";
    var name = rule.rule_name || "-";
    var riskLevel = rule.risk_level !== undefined ? rule.risk_level : "-";
    var desc = rule.description || "-";
    var aiaName = rule.aia_name || "-";

    // 风险等级显示为 emoji
    var riskEmoji = "";
    if (riskLevel >= 3) riskEmoji = "🔴";
    else if (riskLevel === 2) riskEmoji = "🟠";
    else if (riskLevel === 1) riskEmoji = "🟡";
    else riskEmoji = "⚪";

    lines.push("| " + code + " | " + name + " | " + riskEmoji + " " + riskLevel + " | " + desc + " | " + aiaName + " |");
  }
  lines.push("");
  lines.push("**如需继续操作，请联系管理员或调整请求内容。**");
  return lines.join("\n");
}

// ─── 响应构造 ───

function guessRequestWantsSse(url, reqHeaders, reqBodyText) {
  try {
    if (reqBodyText) {
      var obj = JSON.parse(reqBodyText);
      if (obj && obj.stream === true) return true;
    }
  } catch {}
  var accept = (reqHeaders["accept"] || reqHeaders["Accept"] || "").toLowerCase();
  if (accept.includes("text/event-stream")) return true;
  if (url.includes("/chat/completions")) return true;
  return false;
}

function isSseResponse(resp) {
  var ct = (resp.headers.get("content-type") || "").toLowerCase();
  return ct.includes("text/event-stream");
}

function buildOpenAiSseBodyFromText(replacementText, id) {
  var now = Math.floor(Date.now() / 1000);
  var model = "tomzang-security";
  var chunkObj = {
    id: id,
    object: "chat.completion.chunk",
    created: now,
    model: model,
    choices: [{ index: 0, delta: { content: replacementText }, finish_reason: null }]
  };
  var finishObj = {
    id: id,
    object: "chat.completion.chunk",
    created: now,
    model: model,
    choices: [{ index: 0, delta: { content: "" }, finish_reason: "stop" }]
  };
  return "data: " + JSON.stringify(chunkObj) + "\n\ndata: " + JSON.stringify(finishObj) + "\n\ndata: [DONE]\n\n";
}

function buildOpenAiJsonBodyFromText(replacementText, id) {
  var now = Math.floor(Date.now() / 1000);
  var model = "tomzang-security";
  var jsonObj = {
    id: id,
    object: "chat.completion",
    created: now,
    model: model,
    choices: [{
      index: 0,
      message: { role: "assistant", content: replacementText },
      finish_reason: "stop"
    }]
  };
  return JSON.stringify(jsonObj);
}

// 请求阶段拦截：伪造一个完整的 LLM 响应返回给客户端
function makeBlockedResponseForRequest(wantsSse, replacementText) {
  var id = "chatcmpl-tomzang-request-blocked";
  if (wantsSse) {
    var headers = new Headers({
      "content-type": "text/event-stream; charset=utf-8",
      "cache-control": "no-cache",
      "connection": "keep-alive"
    });
    var body = buildOpenAiSseBodyFromText(replacementText, id);
    return new Response(body, { status: 200, headers: headers });
  }
  var headers2 = new Headers({ "content-type": "application/json; charset=utf-8" });
  var body2 = buildOpenAiJsonBodyFromText(replacementText, id);
  return new Response(body2, { status: 200, headers: headers2 });
}

// 响应阶段拦截：伪造一个完整的 LLM 响应返回给客户端
function makeBlockedResponseForOutput(streaming, replacementText) {
  var id = "chatcmpl-tomzang-output-blocked";
  if (streaming) {
    var headers = new Headers({
      "content-type": "text/event-stream; charset=utf-8",
      "cache-control": "no-cache",
      "connection": "keep-alive",
      "x-firewall-action": "blocked"
    });
    var body = buildOpenAiSseBodyFromText(replacementText, id);
    return new Response(body, { status: 200, headers: headers });
  }
  var headers2 = new Headers({
    "content-type": "application/json; charset=utf-8",
    "x-firewall-action": "blocked"
  });
  var body2 = buildOpenAiJsonBodyFromText(replacementText, id);
  return new Response(body2, { status: 200, headers: headers2 });
}

// ─── 输出内容提取与替换 ───

// 从非流式 JSON 响应中提取助手回复文本（兼容 OpenAI / Anthropic / 通用格式）
function extractAssistantTextFromJson(bodyText) {
  try {
    var obj = typeof bodyText === "string" ? JSON.parse(bodyText) : bodyText;

    // OpenAI 格式: choices[0].message.content
    if (obj.choices && obj.choices.length > 0) {
      var choice = obj.choices[0];
      if (choice.message && typeof choice.message.content === "string") {
        return choice.message.content;
      }
      if (typeof choice.text === "string") {
        return choice.text;
      }
    }

    // Anthropic 格式: content[0].text
    if (obj.content && Array.isArray(obj.content)) {
      var texts = [];
      for (var i = 0; i < obj.content.length; i++) {
        if (obj.content[i].type === "text" && typeof obj.content[i].text === "string") {
          texts.push(obj.content[i].text);
        }
      }
      if (texts.length > 0) return texts.join("");
    }

    // 直接有 response / output 字段
    if (typeof obj.response === "string") return obj.response;
    if (typeof obj.output === "string") return obj.output;

    return "";
  } catch (e) {
    return "";
  }
}

/**
 * 将非流式 JSON 响应体中的助手回复替换为脱敏后的文本
 * 返回替换后的 JSON 字符串；如果替换失败则返回 null
 */
function replaceAssistantTextInJson(bodyText, maskedResponse) {
  try {
    var obj = JSON.parse(bodyText);

    // OpenAI 格式: choices[0].message.content
    if (obj.choices && obj.choices.length > 0) {
      var choice = obj.choices[0];
      if (choice.message && typeof choice.message.content === "string") {
        choice.message.content = maskedResponse;
        return JSON.stringify(obj);
      }
      if (typeof choice.text === "string") {
        choice.text = maskedResponse;
        return JSON.stringify(obj);
      }
    }

    // Anthropic 格式: content[0].text（将所有 text block 合并替换到第一个，清空后续）
    if (obj.content && Array.isArray(obj.content)) {
      var replaced = false;
      for (var i = 0; i < obj.content.length; i++) {
        if (obj.content[i].type === "text" && typeof obj.content[i].text === "string") {
          if (!replaced) {
            obj.content[i].text = maskedResponse;
            replaced = true;
          } else {
            obj.content[i].text = "";
          }
        }
      }
      if (replaced) return JSON.stringify(obj);
    }

    // 直接有 response / output 字段
    if (typeof obj.response === "string") {
      obj.response = maskedResponse;
      return JSON.stringify(obj);
    }
    if (typeof obj.output === "string") {
      obj.output = maskedResponse;
      return JSON.stringify(obj);
    }

    return null;
  } catch (e) {
    return null;
  }
}

// 从 SSE 流式响应的行数组中提取完整的助手回复文本
function extractAssistantTextFromSseLines(lines) {
  var fullText = "";
  for (var i = 0; i < lines.length; i++) {
    var line = lines[i];
    if (!line.startsWith("data: ")) continue;
    var dataStr = line.slice(6).trim();
    if (dataStr === "[DONE]") continue;
    try {
      var obj = JSON.parse(dataStr);
      // OpenAI 流式格式: choices[0].delta.content
      if (obj.choices && obj.choices.length > 0) {
        var delta = obj.choices[0].delta;
        if (delta && typeof delta.content === "string") {
          fullText += delta.content;
        }
      }
      // Anthropic 流式格式: delta.text
      if (obj.delta && typeof obj.delta.text === "string") {
        fullText += obj.delta.text;
      }
      // Anthropic content_block_delta
      if (obj.type === "content_block_delta" && obj.delta && typeof obj.delta.text === "string") {
        fullText += obj.delta.text;
      }
    } catch (e) {
      // 解析失败跳过
    }
  }
  return fullText;
}

/**
 * 构建一个将脱敏内容作为完整 SSE 流返回的响应
 * 复用原始流中第一个 chunk 的 id/model 等元信息，只替换内容
 */
function buildMaskedSseResponse(originalResp, allLines, maskedResponse) {
  // 尝试从原始 SSE 行中提取 id 和 model
  var originalId = "chatcmpl-tomzang-masked";
  var originalModel = "tomzang-security";
  for (var i = 0; i < allLines.length; i++) {
    var line = allLines[i];
    if (!line.startsWith("data: ")) continue;
    var dataStr = line.slice(6).trim();
    if (dataStr === "[DONE]") continue;
    try {
      var obj = JSON.parse(dataStr);
      if (obj.id) originalId = obj.id;
      if (obj.model) originalModel = obj.model;
      break; // 只需要第一个
    } catch (e) {}
  }

  var now = Math.floor(Date.now() / 1000);
  var chunkObj = {
    id: originalId,
    object: "chat.completion.chunk",
    created: now,
    model: originalModel,
    choices: [{ index: 0, delta: { content: maskedResponse }, finish_reason: null }]
  };
  var finishObj = {
    id: originalId,
    object: "chat.completion.chunk",
    created: now,
    model: originalModel,
    choices: [{ index: 0, delta: { content: "" }, finish_reason: "stop" }]
  };
  var sseBody = "data: " + JSON.stringify(chunkObj) + "\n\ndata: " + JSON.stringify(finishObj) + "\n\ndata: [DONE]\n\n";

  var headers = new Headers({
    "content-type": "text/event-stream; charset=utf-8",
    "cache-control": "no-cache",
    "connection": "keep-alive",
    "x-firewall-action": "masked"
  });
  return new Response(sseBody, { status: 200, headers: headers });
}

// ─── 输出审计 ───

// 判断防火墙返回结果是否需要对输出内容进行脱敏替换
function shouldMaskOutput(fwResult) {
  return fwResult.maskedContent
    && typeof fwResult.maskedContent.response === "string"
    && fwResult.maskedContent.response.length > 0;
}

// 对非流式 JSON 响应进行输出审计
async function auditNonStreamingResponse(originalFetch, config, resp, userPrompt, sessionId, callId, url, matchedProvider) {
  var bodyText;
  try {
    bodyText = await resp.text();
  } catch (e) {
    logWarn("firewall", "output_read_failed", { callId: callId, error: String(e && e.message || e) });
    return resp; // 读取失败直接放行
  }

  var assistantText = extractAssistantTextFromJson(bodyText);

  if (!assistantText) {
    logDebug("firewall", "output_no_text", { callId: callId });
    // 没有提取到文本，重建原始响应并放行
    return new Response(bodyText, {
      status: resp.status,
      statusText: resp.statusText,
      headers: resp.headers
    });
  }

  logDebug("firewall", "output_audit_start", {
    callId: callId,
    assistantTextPreview: assistantText.slice(0, BODY_PREVIEW_MAX_LENGTH)
  });

  var fwResult = await callFirewallApi(
    originalFetch, config, userPrompt, assistantText, sessionId, "output"
  );

  // 情况1：完全拦截
  if (fwResult.result === "block") {
    var blockMsg = buildBlockMessageFromHitRules(fwResult.hitRules);
    logInfo("llm", "output_blocked", {
      callId: callId,
      url: url,
      provider: matchedProvider.providerId,
      result: fwResult.result,
      action: fwResult.action,
      violationReason: fwResult.violationReason,
      riskLevel: fwResult.riskLevel,
      streaming: false
    });
    return makeBlockedResponseForOutput(false, blockMsg);
  }

  // 情况2：放行但需要脱敏替换（masked_content.response 存在且非空）
  if (shouldMaskOutput(fwResult)) {
    var maskedResponse = fwResult.maskedContent.response;
    logInfo("llm", "output_masked", {
      callId: callId,
      url: url,
      provider: matchedProvider.providerId,
      result: fwResult.result,
      riskLevel: fwResult.riskLevel,
      hitRules: fwResult.hitRules,
      originalPreview: assistantText.slice(0, BODY_PREVIEW_MAX_LENGTH),
      maskedPreview: maskedResponse.slice(0, BODY_PREVIEW_MAX_LENGTH),
      streaming: false
    });

    var replacedBody = replaceAssistantTextInJson(bodyText, maskedResponse);
    if (replacedBody) {
      var maskedHeaders = new Headers(resp.headers);
      maskedHeaders.set("x-firewall-action", "masked");
      return new Response(replacedBody, {
        status: resp.status,
        statusText: resp.statusText,
        headers: maskedHeaders
      });
    }

    // 替换失败（格式不支持），回退到直接构造完整响应
    logWarn("firewall", "output_mask_replace_failed", { callId: callId });
    var maskedHeaders2 = new Headers({
      "content-type": "application/json; charset=utf-8",
      "x-firewall-action": "masked"
    });
    var maskedBody = buildOpenAiJsonBodyFromText(maskedResponse, "chatcmpl-tomzang-masked");
    return new Response(maskedBody, { status: 200, headers: maskedHeaders2 });
  }

  // 情况3：完全放行
  logDebug("firewall", "output_audit_passed", { callId: callId });
  return new Response(bodyText, {
    status: resp.status,
    statusText: resp.statusText,
    headers: resp.headers
  });
}

// 对流式 SSE 响应进行输出审计（缓冲全部内容后审计再决定输出）
async function auditStreamingResponse(originalFetch, config, resp, userPrompt, sessionId, callId, url, matchedProvider) {
  var reader = resp.body.getReader();
  var decoder = new TextDecoder("utf-8");
  var allChunksRaw = [];   // 存储原始二进制块
  var allLines = [];        // 存储解析出的 SSE 行
  var buffer = "";

  try {
    while (true) {
      var readResult = await reader.read();
      if (readResult.done) break;
      var chunk = readResult.value;
      allChunksRaw.push(chunk);
      buffer += decoder.decode(chunk, { stream: true });

      // 按行拆分
      var lines = buffer.split("\n");
      buffer = lines.pop() || ""; // 最后一个可能不完整，留到下次
      for (var i = 0; i < lines.length; i++) {
        var trimmed = lines[i].trim();
        if (trimmed) allLines.push(trimmed);
      }
    }
    // 处理剩余 buffer
    if (buffer.trim()) {
      allLines.push(buffer.trim());
    }
  } catch (e) {
    logWarn("firewall", "output_stream_read_failed", { callId: callId, error: String(e && e.message || e) });
    // 读取失败，尽量把已读到的数据返回
    return rebuildSseResponse(resp, allChunksRaw);
  }

  // 从 SSE 行中提取完整助手回复
  var assistantText = extractAssistantTextFromSseLines(allLines);

  if (!assistantText) {
    logDebug("firewall", "output_stream_no_text", { callId: callId });
    return rebuildSseResponse(resp, allChunksRaw);
  }

  logDebug("firewall", "output_stream_audit_start", {
    callId: callId,
    assistantTextPreview: assistantText.slice(0, BODY_PREVIEW_MAX_LENGTH)
  });

  var fwResult = await callFirewallApi(
    originalFetch, config, userPrompt, assistantText, sessionId, "output"
  );

  // 情况1：完全拦截
  if (fwResult.result === "block") {
    var blockMsg = buildBlockMessageFromHitRules(fwResult.hitRules);
    logInfo("llm", "output_blocked", {
      callId: callId,
      url: url,
      provider: matchedProvider.providerId,
      result: fwResult.result,
      action: fwResult.action,
      violationReason: fwResult.violationReason,
      riskLevel: fwResult.riskLevel,
      streaming: true
    });
    return makeBlockedResponseForOutput(true, blockMsg);
  }

  // 情况2：放行但需要脱敏替换
  if (shouldMaskOutput(fwResult)) {
    var maskedResponse = fwResult.maskedContent.response;
    logInfo("llm", "output_masked", {
      callId: callId,
      url: url,
      provider: matchedProvider.providerId,
      result: fwResult.result,
      riskLevel: fwResult.riskLevel,
      hitRules: fwResult.hitRules,
      originalPreview: assistantText.slice(0, BODY_PREVIEW_MAX_LENGTH),
      maskedPreview: maskedResponse.slice(0, BODY_PREVIEW_MAX_LENGTH),
      streaming: true
    });
    return buildMaskedSseResponse(resp, allLines, maskedResponse);
  }

  // 情况3：完全放行
  logDebug("firewall", "output_stream_audit_passed", { callId: callId });
  return rebuildSseResponse(resp, allChunksRaw);
}

// 从已缓冲的原始块重建 SSE 响应
function rebuildSseResponse(originalResp, rawChunks) {
  var totalLength = 0;
  for (var i = 0; i < rawChunks.length; i++) {
    totalLength += rawChunks[i].byteLength;
  }
  var merged = new Uint8Array(totalLength);
  var offset = 0;
  for (var j = 0; j < rawChunks.length; j++) {
    merged.set(rawChunks[j], offset);
    offset += rawChunks[j].byteLength;
  }

  return new Response(merged, {
    status: originalResp.status,
    statusText: originalResp.statusText,
    headers: originalResp.headers
  });
}

// 输出审计入口：根据响应类型分发到对应的审计函数
async function auditOutputResponse(originalFetch, config, resp, userPrompt, sessionId, callId, url, matchedProvider) {
  var streaming = isSseResponse(resp);
  if (streaming) {
    return auditStreamingResponse(originalFetch, config, resp, userPrompt, sessionId, callId, url, matchedProvider);
  } else {
    return auditNonStreamingResponse(originalFetch, config, resp, userPrompt, sessionId, callId, url, matchedProvider);
  }
}

// ─── Provider 匹配 ───

var providerCache = { lastTouchedAt: undefined, providers: [] };

function getProviderBaseUrls(config) {
  var lastTouchedAt = config.meta && config.meta.lastTouchedAt;
  if (lastTouchedAt && lastTouchedAt === providerCache.lastTouchedAt) {
    return providerCache.providers;
  }
  var providers = (config.models && config.models.providers) || {};
  var result = [];
  var entries = Object.entries(providers);
  for (var i = 0; i < entries.length; i++) {
    var providerId = entries[i][0];
    var cfg = entries[i][1];
    if (cfg && cfg.baseUrl) {
      result.push({ providerId: providerId, baseUrl: cfg.baseUrl });
    }
  }
  providerCache = { lastTouchedAt: lastTouchedAt, providers: result };
  return result;
}

function matchProviderByUrl(url, providers) {
  for (var i = 0; i < providers.length; i++) {
    if (url.startsWith(providers[i].baseUrl)) {
      return providers[i];
    }
  }
  return null;
}

// ─── LLM 请求智能识别 ───

/**
 * 已知的 LLM API 路径特征
 * 覆盖 OpenAI、Anthropic、Azure OpenAI、Google Gemini、Ollama、各类国产大模型网关等
 */
var LLM_API_PATH_PATTERNS = [
  /\/chat\/completions/i,
  /\/v1\/messages/i,           // Anthropic
  /\/v1\/complete/i,           // Anthropic legacy
  /\/completions/i,            // OpenAI legacy completions
  /\/v1\/engines\/.*\/completions/i,  // Azure OpenAI
  /\/deployments\/.*\/chat\/completions/i, // Azure OpenAI
  /\/v1beta\/models\/.*:generateContent/i, // Google Gemini
  /\/v1\/models\/.*:generateContent/i,     // Google Gemini
  /\/api\/generate/i,          // Ollama
  /\/api\/chat/i,              // Ollama
];

/**
 * 通过 URL 路径特征判断是否为 LLM API 请求
 */
function isLlmApiUrl(url) {
  for (var i = 0; i < LLM_API_PATH_PATTERNS.length; i++) {
    if (LLM_API_PATH_PATTERNS[i].test(url)) return true;
  }
  return false;
}

/**
 * 通过请求体内容特征判断是否为 LLM API 请求
 * 检测 OpenAI/Anthropic 等标准格式的 messages 数组
 */
function isLlmRequestBody(reqBodyText) {
  if (!reqBodyText) return false;
  try {
    var obj = JSON.parse(reqBodyText);
    if (!obj || typeof obj !== "object") return false;

    // OpenAI / Anthropic / 通用格式：包含 messages 数组且有 role 字段
    if (Array.isArray(obj.messages) && obj.messages.length > 0) {
      var firstMsg = obj.messages[0];
      if (firstMsg && typeof firstMsg.role === "string") {
        return true;
      }
    }

    // 包含 model 字段 + prompt 字段（legacy completions 格式）
    if (typeof obj.model === "string" && typeof obj.prompt === "string") {
      return true;
    }

    // Google Gemini 格式：contents 数组
    if (Array.isArray(obj.contents) && obj.contents.length > 0) {
      var firstContent = obj.contents[0];
      if (firstContent && Array.isArray(firstContent.parts)) {
        return true;
      }
    }

    return false;
  } catch (e) {
    return false;
  }
}

/**
 * 综合判断一个 POST 请求是否为 LLM API 调用
 * 策略：URL 路径匹配 OR 请求体结构匹配（双重保险）
 */
function detectLlmRequest(url, method, reqBodyText) {
  // 只拦截 POST 请求
  if (method !== "POST") return false;
  // URL 路径特征匹配
  if (isLlmApiUrl(url)) return true;
  // 请求体结构特征匹配
  if (isLlmRequestBody(reqBodyText)) return true;
  return false;
}

// ─── 插件主体 ───

var FETCH_WRAPPED_KEY = Symbol.for("tomzang_plungin.fetch-wrapped");
var ORIGINAL_FETCH_KEY = Symbol.for("tomzang_plungin.original-fetch");
var BODY_PREVIEW_MAX_LENGTH = 500;

var plugin = {
  id: "tomzang_plungin",
  name: "tomzang_plungin",
  description: "A security plugin that validates user input and output through a firewall API to detect and block sensitive content.",
  configSchema: {
    type: "object",
    additionalProperties: false,
    properties: {
      firewallUrl: { type: "string", description: "Firewall API host and port, e.g. http://localhost:8080 (required, path /api/firewall/openclaw/validate will be appended automatically)" },
      authKey: { type: "string", description: "Authentication key for the firewall API (required)" },
      blockMessage: { type: "string", default: DEFAULT_BLOCK_MESSAGE, description: "Custom block message" },
      debug: { type: "boolean", default: false, description: "Enable debug mode (disabled by default)" },
      timeout: { type: "number", default: DEFAULT_TIMEOUT_MS, description: "Firewall API timeout in milliseconds (default: 3000)" },
      undiciPath: { type: "string", description: "Custom path to undici module (optional, auto-detected if not specified)" }
    },
    required: ["firewallUrl", "authKey"]
  },

  register: function (api) {
    // 保存全局 API 引用，用于在拦截器中访问配置
    globalApi = api;
    currentLogger = api.logger;

    // 使用 api.runtime.config.current() 获取当前配置
    var getPluginConfig = function () {
      try {
        var runtimeConfig = api.runtime.config.current();
        console.log("[tomzang_plungin] [config_debug] runtimeConfig keys:", Object.keys(runtimeConfig || {}));
        console.log("[tomzang_plungin] [config_debug] plugins.entries keys:", Object.keys(runtimeConfig?.plugins?.entries || {}));
        var pluginConfig = runtimeConfig.plugins.entries[plugin.id]?.config || {};
        console.log("[tomzang_plungin] [config_debug] pluginConfig:", pluginConfig);
        return pluginConfig;
      } catch (e) {
        console.log("[tomzang_plungin] [config_debug] Error reading config:", e);
        return {};
      }
    };
    var config = resolveConfig(getPluginConfig());

    // 更新全局配置
    globalConfig = config;
    debugMode = config.debug;

    // 强制输出初始化日志
    console.log("[tomzang_plungin] Plugin registered with config:", {
      firewallUrl: config.firewallUrl,
      hasAuthKey: !!config.authKey,
      debug: config.debug,
      interceptorInstalled: interceptorInstalled
    });

    // 检查必要配置
    var missingFields = validateConfig(config);
    if (missingFields.length > 0) {
      console.log("[tomzang_plungin] ERROR: Missing required config:", missingFields);
      console.log("[tomzang_plungin] Firewall checks will be disabled. Please configure:", missingFields.join(", "));
      // 即使配置缺失，也注册钩子用于日志
      api.on("before_prompt_build", async function (event, ctx) {
        console.log("[tomzang_plungin] [hook] before_prompt_build agentId=" + ctx.agentId);
      });
      api.on("session_start", async function (event, ctx) {
        console.log("[tomzang_plungin] [hook] session_start agentId=" + ctx.agentId);
      });
      api.on("session_end", async function (event, ctx) {
        console.log("[tomzang_plungin] [hook] session_end agentId=" + ctx.agentId);
      });
      return;
    }

    console.log("[tomzang_plungin] Configuration validated successfully");
    console.log("[tomzang_plungin] Fetch interceptor status:", interceptorInstalled ? "ACTIVE" : "INACTIVE");

    // ─── 生命周期钩子（日志记录） ───
    api.on("before_prompt_build", async function (event, ctx) {
      console.log("[tomzang_plungin] [hook] before_prompt_build agentId=" + ctx.agentId);
    });

    api.on("before_agent_start", async function (event, ctx) {
      console.log("[tomzang_plungin] [hook] before_agent_start agentId=" + ctx.agentId);
    });

    api.on("session_start", async function (event, ctx) {
      console.log("[tomzang_plungin] [hook] session_start agentId=" + ctx.agentId);
    });

    api.on("session_end", async function (event, ctx) {
      console.log("[tomzang_plungin] [hook] session_end agentId=" + ctx.agentId);
    });

    // ─── 工具调用钩子 ───
    api.on("before_tool_call", async function (event, ctx) {
      console.log("[tomzang_plungin] [tool] before_call toolName=" + ctx.toolName);

      // 工具调用防火墙检查（默认启用）
      // 默认放行浏览器搜索和飞书 cli
      const allowedTools = ["web_search", "lark-cli"];
      if (allowedTools.includes(event.toolName)) {
        logDebug("tool", "approval_skipped_whitelist", { toolName: ctx.toolName });
        return;
      }

      // ─── skill 正文审计（互斥：命中 skill 则不走 tool_call 审计）───
      // skill 正文不经 HTTP 流转（纯本地 fs 读取），只能在此时主动读取文件后送审
      var skillFilePath = extractSkillFilePath(event);
      if (skillFilePath) {
        var skillContent = readSkillContent(skillFilePath);
        if (skillContent) {
          logDebug("skill", "firewall_skill_check", {
            toolName: event.toolName,
            filePath: skillFilePath,
            contentPreview: skillContent.slice(0, 500)
          });
          var skillFwResult = await callFirewallApi(
            globalOriginalFetch,
            globalConfig,
            skillContent,        // skill 正文 → content.prompt
            "",
            "session-openclaw",
            "input",
            "skill"              // source 字段
          );
          logDebug("skill", "firewall_skill_check_result", {
            toolName: event.toolName,
            filePath: skillFilePath,
            action: skillFwResult.action,
            riskLevel: skillFwResult.riskLevel,
            violationReason: skillFwResult.violationReason
          });
          // 返回值处理逻辑与下方 tool_call 完全一致
          if (skillFwResult.action === "block") {
            var skillBlockMsg = buildBlockMessageFromHitRules(skillFwResult.hitRules);
            logInfo("skill", "skill_blocked", {
              filePath: skillFilePath,
              action: skillFwResult.action,
              violationReason: skillFwResult.violationReason,
              riskLevel: skillFwResult.riskLevel
            });
            return { block: true, blockReason: skillBlockMsg };
          }
          if (!skillFwResult.action || skillFwResult.action === "pass") {
            logDebug("skill", "skill_passed", {
              filePath: skillFilePath,
              action: skillFwResult.action || "(empty)"
            });
            return; // 放行
          }
          // action 为 review/warn 等 → 二次确认（逻辑同 tool_call）
          var skillReason = "读取 skill: " + skillFilePath;
          if (skillFwResult.violationReason) {
            skillReason += "\n\n风险提示: " + skillFwResult.violationReason;
          }
          if (skillReason.length > 256) skillReason = skillReason.slice(0, 253) + "...";
          logDebug("skill", "requesting_approval", {
            filePath: skillFilePath,
            action: skillFwResult.action
          });
          return {
            requireApproval: {
              title: "Skill 二次确认",
              description: skillReason,
              severity: "medium",
              timeoutMs: 60_000,
              timeoutBehavior: "deny"
            }
          };
        }
        // 读不到正文 → fail-open，落到下方 tool_call 审计
      }

      // 通过防火墙 API 判断工具调用是否需要拦截
      var paramsText = "";
      if (event.params) {
        paramsText = typeof event.params === "string" ? event.params : JSON.stringify(event.params);
      }

      logDebug("tool", "firewall_tool_guard_check", {
        toolName: ctx.toolName,
        hasParams: !!paramsText,
        paramsPreview: paramsText ? paramsText.slice(0, 500) : ""
      });

      // 调用防火墙 API 验证工具调用
      var fwCheckResult = await callFirewallApi(
        globalOriginalFetch,
        globalConfig,
        paramsText,
        "",
        "session-openclaw",
        "input",
        "tool_call"
      );

      logDebug("tool", "firewall_tool_guard_check_result", {
        toolName: ctx.toolName,
        action: fwCheckResult.action,
        riskLevel: fwCheckResult.riskLevel,
        violationReason: fwCheckResult.violationReason
      });

      // 根据 action 判断：block 直接终止，pass 直接放行，其他需要二次确认
      if (fwCheckResult.action === "block") {
        var blockMsg = buildBlockMessageFromHitRules(fwCheckResult.hitRules);
        logInfo("tool", "call_blocked", {
          toolName: ctx.toolName,
          action: fwCheckResult.action,
          violationReason: fwCheckResult.violationReason,
          riskLevel: fwCheckResult.riskLevel
        });
        // 返回 block: true 阻止工具执行
        return {
          block: true,
          blockReason: blockMsg
        };
      }

      // action 为 pass 或空字符串/未定义时，直接放行，不需要用户审批
      // 空字符串通常表示防火墙资产关闭，默认放行
      if (!fwCheckResult.action || fwCheckResult.action === "pass") {
        logDebug("tool", "call_passed", {
          toolName: ctx.toolName,
          action: fwCheckResult.action || "(empty)"
        });
        return; // 放行，继续执行工具
      }

      // action 为其他值（如 review、warn 等），需要用户二次确认
      var reason = "执行工具: " + ctx.toolName;
      if (paramsText) {
        // 截断参数预览到100字符，确保总长度不超过256
        var paramsPreview = paramsText.slice(0, 100);
        reason = reason + "\n参数: " + paramsPreview;
        if (paramsText.length > 100) reason = reason + "...";
      }
      // 添加风险提示
      if (fwCheckResult.violationReason) {
        reason = reason + "\n\n风险提示: " + fwCheckResult.violationReason;
      }
      // 确保最终描述不超过256字符
      if (reason.length > 256) {
        reason = reason.slice(0, 253) + "...";
      }
      logDebug("tool", "requesting_approval", {
        toolName: ctx.toolName,
        action: fwCheckResult.action,
        reason: reason
      });
      // 使用 ctx.requireApproval() 自动选择消息渠道
      return {
        requireApproval: {
          title: "二次确认",
          description: reason,
          severity: "medium",
          timeoutMs: 60_000,
          timeoutBehavior: "deny"
        }
      };
    });

    api.on("after_tool_call", async function (ctx) {
      logDebug("tool", "after_call", {
        agentId: ctx.agentId,
        sessionKey: ctx.sessionKey,
        sessionId: ctx.sessionId,
        runId: ctx.runId,
        toolName: ctx.toolName,
        toolCallId: ctx.toolCallId,
        result: ctx.result,
        error: ctx.error,
        durationMs: ctx.durationMs
      });
    });

    logDebug("init", "hooks_registered", {});
  }
};

// ─── 全局拦截器状态 ───
// 这些变量在模块加载时初始化，确保 fetch 包装在 provider 初始化之前完成
var globalOriginalFetch = null;
var globalConfig = {
  firewallUrl: "",
  authKey: "",
  blockMessage: DEFAULT_BLOCK_MESSAGE,
  debug: false,  // 默认关闭 debug
  timeout: DEFAULT_TIMEOUT_MS  // 默认 3 秒超时
};
var globalApi = null;  // 保存 api 实例用于访问配置
var interceptorInstalled = false;
var fetchCallId = 0;

// ─── 全局 fetch 包装函数 ───
// 这个函数在模块加载时立即调用，确保在 provider 初始化之前完成包装
function installGlobalFetchInterceptor() {
  if (interceptorInstalled) {
    console.log("[tomzang_plungin] Global fetch interceptor already installed");
    return;
  }

  if (!globalThis.fetch) {
    console.log("[tomzang_plungin] globalThis.fetch not available");
    return;
  }

  // 保存原始 fetch
  if (!globalThis[ORIGINAL_FETCH_KEY]) {
    globalThis[ORIGINAL_FETCH_KEY] = globalThis.fetch;
  }
  globalOriginalFetch = globalThis[ORIGINAL_FETCH_KEY];

  var wrappedFetch = (async function wrappedFetch2(input, init) {
    var callId = ++fetchCallId;
    var url = getUrlFromFetchArgs(input);
    var method = getMethodFromFetchArgs(input, init);
    var reqBodyText = await getRequestBodyText(input, init);

    // ─── 双重 LLM 检测：provider 匹配 + 智能识别 ───
    var providerUrls = [];
    try {
      if (globalApi && globalApi.config) {
        providerUrls = getProviderBaseUrls(globalApi.config);
      }
    } catch (e) {
      // 配置获取失败，继续处理
    }
    var matchedProvider = matchProviderByUrl(url, providerUrls);

    // 如果 provider 没有匹配到，尝试通过请求特征智能识别
    if (!matchedProvider) {
      if (detectLlmRequest(url, method, reqBodyText)) {
        // 构造一个虚拟 provider 标识
        matchedProvider = { providerId: "_auto_detected", baseUrl: url };
        if (globalConfig.debug) {
          console.log("[tomzang_plungin] [llm] [auto_detected] callId=" + callId + " url=" + url);
        }
      }
    }

    // 非 LLM 请求直接放行
    if (!matchedProvider) {
      return globalOriginalFetch(input, init);
    }

    var reqHeaders = getMergedRequestHeaders(input, init);

    if (globalConfig.debug) {
      console.log("[tomzang_plungin] [llm] [request] callId=" + callId + " url=" + url + " provider=" + matchedProvider.providerId);
    }

    // ─── 输入防火墙内容检测 ───
    var userPrompt = extractLastUserPrompt(reqBodyText);

    if (globalConfig.debug) {
      console.log("[tomzang_plungin] [llm] [extracted_user_prompt] callId=" + callId + " promptLength=" + (userPrompt ? userPrompt.length : 0));
      if (userPrompt) {
        console.log("[tomzang_plungin] [llm] [user_prompt_preview] callId=" + callId + " preview=" + userPrompt.slice(0, 200));
      }
    }

    // 记录是否跳过防火墙检测
    var skipReason = null;
    if (!userPrompt) {
      skipReason = "user_prompt_empty";
    } else if (shouldSkipFirewall(userPrompt)) {
      skipReason = "should_skip_firewall_true";
    }

    if (globalConfig.debug && skipReason) {
      console.log("[tomzang_plungin] [llm] [firewall_skipped] callId=" + callId + " reason=" + skipReason);
    }

    if (userPrompt && !shouldSkipFirewall(userPrompt)) {
      console.log("[tomzang_plungin] [llm] [firewall_check_start] callId=" + callId);
      try {
        var fwResult = await callFirewallApi(globalOriginalFetch, globalConfig, userPrompt, "", "session-openclaw", "input");
        console.log("[tomzang_plungin] [llm] [firewall_check_result] callId=" + callId + " action=" + fwResult.action + " result=" + fwResult.result);
        if (fwResult.result === "block") {
          var wantsSse = guessRequestWantsSse(url, reqHeaders, reqBodyText);
          console.log("[tomzang_plungin] [llm] [request_blocked] callId=" + callId);
          var blockMsg = buildBlockMessageFromHitRules(fwResult.hitRules);
          return makeBlockedResponseForRequest(wantsSse, blockMsg);
        }
      } catch (e) {
        console.log("[tomzang_plungin] [firewall] [error] callId=" + callId + " error=" + String(e && e.message || e));
      }
    }

    // ─── 放行请求，获取响应 ───
    var resp;
    var fetchStartTime = Date.now();
    try {
      resp = await globalOriginalFetch(input, init);
    } catch (e) {
      console.log("[tomzang_plungin] [fetch] [error] callId=" + callId + " error=" + String(e && e.message || e));
      throw e;
    }

    var fetchDurationMs = Date.now() - fetchStartTime;

    if (globalConfig.debug) {
      console.log("[tomzang_plungin] [llm] [response_received] callId=" + callId + " status=" + resp.status);
    }

    // ─── 输出防火墙内容检测 ───
    if (resp.ok && userPrompt && !shouldSkipFirewall(userPrompt)) {
      try {
        var auditedResp = await auditOutputResponse(
          globalOriginalFetch,
          globalConfig,
          resp,
          userPrompt,
          "session-openclaw",
          callId,
          url,
          matchedProvider
        );
        var fwAction = auditedResp.headers.get("x-firewall-action") || "passed";
        if (globalConfig.debug) {
          console.log("[tomzang_plungin] [llm] [response_audited] callId=" + callId + " action=" + fwAction);
        }
        return auditedResp;
      } catch (auditError) {
        console.log("[tomzang_plungin] [firewall] [output_audit_error] callId=" + callId);
      }
    }

    if (globalConfig.debug) {
      console.log("[tomzang_plungin] [llm] [response_passed] callId=" + callId);
    }

    return resp;
  });

  // 继承原始 fetch 的属性
  Object.assign(wrappedFetch, globalOriginalFetch);
  globalThis.fetch = wrappedFetch;
  globalThis[FETCH_WRAPPED_KEY] = true;

  // 🔧 尝试拦截 undici fetch（OpenClaw 使用的 HTTP 客户端）
  try {
    // 多策略加载 undici，按优先级尝试
    var undici = null;
    var loadedFrom = null;
    var path = require('path');

    // 策略1: 官方推荐方式 - 直接通过 require('undici')
    try {
      undici = require('undici');
      if (undici && undici.fetch) {
        loadedFrom = 'official (require undici)';
        console.log("[tomzang_plungin] Loaded undici via official require('undici')");
      }
    } catch (e) {
      // 官方方式失败，继续尝试其他策略
    }

    // 策略2: 动态解析 - 尝试从 openclaw 的 node_modules 解析
    if (!undici) {
      try {
        var openclawPath = require.resolve('openclaw');
        var openclawDir = path.dirname(openclawPath);
        var undiciViaOpenclaw = path.join(openclawDir, 'node_modules', 'undici');
        undici = require(undiciViaOpenclaw);
        if (undici && undici.fetch) {
          loadedFrom = 'dynamic (via openclaw node_modules): ' + undiciViaOpenclaw;
          console.log("[tomzang_plungin] Loaded undici from:", loadedFrom);
        }
      } catch (e) {
        // openclaw 解析失败，继续尝试
      }
    }

    // 策略3: 常见系统路径 - 按不同系统和安装方式尝试
    if (!undici) {
      var commonPaths = [
        // Homebrew (Apple Silicon)
        '/opt/homebrew/lib/node_modules/openclaw/node_modules/undici',
        // Homebrew (Intel)
        '/usr/local/lib/node_modules/openclaw/node_modules/undici',
        // npm 全局安装
        '/usr/local/lib/node_modules/openclaw/node_modules/undici',
        // npm 用户级安装
        path.join(require('os').homedir(), '.npm-global/lib/node_modules/openclaw/node_modules/undici'),
        path.join(require('os').homedir(), '.npm-global/node_modules/openclaw/node_modules/undici'),
        // nvm/nfv 安装
        path.join(require('os').homedir(), '.nvm/versions/node/v18/lib/node_modules/openclaw/node_modules/undici'),
        path.join(require('os').homedir(), '.nvm/versions/node/v20/lib/node_modules/openclaw/node_modules/undici'),
        path.join(require('os').homedir(), '.nvm/versions/node/v22/lib/node_modules/openclaw/node_modules/undici'),
        // fnm
        path.join(require('os').homedir(), '.fnm/current/lib/node_modules/openclaw/node_modules/undici'),
        // Windows (如果在 Windows 环境下)
        process.env.APPDATA && path.join(process.env.APPDATA, 'npm/node_modules/openclaw/node_modules/undici'),
        process.env.APPDATA && path.join(process.env.USERPROFILE || '', 'AppData/Roaming/npm/node_modules/openclaw/node_modules/undici'),
        // Linux 系统级
        '/usr/lib/node_modules/openclaw/node_modules/undici',
        '/usr/lib64/node_modules/openclaw/node_modules/undici'
      ].filter(function(p) { return p != null; }); // 过滤掉 null 路径

      for (var i = 0; i < commonPaths.length; i++) {
        try {
          undici = require(commonPaths[i]);
          if (undici && undici.fetch) {
            loadedFrom = 'common path: ' + commonPaths[i];
            console.log("[tomzang_plungin] Loaded undici from:", loadedFrom);
            break;
          }
        } catch (e) {
          // 继续尝试下一个路径
        }
      }
    }

    // 策略4: 用户配置路径 - 从 config 读取用户手动指定的路径
    if (!undici && globalConfig && globalConfig.undiciPath) {
      try {
        undici = require(globalConfig.undiciPath);
        if (undici && undici.fetch) {
          loadedFrom = 'user config: ' + globalConfig.undiciPath;
          console.log("[tomzang_plungin] Loaded undici from:", loadedFrom);
        }
      } catch (e) {
        console.log("[tomzang_plungin] Failed to load undici from user config path:", globalConfig.undiciPath, e.message);
      }
    }

    // 如果所有策略都失败，输出警告
    if (!undici || !undici.fetch) {
      console.log("[tomzang_plungin] WARNING: Could not load undici module. Only globalThis.fetch will be intercepted.");
      console.log("[tomzang_plungin] To enable undici interception, either:");
      console.log("[tomzang_plungin]   1. Ensure undici is available via require('undici')");
      console.log("[tomzang_plungin]   2. Install undici globally: npm install -g undici");
      console.log("[tomzang_plungin]   3. Set undiciPath in config to specify the path manually");
    }

    if (undici && undici.fetch) {
      // 保存原始 undici fetch
      var undiciOriginalFetchKey = '__tomzang_plungin_original_undici_fetch__';
      if (!globalThis[undiciOriginalFetchKey]) {
        globalThis[undiciOriginalFetchKey] = undici.fetch;
      }
      var undiciOriginalFetch = globalThis[undiciOriginalFetchKey];

      console.log("[tomzang_plungin] Installing undici fetch interceptor");

      // 包装 undici fetch
      var undiciFetchCallId = 0;
      var wrappedUndiciFetch = (async function wrappedUndiciFetch2(input, init) {
        var callId = ++undiciFetchCallId;
        var url = getUrlFromFetchArgs(input);
        var method = getMethodFromFetchArgs(input, init);
        var reqBodyText = await getRequestBodyText(input, init);

        // ─── 双重 LLM 检测：provider 匹配 + 智能识别 ───
        var providerUrls = [];
        try {
          if (globalApi && globalApi.config) {
            providerUrls = getProviderBaseUrls(globalApi.config);
          }
        } catch (e) {
          // 配置获取失败，继续处理
        }
        var matchedProvider = matchProviderByUrl(url, providerUrls);

        // 如果 provider 没有匹配到，尝试通过请求特征智能识别
        if (!matchedProvider) {
          if (detectLlmRequest(url, method, reqBodyText)) {
            matchedProvider = { providerId: "_auto_detected_undici", baseUrl: url };
            if (globalConfig.debug) {
              console.log("[tomzang_plungin] [undici] [auto_detected] callId=" + callId + " url=" + url);
            }
          }
        }

        // 非 LLM 请求直接放行
        if (!matchedProvider) {
          return undiciOriginalFetch(input, init);
        }

        var reqHeaders = getMergedRequestHeaders(input, init);

        if (globalConfig.debug) {
          console.log("[tomzang_plungin] [undici] [request] callId=" + callId + " url=" + url + " provider=" + matchedProvider.providerId);
        }

        // ─── 输入防火墙内容检测 ───
        var userPrompt = extractLastUserPrompt(reqBodyText);

        if (globalConfig.debug) {
          console.log("[tomzang_plungin] [undici] [extracted_prompt] callId=" + callId + " promptLength=" + (userPrompt ? userPrompt.length : 0));
          if (userPrompt) {
            console.log("[tomzang_plungin] [undici] [prompt_preview] callId=" + callId + " preview=" + userPrompt.slice(0, 200));
          }
        }

        // 记录是否跳过防火墙检测
        var skipReason = null;
        if (!userPrompt) {
          skipReason = "user_prompt_empty";
        } else if (shouldSkipFirewall(userPrompt)) {
          skipReason = "should_skip_firewall_true";
        }

        if (globalConfig.debug && skipReason) {
          console.log("[tomzang_plungin] [undici] [firewall_skipped] callId=" + callId + " reason=" + skipReason);
        }

        if (userPrompt && !shouldSkipFirewall(userPrompt)) {
          console.log("[tomzang_plungin] [undici] [firewall_check_start] callId=" + callId);
          try {
            var fwResult = await callFirewallApi(undiciOriginalFetch, globalConfig, userPrompt, "", "session-openclaw", "input");
            console.log("[tomzang_plungin] [undici] [firewall_check_result] callId=" + callId + " action=" + fwResult.action + " result=" + fwResult.result);
            if (fwResult.result === "block") {
              var wantsSse = guessRequestWantsSse(url, reqHeaders, reqBodyText);
              console.log("[tomzang_plungin] [undici] [blocked] callId=" + callId);
              var blockMsg = buildBlockMessageFromHitRules(fwResult.hitRules);
              return makeBlockedResponseForRequest(wantsSse, blockMsg);
            }
          } catch (e) {
            console.log("[tomzang_plungin] [undici] [firewall_error] callId=" + callId + " error=" + String(e && e.message || e));
          }
        }

        // ─── 放行请求，获取响应 ───
        var resp;
        var fetchStartTime = Date.now();
        try {
          resp = await undiciOriginalFetch(input, init);
        } catch (e) {
          console.log("[tomzang_plungin] [undici] [fetch_error] callId=" + callId + " error=" + String(e && e.message || e));
          throw e;
        }

        if (globalConfig.debug) {
          console.log("[tomzang_plungin] [undici] [response_received] callId=" + callId + " status=" + resp.status);
        }

        return resp;
      });

      // 替换 undici.fetch
      undici.fetch = wrappedUndiciFetch;
      console.log("[tomzang_plungin] Undici fetch interceptor installed successfully");
    } else {
      console.log("[tomzang_plungin] Undici not available in any expected path");
    }
  } catch (e) {
    console.log("[tomzang_plungin] Undici interception failed:", String(e && e.message || e));
  }

  interceptorInstalled = true;

  console.log("[tomzang_plungin] Global fetch interceptor installed at module load time");
}

// ─── 立即安装拦截器（模块加载时执行） ───
installGlobalFetchInterceptor();

// 导出插件：如果 definePluginEntry 可用则使用它包装，否则直接导出
var pluginEntry = typeof definePluginEntry !== "undefined"
  ? definePluginEntry(plugin)
  : plugin;

// 调试日志：验证模块是否被加载
console.log("[tomzang_plungin] Module loaded, pluginEntry:", pluginEntry ? (typeof definePluginEntry !== "undefined" ? "wrapped with definePluginEntry" : "direct export") : "FAILED");

module.exports = pluginEntry;

