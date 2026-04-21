// ─── 配置解析 ───

var DEFAULT_BLOCK_MESSAGE = "当前请求包含敏感关键字，已被安全组件拦截";
var FIREWALL_API_PATH = "/api/firewall/openclaw/validate";

function buildFullFirewallUrl(host) {
  if (!host) return "";
  var base = host.trim().replace(/\/+$/, "");
  return base + FIREWALL_API_PATH;
}

function resolveConfig(rawConfig) {
  var cfg = rawConfig ?? {};
  return {
    firewallUrl: buildFullFirewallUrl(cfg.firewallUrl),
    authKey: typeof cfg.authKey === "string" && cfg.authKey.trim() !== ""
      ? cfg.authKey.trim()
      : "",
    blockMessage: typeof cfg.blockMessage === "string" && cfg.blockMessage.trim() !== ""
      ? cfg.blockMessage.trim()
      : DEFAULT_BLOCK_MESSAGE,
    debug: typeof cfg.debug === "boolean" ? cfg.debug : false
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

async function callFirewallApi(fetchFn, config, prompt, response, sessionId, stage) {
  var callId = ++firewallCallId;
  var traceId = "trace-" + Date.now() + "-" + callId;
  var requestBody = {
    auth_key: config.authKey,
    session_id: sessionId || "session-openclaw",
    trace_id: traceId,
    stage: stage || "input",
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
    var resp = await fetchFn(config.firewallUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(requestBody)
    });

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
    logError("firewall", "api_call_failed", { callId: callId, error: String(e && e.message || e) });
    // 接口异常时放行，避免阻断正常请求
    return { action: "pass", error: String(e && e.message || e) };
  }
}

// ─── 用户输入提取 ───
function extractLastUserPrompt(reqBodyText) {
  if (!reqBodyText) return "";
  try {
    var obj = JSON.parse(reqBodyText);
    if (obj && Array.isArray(obj.messages)) {
      for (var i = obj.messages.length - 1; i >= 0; i--) {
        var msg = obj.messages[i];
        if (msg.role === "user" && msg.content) {
          var raw = typeof msg.content === "string"
            ? msg.content
            : extractTextFromContentArray(msg.content);
          return stripMetadataPrefix(raw);
        }
      }
      return "";
    }
    return reqBodyText.slice(0, 2000);
  } catch (e) {
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

/**
 * 去除系统前缀 / 元数据块，提取末尾真正的用户输入
 *
 * 已知的噪声结构（按出现顺序）：
 *   1. System: [...] Feishu[...] DM | ...\n\n
 *   2. Conversation info (untrusted metadata):\n```json\n{...}\n```\n\n
 *   3. Sender (untrusted metadata):\n```json\n{...}\n```\n\n
 *
 * 策略：找到最后一个 ``` 代码块结束标记后面的内容；
 *       再去掉可能的时间戳行前缀 [Mon 2026-04-20 18:08 GMT+8]
 */
function stripMetadataPrefix(text) {
  if (!text || typeof text !== "string") return text || "";

  // 找最后一个 ``` 标记的位置（元数据代码块的结束）
  var lastFence = text.lastIndexOf("```");
  if (lastFence !== -1) {
    // 取 ``` 之后的内容
    var afterFence = text.substring(lastFence + 3);
    // 去掉开头的空白换行
    afterFence = afterFence.replace(/^\s*\n*/, "");
    if (afterFence.length > 0) {
      return stripTimestampPrefix(afterFence).trim();
    }
    // 如果 ``` 后面没内容，回退到原文
  }

  // 没有 ``` 代码块的情况：尝试按 \n\n 分割，取最后一段
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


// // 从OpenAI格式的请求体中提取最后一条用户输入内容
// function extractLastUserPrompt(reqBodyText) {
//   if (!reqBodyText) return "";
//   try {
//     var obj = JSON.parse(reqBodyText);
//     if (obj && Array.isArray(obj.messages)) {
//       for (var i = obj.messages.length - 1; i >= 0; i--) {
//         var msg = obj.messages[i];
//         if (msg.role === "user" && msg.content) {
//           return typeof msg.content === "string" ? msg.content : JSON.stringify(msg.content);
//         }
//       }
//       return "";
//     }
//     return reqBodyText.slice(0, 2000);
//   } catch (e) {
//     return reqBodyText.slice(0, 2000);
//   }
// }

// 判断是否为内置命令（以 / 开头的指令，如 /reset, /help, /clear 等）
function isBuiltInCommand(text) {
  if (!text || typeof text !== "string") return false;
  var trimmed = text.trim();
  return trimmed.length > 1 && trimmed[0] === "/";
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

// 从防火墙返回的 hit_rules 中提取 rule_name 和 description，生成 markdown 表格
function buildBlockMessageFromHitRules(hitRules) {
  if (!Array.isArray(hitRules) || hitRules.length === 0) {
    return DEFAULT_BLOCK_MESSAGE;
  }
  var lines = [
    "**当前请求已被安全组件拦截，命中以下规则：**",
    "| rule_code | rule_name | description |",
    "| --- | --- | --- |"
  ];
  for (var i = 0; i < hitRules.length; i++) {
    var rule = hitRules[i];
    var code = rule.rule_code || "-";
    var name = rule.rule_name || "-";
    var desc = rule.description || "-";
    lines.push("| " + code + " | " + name + " | " + desc + " |");
  }
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
      debug: { type: "boolean", default: false, description: "Enable debug mode" }
    },
    required: ["firewallUrl", "authKey"]
  },

  register: function (api) {
    var config = resolveConfig(api.pluginConfig);
    currentLogger = api.logger;
    debugMode = config.debug;

    // 检查必要配置
    var missingFields = validateConfig(config);
    if (missingFields.length > 0) {
      logError("init", "missing_required_config", {
        missing: missingFields,
        message: "插件缺少必要配置项: " + missingFields.join(", ") + "。请在 openclaw.json 的 plugins.entries.tomzang_plungin.config 中配置这些字段。"
      });
      // 仍然注册生命周期钩子（仅日志），但不注册防火墙拦截
      api.on("before_prompt_build", async function (event, ctx) {
        logDebug("hook", "before_prompt_build", { agentId: ctx.agentId, sessionKey: ctx.sessionKey });
      });
      api.on("session_start", async function (event, ctx) {
        logDebug("hook", "session_start", { agentId: ctx.agentId, sessionId: event.sessionId });
      });
      api.on("session_end", async function (event, ctx) {
        logDebug("hook", "session_end", { agentId: ctx.agentId, sessionId: event.sessionId });
      });
      return;
    }

    logDebug("init", "register", {
      firewallUrl: config.firewallUrl,
      blockMessage: config.blockMessage,
      debug: config.debug
    });

    // 保存原始 fetch
    if (!globalThis[ORIGINAL_FETCH_KEY] && globalThis.fetch) {
      globalThis[ORIGINAL_FETCH_KEY] = globalThis.fetch;
    }
    var originalFetch = globalThis[ORIGINAL_FETCH_KEY];
    if (!originalFetch) {
      logError("init", "fetch_unavailable", { message: "globalThis.fetch is not available" });
      return;
    }

    // 防止重复包装
    var alreadyWrapped = globalThis[FETCH_WRAPPED_KEY];
    if (alreadyWrapped) {
      logDebug("init", "skip_double_wrap", {});
    } else {
      var fetchCallId = 0;
      var wrappedFetch = (async function wrappedFetch2(input, init) {
        var callId = ++fetchCallId;
        var url = getUrlFromFetchArgs(input);
        var method = getMethodFromFetchArgs(input, init);
        var reqBodyText = await getRequestBodyText(input, init);

        // ─── 双重 LLM 检测：provider 匹配 + 智能识别 ───
        var providerUrls = getProviderBaseUrls(api.config);
        var matchedProvider = matchProviderByUrl(url, providerUrls);

        // 如果 provider 没有匹配到，尝试通过请求特征智能识别
        if (!matchedProvider) {
          if (detectLlmRequest(url, method, reqBodyText)) {
            // 构造一个虚拟 provider 标识，用于日志和后续处理
            matchedProvider = { providerId: "_auto_detected", baseUrl: url };
            logDebug("llm", "auto_detected", {
              callId: callId,
              url: url,
              method: method,
              message: "LLM request detected by URL/body heuristics (not in models.providers)"
            });
          }
        }

        // 非 LLM 请求直接放行
        if (!matchedProvider) {
          return originalFetch(input, init);
        }

        var reqHeaders = getMergedRequestHeaders(input, init);

        logDebug("llm", "request", {
          callId: callId,
          url: url,
          provider: matchedProvider.providerId,
          method: method,
          bodyPreview: reqBodyText ? reqBodyText.slice(0, BODY_PREVIEW_MAX_LENGTH) : ""
        });

        // ─── 输入防火墙内容检测 ───
        var userPrompt = extractLastUserPrompt(reqBodyText);
        if (userPrompt && !shouldSkipFirewall(userPrompt)) {
          var freshConfig = resolveConfig(api.pluginConfig);
          var fwResult = await callFirewallApi(originalFetch, freshConfig, userPrompt, "", "session-openclaw", "input");
          if (fwResult.result === "block") {
            var wantsSse = guessRequestWantsSse(url, reqHeaders, reqBodyText);
            logInfo("llm", "request_blocked", {
              callId: callId,
              url: url,
              provider: matchedProvider.providerId,
              result: fwResult.result,
              action: fwResult.action,
              violationReason: fwResult.violationReason,
              riskLevel: fwResult.riskLevel,
              streaming: wantsSse
            });
            var blockMsg = buildBlockMessageFromHitRules(fwResult.hitRules);
            return makeBlockedResponseForRequest(wantsSse, blockMsg);
          }
        }

        // ─── 放行请求，获取响应 ───
        var resp;
        var fetchStartTime = Date.now();
        try {
          resp = await originalFetch(input, init);
        } catch (e) {
          logError("fetch", "error", {
            callId: callId,
            url: url,
            provider: matchedProvider.providerId,
            error: String(e && e.message || e),
            durationMs: Date.now() - fetchStartTime
          });
          throw e;
        }

        var fetchDurationMs = Date.now() - fetchStartTime;

        logDebug("llm", "response_received", {
          callId: callId,
          url: url,
          provider: matchedProvider.providerId,
          status: resp.status,
          durationMs: fetchDurationMs
        });

        // ─── 输出防火墙内容检测 ───
        // 仅对成功的 LLM 响应进行输出审计（非 2xx 状态码直接放行）
        if (resp.ok && userPrompt && !shouldSkipFirewall(userPrompt)) {
          var outputConfig = resolveConfig(api.pluginConfig);
          try {
            var auditedResp = await auditOutputResponse(
              originalFetch,
              outputConfig,
              resp,
              userPrompt,
              "session-openclaw",
              callId,
              url,
              matchedProvider
            );

            var fwAction = auditedResp.headers.get("x-firewall-action") || "passed";
            logDebug("llm", "response_audited", {
              callId: callId,
              url: url,
              provider: matchedProvider.providerId,
              firewallAction: fwAction,
              totalDurationMs: Date.now() - fetchStartTime
            });

            return auditedResp;
          } catch (auditError) {
            logError("firewall", "output_audit_error", {
              callId: callId,
              error: String(auditError && auditError.message || auditError)
            });
            // 输出审计异常时放行（注意：resp.body 可能已被消费，此时无法恢复）
            // 正常情况下异常应在 auditOutputResponse 内部已处理并返回重建的响应
            return resp;
          }
        }

        logDebug("llm", "response_passed", {
          callId: callId,
          url: url,
          provider: matchedProvider.providerId,
          status: resp.status,
          durationMs: fetchDurationMs
        });

        return resp;
      });

      // 继承原始 fetch 的属性
      Object.assign(wrappedFetch, originalFetch);
      globalThis.fetch = wrappedFetch;
      globalThis[FETCH_WRAPPED_KEY] = true;
      logDebug("init", "fetch_interceptor_installed", {});
    }

    // ─── 生命周期钩子（日志记录） ───
    api.on("before_prompt_build", async function (event, ctx) {
      logDebug("hook", "before_prompt_build", {
        agentId: ctx.agentId,
        sessionKey: ctx.sessionKey,
        messagesCount: Array.isArray(event.messages) ? event.messages.length : 0
      });
    });

    api.on("before_agent_start", async function (event, ctx) {
      logDebug("hook", "before_agent_start", {
        agentId: ctx.agentId,
        sessionKey: ctx.sessionKey
      });
    });

    api.on("session_start", async function (event, ctx) {
      logDebug("hook", "session_start", {
        agentId: ctx.agentId,
        sessionId: event.sessionId
      });
    });

    api.on("session_end", async function (event, ctx) {
      logDebug("hook", "session_end", {
        agentId: ctx.agentId,
        sessionId: event.sessionId
      });
    });

    logDebug("init", "hooks_registered", {});
  }
};

export default plugin;
