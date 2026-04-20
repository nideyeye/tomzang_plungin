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

async function callFirewallApi(fetchFn, config, prompt, sessionId, stage) {
  var callId = ++firewallCallId;
  var traceId = "trace-" + Date.now() + "-" + callId;
  var requestBody = {
    auth_key: config.authKey,
    session_id: sessionId || "session-openclaw",
    trace_id: traceId,
    stage: stage || "input",
    content_type: "text",
    content: {
      prompt: prompt,
      response: "",
      image: ""
    }
  };

  logDebug("firewall", "api_request", {
    callId: callId,
    stage: stage,
    url: config.firewallUrl,
    requestBody: requestBody,
    promptPreview: prompt ? prompt.slice(0, 200) : ""
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
      logDebug("firewall", "api_response", {
        callId: callId,
        action: data.action,
        result: data.result,
        riskLevel: data.risk_level,
        violationReason: data.violation_reason,
        hitRules: data.hit_rules,
        durationMs: durationMs
      });
      return {
        action: data.action,
        result: data.result || "",
        riskLevel: data.risk_level || 0,
        violationReason: data.violation_reason || "",
        hitRules: data.hit_rules || []
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

// 从OpenAI格式的请求体中提取最后一条用户输入内容
function extractLastUserPrompt(reqBodyText) {
  if (!reqBodyText) return "";
  try {
    var obj = JSON.parse(reqBodyText);
    if (obj && Array.isArray(obj.messages)) {
      for (var i = obj.messages.length - 1; i >= 0; i--) {
        var msg = obj.messages[i];
        if (msg.role === "user" && msg.content) {
          return typeof msg.content === "string" ? msg.content : JSON.stringify(msg.content);
        }
      }
      return "";
    }
    return reqBodyText.slice(0, 2000);
  } catch (e) {
    return reqBodyText.slice(0, 2000);
  }
}

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

// ─── 插件主体 ───

var FETCH_WRAPPED_KEY = Symbol.for("tomzang_plungin.fetch-wrapped");
var ORIGINAL_FETCH_KEY = Symbol.for("tomzang_plungin.original-fetch");
var BODY_PREVIEW_MAX_LENGTH = 500;

var plugin = {
  id: "tomzang_plungin",
  name: "tomzang_plungin",
  description: "A security plugin that validates user input through a firewall API to detect and block sensitive content.",
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
        var providerUrls = getProviderBaseUrls(api.config);
        var matchedProvider = matchProviderByUrl(url, providerUrls);

        // 非 LLM 请求直接放行
        if (!matchedProvider) {
          return originalFetch(input, init);
        }

        var method = getMethodFromFetchArgs(input, init);
        var reqHeaders = getMergedRequestHeaders(input, init);
        var reqBodyText = await getRequestBodyText(input, init);

        logDebug("llm", "request", {
          callId: callId,
          url: url,
          provider: matchedProvider.providerId,
          method: method,
          bodyPreview: reqBodyText ? reqBodyText.slice(0, BODY_PREVIEW_MAX_LENGTH) : ""
        });

        // ─── 防火墙内容检测 ───
        var userPrompt = extractLastUserPrompt(reqBodyText);
        if (userPrompt && !shouldSkipFirewall(userPrompt)) {
          var freshConfig = resolveConfig(api.pluginConfig);
          var fwResult = await callFirewallApi(originalFetch, freshConfig, userPrompt, "session-openclaw", "input");
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

        // 放行请求，获取响应
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

        logDebug("llm", "response_passed", {
          callId: callId,
          url: url,
          provider: matchedProvider.providerId,
          status: resp.status,
          durationMs: Date.now() - fetchStartTime
        });

        return resp;
      });

      // 继承原始 fetch 的属性
      Object.assign(wrappedFetch, originalFetch);
      globalThis.fetch = wrappedFetch;
      globalThis[FETCH_WRAPPED_KEY] = true;
      logDebug("init", "fetch_interceptor_installed", {});
    }

    // ─── 工具调用审计：before_tool_call ───
    api.on("before_tool_call", async function (event, ctx) {
      try {
        // 跳过内置命令和系统内部操作
        if (shouldSkipFirewall(event.toolName)) return;
        var toolInput = event.toolName;
        if (event.params) {
          toolInput += " " + (typeof event.params === "string"
            ? event.params
            : JSON.stringify(event.params));
        }
        var fwResult = await callFirewallApi(originalFetch, resolveConfig(api.pluginConfig), toolInput, "session-openclaw", "input");
        if (fwResult.result === "block") {
          logInfo("tool_call", "request_blocked", {
            toolName: event.toolName,
            violationReason: fwResult.violationReason,
            riskLevel: fwResult.riskLevel,
            hitRules: (fwResult.hitRules || []).map(function (r) { return r.rule_code + ": " + r.description; })
          });
          var blockMsg = buildBlockMessageFromHitRules(fwResult.hitRules);
          return { block: true, blockReason: blockMsg };
        }
      } catch (e) {
        logWarn("tool_call", "request_check_failed", {
          toolName: event.toolName,
          error: String(e && e.message || e)
        });
      }
      return;
    });

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