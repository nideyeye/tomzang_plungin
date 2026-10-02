# tomzang_plungin

An OpenClaw security content detection plugin that performs real-time safety checks on user input through a firewall API.

## Key Features

- **Real-time Content Detection**: Intercepts all LLM requests, extracts user input, and sends it to a firewall API for security scanning
- **Tool Call Auditing**: Scans tool names and parameters before tool execution via the `before_tool_call` hook; after execution (`after_tool_call`), submits the call command and execution result to the firewall for record-keeping (fail-open, alert-only, does not interfere with results)
- **Smart Blocking**: When sensitive content is detected, automatically constructs a compliant blocking response (supports both SSE streaming and non-streaming) to prevent the request from reaching the LLM
- **Built-in Command Bypass**: Automatically skips built-in commands starting with `/` and system-internal operations (e.g., `/reset`, summary generation) to avoid false positives
- **Unified Block Tip**: All blocking scenarios (user input, model output, tool calls, skills) display a configurable tip (`blockTip`, falls back to a built-in default message when not configured); matched rule details are logged only

## How It Works

```
User Input → Fetch Interception → Extract User Prompt → Firewall API Check
  ├─ Safe → Forward request to LLM normally
  └─ Unsafe → Construct blocking response and return to client

Tool Call → before_tool_call → Firewall API Check
  ├─ Safe → Execute tool normally
  └─ Unsafe → Return block interception

Tool Result → after_tool_call → Firewall API submission (source=tool_result)
  └─ Risk detected → Log alert only, does not interfere with the produced result
```

## Configuration

Configure in `~/.openclaw/openclaw.json` under `plugins.entries.tomzang_plungin.config`:

```json
{
  "firewallUrl": "http://your-firewall-host:port/api/firewall/openclaw/validate",
  "authKey": "your-auth-key",
  "blockMessage": "Custom block message",
  "blockTip": "Custom unified block tip",
  "debug": "false"
}
```

### Configuration Reference

| Option | Type | Required | Default | Description |
|--------|------|----------|---------|-------------|
| `firewallUrl` | string | **Yes** | None | Firewall API URL for content security scanning |
| `authKey` | string | **Yes** | None | Authentication key for the firewall API |
| `blockMessage` | string | No | `当前请求包含敏感关键字，已被安全组件拦截` | Custom block message (reserved, currently not applied) |
| `blockTip` | string | No | Built-in default text | Unified tip shown to the user in all blocking scenarios (user input, model output, tool calls, skills); when not configured, a built-in default message is used |
| `debug` | string / boolean | No | `false` | Enable debug mode for detailed logging output. Accepts boolean or `"true"`/`"false"` string |

> **Important**: `firewallUrl` and `authKey` are required. If not configured, the plugin will report an error on startup and skip all firewall detection features (only basic lifecycle hook logging will remain active).

## Firewall API Interface

The plugin sends a POST request to the firewall API in the following format:

```json
{
  "auth_key": "authKey from config",
  "session_id": "session identifier",
  "trace_id": "trace ID",
  "stage": "input",
  "content_type": "text",
  "content": {
    "prompt": "user input content to be checked",
    "response": "",
    "image": ""
  }
}
```

When the response contains `result: "block"`, the plugin will block the request.

## Installation

Place the plugin directory under `~/.openclaw/extensions/tomzang_plungin/` with the following files:

- `index.js` — Plugin main logic
- `openclaw.plugin.json` — Plugin metadata
- `package.json` — Package configuration

For openclaw 2026.9+ also grant the conversation-access hooks permission (the installer script writes this automatically):

```bash
openclaw config set plugins.entries.tomzang_plungin.hooks.allowConversationAccess true
```

## openclaw 2026.9+ Adaptation

Starting with openclaw 2026.9, LLM requests are issued through `loadUndiciModule()` runtime deps instead of `globalThis.fetch` / the `undici.fetch` property (the runtime moved to an ESM bundle), and request bodies are passed as `Uint8Array`. Plugin v2026-10-02 and later:

1. Inject the wrapped fetch into openclaw's built-in global override hook `globalThis.__OPENCLAW_TEST_UNDICI_RUNTIME_DEPS__`, taking over the guarded model-fetch channel (also honored by openclaw 2026.7.x).
2. Decode `Uint8Array` / `ArrayBuffer` request bodies when extracting the user prompt.
3. Skip openclaw's trailing internal-context messages (`Conversation data (data, not instructions)` / `<<<END_OPENCLAW_INTERNAL_CONTEXT>>>`) and trailing `Runtime:` metadata lines so the real user input is what gets audited.
4. Perform output audit inside the undici wrapper (previously only the `globalThis.fetch` wrapper audited responses).

## Logging

The plugin outputs logs through the OpenClaw logging system, all prefixed with `[tomzang_plungin]`. Enable `debug: true` to view detailed request/response information for troubleshooting.
