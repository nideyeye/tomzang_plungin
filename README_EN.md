# tomzang_plungin

An OpenClaw security content detection plugin that performs real-time safety checks on user input through a firewall API.

## Key Features

- **Real-time Content Detection**: Intercepts all LLM requests, extracts user input, and sends it to a firewall API for security scanning
- **Tool Call Auditing**: Scans tool names and parameters before tool execution via the `before_tool_call` hook
- **Smart Blocking**: When sensitive content is detected, automatically constructs a compliant blocking response (supports both SSE streaming and non-streaming) to prevent the request from reaching the LLM
- **Built-in Command Bypass**: Automatically skips built-in commands starting with `/` and system-internal operations (e.g., `/reset`, summary generation) to avoid false positives
- **Hit Rule Display**: When blocking, displays matched security rules in a Markdown table format (rule_code, rule_name, description)

## How It Works

```
User Input → Fetch Interception → Extract User Prompt → Firewall API Check
  ├─ Safe → Forward request to LLM normally
  └─ Unsafe → Construct blocking response and return to client

Tool Call → before_tool_call → Firewall API Check
  ├─ Safe → Execute tool normally
  └─ Unsafe → Return block interception
```

## Configuration

Configure in `~/.openclaw/openclaw.json` under `plugins.entries.tomzang_plungin.config`:

```json
{
  "firewallUrl": "http://your-firewall-host:port/api/firewall/openclaw/validate",
  "authKey": "your-auth-key",
  "blockMessage": "Custom block message",
  "debug": false
}
```

### Configuration Reference

| Option | Type | Required | Default | Description |
|--------|------|----------|---------|-------------|
| `firewallUrl` | string | **Yes** | None | Firewall API URL for content security scanning |
| `authKey` | string | **Yes** | None | Authentication key for the firewall API |
| `blockMessage` | string | No | `当前请求包含敏感关键字，已被安全组件拦截` | Custom block message (displayed when no hit rules are matched) |
| `debug` | boolean | No | `false` | Enable debug mode for detailed logging output |

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

## Logging

The plugin outputs logs through the OpenClaw logging system, all prefixed with `[tomzang_plungin]`. Enable `debug: true` to view detailed request/response information for troubleshooting.
