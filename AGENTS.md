# AGENTS.md

## What this repo is

Single-file OpenCode V1 plugin (`index.js`) that logs user input and all tool executions to the console, with optional OpenClaw ToolGuard firewall integration for security auditing. No build step, no tests, no lint, no TypeScript.

## Key files

- `index.js` — plugin entry (ES module, exports default async function returning hooks)
- `opencode.json` — registers `./index.js` as a plugin with firewall config options
- `package.json` — metadata only; `"type": "module"`

## Architecture

The plugin uses the OpenCode V1 plugin API:

- `chat.message` hook — fires on every user message, extracts text parts, prints `[USER]` log, calls firewall API (`source=text`) for security audit
- `tool.execute.before` hook — fires before every tool call, prints `[TOOL:name]` log with args summary, calls firewall API (`source=tool_call`) for security audit
- `tool.execute.after` hook — fires after every tool call, prints `[TOOL_RESULT:name]` log, calls firewall API (`source=tool_result`) for output audit
- `dispose` hook — prints unload message

When firewall returns `block`:
- `chat.message`: replaces message parts with block reason, throws Error to end conversation
- `tool.execute.before`: returns `{ block: true, blockReason }` to prevent execution
- `tool.execute.after`: replaces tool output with block reason

## Configuration

Options passed via `opencode.json` plugin config:

| Option | Type | Required | Default |
|--------|------|----------|---------|
| `firewallUrl` | string | yes | - |
| `authKey` | string | yes | - |
| `blockMessage` | string | no | `当前请求包含敏感信息，已被安全组件拦截` |
| `debug` | boolean | no | `false` |

If `firewallUrl` or `authKey` is empty, firewall is disabled and only logging occurs.

## Code style

- Plain ES module JavaScript. Use `var`, not `const`/`let`.
- Semicolons throughout.
- All logs prefixed with `[tomzang_plungin]`.
- Chinese comments are common; keep them as-is.

## No test / lint / typecheck commands

This repo has none. Verify changes by reading the code and ensuring it matches the existing patterns.

## Git notes

- Active work branch: `open-code`
- Plugin SDK: `@opencode-ai/plugin` v1.18.1 (installed globally at `~/.config/opencode/node_modules/`)
