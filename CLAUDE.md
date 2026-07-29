# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is an **OpenCode V1 Plugin** — a single-file JavaScript plugin that integrates with the OpenCode CLI tool to provide audit logging and security firewall functionality for AI coding assistant interactions.

**Key characteristic:** Zero-dependency, zero-build-step ES module. The entire plugin lives in `index.js`.

## Architecture

The plugin uses the OpenCode V1 Plugin API hook system. All plugin logic is in a single async function that returns hook handlers:

```
chat.message → Log user input → Firewall API (source=text) → Block or Pass
tool.execute.before → Log tool call → Firewall API (source=tool_call) → Block or Execute
tool.execute.after → Log tool result → Firewall API (source=tool_result) → Block or Return
dispose → Cleanup
```

**Blocking behavior:**
- `chat.message`: Replaces message content with block reason, throws Error to terminate conversation
- `tool.execute.before`: Returns `{ block: true, blockReason }` to prevent execution
- `tool.execute.after`: Replaces tool output with block message

**Firewall API:** `POST {firewallUrl}/api/firewall/openclaw/validate`

The firewall API has a timeout (default 3000ms). If it times out or fails, the plugin automatically falls back to logging-only mode to avoid breaking the user's session.

## Development

**Verification only** — no build, test, or lint commands:

```bash
node --check index.js  # Syntax validation only
```

When making changes, read through `index.js` to understand the existing patterns. The plugin:
- Uses `var` declarations (not `const`/`let`)
- Has semicolons throughout
- Contains Chinese comments (preserve them)
- Uses timestamp-prefixed logging: `[2026/7/16 14:30:00]`

## Configuration

Plugin options are passed via `opencode.json`:

| Option | Type | Required | Purpose |
|--------|------|----------|---------|
| `firewallUrl` | string | Yes | Firewall audit endpoint |
| `authKey` | string | Yes | Authentication key for API calls |
| `blockMessage` | string | No | Message shown when content is blocked |
| `firewallTimeout` | number | No | API timeout in milliseconds (default: 3000) |
| `debug` | boolean | No | Enable verbose request/response logging |

If `firewallUrl` or `authKey` is not configured, the plugin operates in logging-only mode without security checks.

## Documentation

- `README.md` — Comprehensive Chinese documentation covering features, installation, log formats, and implementation logic
- `AGENTS.md` — English documentation for Claude Code agents
- `openclaw.plugin.json` — Plugin manifest with config schema

## Git Workflow

Active development branch: `open-code`

Main branch for PRs: `main`
