---
name: mcp-sync
description: Sync MCP server configurations from Mallory to your local Claude Code environment. Use when setting up or refreshing MCP server connections.
allowed-tools: Bash(python *), Bash(uv *), Bash(pip *)
---

# MCP Server Sync

Sync your organization's registered MCP servers from Mallory to your local Claude Code environment. This fetches the servers your admin has enabled for plugin use and writes a local config file that Claude Code can reference.

## Prerequisites

- `MALLORY_API_KEY` environment variable must be set (your personal API key from the Mallory dashboard)
- Python 3.10+ available

## How to Sync

Run the sync script:

```bash
python plugins/mallory/skills/mcp-sync/scripts/sync_mcp_servers.py
```

This will:

1. Call the Mallory discovery API (`GET /v1/mcp/registered-servers`)
2. Write `~/.mallory/mcp-servers.json` with servers that have valid credentials
3. Print a summary of synced servers, available tools, and any servers pending authentication

## After Syncing

Claude Code does not currently support referencing external MCP config files via `$ref`. After syncing, you need to add the servers to your Claude Code config.

**Option A — Project-scoped (recommended for teams):**

Copy the `mcpServers` block from `~/.mallory/mcp-servers.json` into your project's `.mcp.json` file.

**Option B — User-scoped:**

Copy the `mcpServers` block into `~/.claude.json` under the top-level `mcpServers` key.

**Option C — CLI one-liner per server:**

```bash
claude mcp add-json <server-name> '<server-config-json>'
```

The sync script prints the exact commands you need.

## Pending Authentication

If a server requires per-user credentials and you haven't provided yours yet, the sync script will flag it as "pending setup" and print instructions:

- **Static token:** You'll be prompted to provide your token. The script will store it via the Mallory API for future syncs.
- **OAuth:** You'll receive a URL to complete the authorization flow in your browser. Re-run sync after completing it.

## Re-syncing

Run the sync script again at any time to pick up:

- New servers your admin registered
- Updated credentials
- Newly enabled tools
- Servers where you've completed pending auth

The config file is fully overwritten on each sync (no duplicate accumulation).
