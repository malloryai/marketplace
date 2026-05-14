---
name: mcp-sync
description: Sync MCP server configurations from Mallory to your local Claude Code environment. Handles OAuth, static token, and shared credential patterns. Use when setting up or refreshing MCP server connections.
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
2. Handle each server based on its credential pattern:
   - **OAuth servers** — writes OAuth metadata so Claude Code handles the flow natively
   - **Static token servers** — prompts you for your API key if not yet provided
   - **Shared credential servers** — uses the org-level credential automatically
3. Write `~/.mallory/mcp-servers.json` with the merged configuration
4. Print a summary with `claude mcp add-json` commands per server

## Credential Patterns

### Pattern A — OAuth (per_user_oauth)

The server requires per-user OAuth authorization. The sync script writes the OAuth metadata (authorization endpoint, client ID, scopes) into the config so Claude Code can handle the OAuth flow natively. No token is stored locally.

### Pattern B — Static Token (per_user_static)

The server requires a per-user API key or token. On first sync, the script prompts you to enter your token. If provided, it's stored securely via the Mallory API and written to your local config. You can skip and provide it on a later sync.

### Pattern C — Shared Credential (per_tenant_shared)

The server uses an org-level credential managed by your admin. The token is included automatically from the discovery API.

## After Syncing

Add the servers to your Claude Code config:

**Option A — Project-scoped (recommended for teams):**

Copy the `mcpServers` block from `~/.mallory/mcp-servers.json` into your project's `.mcp.json` file.

**Option B — User-scoped:**

Copy the `mcpServers` block into `~/.claude.json` under the top-level `mcpServers` key.

**Option C — CLI one-liner per server:**

```bash
claude mcp add-json <server-name> '<server-config-json>'
```

The sync script prints the exact commands you need.

## Re-syncing

Run the sync script again at any time. It handles re-syncing cleanly:

- **User modifications preserved** — if you've edited a server's config locally, the script won't overwrite your changes
- **OAuth metadata updated** — if the upstream OAuth config changes, your entry is updated
- **Revoked servers removed** — servers no longer in the discovery API are cleaned up
- **New servers added** — newly registered servers appear on re-sync
