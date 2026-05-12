#!/usr/bin/env python3
"""Sync MCP server configurations from Mallory to local Claude Code config.

Calls GET /v1/mcp/registered-servers, writes ~/.mallory/mcp-servers.json,
and prints a summary with setup instructions.

Requires MALLORY_API_KEY environment variable.
"""

import json
import os
import sys
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

MALLORY_BASE_URL = os.environ.get("MALLORY_BASE_URL", "https://api.mallory.ai")
MALLORY_API_KEY = os.environ.get("MALLORY_API_KEY", "")
OUTPUT_DIR = Path.home() / ".mallory"
OUTPUT_FILE = OUTPUT_DIR / "mcp-servers.json"


def fetch_registered_servers():
    if not MALLORY_API_KEY:
        print("ERROR: MALLORY_API_KEY environment variable is not set.")
        print("Get your API key from the Mallory dashboard: Settings > API Keys")
        sys.exit(1)

    url = f"{MALLORY_BASE_URL}/v1/mcp/registered-servers"
    req = Request(url, headers={"Authorization": f"Bearer {MALLORY_API_KEY}"})

    try:
        with urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode())
    except HTTPError as e:
        if e.code == 401:
            print("ERROR: Invalid or expired MALLORY_API_KEY.")
        elif e.code == 403:
            print("ERROR: Insufficient permissions. Check your API key.")
        else:
            print(f"ERROR: API returned HTTP {e.code}")
        sys.exit(1)
    except URLError as e:
        print(f"ERROR: Could not reach Mallory API: {e.reason}")
        sys.exit(1)


def build_mcp_config(servers):
    mcp_servers = {}
    ready = []
    pending = []

    for server in servers:
        if server.get("auth_status") == "pending":
            pending.append(server)
            continue

        name_slug = server["name"].lower().replace(" ", "-").replace("_", "-")
        credential = server.get("credential") or {}
        env = {}

        if credential.get("token"):
            env_key = f"MCP_{name_slug.upper().replace('-', '_')}_TOKEN"
            env[env_key] = credential["token"]

        entry = {"type": "http", "url": server["url"]}
        if env:
            entry["env"] = env
            entry["headers"] = {"Authorization": f"Bearer ${{{env_key}}}"}

        mcp_servers[f"mallory-{name_slug}"] = entry
        ready.append(server)

    return mcp_servers, ready, pending


def write_config(mcp_servers):
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    config = {"mcpServers": mcp_servers}
    OUTPUT_FILE.write_text(json.dumps(config, indent=2) + "\n")


def print_summary(ready, pending, mcp_servers):
    total_tools = sum(len(s.get("tools", [])) for s in ready)

    print(f"\n{'='*60}")
    print("  Mallory MCP Server Sync")
    print(f"{'='*60}\n")

    if ready:
        print(f"  Synced: {len(ready)} server(s), {total_tools} tool(s)")
        print(f"  Config: {OUTPUT_FILE}\n")

        for server in ready:
            tools = server.get("tools", [])
            scope = server.get("credential_scope", "shared")
            print(f"  - {server['name']} ({scope})")
            for tool in tools:
                desc = tool.get("description") or ""
                desc_suffix = f" — {desc}" if desc else ""
                print(f"      {tool['name']}{desc_suffix}")
            print()

    if pending:
        print(f"  Pending setup: {len(pending)} server(s)\n")
        for server in pending:
            scope = server.get("credential_scope", "per_user")
            print(f"  - {server['name']} (credential_scope: {scope})")
            print(
                "      Provide your credentials via the Mallory web app "
                "or run the credential store command."
            )
            print()

    if not ready and not pending:
        print("  No MCP servers registered for plugin use.")
        print(
            "  Ask your admin to register servers with 'plugin' surface "
            "in the Mallory web app.\n"
        )
        return

    if ready:
        print(f"{'─'*60}")
        print("  Next steps:\n")
        print("  Add these servers to your Claude Code config.\n")

        for name, config in mcp_servers.items():
            config_json = json.dumps(config).replace("'", "'\\''")
            print(f"  claude mcp add-json {name} '{config_json}'")

        print(f"\n  Or copy the mcpServers block from {OUTPUT_FILE}")
        print("  into your project's .mcp.json or ~/.claude.json")
        print()


def main():
    servers = fetch_registered_servers()
    mcp_servers, ready, pending = build_mcp_config(servers)

    if mcp_servers:
        write_config(mcp_servers)

    print_summary(ready, pending, mcp_servers)


if __name__ == "__main__":
    main()
