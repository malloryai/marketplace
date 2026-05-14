#!/usr/bin/env python3
"""Sync MCP server configurations from Mallory to local Claude Code config.

Calls GET /v1/mcp/registered-servers, writes ~/.mallory/mcp-servers.json,
and prints a summary with setup instructions.

Handles three credential patterns:
  Pattern A (per_user_oauth)  — writes OAuth metadata for Claude Code native flow
  Pattern B (per_user_static) — prompts for API key, stores via Mallory API
  Pattern C (per_tenant_shared) — uses shared credential from discovery API

Requires MALLORY_API_KEY environment variable.
"""

import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

MALLORY_BASE_URL = os.environ.get("MALLORY_BASE_URL", "https://api.mallory.ai")
MALLORY_API_KEY = os.environ.get("MALLORY_API_KEY", "")
OUTPUT_DIR = Path.home() / ".mallory"
OUTPUT_FILE = OUTPUT_DIR / "mcp-servers.json"
STATE_FILE = OUTPUT_DIR / "mcp-sync-state.json"

_input_fn = input


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


def store_user_credential(server_uuid, credential):
    url = f"{MALLORY_BASE_URL}/v1/mcp/user-credential"
    body = json.dumps({
        "mcp_server_uuid": server_uuid,
        "auth_type": "bearer",
        "credential": credential,
    }).encode()
    req = Request(
        url,
        data=body,
        headers={
            "Authorization": f"Bearer {MALLORY_API_KEY}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode())
    except HTTPError as e:
        print(f"  WARNING: Failed to store credential (HTTP {e.code})")
        return None
    except URLError as e:
        print(f"  WARNING: Could not reach Mallory API: {e.reason}")
        return None


def _config_hash(entry):
    return hashlib.sha256(json.dumps(entry, sort_keys=True).encode()).hexdigest()


def load_existing_config():
    if OUTPUT_FILE.exists():
        try:
            data = json.loads(OUTPUT_FILE.read_text())
            return data.get("mcpServers", {})
        except (json.JSONDecodeError, KeyError):
            return {}
    return {}


def load_sync_state():
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text())
        except json.JSONDecodeError:
            return {"servers": {}}
    return {"servers": {}}


def save_sync_state(state):
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    state["last_sync"] = datetime.now(timezone.utc).isoformat()
    STATE_FILE.write_text(json.dumps(state, indent=2) + "\n")


def server_key(server, credential_scope):
    name_slug = server["name"].lower().replace(" ", "_").replace("-", "_")
    if credential_scope == "per_user_oauth":
        return f"mcp__{name_slug}__"
    return f"mallory-{server['name'].lower().replace(' ', '-').replace('_', '-')}"


def is_user_modified(key, existing_config, sync_state):
    if key not in existing_config:
        return False
    state_entry = sync_state.get("servers", {}).get(key)
    if not state_entry:
        return True
    return _config_hash(existing_config[key]) != state_entry.get("config_hash")


def build_entry_pattern_a(server):
    entry = {"url": server["url"]}
    auth = {"type": "oauth2"}
    if server.get("oauth_authorization_endpoint"):
        auth["authorization_endpoint"] = server["oauth_authorization_endpoint"]
    if server.get("oauth_client_id"):
        auth["client_id"] = server["oauth_client_id"]
    if server.get("oauth_scopes"):
        auth["scopes"] = server["oauth_scopes"]
    entry["auth"] = auth
    return entry


def build_entry_pattern_b(server, token=None):
    entry = {"type": "http", "url": server["url"]}
    if token:
        name_slug = server["name"].lower().replace(" ", "-").replace("_", "-")
        env_key = f"MCP_{name_slug.upper().replace('-', '_')}_TOKEN"
        entry["env"] = {env_key: token}
        entry["headers"] = {"Authorization": f"Bearer ${{{env_key}}}"}
    return entry


def build_entry_pattern_c(server):
    entry = {"type": "http", "url": server["url"]}
    credential = server.get("credential") or {}
    if credential.get("token"):
        name_slug = server["name"].lower().replace(" ", "-").replace("_", "-")
        env_key = f"MCP_{name_slug.upper().replace('-', '_')}_TOKEN"
        entry["env"] = {env_key: credential["token"]}
        entry["headers"] = {"Authorization": f"Bearer ${{{env_key}}}"}
    return entry


def prompt_for_token(server_name):
    try:
        print(f"\n  Server '{server_name}' requires your API key.")
        token = _input_fn("  Enter it now or press Enter to skip: ").strip()
        return token if token else None
    except (EOFError, KeyboardInterrupt):
        return None


def build_mcp_config(servers, existing_config, sync_state):
    mcp_servers = dict(existing_config)
    new_state = {"servers": {}}
    ready = []
    pending = []
    skipped_modified = []
    api_server_keys = set()

    for server in servers:
        scope = server.get("credential_scope", "per_tenant_shared")
        key = server_key(server, scope)
        api_server_keys.add(key)
        server_uuid = server.get("uuid", "")

        if is_user_modified(key, existing_config, sync_state):
            skipped_modified.append(server)
            new_state["servers"][key] = sync_state.get("servers", {}).get(key, {})
            continue

        if scope == "per_user_oauth":
            entry = build_entry_pattern_a(server)
            mcp_servers[key] = entry
            new_state["servers"][key] = {
                "server_uuid": str(server_uuid),
                "config_hash": _config_hash(entry),
                "credential_scope": scope,
            }
            ready.append(server)

        elif scope == "per_user_static":
            credential = server.get("credential") or {}
            has_token = bool(credential.get("token"))

            if has_token:
                entry = build_entry_pattern_b(server, credential["token"])
                mcp_servers[key] = entry
                new_state["servers"][key] = {
                    "server_uuid": str(server_uuid),
                    "config_hash": _config_hash(entry),
                    "credential_scope": scope,
                }
                ready.append(server)
            elif server.get("auth_status") == "pending":
                token = prompt_for_token(server["name"])
                if token:
                    result = store_user_credential(str(server_uuid), token)
                    if result:
                        entry = build_entry_pattern_b(server, token)
                        mcp_servers[key] = entry
                        new_state["servers"][key] = {
                            "server_uuid": str(server_uuid),
                            "config_hash": _config_hash(entry),
                            "credential_scope": scope,
                        }
                        ready.append(server)
                    else:
                        pending.append(server)
                else:
                    entry = build_entry_pattern_b(server)
                    mcp_servers[key] = entry
                    new_state["servers"][key] = {
                        "server_uuid": str(server_uuid),
                        "config_hash": _config_hash(entry),
                        "credential_scope": scope,
                        "pending": True,
                    }
                    pending.append(server)
            else:
                pending.append(server)

        else:
            credential = server.get("credential") or {}
            if credential.get("token"):
                entry = build_entry_pattern_c(server)
                mcp_servers[key] = entry
                new_state["servers"][key] = {
                    "server_uuid": str(server_uuid),
                    "config_hash": _config_hash(entry),
                    "credential_scope": scope,
                }
                ready.append(server)
            elif server.get("auth_status") == "pending":
                pending.append(server)

    old_state_servers = sync_state.get("servers", {})
    for old_key, old_meta in old_state_servers.items():
        if old_key not in api_server_keys and old_key in mcp_servers:
            del mcp_servers[old_key]

    for key in list(mcp_servers.keys()):
        if key not in new_state["servers"] and key not in api_server_keys:
            state_entry = old_state_servers.get(key)
            if state_entry:
                new_state["servers"][key] = state_entry

    return mcp_servers, ready, pending, skipped_modified, new_state


def write_config(mcp_servers):
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    config = {"mcpServers": mcp_servers}
    OUTPUT_FILE.write_text(json.dumps(config, indent=2) + "\n")


def print_summary(ready, pending, skipped_modified, mcp_servers):
    total_tools = sum(len(s.get("tools", [])) for s in ready)

    print(f"\n{'='*60}")
    print("  Mallory MCP Server Sync")
    print(f"{'='*60}\n")

    if ready:
        print(f"  Synced: {len(ready)} server(s), {total_tools} tool(s)")
        print(f"  Config: {OUTPUT_FILE}\n")

        for server in ready:
            tools = server.get("tools", [])
            scope = server.get("credential_scope", "per_tenant_shared")
            print(f"  - {server['name']} ({scope})")
            for tool in tools:
                desc = tool.get("description") or ""
                desc_suffix = f" — {desc}" if desc else ""
                print(f"      {tool['name']}{desc_suffix}")
            print()

    if pending:
        print(f"  Pending setup: {len(pending)} server(s)\n")
        for server in pending:
            scope = server.get("credential_scope", "per_user_static")
            print(f"  - {server['name']} (credential_scope: {scope})")
            if scope == "per_user_oauth":
                print("      Complete the OAuth flow in your browser, then re-sync.")
            else:
                print("      Run mcp-sync again to provide your API key.")
            print()

    if skipped_modified:
        print(f"  Preserved (user-modified): {len(skipped_modified)} server(s)\n")
        for server in skipped_modified:
            print(f"  - {server['name']} (local changes preserved)")
        print()

    if not ready and not pending and not skipped_modified:
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
    existing_config = load_existing_config()
    sync_state = load_sync_state()

    mcp_servers, ready, pending, skipped_modified, new_state = build_mcp_config(
        servers, existing_config, sync_state
    )

    if mcp_servers:
        write_config(mcp_servers)

    save_sync_state(new_state)
    print_summary(ready, pending, skipped_modified, mcp_servers)


if __name__ == "__main__":
    main()
