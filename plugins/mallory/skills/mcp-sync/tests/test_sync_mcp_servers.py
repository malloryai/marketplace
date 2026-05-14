#!/usr/bin/env python3
"""Tests for mcp-sync skill — three credential patterns + re-sync idempotency."""

import json
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(
    0,
    str(Path(__file__).parent.parent / "scripts"),
)

import sync_mcp_servers as sync


def _make_server(
    name="test-server",
    url="https://example.com/mcp",
    credential_scope="per_tenant_shared",
    auth_status=None,
    credential=None,
    oauth_authorization_endpoint=None,
    oauth_client_id=None,
    oauth_scopes=None,
    uuid="aaaa-bbbb-cccc",
    tools=None,
):
    s = {
        "uuid": uuid,
        "name": name,
        "url": url,
        "transport": "http",
        "credential_scope": credential_scope,
    }
    if auth_status:
        s["auth_status"] = auth_status
    if credential:
        s["credential"] = credential
    if oauth_authorization_endpoint:
        s["oauth_authorization_endpoint"] = oauth_authorization_endpoint
    if oauth_client_id:
        s["oauth_client_id"] = oauth_client_id
    if oauth_scopes:
        s["oauth_scopes"] = oauth_scopes
    if tools:
        s["tools"] = tools
    return s


class TestPatternA_OAuth(unittest.TestCase):
    """Pattern A: per_user_oauth — writes OAuth metadata in Claude Code format."""

    def test_oauth_metadata_written(self):
        server = _make_server(
            name="ServiceNow",
            url="https://customer.service-now.com/mcp",
            credential_scope="per_user_oauth",
            oauth_authorization_endpoint="https://customer.service-now.com/oauth/authorize",
            oauth_client_id="abc123",
            oauth_scopes="read write",
        )
        mcp_servers, ready, pending, skipped, state = sync.build_mcp_config(
            [server], {}, {"servers": {}}
        )
        key = "mcp__servicenow__"
        self.assertIn(key, mcp_servers)
        entry = mcp_servers[key]
        self.assertEqual(entry["url"], "https://customer.service-now.com/mcp")
        self.assertEqual(entry["auth"]["type"], "oauth2")
        self.assertEqual(
            entry["auth"]["authorization_endpoint"],
            "https://customer.service-now.com/oauth/authorize",
        )
        self.assertEqual(entry["auth"]["client_id"], "abc123")
        self.assertEqual(entry["auth"]["scopes"], "read write")
        self.assertEqual(len(ready), 1)
        self.assertEqual(len(pending), 0)

    def test_oauth_key_uses_underscore_format(self):
        server = _make_server(
            name="My OAuth Server",
            credential_scope="per_user_oauth",
            oauth_authorization_endpoint="https://auth.example.com/authorize",
            oauth_client_id="cid",
        )
        mcp_servers, *_ = sync.build_mcp_config([server], {}, {"servers": {}})
        self.assertIn("mcp__my_oauth_server__", mcp_servers)

    def test_oauth_no_type_field(self):
        """Pattern A entries should not have 'type: http' — just url + auth."""
        server = _make_server(
            name="OAuth Only",
            credential_scope="per_user_oauth",
            oauth_authorization_endpoint="https://auth.example.com",
            oauth_client_id="c1",
        )
        mcp_servers, *_ = sync.build_mcp_config([server], {}, {"servers": {}})
        entry = mcp_servers["mcp__oauth_only__"]
        self.assertNotIn("type", entry)

    def test_oauth_state_tracked(self):
        server = _make_server(
            name="Tracked",
            credential_scope="per_user_oauth",
            oauth_authorization_endpoint="https://auth.example.com",
            oauth_client_id="c1",
        )
        _, _, _, _, state = sync.build_mcp_config([server], {}, {"servers": {}})
        self.assertIn("mcp__tracked__", state["servers"])
        self.assertEqual(
            state["servers"]["mcp__tracked__"]["credential_scope"], "per_user_oauth"
        )


class TestPatternB_StaticToken(unittest.TestCase):
    """Pattern B: per_user_static — prompt for token, store via API."""

    def test_token_already_provided(self):
        server = _make_server(
            name="GitHub",
            credential_scope="per_user_static",
            credential={"type": "bearer", "token": "ghp_abc123"},
        )
        mcp_servers, ready, pending, *_ = sync.build_mcp_config(
            [server], {}, {"servers": {}}
        )
        key = "mallory-github"
        self.assertIn(key, mcp_servers)
        entry = mcp_servers[key]
        self.assertEqual(entry["type"], "http")
        self.assertIn("env", entry)
        self.assertIn("MCP_GITHUB_TOKEN", entry["env"])
        self.assertEqual(entry["env"]["MCP_GITHUB_TOKEN"], "ghp_abc123")
        self.assertEqual(len(ready), 1)

    @patch.object(sync, "_input_fn", return_value="my-secret-token")
    @patch.object(sync, "store_user_credential", return_value={"mcp_server_uuid": "x"})
    def test_prompt_token_provided(self, mock_store, mock_input):
        server = _make_server(
            name="Jira",
            credential_scope="per_user_static",
            auth_status="pending",
            uuid="jira-uuid",
        )
        mcp_servers, ready, pending, *_ = sync.build_mcp_config(
            [server], {}, {"servers": {}}
        )
        key = "mallory-jira"
        self.assertIn(key, mcp_servers)
        mock_store.assert_called_once_with("jira-uuid", "my-secret-token")
        self.assertEqual(len(ready), 1)
        self.assertEqual(len(pending), 0)

    @patch.object(sync, "_input_fn", return_value="")
    def test_prompt_token_skipped(self, mock_input):
        server = _make_server(
            name="Jira",
            credential_scope="per_user_static",
            auth_status="pending",
        )
        mcp_servers, ready, pending, *_ = sync.build_mcp_config(
            [server], {}, {"servers": {}}
        )
        key = "mallory-jira"
        self.assertIn(key, mcp_servers)
        entry = mcp_servers[key]
        self.assertNotIn("env", entry)
        self.assertEqual(len(ready), 0)
        self.assertEqual(len(pending), 1)

    @patch.object(sync, "_input_fn", return_value="tok")
    @patch.object(sync, "store_user_credential", return_value=None)
    def test_prompt_token_api_failure(self, mock_store, mock_input):
        server = _make_server(
            name="Fail",
            credential_scope="per_user_static",
            auth_status="pending",
        )
        _, ready, pending, *_ = sync.build_mcp_config(
            [server], {}, {"servers": {}}
        )
        self.assertEqual(len(ready), 0)
        self.assertEqual(len(pending), 1)


class TestPatternC_SharedCredential(unittest.TestCase):
    """Pattern C: per_tenant_shared — unchanged from MCP-006."""

    def test_shared_credential_written(self):
        server = _make_server(
            name="Internal Scanner",
            credential_scope="per_tenant_shared",
            credential={"type": "bearer", "token": "shared-tok-123"},
        )
        mcp_servers, ready, *_ = sync.build_mcp_config(
            [server], {}, {"servers": {}}
        )
        key = "mallory-internal-scanner"
        self.assertIn(key, mcp_servers)
        entry = mcp_servers[key]
        self.assertEqual(entry["type"], "http")
        self.assertIn("MCP_INTERNAL_SCANNER_TOKEN", entry["env"])
        self.assertEqual(len(ready), 1)

    def test_shared_no_credential_pending(self):
        server = _make_server(
            name="No Cred",
            credential_scope="per_tenant_shared",
            auth_status="pending",
        )
        _, ready, pending, *_ = sync.build_mcp_config(
            [server], {}, {"servers": {}}
        )
        self.assertEqual(len(ready), 0)
        self.assertEqual(len(pending), 1)


class TestResyncIdempotency(unittest.TestCase):
    """Re-sync: don't clobber user edits, update OAuth metadata, handle revocations."""

    def test_user_modified_entry_preserved(self):
        server = _make_server(
            name="Modified",
            credential_scope="per_tenant_shared",
            credential={"type": "bearer", "token": "new-tok"},
        )
        existing_config = {
            "mallory-modified": {"type": "http", "url": "https://user-custom.com/mcp"},
        }
        sync_state = {
            "servers": {
                "mallory-modified": {
                    "server_uuid": "aaaa-bbbb-cccc",
                    "config_hash": sync._config_hash(
                        {"type": "http", "url": "https://example.com/mcp"}
                    ),
                    "credential_scope": "per_tenant_shared",
                }
            }
        }
        mcp_servers, ready, _, skipped, _ = sync.build_mcp_config(
            [server], existing_config, sync_state
        )
        self.assertEqual(
            mcp_servers["mallory-modified"]["url"], "https://user-custom.com/mcp"
        )
        self.assertEqual(len(skipped), 1)
        self.assertEqual(len(ready), 0)

    def test_unmodified_entry_updated(self):
        old_entry = {
            "url": "https://old.example.com/mcp",
            "auth": {
                "type": "oauth2",
                "authorization_endpoint": "https://old-auth.example.com",
                "client_id": "old-cid",
                "scopes": "read",
            },
        }
        server = _make_server(
            name="Updated",
            credential_scope="per_user_oauth",
            url="https://new.example.com/mcp",
            oauth_authorization_endpoint="https://new-auth.example.com",
            oauth_client_id="new-cid",
            oauth_scopes="read write",
        )
        existing_config = {"mcp__updated__": old_entry}
        sync_state = {
            "servers": {
                "mcp__updated__": {
                    "server_uuid": "aaaa-bbbb-cccc",
                    "config_hash": sync._config_hash(old_entry),
                    "credential_scope": "per_user_oauth",
                }
            }
        }
        mcp_servers, ready, *_ = sync.build_mcp_config(
            [server], existing_config, sync_state
        )
        entry = mcp_servers["mcp__updated__"]
        self.assertEqual(entry["url"], "https://new.example.com/mcp")
        self.assertEqual(entry["auth"]["client_id"], "new-cid")
        self.assertEqual(entry["auth"]["scopes"], "read write")
        self.assertEqual(len(ready), 1)

    def test_revoked_server_removed(self):
        existing_config = {
            "mallory-revoked": {"type": "http", "url": "https://old.com/mcp"},
        }
        sync_state = {
            "servers": {
                "mallory-revoked": {
                    "server_uuid": "revoked-uuid",
                    "config_hash": sync._config_hash(existing_config["mallory-revoked"]),
                    "credential_scope": "per_tenant_shared",
                }
            }
        }
        mcp_servers, *_ = sync.build_mcp_config([], existing_config, sync_state)
        self.assertNotIn("mallory-revoked", mcp_servers)

    def test_user_created_entry_preserved(self):
        existing_config = {
            "my-custom-server": {"type": "http", "url": "https://custom.com/mcp"},
        }
        server = _make_server(
            name="New",
            credential_scope="per_tenant_shared",
            credential={"type": "bearer", "token": "tok"},
        )
        mcp_servers, *_ = sync.build_mcp_config(
            [server], existing_config, {"servers": {}}
        )
        self.assertIn("my-custom-server", mcp_servers)
        self.assertIn("mallory-new", mcp_servers)

    def test_fresh_sync_no_state(self):
        server = _make_server(
            name="Fresh",
            credential_scope="per_tenant_shared",
            credential={"type": "bearer", "token": "tok"},
        )
        mcp_servers, ready, *_ = sync.build_mcp_config([server], {}, {"servers": {}})
        self.assertIn("mallory-fresh", mcp_servers)
        self.assertEqual(len(ready), 1)


class TestMixedPatterns(unittest.TestCase):
    """Multiple servers with different patterns in one sync."""

    def test_all_three_patterns_together(self):
        servers = [
            _make_server(
                name="OAuth Server",
                credential_scope="per_user_oauth",
                oauth_authorization_endpoint="https://auth.example.com",
                oauth_client_id="cid",
                oauth_scopes="read",
                uuid="uuid-a",
            ),
            _make_server(
                name="Token Server",
                credential_scope="per_user_static",
                credential={"type": "bearer", "token": "my-token"},
                uuid="uuid-b",
            ),
            _make_server(
                name="Shared Server",
                credential_scope="per_tenant_shared",
                credential={"type": "bearer", "token": "shared-token"},
                uuid="uuid-c",
            ),
        ]
        mcp_servers, ready, pending, *_ = sync.build_mcp_config(
            servers, {}, {"servers": {}}
        )
        self.assertIn("mcp__oauth_server__", mcp_servers)
        self.assertIn("mallory-token-server", mcp_servers)
        self.assertIn("mallory-shared-server", mcp_servers)
        self.assertEqual(len(ready), 3)
        self.assertEqual(len(pending), 0)

        oauth_entry = mcp_servers["mcp__oauth_server__"]
        self.assertEqual(oauth_entry["auth"]["type"], "oauth2")
        self.assertNotIn("type", oauth_entry)

        token_entry = mcp_servers["mallory-token-server"]
        self.assertEqual(token_entry["type"], "http")
        self.assertIn("env", token_entry)

        shared_entry = mcp_servers["mallory-shared-server"]
        self.assertEqual(shared_entry["type"], "http")
        self.assertIn("env", shared_entry)


class TestConfigIO(unittest.TestCase):
    """Config and state file I/O."""

    def test_write_and_load_config(self, tmp_path=None):
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            output_file = Path(td) / "mcp-servers.json"
            original_output = sync.OUTPUT_FILE
            original_dir = sync.OUTPUT_DIR
            try:
                sync.OUTPUT_FILE = output_file
                sync.OUTPUT_DIR = Path(td)
                servers = {"test": {"type": "http", "url": "https://x.com"}}
                sync.write_config(servers)
                loaded = sync.load_existing_config()
                self.assertEqual(loaded, servers)
            finally:
                sync.OUTPUT_FILE = original_output
                sync.OUTPUT_DIR = original_dir

    def test_load_missing_config(self):
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            original_output = sync.OUTPUT_FILE
            try:
                sync.OUTPUT_FILE = Path(td) / "nonexistent.json"
                loaded = sync.load_existing_config()
                self.assertEqual(loaded, {})
            finally:
                sync.OUTPUT_FILE = original_output

    def test_state_round_trip(self):
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            state_file = Path(td) / "state.json"
            original_state = sync.STATE_FILE
            original_dir = sync.OUTPUT_DIR
            try:
                sync.STATE_FILE = state_file
                sync.OUTPUT_DIR = Path(td)
                state = {
                    "servers": {
                        "test-key": {
                            "server_uuid": "123",
                            "config_hash": "abc",
                        }
                    }
                }
                sync.save_sync_state(state)
                loaded = sync.load_sync_state()
                self.assertEqual(loaded["servers"], state["servers"])
                self.assertIn("last_sync", loaded)
            finally:
                sync.STATE_FILE = original_state
                sync.OUTPUT_DIR = original_dir


class TestDiscoveryError(unittest.TestCase):
    """Discovery API error handling."""

    @patch.object(sync, "MALLORY_API_KEY", "")
    def test_missing_api_key(self):
        with self.assertRaises(SystemExit):
            sync.fetch_registered_servers()

    @patch("sync_mcp_servers.urlopen")
    @patch.object(sync, "MALLORY_API_KEY", "test-key")
    def test_http_401(self, mock_urlopen):
        from urllib.error import HTTPError

        mock_urlopen.side_effect = HTTPError(
            "url", 401, "Unauthorized", {}, None
        )
        with self.assertRaises(SystemExit):
            sync.fetch_registered_servers()


class TestServerKey(unittest.TestCase):
    """Server key generation."""

    def test_oauth_key_format(self):
        server = _make_server(name="My Server")
        key = sync.server_key(server, "per_user_oauth")
        self.assertEqual(key, "mcp__my_server__")

    def test_static_key_format(self):
        server = _make_server(name="My Server")
        key = sync.server_key(server, "per_user_static")
        self.assertEqual(key, "mallory-my-server")

    def test_shared_key_format(self):
        server = _make_server(name="My Server")
        key = sync.server_key(server, "per_tenant_shared")
        self.assertEqual(key, "mallory-my-server")


if __name__ == "__main__":
    unittest.main()
