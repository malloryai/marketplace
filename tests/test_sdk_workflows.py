"""Exercise public recipes against the real 0.4.0 client and an offline transport."""

import importlib.util
import json
import unittest
from datetime import datetime, timezone
from importlib.metadata import version
from pathlib import Path

import httpx
from malloryapi import MalloryApi
from malloryapi.exceptions import APIError

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "workspace",
    ROOT / "plugins/mallory/skills/daily-briefing/scripts/workspace_briefing.py",
)
workspace = importlib.util.module_from_spec(spec)
spec.loader.exec_module(workspace)


class SdkWorkflowTests(unittest.TestCase):
    def test_workspace_collector_uses_real_sdk_contract(self):
        calls = []

        def handler(request):
            calls.append(request)
            self.assertEqual(request.headers["authorization"], "Bearer fixture-key")
            if request.url.path == "/v1/workspaces/ws":
                return httpx.Response(200, json={"uuid": "ws", "tenant_uuid": "tenant"})
            rows = []
            if (
                request.url.path == "/v1/stories"
                and "matched_asset_count__gt" in request.url.params
            ):
                rows = [
                    {
                        "uuid": "old",
                        "title": "Older story",
                        "fresh_at": "2020-01-01T00:00:00Z",
                    }
                ]
            return httpx.Response(
                200, json={"data": rows, "total": len(rows), "offset": 0, "limit": 100}
            )

        with MalloryApi(
            api_key="fixture-key", transport=httpx.MockTransport(handler)
        ) as client:
            report, state = workspace.collect_workspace(
                client, "ws", now=datetime(2026, 1, 2, tzinfo=timezone.utc)
            )
        self.assertEqual(report["status"], "complete")
        self.assertEqual(state["matched_story_ids"], ["old"])
        vuln = next(r for r in calls if r.url.path.endswith("/vulnerabilities"))
        self.assertEqual(vuln.url.params["matched_asset_count__gt"], "0")
        self.assertIn("first_exploitation_at__gte", vuln.url.params)
        self.assertNotIn("workspace_uuids", vuln.url.params)

    def test_new_skill_recipes_and_detail_write_response(self):
        calls = []

        def handler(request):
            calls.append(request)
            if request.method == "POST":
                return httpx.Response(201, json={"uuid": "finding-1", "status": "open"})
            return httpx.Response(200, json={"data": [], "items": [], "total": 0})

        with MalloryApi(
            api_key="fixture-key", transport=httpx.MockTransport(handler)
        ) as client:
            client.organizations.get("merged-org")
            client.organizations.breaches(
                "survivor", sort="created_at", order="desc", offset=0, limit=100
            )
            client.advisories.sources()
            client.advisories.list(
                source="vendor_feed", created_at__gte="start", created_at__lt="end"
            )
            client.advisories.export("advisory")
            client.exploitations.list(
                filter="begins_at>=start", sort="begins_at", order="asc"
            )
            client.assets.exposure_check(
                {"entities": [{"type": "vulnerability", "identifier": "CVE-DEMO"}]}
            )
            client.sightings.list(created_at__gte="start", created_at__lt="end")
            client.observables.opinions("observable", verdict="malicious", limit=1)
            client.finding_definitions.get(
                "malicious-observable-sighting", scope="global"
            )
            client.findings.list(
                definition_slug="malicious-observable-sighting",
                asset_type="generic",
                asset_identifier="a&b.test",
            )
            result = client.findings.create(
                {
                    "definition_slug": "demo",
                    "asset_type": "generic",
                    "asset_identifier": "demo",
                    "title": "demo",
                }
            )
        self.assertEqual(result["uuid"], "finding-1")
        exposure = next(r for r in calls if r.url.path.endswith("/exposure-check"))
        self.assertEqual(
            json.loads(exposure.content)["entities"][0]["type"], "vulnerability"
        )
        sightings = next(r for r in calls if r.url.path.endswith("/sightings"))
        self.assertEqual(sightings.url.params["created_at__gte"], "start")
        findings = next(
            r for r in calls if r.url.path.endswith("/findings") and r.method == "GET"
        )
        self.assertEqual(findings.url.params["asset_identifier"], "a&b.test")
        self.assertNotIn("qualifier", findings.url.params)

    def test_duplicate_is_sdk_exception_not_batch_result(self):
        with MalloryApi(
            api_key="fixture-key",
            transport=httpx.MockTransport(
                lambda request: httpx.Response(
                    409, json={"detail": {"existing_finding_uuid": "existing"}}
                )
            ),
        ) as client:
            with self.assertRaises(APIError) as caught:
                client.findings.create({})
        self.assertEqual(caught.exception.status_code, 409)

    def test_test_environment_is_release_040(self):
        self.assertEqual(version("malloryapi"), "0.4.0")


if __name__ == "__main__":
    unittest.main()
