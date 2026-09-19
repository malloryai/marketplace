"""Execute the shipped Markdown recipes against the SDK and offline responses."""

import ast
import importlib.util
import re
import unittest
from pathlib import Path

import httpx
from malloryapi import MalloryApi

ROOT = Path(__file__).resolve().parents[1]
EXPOSURE = ROOT / "plugins/mallory-investigations/skills/exposure-validation/SKILL.md"
BREACH = ROOT / "plugins/mallory-monitoring/skills/third-party-breach-monitor/SKILL.md"
spec = importlib.util.spec_from_file_location(
    "playbook_support", ROOT / "shared/workflow_support.py"
)
support = importlib.util.module_from_spec(spec)
spec.loader.exec_module(support)


def python_blocks(path):
    return re.findall(r"```python\n(.*?)```", path.read_text(), re.S)


def exposure_namespace():
    namespace = {
        "collect_pages": support.collect_pages,
        "CoverageError": support.CoverageError,
    }
    # Run the actual initialization and helper without starting event collection.
    nodes = ast.parse(python_blocks(EXPOSURE)[0]).body
    initialization = ast.Module(body=nodes[:2], type_ignores=[])
    exec(compile(initialization, str(EXPOSURE), "exec"), namespace)
    return namespace


class PlaybookRecipeTests(unittest.TestCase):
    def test_documented_python_blocks_parse(self):
        for path in (EXPOSURE, BREACH, ROOT / "shared/finding-lifecycle.md"):
            for code in python_blocks(path):
                with self.subTest(path=str(path)):
                    ast.parse(code)

    def test_breach_recipe_queries_verified_survivor_and_preserves_chains(self):
        calls = []

        def handler(request):
            calls.append(request)
            self.assertEqual(request.method, "GET")
            path = request.url.path
            if path.startswith("/v1/organizations/") and not path.endswith("/breaches"):
                identifier = path.rsplit("/", 1)[1]
                return httpx.Response(
                    200,
                    json={
                        "uuid": identifier,
                        "merged_into_uuid": str(int(identifier) + 1)
                        if identifier != "3"
                        else None,
                    },
                )
            if path == "/v1/organizations/3/breaches":
                return httpx.Response(
                    200, json={"items": [{"uuid": "old-breach"}], "total": 1}
                )
            if path == "/v1/breaches/old-breach":
                return httpx.Response(
                    200, json={"uuid": "old-breach", "merged_into_uuid": "new-breach"}
                )
            if path == "/v1/breaches/new-breach":
                return httpx.Response(200, json={"uuid": "new-breach"})
            self.fail(f"Unexpected request: {request.method} {path}")

        with MalloryApi(
            api_key="fixture-key", transport=httpx.MockTransport(handler)
        ) as client:
            namespace = {
                "client": client,
                "organization_uuid": "0",
                "collect_pages": support.collect_pages,
            }
            exec(python_blocks(BREACH)[0], namespace)
        self.assertEqual(namespace["survivor_uuid"], "3")
        self.assertEqual(namespace["organization_chain"], ["0", "1", "2", "3"])
        self.assertEqual(
            namespace["canonical_breaches"],
            [
                {
                    "breach": {"uuid": "new-breach"},
                    "merge_chain": ["old-breach", "new-breach"],
                }
            ],
        )
        relationship_calls = [r for r in calls if r.url.path.endswith("/breaches")]
        self.assertEqual(
            [r.url.path for r in relationship_calls], ["/v1/organizations/3/breaches"]
        )
        self.assertEqual(relationship_calls[0].url.params["sort"], "created_at")

    def test_merge_recipe_rejects_cycle_wrong_identity_and_fourth_hop(self):
        namespace = {}
        helper = ast.Module(
            body=ast.parse(python_blocks(BREACH)[0]).body[:1], type_ignores=[]
        )
        exec(compile(helper, str(BREACH), "exec"), namespace)
        for name, fetch in {
            "cycle": lambda key: {"uuid": key, "merged_into_uuid": key},
            "wrong_identity": lambda key: {"uuid": "different"},
            "missing_identity": lambda key: {},
            "fourth_hop": lambda key: {
                "uuid": key,
                "merged_into_uuid": str(int(key) + 1),
            },
        }.items():
            with self.subTest(case=name), self.assertRaises(ValueError):
                namespace["resolve_survivor"](fetch, "0")

    def test_exposure_recipe_exhausts_mentions_and_stories_and_preserves_failures(self):
        for failing_scope in (None, "mentions", "stories"):
            with self.subTest(failing_scope=failing_scope):
                calls = []

                def handler(request):
                    calls.append(request)
                    path = request.url.path
                    self.assertFalse(path.startswith("/v1/findings"))
                    if path == "/v1/vulnerabilities/CVE-DEMO":
                        return httpx.Response(
                            200, json={"uuid": "vuln", "cve_id": "CVE-DEMO"}
                        )
                    if path == "/v1/assets/exposure-check":
                        self.assertEqual(request.method, "POST")
                        return httpx.Response(200, json={"assets": []})
                    self.assertEqual(request.method, "GET")
                    scope = "mentions" if path.endswith("/mentions") else "stories"
                    self.assertIn(
                        path, ["/v1/vulnerabilities/CVE-DEMO/mentions", "/v1/stories"]
                    )
                    offset = int(request.url.params["offset"])
                    if scope == failing_scope and offset == 1:
                        return httpx.Response(
                            400, json={"detail": "Fixture later-page failure"}
                        )
                    return httpx.Response(
                        200,
                        json={
                            "data": [{"uuid": f"{scope}-{offset}"}],
                            "total": 2,
                            "offset": offset,
                            "limit": 1,
                        },
                    )

                namespace = exposure_namespace()
                with MalloryApi(
                    api_key="fixture-key", transport=httpx.MockTransport(handler)
                ) as client:
                    namespace.update(client=client, cve="CVE-DEMO")
                    exec(python_blocks(EXPOSURE)[1], namespace)
                for scope, variable in [
                    ("mentions", "references"),
                    ("stories", "stories"),
                ]:
                    failed = scope == failing_scope
                    self.assertEqual(namespace[variable + "_complete"], not failed)
                    self.assertEqual(len(namespace[variable]), 1 if failed else 2)
                    self.assertEqual(namespace[variable][0]["uuid"], f"{scope}-0")
                    scope_calls = [r for r in calls if r.url.path.endswith("/" + scope)]
                    self.assertEqual(
                        [int(r.url.params["offset"]) for r in scope_calls], [0, 1]
                    )
                if failing_scope:
                    gap = namespace["coverage_gaps"][0]
                    self.assertEqual(gap["scope"], "CVE-DEMO:" + failing_scope)
                    self.assertEqual(gap["offset"], 1)
                    self.assertEqual(
                        gap["partial_items"], [{"uuid": failing_scope + "-0"}]
                    )
                else:
                    self.assertEqual(namespace["coverage_gaps"], [])

    def test_partial_event_listing_retains_rows_and_incomplete_flag(self):
        def handler(request):
            self.assertEqual(request.method, "GET")
            self.assertEqual(request.url.path, "/v1/exploitations")
            self.assertEqual(
                request.url.params["filter"], "begins_at>=2026-01-01T00:00:00Z"
            )
            if int(request.url.params["offset"]) == 0:
                return httpx.Response(
                    200, json={"data": [{"uuid": "event-1"}], "total": 2}
                )
            return httpx.Response(400, json={"detail": "Fixture listing gap"})

        namespace = exposure_namespace()
        with MalloryApi(
            api_key="fixture-key", transport=httpx.MockTransport(handler)
        ) as client:
            namespace.update(client=client, start="2026-01-01T00:00:00Z")
            exec(python_blocks(EXPOSURE)[0], namespace)
        self.assertFalse(namespace["events_complete"])
        self.assertEqual(namespace["events"], [{"uuid": "event-1"}])
        self.assertEqual(namespace["coverage_gaps"][0]["offset"], 1)
        self.assertEqual(
            namespace["coverage_gaps"][0]["partial_items"], namespace["events"]
        )


if __name__ == "__main__":
    unittest.main()
