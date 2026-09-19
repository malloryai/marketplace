import importlib.util
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from malloryapi._types import PaginatedResponse

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "workspace_briefing",
    ROOT / "plugins/mallory/skills/daily-briefing/scripts/workspace_briefing.py",
)
brief = importlib.util.module_from_spec(spec)
spec.loader.exec_module(brief)
NOW = datetime(2026, 1, 2, tzinfo=timezone.utc)


class Client:
    def __init__(self, fail_matches=False):
        self.fail_matches = fail_matches
        self.calls = []
        self.workspaces = type(
            "Workspaces",
            (),
            {
                "get": lambda _, uuid: {
                    "uuid": uuid,
                    "tenant_uuid": "tenant-1",
                    "name": "Demo",
                }
            },
        )()
        self.stories = type("Stories", (), {"list": self.stories_list})()
        self.findings = type(
            "Findings",
            (),
            {"list": lambda _, **kw: PaginatedResponse(items=[], total=0)},
        )()
        self.vulnerabilities = type(
            "Vulns", (), {"list": lambda _, **kw: PaginatedResponse(items=[], total=0)}
        )()

    def stories_list(self, **kw):
        self.calls.append(kw)
        if "matched_asset_count__gt" in kw:
            if self.fail_matches:
                raise RuntimeError("Unavailable")
            return PaginatedResponse(
                items=[
                    {
                        "uuid": "old-story",
                        "title": "Older incident",
                        "fresh_at": "2025-01-01T00:00:00Z",
                    }
                ],
                total=1,
            )
        return PaginatedResponse(items=[], total=0)


class BriefingTests(unittest.TestCase):
    def test_first_run_records_baseline_without_callout(self):
        report, state = brief.collect_workspace(Client(), "workspace-1", now=NOW)
        self.assertEqual(report["status"], "complete")
        self.assertEqual(report["sections"]["newly_matched_stories"], [])
        self.assertEqual(state["matched_story_ids"], ["old-story"])
        self.assertEqual(report["coverage"]["examined"], 4)
        self.assertEqual(report["coverage"]["requested"], 4)
        self.assertTrue(
            all(row["assessed_at"] == NOW.isoformat() for row in report["results"])
        )
        with tempfile.TemporaryDirectory() as directory:
            paths = brief.write_report(
                report, Path(directory) / "briefing", html_output=True
            )
            self.assertTrue(Path(paths["html"]).is_file())

    def test_new_match_can_be_old_story(self):
        client = Client()
        state = {
            "schema_version": 1,
            "workspace_uuid": "workspace-1",
            "tenant_uuid": "tenant-1",
            "matched_story_ids": [],
            "checkpoints": {},
        }
        report, _ = brief.collect_workspace(client, "workspace-1", state=state, now=NOW)
        self.assertEqual(
            report["sections"]["newly_matched_stories"][0]["uuid"], "old-story"
        )
        matches = next(
            call for call in client.calls if "matched_asset_count__gt" in call
        )
        self.assertNotIn("fresh_at__gte", matches)

    def test_failure_preserves_previous_matching_state(self):
        state = {
            "schema_version": 1,
            "workspace_uuid": "workspace-1",
            "tenant_uuid": "tenant-1",
            "matched_story_ids": ["previous"],
            "checkpoints": {"matches": "2026-01-01T00:00:00Z"},
        }
        report, next_state = brief.collect_workspace(
            Client(True), "workspace-1", state=state, now=NOW
        )
        self.assertEqual(report["status"], "partial")
        self.assertEqual(next_state["matched_story_ids"], ["previous"])
        self.assertEqual(report["coverage"]["examined"], 3)
        self.assertEqual(next_state["checkpoints"]["matches"], "2026-01-01T00:00:00Z")

    def test_first_failed_section_keeps_initial_window_for_retry(self):
        client = Client()

        def fail(**kw):
            raise RuntimeError("Unavailable")

        client.findings = type("Findings", (), {"list": lambda _, **kw: fail(**kw)})()
        report, state = brief.collect_workspace(client, "workspace-1", now=NOW)
        self.assertEqual(report["status"], "partial")
        self.assertEqual(
            state["checkpoints"]["new_findings"], "2026-01-01T00:00:00+00:00"
        )

    def test_state_cannot_cross_workspace_or_tenant(self):
        for key in ("workspace_uuid", "tenant_uuid"):
            state = {
                "schema_version": 1,
                "workspace_uuid": "workspace-1",
                "tenant_uuid": "tenant-1",
                "checkpoints": {},
            }
            state[key] = "other"
            with self.assertRaises(ValueError):
                brief.collect_workspace(Client(), "workspace-1", state=state, now=NOW)


if __name__ == "__main__":
    unittest.main()
