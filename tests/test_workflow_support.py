import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

from malloryapi._types import PaginatedResponse

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "support", ROOT / "shared/workflow_support.py"
)
support = importlib.util.module_from_spec(spec)
spec.loader.exec_module(support)


class SupportTests(unittest.TestCase):
    def test_sdk_pagination_uses_returned_row_count(self):
        offsets = []

        def fetch(**kw):
            offsets.append(kw["offset"])
            return PaginatedResponse(
                items=[{"uuid": str(kw["offset"])}],
                total=3,
                limit=1,
                offset=kw["offset"],
            )

        self.assertEqual(len(support.collect_pages(fetch, limit=100)), 3)
        self.assertEqual(offsets, [0, 1, 2])

    def test_raw_relationship_envelope(self):
        rows = support.collect_pages(
            lambda **kw: {"items": [{"uuid": "a"}], "total": 1}
        )
        self.assertEqual(rows[0]["uuid"], "a")

    def test_repeated_rows_and_missing_rows_are_not_complete(self):
        for fetch in (
            lambda **kw: {"items": [{"uuid": "a"}], "total": 3},
            lambda **kw: {"items": [], "total": 3},
        ):
            with self.assertRaises(support.CoverageError):
                support.collect_pages(fetch)

    def test_changed_totals_are_not_complete(self):
        with self.assertRaises(support.CoverageError):
            support.collect_pages(
                lambda **kw: {
                    "items": [{"uuid": str(kw["offset"])}],
                    "total": 3 + kw["offset"],
                }
            )

    def test_truncation_is_not_empty(self):
        with self.assertRaises(support.CoverageError):
            support.collect_pages(
                lambda **kw: {
                    "items": [],
                    "total": 0,
                    "_truncation": {"truncated": True},
                }
            )

    def test_report_escapes_html_and_preserves_json(self):
        report = {
            "schema_version": 1,
            "skill": "test",
            "scope": {"workspace": "x"},
            "window": None,
            "status": "partial",
            "summary": "<script>alert(1)</script>",
            "results": [],
            "coverage": {
                "examined": 0,
                "requested": 1,
                "gaps": ["inventory unavailable"],
            },
            "finding_actions": [],
        }
        with tempfile.TemporaryDirectory() as directory:
            paths = support.write_report(
                report, Path(directory) / "report", html_output=True
            )
            self.assertEqual(json.loads(Path(paths["json"]).read_text()), report)
            self.assertNotIn("<script>", Path(paths["html"]).read_text())
            self.assertIn("inventory unavailable", Path(paths["markdown"]).read_text())

    def test_complete_report_cannot_hide_gaps(self):
        with self.assertRaises(ValueError):
            support.validate_report(
                {
                    "schema_version": 1,
                    "skill": "test",
                    "scope": {},
                    "window": None,
                    "status": "complete",
                    "summary": "clear",
                    "results": [],
                    "coverage": {"examined": 0, "requested": 1, "gaps": ["failed"]},
                    "finding_actions": [],
                }
            )


if __name__ == "__main__":
    unittest.main()
