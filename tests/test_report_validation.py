"""Regression checks for PR review findings in report and pagination contracts."""

import tempfile
import unittest
from copy import deepcopy
from pathlib import Path

from malloryapi._types import PaginatedResponse
from test_workflow_support import support


def example_report():
    """A valid assessment and unwritten finding using synthetic identities."""
    return {
        "schema_version": 1,
        "skill": "third-party-breach-monitor",
        "scope": {"roster": ["Example vendor"]},
        "window": None,
        "status": "complete",
        "summary": "A synthetic matched vendor",
        "results": [
            {
                "subject": "Example vendor",
                "verdict": "matched",
                "assessed_at": "2026-01-02T00:00:00Z",
                "evidence": [],
                "recommended_actions": [],
            }
        ],
        "coverage": {"examined": 1, "requested": 1, "gaps": []},
        "finding_actions": [
            {
                "identity": {
                    "tenant_uuid": "tenant",
                    "definition_tenant_uuid": "global",
                    "definition_slug": "breach",
                    "asset_type": "generic",
                    "asset_identifier": "Example vendor",
                    "qualifier": "breach-id",
                },
                "status": "not_requested",
            }
        ],
    }


class ReviewRegressionTests(unittest.TestCase):
    def test_assessment_time_requires_a_valid_utc_timestamp(self):
        """Missing, naive, non-UTC, and impossible assessment times are rejected."""
        for value in (
            None,
            "",
            "2026-01-02",
            "2026-01-02T00:00:00",
            "2026-01-02T01:00:00+01:00",
            "2026-02-30T00:00:00Z",
        ):
            report = example_report()
            if value is None:
                del report["results"][0]["assessed_at"]
            else:
                report["results"][0]["assessed_at"] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                support.validate_report(report)
        for value in ("2026-01-02T00:00:00Z", "2026-01-02T00:00:00.123456+00:00"):
            report = example_report()
            report["results"][0]["assessed_at"] = value
            support.validate_report(report)

    def test_coverage_requires_consistent_nonnegative_counts(self):
        """A complete label cannot hide missing or incomplete subject counts."""
        for coverage in (
            {"gaps": []},
            {"examined": -1, "requested": 1, "gaps": []},
            {"examined": True, "requested": 1, "gaps": []},
            {"examined": 2, "requested": 1, "gaps": []},
            {"examined": 0, "requested": 1, "gaps": []},
        ):
            report = example_report()
            report["coverage"] = coverage
            with self.subTest(coverage=coverage), self.assertRaises(ValueError):
                support.validate_report(report)
        report = example_report()
        report["custom_metadata"] = {"allowed": True}
        support.validate_report(report)

    def test_nested_records_are_validated_before_writing(self):
        """Malformed assessments and claimed writes cannot produce complete files."""
        report = example_report()
        result = report["results"][0]
        action = report["finding_actions"][0]
        cases = {
            "results": [
                {},
                "invalid",
                dict(result, verdict="cleared"),
                dict(result, verdict="affected"),
                dict(result, verdict="unchecked"),
                dict(result, evidence="not-a-list"),
            ],
            "finding_actions": [
                {},
                "invalid",
                dict(action, status="done"),
                dict(action, identity={}),
                dict(action, status="created"),
                dict(action, status="qualifies_but_not_filed"),
                dict(action, status="escalated", finding_uuid="id"),
            ],
        }
        for field, records in cases.items():
            for record in records:
                invalid = deepcopy(report)
                invalid[field] = [record]
                with (
                    self.subTest(field=field, record=record),
                    tempfile.TemporaryDirectory() as directory,
                ):
                    with self.assertRaises(ValueError):
                        support.write_report(invalid, Path(directory) / "report")
                    self.assertEqual(list(Path(directory).iterdir()), [])

    def test_returned_offsets_must_match_requested_page(self):
        """Unique rows cannot legitimize a response from the wrong SDK/raw page."""
        for raw in (False, True):

            def fetch(**kw):
                data = {
                    "items": [{"uuid": str(kw["offset"])}],
                    "total": 2,
                    "offset": 0,
                    "limit": 1,
                }
                return data if raw else PaginatedResponse(**data)

            with self.subTest(raw=raw):
                with self.assertRaises(support.CoverageError) as caught:
                    support.collect_pages(fetch, limit=1)
                self.assertEqual(caught.exception.items, [{"uuid": "0"}])
                self.assertEqual(caught.exception.offset, 1)

    def test_review_cap_records_first_unconsumed_offset(self):
        """A cap within a page resumes after the rows already retained."""
        with self.assertRaises(support.CoverageError) as caught:
            support.collect_pages(
                lambda **kw: {
                    "items": [{"uuid": str(i)} for i in range(10)],
                    "total": 10,
                },
                max_items=3,
            )
        self.assertEqual(len(caught.exception.items), 3)
        self.assertEqual(caught.exception.offset, 3)


if __name__ == "__main__":
    unittest.main()
