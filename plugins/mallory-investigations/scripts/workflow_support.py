"""Portable artifact/pagination helpers. Mallory transport belongs to malloryapi."""

from __future__ import annotations

import argparse
import html
import json
import re
from datetime import datetime
from pathlib import Path

RESULT_VERDICTS = {
    "third-party-breach-monitor": {
        "matched",
        "no_matching_breaches",
        "linked_not_breached_party",
        "linked_role_unclear",
        "unchecked",
    },
    "technology-advisory-monitor": {
        "affected",
        "not_affected",
        "unresolved",
        "unchecked",
    },
    "exposure-validation": {"exposed", "not_exposed", "unverifiable", "unchecked"},
    "observable-investigation": {
        "malicious_opinion",
        "no_malicious_opinion",
        "unchecked",
    },
    "supply-chain-compromise-monitor": {
        "confirmed_component_exposure",
        "potential_match",
        "no_affected_version",
        "unchecked",
    },
    "compromised-package-scan": {
        "confirmed_component_exposure",
        "potential_match",
        "no_affected_version",
        "unchecked",
    },
    "story-based-tabletop-exercise": {"selected", "not_selected", "unchecked"},
    "daily-briefing": {"reported", "incomplete"},
}
FINDING_STATUSES = {
    "not_requested",
    "created",
    "already_open",
    "escalated",
    "suppressed_by_prior_resolution",
    "qualifies_but_not_filed",
}


class CoverageError(ValueError):
    """A listing was not exhausted; partial items are evidence, not an all-clear."""

    def __init__(self, message, items=(), offset=0):
        super().__init__(message)
        self.items = list(items)
        self.offset = offset


def collect_pages(fetch, *, limit=100, max_items=None, **params):
    """Collect a stable SDK page or raw relationship envelope; never silently cap.

    Pass a bound resource method, or a lambda binding a relationship identifier.
    Raises CoverageError with collected items/next offset for incomplete reads.
    Plain lists are accepted only as a single, explicitly unpaginated response.
    """
    if limit < 1 or (max_items is not None and max_items < 1):
        raise ValueError("limits must be positive")
    items, seen, offset, expected_total = [], set(), 0, None
    while True:
        try:
            page = fetch(limit=limit, offset=offset, **params)
        except Exception as exc:
            raise CoverageError(
                f"Listing failed at offset {offset}: {type(exc).__name__}",
                items,
                offset,
            ) from exc
        if isinstance(page, list):
            if offset:
                raise CoverageError(
                    "List response appeared during pagination", items, offset
                )
            rows, total, metadata = page, len(page), {}
        elif isinstance(page, dict):
            if "offset" in page and (
                type(page["offset"]) is not int or page["offset"] != offset
            ):
                raise CoverageError(
                    "Returned page offset does not match request", items, offset
                )
            rows, total, metadata = (
                page.get("items", page.get("data")),
                page.get("total"),
                page,
            )
        else:
            returned_offset = getattr(page, "offset", None)
            if type(returned_offset) is not int or returned_offset != offset:
                raise CoverageError(
                    "Returned page offset does not match request", items, offset
                )
            rows, total, metadata = (
                getattr(page, "items", None),
                getattr(page, "total", None),
                getattr(page, "metadata", {}),
            )
        if metadata.get("_truncation") or metadata.get("truncated"):
            raise CoverageError("Truncated listing", items, offset)
        if (
            not isinstance(rows, list)
            or not isinstance(total, int)
            or isinstance(total, bool)
            or total < 0
        ):
            raise CoverageError("Missing/malformed rows or total", items, offset)
        if expected_total is not None and total != expected_total:
            raise CoverageError(
                "Listing total changed during pagination", items, offset
            )
        expected_total = total
        if offset + len(rows) > total or (not rows and offset < total):
            raise CoverageError("Listing does not reconcile with total", items, offset)
        for row in rows:
            if not isinstance(row, dict):
                raise CoverageError("Malformed listing row", items, offset)
            identity = row.get("uuid") or json.dumps(row, sort_keys=True)
            if identity in seen:
                raise CoverageError("Repeated row during pagination", items, offset)
            seen.add(identity)
            items.append(row)
            if max_items is not None and len(items) >= max_items and len(items) < total:
                raise CoverageError(
                    "Review cap reached before exhaustion", items, len(items)
                )
        offset += len(rows)
        if offset == total:
            return items


def nonempty_string(value):
    """Return whether a field contains text rather than an empty value."""
    return isinstance(value, str) and bool(value.strip())


def validate_result(result, verdicts):
    """Validate an assessment before it can appear in a readable artifact."""
    required = {"subject", "verdict", "assessed_at", "evidence", "recommended_actions"}
    if not isinstance(result, dict) or required - result.keys():
        raise ValueError("Result is missing required fields")
    if (
        not nonempty_string(result["subject"])
        or not nonempty_string(result["verdict"])
        or result["verdict"] not in verdicts
    ):
        raise ValueError("Invalid result subject or verdict")
    timestamp = result["assessed_at"]
    if not isinstance(timestamp, str) or not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)", timestamp
    ):
        raise ValueError("Result assessed_at must be a UTC timestamp")
    datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    if not isinstance(result["evidence"], list) or not all(
        isinstance(item, (dict, str)) for item in result["evidence"]
    ):
        raise ValueError("Result evidence must be a list of objects or strings")
    if not isinstance(result["recommended_actions"], list) or not all(
        nonempty_string(item) for item in result["recommended_actions"]
    ):
        raise ValueError("Result recommended_actions must be a list of strings")


def validate_finding_action(action):
    """Require exact finding identity and distinguish verified writes from intentions."""
    if not isinstance(action, dict) or not {"identity", "status"} <= action.keys():
        raise ValueError("Finding action is missing identity or status")
    if (
        not nonempty_string(action["status"])
        or action["status"] not in FINDING_STATUSES
    ):
        raise ValueError("Invalid finding action status")
    identity = action["identity"]
    fields = {
        "tenant_uuid",
        "definition_tenant_uuid",
        "definition_slug",
        "asset_type",
        "asset_identifier",
    }
    if (
        not isinstance(identity, dict)
        or not (fields | {"qualifier"}) <= identity.keys()
    ):
        raise ValueError("Finding action is missing exact identity fields")
    if not all(nonempty_string(identity[field]) for field in fields) or not isinstance(
        identity["qualifier"], (str, type(None))
    ):
        raise ValueError("Invalid finding action identity")
    if action["status"] in {
        "created",
        "already_open",
        "escalated",
    } and not nonempty_string(action.get("finding_uuid")):
        raise ValueError("Verified finding action requires finding_uuid")
    if action["status"] == "escalated" and not all(
        isinstance(action.get(field), dict) and action[field]
        for field in ("before", "after")
    ):
        raise ValueError("Escalated finding requires before and after values")


def validate_report(report):
    """Validate version-one evidence, coverage, and actions; allow extra metadata."""
    required = {
        "schema_version",
        "skill",
        "scope",
        "window",
        "status",
        "summary",
        "results",
        "coverage",
        "finding_actions",
    }
    if not isinstance(report, dict) or required - report.keys():
        raise ValueError("Report is missing required envelope fields")
    if (
        type(report["schema_version"]) is not int
        or report["schema_version"] != 1
        or not isinstance(report["status"], str)
        or report["status"]
        not in {
            "complete",
            "partial",
            "blocked",
        }
    ):
        raise ValueError("Invalid report version or status")
    if not isinstance(report["skill"], str) or not isinstance(report["summary"], str):
        raise ValueError("skill and summary must be strings")
    if (
        not isinstance(report["scope"], dict)
        or not isinstance(report["results"], list)
        or not isinstance(report["finding_actions"], list)
    ):
        raise ValueError("Invalid scope, results, or finding_actions")
    coverage = report["coverage"]
    if not isinstance(coverage, dict) or not isinstance(coverage.get("gaps"), list):
        raise ValueError("coverage.gaps must be a list")
    for field in ("examined", "requested"):
        if type(coverage.get(field)) is not int or coverage[field] < 0:
            raise ValueError(f"coverage.{field} must be a nonnegative integer")
    if coverage["examined"] > coverage["requested"]:
        raise ValueError("Examined coverage exceeds requested coverage")
    if report["status"] == "complete" and coverage["gaps"]:
        raise ValueError("A report with coverage gaps cannot be complete")
    if report["status"] == "complete" and coverage["examined"] != coverage["requested"]:
        raise ValueError("A complete report must examine every requested subject")
    verdicts = RESULT_VERDICTS.get(
        report["skill"], set().union(*RESULT_VERDICTS.values())
    )
    for result in report["results"]:
        validate_result(result, verdicts)
    for action in report["finding_actions"]:
        validate_finding_action(action)
    if report["status"] == "complete" and (
        any(
            result["verdict"]
            in {
                "unchecked",
                "incomplete",
                "unresolved",
                "unverifiable",
                "linked_role_unclear",
            }
            for result in report["results"]
        )
        or any(
            action["status"] == "qualifies_but_not_filed"
            for action in report["finding_actions"]
        )
    ):
        raise ValueError("Incomplete assessments or filing gaps cannot be complete")
    if report["window"] is not None and (
        not isinstance(report["window"], dict)
        or not {"start", "end"} <= report["window"].keys()
    ):
        raise ValueError("window must be null or contain start and end")
    return report


def write_report(report, output_prefix, *, html_output=False):
    """Write the exact JSON evidence plus Markdown and optionally escaped HTML."""
    validate_report(report)
    prefix = Path(output_prefix)
    prefix.parent.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(report, indent=2, ensure_ascii=False, allow_nan=False)
    lines = [
        f"# {report['skill']}",
        "",
        f"Status: **{report['status']}**",
        "",
        report["summary"],
        "",
        "## Scope",
        "",
    ]
    for key, value in report["scope"].items():
        lines.append(f"- **{key.replace('_', ' ')}:** {value}")
    if report["window"]:
        lines.extend(
            [
                "",
                f"Review window: {report['window']['start']} to {report['window']['end']} (end exclusive).",
            ]
        )
    for result in report["results"]:
        lines.extend(
            [
                "",
                "## " + str(result.get("subject", "Result")),
                "",
                "**Verdict:** " + str(result.get("verdict", "reported")),
                "",
                "Assessed at: " + result["assessed_at"],
                "",
            ]
        )
        if result.get("summary"):
            lines.extend([str(result["summary"]), ""])
        for evidence in result.get("evidence", []):
            if isinstance(evidence, dict):
                title = next(
                    (
                        evidence.get(key)
                        for key in ("title", "display_name", "name", "cve_id", "uuid")
                        if evidence.get(key)
                    ),
                    "Evidence",
                )
                lines.append(f"- **{title}**")
                for key in (
                    "uuid",
                    "source_url",
                    "url",
                    "fresh_at",
                    "created_at",
                    "description",
                    "summary",
                ):
                    if evidence.get(key):
                        lines.append(f"  - {key}: {evidence[key]}")
            else:
                lines.append(f"- {evidence}")
        if not result.get("evidence"):
            lines.append(
                "No evidence records in this section; see the verdict and coverage below."
            )
        for action in result.get("recommended_actions", []):
            lines.append(f"- Recommended action: {action}")
    lines.extend(["", "## Coverage", ""])
    for key, value in report["coverage"].items():
        lines.append(f"- **{key.replace('_', ' ')}:** {value}")
    lines.extend(["", "## Finding actions", ""])
    if report["finding_actions"]:
        for action in report["finding_actions"]:
            lines.append("- " + json.dumps(action, ensure_ascii=False))
    else:
        lines.append("No finding writes were performed.")
    lines.extend(
        ["", "Full structured evidence is preserved in the accompanying JSON file.", ""]
    )
    markdown = "\n".join(lines)
    paths = {"json": str(prefix) + ".json", "markdown": str(prefix) + ".md"}
    Path(paths["json"]).write_text(encoded + "\n", encoding="utf-8")
    Path(paths["markdown"]).write_text(markdown, encoding="utf-8")
    if html_output:
        paths["html"] = str(prefix) + ".html"
        document = (
            '<!doctype html><html lang="en"><meta charset="utf-8"><title>'
            + html.escape(report["skill"])
            + "</title><style>body{max-width:960px;margin:3rem auto;padding:0 1rem;font:16px system-ui}pre{white-space:pre-wrap;overflow-wrap:anywhere;line-height:1.5}</style><body><pre>"
            + html.escape(markdown)
            + "</pre></body></html>"
        )
        Path(paths["html"]).write_text(document, encoding="utf-8")
    return paths


def main():
    """Render a caller-owned JSON assessment without making API requests."""
    parser = argparse.ArgumentParser(
        description="Render a workflow JSON result as Markdown and optional HTML; no API calls."
    )
    parser.add_argument("input", type=Path)
    parser.add_argument("--output-prefix", required=True)
    parser.add_argument("--html", action="store_true")
    args = parser.parse_args()
    report = json.loads(args.input.read_text(encoding="utf-8"))
    print(json.dumps(write_report(report, args.output_prefix, html_output=args.html)))


if __name__ == "__main__":
    main()
