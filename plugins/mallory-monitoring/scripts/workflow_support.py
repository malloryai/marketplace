"""Portable artifact/pagination helpers. Mallory transport belongs to malloryapi."""

from __future__ import annotations

import argparse
import html
import json
from pathlib import Path


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
            rows, total, metadata = (
                page.get("items", page.get("data")),
                page.get("total"),
                page,
            )
        else:
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
                    "Review cap reached before exhaustion", items, offset
                )
        offset += len(rows)
        if offset == total:
            return items


def validate_report(report):
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
    if report["schema_version"] != 1 or report["status"] not in {
        "complete",
        "partial",
        "blocked",
    }:
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
    if report["status"] == "complete" and coverage["gaps"]:
        raise ValueError("A report with coverage gaps cannot be complete")
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
