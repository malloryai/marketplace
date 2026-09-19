#!/usr/bin/env python3
"""Workspace briefing via malloryapi 0.4.0; local artifacts/state, no delivery or writes."""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path

from malloryapi import MalloryApi

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "scripts"))
from workflow_support import CoverageError, collect_pages, write_report


def utc(value):
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("Checkpoint must include a timezone")
    return parsed.astimezone(timezone.utc)


def collect_workspace(client, workspace_uuid, *, state=None, now=None):
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise ValueError("Assessment time must include a timezone")
    end = now.astimezone(timezone.utc).isoformat()
    default_start = (now - timedelta(days=1)).isoformat()
    workspace = client.workspaces.get(workspace_uuid)
    if workspace.get("uuid") != workspace_uuid or not workspace.get("tenant_uuid"):
        raise ValueError("Workspace identity could not be verified")
    tenant_uuid = workspace["tenant_uuid"]
    if state is not None:
        if (
            state.get("schema_version") != 1
            or state.get("workspace_uuid") != workspace_uuid
            or state.get("tenant_uuid") != tenant_uuid
        ):
            raise ValueError("State belongs to another workspace/tenant or schema")
        if not isinstance(state.get("checkpoints"), dict):
            raise ValueError("Malformed checkpoint state")
        if "matched_story_ids" in state and (
            not isinstance(state["matched_story_ids"], list)
            or not all(isinstance(x, str) for x in state["matched_story_ids"])
        ):
            raise ValueError("Malformed matched-story baseline")
    previous = state or {
        "schema_version": 1,
        "workspace_uuid": workspace_uuid,
        "tenant_uuid": tenant_uuid,
        "checkpoints": {},
    }
    next_state = deepcopy(previous)
    sections, gaps, windows = {}, [], {}

    def read(name, fetch, **params):
        try:
            rows = collect_pages(fetch, **params)
        except CoverageError as exc:
            gaps.append(f"{name}: {exc}")
            sections[name] = exc.items
            return False
        if any(not row.get("uuid") for row in rows):
            gaps.append(f"{name}: a row has no UUID")
            sections[name] = rows
            return False
        sections[name] = rows
        next_state["checkpoints"][name] = end
        return True

    def start_for(name):
        start = previous["checkpoints"].get(name, default_start)
        if utc(start) > now:
            raise ValueError(f"{name} checkpoint is in the future")
        windows[name] = {"start": start, "end": end}
        next_state["checkpoints"].setdefault(name, start)
        return start

    read(
        "stories",
        client.stories.list,
        workspace_uuids=workspace_uuid,
        fresh_at__gte=start_for("stories"),
        fresh_at__lt=end,
        sort="fresh_at",
        order="desc",
    )
    # These are tenant-wide datasets: do not invent workspace filters.
    read(
        "new_findings",
        client.findings.list,
        created_at__gte=start_for("new_findings"),
        created_at__lt=end,
        sort="created_at",
        order="asc",
    )
    read(
        "exploited_vulnerabilities",
        client.vulnerabilities.list,
        first_exploitation_at__gte=start_for("exploited_vulnerabilities"),
        first_exploitation_at__lt=end,
        matched_asset_count__gt=0,
        sort="created_at",
        order="desc",
    )

    # No freshness bound: an older story can acquire its first asset match today.
    complete_matches = read(
        "matches",
        client.stories.list,
        workspace_uuids=workspace_uuid,
        matched_asset_count__gt=0,
        sort="fresh_at",
        order="desc",
    )
    sections["newly_matched_stories"] = []
    if complete_matches:
        if "matched_story_ids" in previous:
            prior_ids = set(previous["matched_story_ids"])
            sections["newly_matched_stories"] = [
                row for row in sections["matches"] if row["uuid"] not in prior_ids
            ]
        next_state["matched_story_ids"] = sorted(
            {row["uuid"] for row in sections["matches"]}
        )
    sections.pop(
        "matches"
    )  # Only the compact ID baseline persists; don't duplicate all historical stories.

    # Prefer demonstrated asset relevance, then freshness, inside the matched workspace.
    def story_rank(row):
        count = row.get("matched_asset_count")
        return (
            count if isinstance(count, (int, float)) else 0,
            row.get("fresh_at") or "",
        )

    sections["stories"] = sorted(sections["stories"], key=story_rank, reverse=True)[:5]
    match_baseline = (
        "baseline_recorded"
        if complete_matches and "matched_story_ids" not in previous
        else "compared"
        if complete_matches
        else "unchecked"
    )
    results = []
    for name in (
        "new_findings",
        "newly_matched_stories",
        "exploited_vulnerabilities",
        "stories",
    ):
        results.append(
            {
                "subject": name,
                "verdict": "incomplete"
                if any(gap.startswith(name + ":") for gap in gaps)
                or (name == "newly_matched_stories" and not complete_matches)
                else "reported",
                "count": len(sections[name]),
                "evidence": sections[name],
                "recommended_actions": [],
            }
        )
    report = {
        "schema_version": 1,
        "skill": "daily-briefing",
        "scope": {
            "workspace_uuid": workspace_uuid,
            "tenant_uuid": tenant_uuid,
            "stories": "workspace followed entities/topics/sources",
            "findings_and_vulnerabilities": "tenant-wide",
        },
        "window": {
            "start": min((w["start"] for w in windows.values()), key=utc),
            "end": end,
        },
        "section_windows": windows,
        "status": "partial" if gaps else "complete",
        "summary": f"{len(sections['new_findings'])} new findings; {len(sections['newly_matched_stories'])} newly matched stories; {len(sections['exploited_vulnerabilities'])} newly exploited asset-matched vulnerabilities; {len(sections['stories'])} selected stories. Match state: {match_baseline}.",
        "results": results,
        "sections": sections,
        "coverage": {"gaps": gaps, "match_baseline": match_baseline},
        "finding_actions": [],
    }
    return report, next_state


def save_state(path, state):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=path.parent,
        prefix=path.name + ".",
        delete=False,
    ) as stream:
        temporary = Path(stream.name)
        json.dump(state, stream, indent=2, allow_nan=False)
        stream.write("\n")
    try:
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True)
    parser.add_argument(
        "--state",
        type=Path,
        required=True,
        help="Dedicated state file per workspace and API environment",
    )
    parser.add_argument("--output-prefix", default="daily-briefing")
    args = parser.parse_args()
    # State is caller-owned; malformed state is an error, never silently reset.
    state = json.loads(args.state.read_text()) if args.state.exists() else None
    with MalloryApi() as client:
        report, next_state = collect_workspace(client, args.workspace, state=state)
    paths = write_report(report, args.output_prefix, html_output=True)
    save_state(
        args.state, next_state
    )  # Report persisted before any successful checkpoint advances.
    print(
        json.dumps(
            {"artifacts": paths, "status": report["status"], "state": str(args.state)}
        )
    )
    return 0 if report["status"] == "complete" else 2


if __name__ == "__main__":
    raise SystemExit(main())
