# Workflow output contract (version 1)

Produce a concise readable answer and save a JSON artifact with these fields:

```json
{
  "schema_version": 1,
  "skill": "third-party-breach-monitor",
  "scope": {"roster": ["Example vendor"]},
  "window": {"start": "2026-01-01T00:00:00Z", "end": "2026-01-02T00:00:00Z"},
  "status": "partial",
  "summary": "One company could not be checked.",
  "results": [{"subject": "Example vendor", "verdict": "unchecked", "evidence": [], "recommended_actions": ["Retry the failed lookup"]}],
  "coverage": {"examined": 0, "requested": 1, "gaps": ["Organization lookup unavailable"]},
  "finding_actions": []
}
```

This is a synthetic shape example, not real intelligence. `scope` carries the
confirmed workspace/roster/profiles/repositories and authenticated tenant UUID
when relevant. `window` is null for specified-advisory or supplied-SBOM requests
without a time window. An assessment timestamp belongs in each result.

Each result identifies its subject, verdict, supporting evidence (actual SDK
method/parameters, record IDs, source links, relevant returned values and dates),
and recommended actions. Use the workflow's verdict vocabulary. Include every
requested subject, including unchecked ones; a negative means only the stated
scope and evidence were checked. Do not invent links, IDs or receipts.

`finding_actions` contains the exact identity and `not_requested`, `created`,
`already_open`, `escalated`, `suppressed_by_prior_resolution`, or
`qualifies_but_not_filed`, verified UUID/link if available, and before/after
values for escalation. Report-only matching results use `not_requested`.

- **complete:** all promised checks completed for the declared scope.
- **partial:** useful work completed but unresolved evidence, failed reads,
  unreviewed records, required missing fields or requested write/delivery gaps remain.
- **blocked:** no useful assessment could run due to missing prerequisites.

Never emit complete with coverage gaps. Limits are visible: a deliberately
bounded tabletop's 20-story selection is its scope; a capped exhaustive
inventory assessment is partial. An empty complete result is distinct from a
failed query. Keep evidence concise enough to read; large raw input stays in
separate files with verified paths.

Render the JSON artifact with the bundled helper, using the installed plugin's
absolute root and a caller-selected output directory:

```bash
python "$PLUGIN_ROOT/scripts/workflow_support.py" result.json --output-prefix output/review
# Add --html for a dependency-free, escaped HTML copy.
```

The helper makes Markdown and preserves the exact JSON. Tabletop additionally
writes the complete exercise Markdown (not just a report summary). Briefings
also emit HTML. Never claim files exist before writing and checking them.
