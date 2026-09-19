---
name: observable-investigation
description: Use when reviewing tenant observable sightings against existing malicious opinions, optionally filing findings, or investigating the evidence of a resulting finding. Covers exact canonical domains, IPs, hashes, URIs, endpoints and certificate thumbprints.
---

# Observable investigation

Read [runtime](../../references/runtime.md), [outputs](../../references/output-contract.md)
and [finding lifecycle](../../references/finding-lifecycle.md). All baseline
reads use `malloryapi==0.4.0`; no provider connection is required.

## Scope and identity

Run once over a fresh fixed last-24-hours UTC receipt window, with all sighting
sources or an explicit exact source. Use `created_at` (receipt), not `matched_at`
(occurrence), to select the review. Resolve authenticated tenant UUID from a
readable workspace returned by `client.workspaces.list(limit=1, sort='created_at',
order='asc')`; never infer it from a sighting or accept an arbitrary tenant input.
If no authoritative tenant is available, report blocked.

Default to report-only; finding requests enable the lifecycle below. A follow-up
about an existing finding continues from its evidence rather than restarting the
24-hour sweep. A new explicit review captures a new window even in the same chat.

## Read sightings and opinions

```python
sightings = collect_pages(client.sightings.list, limit=100, max_items=1000,
    created_at__gte=start, created_at__lt=end, source=source)
opinions = client.observables.opinions(observable_uuid,
    verdict='malicious', limit=1, offset=0, sort='uuid', order='desc')
```

Use CoverageError's partial rows/offset when the cap or a read fails. Report
unread records; reserve time for output and any writes. Group by the exact
canonical `(observable_type, observable_name)` and require consistent observable
UUIDs. Preserve type/name byte-for-byte. Never extract a domain from a URI,
normalize away ports, fuzzy-match names, or treat a related identity as exact.
Validate tenant/identity fields and retain malformed records as unchecked.

Query one malicious opinion per exact observable UUID. Omit scope so global and
current-tenant opinions remain visible. Verify returned identity/visibility and
verdict. One stored visible malicious opinion qualifies; it is not consensus,
proof of compromise, or a guarantee that the opinion is current. Preserve source,
age, confidence and conflicting evidence when returned.

A valid filtered response with total zero means `no_malicious_opinion`. A failed,
malformed or truncated response is `unchecked`. Do not visit observable/evidence
URLs, submit samples, create opinions/sightings, or substitute external enrichment
for the stored-opinion assessment. Optional follow-up investigation is separately
requested, happens after baseline assessment, and uses the same exact identity.

## Optional finding lifecycle

Use `malicious-observable-sighting`, global definition, `asset_type='generic'`,
exact canonical name as identifier and exact canonical type as qualifier.
Sighting/source/opinion UUIDs are evidence, not dedupe keys.

- Exact open row: link unchanged.
- Exact dismissed row: suppress; never auto-reopen.
- Exact fixed row: use the latest closed row's `updated_at` as the conservative
  resolution boundary. Only a qualifying sighting with `matched_at` strictly
  later may recur. Recent ingestion of an old occurrence or a new opinion does
  not qualify. Apply per occurrence when old/new sightings share an identity.
- No exact history after full reads, or established fixed recurrence: create.

Severity HIGH, confidence medium. Include representative sightings, their
count/omitted count, source, external ID, occurrence/receipt times; selected opinion
UUID, owner, verdict, confidence, dates and description; and assessment time.
Recommended actions recover original events and assess hosts, direction,
blocked/successful activity and false positives. No response action is automatic.

Write `observable-review.json` and `.md`: exact verdicts, examined counts,
findings created/linked/suppressed/not requested/unfiled, and unread/unchecked
coverage. Finding writes use SDK detail responses and error handling from the
shared lifecycle. Unavailable Findings does not block report-only assessment.
