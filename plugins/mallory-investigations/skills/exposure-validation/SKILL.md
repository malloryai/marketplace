---
name: exposure-validation
description: Use when checking newly exploited vulnerabilities or KEV entries against the caller's assets, assessing their reachability, or creating evidence-backed exposure findings and recommending escalations. Malicious package releases use supply-chain-compromise-monitor instead.
---

# Exploited-CVE exposure validation

Read [runtime](../../references/runtime.md), [outputs](../../references/output-contract.md)
and [findings](../../references/finding-lifecycle.md). Use `malloryapi==0.4.0`.
This assesses exposure, not whether the tenant has been compromised.

## Select the queue

Capture fixed UTC start/end from explicit scope or the last completed checkpoint,
else the last 24 hours. Keep that exact window until its work is complete. Fetch
exploitation events, not CVEs created recently:

```python
coverage_gaps = []

def read_all(scope, fetch, **params):
    """Exhaust a collection while retaining partial evidence and failure offsets."""
    try:
        return collect_pages(fetch, **params), True
    except CoverageError as exc:
        coverage_gaps.append({
            'scope': scope, 'reason': str(exc),
            'partial_items': exc.items, 'offset': exc.offset,
        })
        return exc.items, False

events, events_complete = read_all('exploitation_events',
    client.exploitations.list,
    filter=f'begins_at>={start}', sort='begins_at', order='asc')
```

Bound event rows locally to `begins_at < end`. Read each event's detail with
`client.exploitations.get(event_uuid)` to obtain `vulnerability_uuid`,
`vulnerability_cve_id` and source evidence; the list model may omit these fields.
Unresolved identities or detail failures remain queued gaps. A Mallory story is
not an entry gate.

Persist a caller-owned queue with `window.start/end`, `completed_event_uuids`,
and `pending` jobs containing canonical vulnerability UUID/CVE, event UUIDs,
earliest exploitation time, and `last_attempt` (null until first attempted).
Keep unresolved event IDs separately for identity retries. Scope state to the
same authenticated tenant and caller-selected inventory; reject other scopes.

1. At every execution, list the **entire same window from offset zero** and merge
   discovered event UUIDs into the saved queue. Persist `CoverageError.items` and
   `offset` in the report, but do not resume a mutable listing at that offset or
   interpret its partial rows as the full queue. Previously queued work survives
   an incomplete read. A failed event listing prevents completing the window,
   even if every event seen so far was reviewed.
2. Exclude `completed_event_uuids`, then group remaining events by canonical
   vulnerability identity. New event IDs for an already reviewed CVE form new
   pending work. Review at most 20 distinct CVEs per execution. Select never
   attempted jobs first, then least recently attempted retries; use earliest
   exploitation time and CVE as deterministic tie-breakers. Persist the attempt
   order so one repeatedly failing group cannot starve unattempted CVEs.
3. After a CVE's full evidence review and any requested filing have succeeded,
   been verified as already open, or been deliberately suppressed by history,
   add its reviewed event UUIDs to `completed_event_uuids`. Save these IDs only
   after the corresponding artifacts and write outcomes are durable. Failed or
   incomplete jobs retain their event UUIDs for retry, with the new `last_attempt`.
4. Advance the completed checkpoint to `end` only after a complete event listing,
   no unresolved event IDs, and no pending jobs or coverage gaps. Then clear the
   finished window's queue. Do not advance to an earliest pending timestamp:
   completed IDs, not timestamp alone, distinguish more than 20 tied CVEs.

For example, 25 CVEs sharing one timestamp leave five pending after the first
20 succeed; the next execution skips their completed event IDs and reviews the
remaining five. A failed job is retained and retried without replaying those
20 successes or skipping unseen rows after a partial listing.

## Assess each CVE and asset

```python
vulnerability = client.vulnerabilities.get(cve)
presence = client.assets.exposure_check({
    'entities': [{'type':'vulnerability', 'identifier':cve}]
})
references, references_complete = read_all(f'{cve}:mentions',
    lambda **kw: client.vulnerabilities.mentions(cve, **kw))
stories, stories_complete = read_all(f'{cve}:stories', client.stories.list,
    topic_group='active-exploitation', filter='search:'+cve)
```

1. **Presence:** inspect affected asset families in the exposure response and
   inventory details. A version inside the affected range yields high confidence;
   established software presence with unknown version is medium. Confirmed
   outside-range assets do not qualify. A name resemblance alone does not pass.
   A failed/unpopulated inventory is unverifiable, not absent. Record the exact
   SDK query and returned asset/version evidence.
2. **Materiality:** retain the actual exploitation record/source and time.
3. **Reachability:** use available authorized code/cloud evidence to determine
   `reachable_exposed`, `reachable`, `not_reachable`, or `not_assessable`.
   Record queried evidence or the precise missing capability. Public 0.4.0 lacks
   general cached/live SQL query methods; do not use private transport or invent
   a cache-query client. Use existing host-connected provider tools if authorized,
   or return not_assessable. Presence checks remain useful without these tools.

Read full story matches with `client.stories.get(story_uuid)` and their relevant
reference evidence. Ambiguous stories require matching reference evidence; no
story is not a reason to skip exposure. Both mentions and story collections must
be exhausted, including when evidence appears on later pages. Preserve partial
rows and the failing offset from either read. A failed detail read is also a
coverage gap. Continue independent CVEs, but keep this CVE pending, label its
assessment partial, and withhold finding writes until its required evidence
review is complete. Only a successful complete empty read supports no
corroboration; a failed or capped collection does not.

| Reachability | Without corroborating story | With story |
| --- | --- | --- |
| reachable_exposed | CRITICAL | CRITICAL |
| reachable | HIGH | CRITICAL |
| not_reachable | MEDIUM | HIGH |
| not_assessable | CRITICAL | CRITICAL |

Unknown reachability stays conservative. Confidence follows presence only;
story coverage does not increase it. Clearly disclose these prioritization rules.

## Findings, continuation and output

Default to report-only. With writes authorized, use definition
`intel.vuln.exploited_cve_validated`, canonical asset type/identifier and CVE
qualifier, one finding per asset/CVE. Link verified vulnerability/story UUIDs and
include evidence for each gate. Preserve closed decisions. For an exact open
finding with stronger new evidence, report the proposed severity/confidence
increase and retain its existing body and values in the recommendation. Do not
PATCH: 0.4.0 provides no server-side conditional or monotonic update operation,
so a stale read can overwrite another writer's evidence. Record
`qualifies_but_not_filed` with `atomic_escalation_unavailable` when writes were
requested and keep that job pending. An exact open finding already meeting the
assessment can be linked as `already_open`. See the shared finding lifecycle;
this limitation preserves report-only assessment and authorized new creates.

Save `exploitation-review.json` and `.md` with reviewed CVEs, assets, gates,
severity/confidence, finding actions, skip reasons and incomplete work. Each
result includes UTC `assessed_at` and a verdict: `exposed` for supported software
presence satisfying the gates, `not_exposed` for a complete assessment ruling it
out, `unverifiable` for attempted but insufficient evidence, or `unchecked` for
pending work not yet assessed. Keep reachability separate from this verdict.
Save caller-owned queue/checkpoint JSON only after artifacts/writes are accounted
for. A cap, incomplete event/mention/story read, unresolved presence or requested
filing failure retains the frozen window and affected pending jobs. Record
successful event IDs so repeated capped executions still make progress.
Report-only does not require Findings access.
No active exploitation, remediation, schedule or delivery is part of assessment.
