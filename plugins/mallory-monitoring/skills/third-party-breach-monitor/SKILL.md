---
name: third-party-breach-monitor
description: Use when checking whether named vendors, suppliers, partners, or acquisition targets were breached, or monitoring a confirmed company roster for new breach intelligence. A breach at a vendor does not establish compromise of the caller.
---

# Third-party breach monitor

Read [runtime](../../references/runtime.md), [outputs](../../references/output-contract.md),
and [optional findings](../../references/finding-lifecycle.md). All reads use
`malloryapi==0.4.0`; connected provider integrations are unnecessary.

## Scope and saved roster

Confirm the roster before a monitoring setup. Workspace stars may seed a list
only if the user confirms it. Resolve names through `client.search.query(q=name,
types='organization')`; fall back to `client.organizations.list(filter='name:'+name)`
when search has not indexed a new organization. SDK parameters handle URL encoding.
Ask about ambiguous matches; preserve unresolved companies as unchecked.

Save unique, stable caller roster labels, canonical organization UUID/name and
unresolved markers in caller-owned JSON. Labels identify findings and must not
silently change on company rename. A one-time historical question searches all
history unless a range was supplied; do not answer it from a 24-hour window.
Monitoring uses a fixed UTC window since each company's previous completed
checkpoint, or the last 24 hours on its first run.

## Check every company

Resolve the canonical survivor before requesting relationships:

```python
def resolve_survivor(fetch, initial_uuid):
    """Verify each identity and return the final record plus its merge chain."""
    current, visited, chain = str(initial_uuid), set(), []
    for _ in range(4):  # Initial record plus at most three merge hops.
        if current in visited:
            raise ValueError('Merge cycle')
        visited.add(current)
        record = fetch(current)
        if not record.get('uuid') or str(record['uuid']) != current:
            raise ValueError('Merge target identity could not be verified')
        chain.append(current)
        successor = record.get('merged_into_uuid')
        if not successor:
            return record, chain
        current = str(successor)
    raise ValueError('Merge chain exceeds three hops')

organization, organization_chain = resolve_survivor(
    client.organizations.get, organization_uuid)
survivor_uuid = organization['uuid']
breaches = collect_pages(lambda **kw: client.organizations.breaches(
    survivor_uuid, sort='created_at', order='desc', **kw))
canonical_breaches = []
for row in breaches:
    breach, breach_chain = resolve_survivor(client.breaches.get, row['uuid'])
    canonical_breaches.append({'breach': breach, 'merge_chain': breach_chain})
```

Catch resolution failures per company/breach: a cycle, unreadable record,
unverified target or unfinished merge makes that subject unchecked. Do not query
the tombstone and call an empty result clean. Report changed canonical identifiers
and keep predecessor/survivor chains with the stable roster label. On
`CoverageError`, preserve its `items` and `offset`, assess available evidence as
partial, and keep the company unchecked with its prior checkpoint. Continue
independent companies; do not label an incomplete relationship read clean.

Use the breach record's **created_at** for monitoring: when Mallory learned of
it, not occurrence or publication. Filter the exhausted descending collection
locally to the fixed window (an optimized walk may stop only once every later
row is provably older). Keep old incidents ingested today. Read breach details:
a relation alone does not prove victimhood. A responder, journalist or software
vendor mentioned in someone else's breach is not automatically breached.

Emit one verdict for every roster entry:
- `matched`: evidence explicitly identifies the company as breached.
- `no_matching_breaches`: successful complete read, no qualifying breach.
- `linked_not_breached_party`: evidence establishes another role.
- `linked_role_unclear`: insufficient evidence to establish victimhood.
- `unchecked`: resolution/query/pagination failed or was not reached.

Include each matching breach separately. Uncertain roles remain visible without
creating findings. Tenant impact is a recommended follow-up, not a requirement
to report an established vendor breach. One company's failure does not stop the
others; complete is impossible when requested companies remain unchecked.

## Findings and checkpoint

Only when explicitly requested, use definition `intel.breach.third_party_breached`,
`asset_type='generic'`, stable roster label as `asset_identifier`, and canonical
breach UUID as `qualifier`. Check history against predecessor and survivor UUIDs
when a breach merged. Preserve dismissals/fixed history; link exact open findings.
Severity HIGH, raised to CRITICAL for supported ransomware/credential-loss evidence;
confidence high only when the company is established as the victim. Retain the
roster label, resolved UUID, breach detail, dates, source and victim-role proof.

Advance a company's checkpoint only after its full window was reviewed and all
requested finding writes succeeded, linked or were deliberately suppressed.
Unchecked or matched-but-not-filed companies keep their prior checkpoint.
Save checkpoints per company; a global last-run timestamp loses failed intervals.
With report-only mode, successful assessed matches may advance without Findings
access. Report unknown roles and any resulting unresolved work explicitly.

Write `vendor-breach-review.json` and `.md`; include every company's verdict,
checkpoints, merge changes, evidence, follow-up and finding action. Save state
only after the report is safely written. Delivery and scheduling are separate
host actions, performed only when requested.
