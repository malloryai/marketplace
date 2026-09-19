---
name: story-based-tabletop-exercise
description: Use when a team wants a cybersecurity tabletop exercise based on recent threat intelligence, with timed injects, facilitator notes, and a debrief. For executable adversary testing, use adversary-emulation-planning instead.
---

# Story-based tabletop exercise

Produce a complete discussion exercise and a JSON source/coverage record. Read
[public runtime](../../references/runtime.md) and [output contract](../../references/output-contract.md).
Use `malloryapi==0.4.0`; no agent-server tool or mail service is required.

## Confirm the exercise

Reuse preferences already given. Resolve audience, relevant systems/business
context, workspace UUID or explicit topic/entity scope, lookback (default seven
days), and duration (default 30 minutes). A workspace's sources/entities/topics
are an OR scope, not a source-only restriction. Ask for a supported scope rather
than claiming source-only filtering. Missing environment details become explicit
fictional assumptions, not facts about the user. Run once unless recurrence was
requested separately. Scheduling/delivery use the host with saved configuration.

## Gather evidence with the SDK

Capture one UTC `end`; `start` is midnight UTC at the beginning of the configured
lookback. Resolve the workspace using `client.workspaces.list/get`. Retrieve the
20 most recently fresh stories within the confirmed scope:

```python
page = client.stories.list(limit=20, offset=0, sort='fresh_at', order='desc',
    fresh_at__gte=start, fresh_at__lt=end, workspace_uuids=workspace_uuid)
story = client.stories.get(story_uuid)
references = collect_pages(lambda **kw: client.stories.references(story_uuid, **kw))
reference = client.references.get(reference_uuid)
```

Follow pages until 20 unique stories or verified exhaustion; advance by actual
rows returned. If using explicit topics/entities, use verified filters from the
API reference and preserve their intended combination; no semantic search rank
as a substitute for recency. State that the 20-story review is bounded.

Read full story details and the strongest underlying references. Select one to
three compatible stories forming one coherent attack narrative. Analyze initial
access, attacker actions, affected technology, business impact and relevance to
the participants. Record titles, UUIDs, source links, publication/incident dates,
and freshness dates separately. Headlines alone do not support a scenario.

If no sufficiently detailed relevant evidence exists, return a coverage/result
record explaining the skip; do not invent a recent incident or silently widen
scope. A failed source read is incomplete coverage, not no relevant threats.

## Write the complete exercise

Create `tabletop-exercise.md` with:

1. Title beginning **EXERCISE — fictional scenario**, audience and duration.
2. Two or three learning objectives tied to the chosen threat.
3. A short sourced intelligence briefing separating reported facts from fiction.
4. Opening scenario: fictional organization/systems, symptoms and business stakes.
5. Three timed injects (default minutes 0, 10 and 20), each with new information,
   a decision, and discussion questions about detection, containment, communication
   or recovery. Scale timings proportionally to the confirmed duration.
6. Facilitator notes, expected decision considerations and evidence to seek.
7. Debrief, success criteria and follow-up actions with owner roles.
8. Source references and exact review window.

Also save `tabletop-review.json` using the shared envelope; each selected story
is a result with evidence/relevance. Put the verified exercise path in the report.
The Markdown is the whole exercise, not a short vignette. Fictional events never
produce findings. No active scans, exploits, real account changes, or emails are
part of generation. When delivery is separately authorized, send the finished
exercise only, check the receipt, and distinguish provider acceptance from inbox
delivery. Do not automatically resend after an ambiguous acknowledgment.
