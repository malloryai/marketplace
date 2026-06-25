---
name: actor-tactic-timeline
description: Chart how a threat actor's TTPs change over time by placing their observed MITRE ATT&CK attack patterns on a timeline. Use to track tactic evolution, spot emerging techniques, or detect shifts in an actor's playbook.
allowed-tools: Bash(python *), Bash(python3 *), Bash(uv *), Bash(pip *)
---

# Actor Tactic Timeline

You are a threat intelligence analyst studying how an adversary's behavior
evolves. This skill pulls every ATT&CK attack-pattern **observation** Mallory
has attributed to a threat actor, places those observations on a timeline, and
reveals how the actor's tactic mix shifts period to period — which techniques
**emerge**, which **recur**, and which **fade**.

Each observation is a dated, cited record: a technique (`mitre_attack_id`), the
source reference that reported it, and the context. The skill enriches each
technique with its MITRE ATT&CK tactic (kill-chain phase) so you can reason at
the tactic level, not just technique-by-technique.

## When to Use

- Track how an actor's tactics have changed over months or quarters
- Detect a shift in playbook (e.g. a move toward ransomware/impact, or new lateral-movement tooling)
- Identify techniques that newly emerged in a recent period
- Build an evidence-backed narrative of an actor's evolution for a report
- Compare an actor's early vs. recent tradecraft

## Prerequisites

Install the SDK and set your key (see the **mallory-api** skill for details):

```bash
uv pip install --system --upgrade malloryapi
export MALLORY_API_KEY=sk-...
```

## Usage

Run the timeline script. It accepts a threat-actor **name or UUID**:

```bash
# Quarterly timeline, JSON (default) — machine-readable
python ${CLAUDE_PLUGIN_ROOT}/skills/actor-tactic-timeline/scripts/tactic_timeline.py "ShinyHunters"

# Monthly cadence, human-readable report with a tactic-over-time matrix
python ${CLAUDE_PLUGIN_ROOT}/skills/actor-tactic-timeline/scripts/tactic_timeline.py "Scattered Spider" --period month --format markdown

# Anchor the timeline to when Mallory OBSERVED each record instead of source
# publication dates (faster, but reflects ingest order, not real chronology)
python ${CLAUDE_PLUGIN_ROOT}/skills/actor-tactic-timeline/scripts/tactic_timeline.py "APT28" --date-source observed

# Skip tactic enrichment for a fast technique-only pass
python ${CLAUDE_PLUGIN_ROOT}/skills/actor-tactic-timeline/scripts/tactic_timeline.py "Qilin" --no-tactics
```

### Options

| Flag | Default | Meaning |
|------|---------|---------|
| `--period {month,quarter,year}` | `quarter` | Time-bucket granularity |
| `--date-source {observed,published}` | `published` | `published` = source publication date (accurate, one fetch per reference); `observed` = when Mallory recorded the observation (fast) |
| `--format {json,markdown}` | `json` | Output format |
| `--top N` | `10` | Max techniques shown per period (markdown) |
| `--max-observations N` | `5000` | Cap on observations pulled |
| `--no-tactics` | off | Skip ATT&CK tactic enrichment (faster) |

### Output

- **JSON** (default): `actor`, `total_observations`, `periods[]` (each with
  `observation_count`, `distinct_techniques`, per-tactic counts, `top_techniques`,
  and `emerging_techniques` first seen in that period), plus a `tactic_matrix`
  (tactic × period counts) for charting.
- **Markdown**: a tactic-emphasis matrix across periods followed by per-period
  detail highlighting newly emerging and most-observed techniques.

## Analysis Workflow

1. **Resolve the actor** — pass the common name; the script resolves it via
   `threat_actors.get` and falls back to search.
2. **Pull observations** — every attack-pattern observation, paginated.
3. **Enrich** — map techniques to ATT&CK tactics; optionally resolve source
   publication dates.
4. **Bucket & aggregate** — group by period; flag first-seen techniques.
5. **Interpret the shift** — read the tactic matrix for emphasis changes
   (e.g. rising `impact` = ransomware pivot; new `lateral-movement` = expanded
   intrusion depth) and call out emerging techniques with their citations.
6. **Cite** — every technique traces to a `reference_url`; ground claims in
   sources rather than asserting evolution without evidence.

## Caveats

- The timeline defaults to source **publication** dates for real-world
  chronology. The `--date-source observed` axis is faster but reflects when
  Mallory ingested a report, not when the activity occurred.
- Observation **counts** track reporting volume, not necessarily operational
  frequency — a heavily-covered campaign inflates its techniques. Weigh
  emergence and presence over raw counts.

## Data Access

Built on the **mallory-api** skill. Key accessors used:

- `client.threat_actors.get(identifier)` — resolve the actor
- `client.threat_actors.attack_patterns(uuid)` — dated attack-pattern observations
- `client.attack_patterns.get("T1486")` — technique → ATT&CK tactics
- `client.references.get(uuid)` — source publication date (for `--date-source published`)

Related: the **adversary-emulation-planning** skill turns the resulting TTP
profile into a simulation plan.
