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

# Standalone HTML report (heatmap matrix + period detail) written to a file
python ${CLAUDE_PLUGIN_ROOT}/skills/actor-tactic-timeline/scripts/tactic_timeline.py "Scattered Spider" --format html --out ./scattered_spider_tactics.html

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
| `--date-source {observed,published}` | `observed` | `observed` = when Mallory recorded the observation (instant, but reflects ingest order); `published` = source publication date (real-world chronology, but reads every distinct reference — see below) |
| `--format {json,markdown,html}` | `json` | Output format |
| `--out PATH` | stdout | Write the report to a file instead of stdout. For `--format html`, defaults to `<actor-slug>_tactics.html` in the current directory |
| `--top N` | `10` | Max techniques shown per period (markdown/html) |
| `--max-observations N` | `5000` | Cap on observations pulled |
| `--no-tactics` | off | Skip ATT&CK tactic enrichment (faster) |
| `--workers N` | `16` | Concurrent reference fetches for `--date-source published` |
| `--no-cache` | off | Bypass the on-disk `published_at` cache (force refetch) |

### Publication-date performance

`--date-source published` is the only axis that yields real chronology, but it
is the slow path: observations carry no inline publication date, the API has no
bulk reference endpoint (UUID filtering on `references.list` is unsupported),
and reference reads are **rate-limited server-side (~1.6/s at scale)**. So a
first run over a heavily-reported actor (e.g. Scattered Spider, ~660 distinct
references) takes several minutes regardless of `--workers` — parallelism
plateaus against that ceiling.

Two mitigations are built in: a thread pool (`--workers`) for the uncached
remainder, and an on-disk cache (`.published_at_cache.json`, keyed by reference
UUID) so the cost is paid **once** — subsequent runs for any actor reuse cached
dates and finish near-instantly. Use `--no-cache` to force a refetch.

### Output

- **JSON** (default): `actor`, `total_observations`, `periods[]` (each with
  `observation_count`, `distinct_techniques`, per-tactic counts, `top_techniques`,
  and `emerging_techniques` first seen in that period), plus a `tactic_matrix`
  (tactic × period counts) for charting.
- **Markdown**: a tactic-emphasis matrix across periods followed by per-period
  detail highlighting newly emerging and most-observed techniques.
- **HTML** (`--format html`): a standalone, interactive report in the Mallory
  dark-brand style — a **technique × time heatmap** (one row per MITRE
  technique, colored by kill-chain tactic, each cell's brightness scaled by
  √(attribution count)) with a sticky technique column and all-time total bars.
  Live in-page controls re-render client-side from an embedded monthly dataset:
  **Top N** (25 / 50 / all), **order** (kill-chain vs. volume), **bucket**
  (quarter vs. month), and **year range**. Headline stat cards and a tactic
  legend frame the chart. Writes to `--out` (or `<actor-slug>_tactics.html` in
  the current directory) and prints the absolute path to stderr. The only
  external dependency is the Geist webfont (loaded from Google Fonts), which
  degrades to the system sans/mono stack offline.

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
