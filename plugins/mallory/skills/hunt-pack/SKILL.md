---
name: hunt-pack
description: Build a threat-hunt pack scoped to an industry and geography from recent threat-actor activity in Mallory. Use when the user asks for a "hunt pack", "hunt package", "threat hunt brief", or "who's targeting <industry> in <region>" and wants a prioritized actor list with ATT&CK techniques, IOCs, CVEs, hunt hypotheses, and a shareable brief. Examples: "build a hunt pack for energy in the US", "hunt package for banking in Europe", "who should we hunt for in healthcare APAC".
allowed-tools: Bash(python *), Bash(python3 *), Bash(uv *), Bash(pip *), Bash(pipx *), Read, Artifact
---

# Threat Hunt Pack Builder

Produces a **prioritized, scoped hunt pack** for a threat-hunt team: the threat
actors most actively targeting a given **industry** and **geography** in the
recent window, each with their MITRE ATT&CK techniques, malware, IOCs, exploited
CVEs, and ready-to-run hunt hypotheses — plus a shareable visual brief.

## When to Use

- "Build a hunt pack for **<industry>** in **<geo>**"
- "Who is targeting **<sector>** in **<region>** right now?"
- Kick off a threat hunt sprint scoped to your business and footprint
- Prioritize detection engineering against the actors who actually matter to you

## Prerequisites

Install the official Mallory SDK (the script imports it):

```bash
uv pip install --system malloryapi      # preferred, all platforms
# or: pip install --user malloryapi
```

> **Warning:** bare `pip install malloryapi` fails on macOS/Linux under
> [PEP 668](https://peps.python.org/pep-0668/). Use `uv pip install --system`
> or `pip install --user`.

Auth: the script reads `MALLORY_API_KEY` from the environment (same as the
**mallory-api** skill). Never print the key.

## How to Run

```bash
python ${CLAUDE_PLUGIN_ROOT}/skills/hunt-pack/scripts/build_hunt_pack.py \
  --industry "Energy" \
  --geo "US" \
  --window 30d \
  --top-actors 10 \
  --out <scratchpad>/hunt-energy-us
```

| Flag | Meaning | Default |
| --- | --- | --- |
| `--industry` | Industry **name** (e.g. `Energy`, `Banks`, `Health Care`) or a **GICS code** (e.g. `10`). Resolved against the live GICS taxonomy; matches every level of that branch. | required |
| `--geo` | Country **codes** (`US`), **names** (`Germany`), or an analyst **region** (`Europe`, `Middle East`, `APAC`, `Five Eyes`). Comma-separate to combine. Omit for a global pack. | none |
| `--window` | Trending window for the candidate pool. **Only `1d`, `7d`, `30d`.** | `30d` |
| `--pool-size` | How many trending/searched actors to score. Raise for thoroughness, lower for speed. | `120` |
| `--top-actors` | Actors kept in the final pack. | `10` |
| `--out` | Output directory. | required |

The script prints the path to `hunt_pack.json` on stdout and a progress/summary
line on stderr. Use the scratchpad directory for `--out`.

## What It Produces

Written to `--out`:

| File | Use |
| --- | --- |
| `report.md` | Analyst-readable brief: ranked actors, **why each is relevant** (dated industry/geo evidence, newest first, with cited sources), and a per-actor **"What to check"** checklist — CVE exposure/patch actions, IOC sweeps (grouped by type → log source, with concrete values), behavioral hunts (technique → specific action), and malware to watch. |
| `hunt_pack.json` | Full structured bundle — feed downstream tooling. |
| `attack_navigator_layer.json` | Import directly into [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/); techniques scored by cross-actor frequency. |
| `iocs.csv` | Observables (type, value, actor) — load into SIEM/EDR for searching. |
| `cve_watchlist.csv` | Exploited CVEs with CVSS, EPSS, in-the-wild flag — exposure/patch prioritization. |
| `hunt_hypotheses.md` | One hypothesis per high-frequency technique, with where-to-look guidance. |
| `brief.html` | Self-contained visual brief, ready for the **Artifact** tool. |

## Publish the Visual Brief (Artifact)

`brief.html` is body-only and CSP-safe by design. To share it:

1. Load the `artifact-design` skill first (required by the Artifact tool).
2. Publish:

```
Artifact(file_path="<out>/brief.html", favicon="🎯", label="<industry>-<geo>-hunt")
```

## Workflow

1. **Confirm scope.** Get the industry and geography from the user. If the
   industry term is ambiguous, the script echoes the GICS branch it resolved
   (stderr `[*] Industry scope: ...`) — surface that so the user can correct it.
2. **Run the script** with a scratchpad `--out`.
3. **Summarize** the top actors and the strongest "why relevant" evidence from
   `report.md`; don't dump the whole file.
4. **Offer the artifacts** — Navigator layer for the ATT&CK team, `iocs.csv` +
   `cve_watchlist.csv` for detection/exposure, and publish `brief.html` as an
   Artifact if the user wants something shareable.

## How Scoping Works (and its limits)

- **Industry → actors** has no direct endpoint. The script pulls a recency-
  weighted candidate pool (`threat_actors.trending` + a name search), then for
  each candidate scores its `target_industries` (GICS-coded, cited) and
  `target_geographies` (ISO country-coded, cited) evidence against the scope.
  Score = matched industry evidence + matched geo evidence + recency + mention
  volume. An actor must have ≥1 matching industry record (and ≥1 geo record if
  `--geo` is given) to appear.
- **GICS is hierarchical.** Asking for `Energy` (sector `10`) matches evidence
  tagged at any depth under it; asking for a specific sub-industry narrows it.
- **Recency is publication/ingest-based.** Targeting evidence is dated by when
  Mallory recorded the reporting — **publication date can differ from intrusion
  date**. A single big profile can attribute a lot at once. Call this out.

## Gotchas (baked into the script)

- `trending` accepts only `1d` / `7d` / `30d` (90d → HTTP 400).
- The geography **taxonomy endpoint is empty**; geo is matched on actor
  `country_code`. Region/country-name resolution uses the bundled
  `assets/regions.json` — extend it if a country/region you need is missing
  (an unresolved token is reported as `UNRESOLVED`).
- Relationship accessors (`attack_patterns`, `malware`, `observables`,
  `exploitations`) return a `data` key (raw dict), while `target_industries` /
  `target_geographies` return `items` (paginated). The script normalizes both.
- The inline `targeted_industries` array on actor objects is unreliable (often
  empty) — the dedicated accessors are the source of truth.

## Files

- `scripts/build_hunt_pack.py` — the whole pipeline (SDK-based, threaded fan-out).
- `assets/regions.json` — region/country-name → ISO-2 country-code map.

## Related Skills

- **mallory-api** — the underlying SDK/CLI and full resource reference.
- **adversary-emulation-planning** — turn a selected actor's TTPs into an emulation plan.
- **ttp-heatmap** — technique-over-time heatmap for a single actor in the pack.
