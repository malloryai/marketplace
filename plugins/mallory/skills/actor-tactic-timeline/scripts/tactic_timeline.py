#!/usr/bin/env python3
"""Build a timeline of a threat actor's observed ATT&CK tactics over time.

Pulls every attack-pattern observation Mallory has attributed to an actor,
buckets the observations into time periods, and reports how the actor's TTP
mix shifts period to period -- which techniques and tactics emerge, recur, or
fade. Each technique's MITRE ATT&CK tactic(s) come from the server-side
attack_patterns/overview aggregation (a few calls), not a per-technique fetch.

Each observation links to the source reference that reported it, so the
timeline is auditable: every technique in a period traces back to citations.

Requires the official SDK and an API key:
    uv pip install --system --upgrade malloryapi
    export MALLORY_API_KEY=sk-...

Usage:
    tactic_timeline.py "ShinyHunters"
    tactic_timeline.py "APT28" --period month --format markdown
    tactic_timeline.py "Scattered Spider" --format html --out /tmp/ss_tactics.html
    tactic_timeline.py <uuid> --date-source published --top 12  # slower
"""
from __future__ import annotations

import argparse
import html
import json
import os
import re
import sys
import threading
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

try:
    from malloryapi import MalloryApi, NotFoundError
except ImportError:
    sys.stderr.write(
        "malloryapi SDK not installed. Run:\n"
        "  uv pip install --system --upgrade malloryapi\n"
    )
    sys.exit(1)

# Geist Sans + Mono inlined as base64 @font-face so the HTML report is fully
# self-contained — no external requests, which keeps it CSP-safe for the
# claude.ai Artifact tool.
_ASSETS_DIR = Path(__file__).resolve().parent.parent / "assets"


def load_font_css() -> str:
    """Return an inline <style> block with the base64 Geist @font-face rules.

    Falls back to an empty string (system sans/mono stack) if the asset is
    missing, so the report still renders rather than failing hard.
    """
    css = _ASSETS_DIR / "fonts_css.txt"
    try:
        return "<style>" + css.read_text(encoding="utf-8") + "</style>"
    except OSError:
        log(f"warning: font asset not found at {css}; using system fonts")
        return ""


def log(msg: str) -> None:
    """Progress to stderr so stdout stays clean JSON/markdown."""
    sys.stderr.write(msg + "\n")
    sys.stderr.flush()


def progress(label: str, i: int, total: int, start: float) -> None:
    """Live-updating single-line progress bar on stderr (count, %, rate, ETA).

    Only animates when stderr is a TTY; otherwise emits a line every 10% so
    piped/redirected runs still show movement without spamming carriage
    returns. Writes a trailing newline once complete.
    """
    elapsed = time.time() - start
    rate = i / elapsed if elapsed > 0 else 0.0
    eta = (total - i) / rate if rate > 0 else 0.0
    pct = (i / total * 100) if total else 100.0
    msg = (f"  {label}: {i}/{total} ({pct:3.0f}%)  "
           f"{rate:4.1f}/s  ETA {eta:4.0f}s")
    if sys.stderr.isatty():
        sys.stderr.write("\r" + msg + "   ")
        if i >= total:
            sys.stderr.write("\n")
    elif total and (i >= total or i % max(1, total // 10) == 0):
        sys.stderr.write(msg + "\n")
    sys.stderr.flush()


def resolve_actor(client: "MalloryApi", identifier: str) -> dict:
    """Resolve a name or UUID to a threat actor record."""
    try:
        return client.threat_actors.get(identifier)
    except NotFoundError:
        pass
    # Fall back to search by name.
    results = client.search.query(q=identifier, types="threat_actor")
    items = results.get("data") if isinstance(results, dict) else list(results)
    if items:
        first = items[0]
        uuid = first.get("uuid") or first.get("entity_uuid")
        if uuid:
            return client.threat_actors.get(uuid)
    raise SystemExit(f"No threat actor found matching '{identifier}'.")


def fetch_observations(client: "MalloryApi", uuid: str, cap: int) -> list[dict]:
    """Paginate all attack-pattern observations for an actor."""
    obs: list[dict] = []
    offset = 0
    while True:
        page = client.threat_actors.attack_patterns(uuid, limit=100, offset=offset)
        data = page.get("data") if isinstance(page, dict) else None
        if not data:
            break
        obs.extend(data)
        offset += len(data)
        total = page.get("total", 0) if isinstance(page, dict) else 0
        log(f"  fetched {len(obs)}/{total} observations")
        if offset >= total or len(obs) >= cap:
            break
    return obs[:cap]


def fetch_tactic_map(client: "MalloryApi", uuid: str) -> dict[str, list[str]]:
    """Map each of the actor's techniques to its ATT&CK tactic(s).

    Uses the server-side ``attack_patterns/overview`` aggregation, which
    returns one row per distinct technique with ``tactics`` already inline --
    a handful of paginated calls total, replacing the old per-technique N+1
    ``attack_patterns.get()`` loop. Keyed by both the attack-pattern UUID and
    the MITRE id so observations can be joined on either.
    """
    tmap: dict[str, list[str]] = {}
    offset = 0
    while True:
        page = client.threat_actors.attack_patterns_overview(
            uuid, limit=100, offset=offset
        )
        data = page.get("data") if isinstance(page, dict) else None
        if not data:
            break
        for row in data:
            ap = row.get("attack_pattern") or {}
            tactics = ap.get("tactics") or ["unknown"]
            if ap.get("uuid"):
                tmap[ap["uuid"]] = tactics
            if ap.get("mitre_attack_id"):
                tmap[ap["mitre_attack_id"]] = tactics
        offset += len(data)
        total = page.get("total", 0) if isinstance(page, dict) else 0
        log(f"  mapped {offset}/{total} techniques to tactics")
        if offset >= total:
            break
    return tmap


CACHE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          ".published_at_cache.json")


def _load_cache() -> dict[str, str]:
    try:
        with open(CACHE_PATH) as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def _save_cache(cache: dict[str, str]) -> None:
    try:
        with open(CACHE_PATH, "w") as fh:
            json.dump(cache, fh)
    except OSError:
        pass


def enrich_published(client: "MalloryApi", ref_uuids: set,
                     workers: int = 16, use_cache: bool = True) -> dict[str, str]:
    """Map each reference UUID to its source publication date (ISO string).

    Reference reads are the slow part of a ``published`` timeline: the API has
    no bulk reference endpoint and no inline publication date on observations,
    and it rate-limits reference reads server-side (~1.6/s at scale). We do two
    things to soften that: (1) an on-disk cache keyed by reference UUID, so the
    cost is paid once across runs, and (2) a thread pool for the uncached
    remainder. Parallelism plateaus against the server's rate limit, so the
    cache is what actually makes reruns instant.
    """
    pub: dict[str, str] = {}
    cache = _load_cache() if use_cache else {}
    refs = sorted(ref_uuids)
    todo = [r for r in refs if r not in cache]
    for r in refs:
        if r in cache:
            pub[r] = cache[r]
    if not todo:
        log(f"  all {len(refs)} references cached")
        return pub
    log(f"  {len(refs) - len(todo)} cached, fetching {len(todo)} "
        f"({workers} workers)")

    start = time.time()
    done = 0
    failed = 0
    lock = threading.Lock()

    def fetch(ruuid: str) -> tuple[str, str | None]:
        # Return None on a lookup failure so the caller can tell a failed read
        # apart from a reference that genuinely has no publication date. We must
        # not turn failures into "" and let them masquerade as resolved dates.
        try:
            ref = client.references.get(ruuid)
            return ruuid, ref.get("published_at") or ref.get("created_at") or ""
        except Exception:
            return ruuid, None

    with ThreadPoolExecutor(max_workers=workers) as ex:
        for ruuid, val in ex.map(fetch, todo):
            with lock:
                done += 1
                if val is None:
                    failed += 1
                elif val:
                    # Cache and keep only references with a real resolved date.
                    pub[ruuid] = val
                    cache[ruuid] = val
                progress("publish dates", done, len(todo), start)

    if failed:
        log(f"  warning: {failed}/{len(todo)} reference lookups failed; those "
            f"observations are excluded from the published timeline")
    if use_cache:
        _save_cache(cache)
    return pub


def bucket_key(iso: str, period: str) -> str | None:
    """Return the period bucket label for an ISO timestamp."""
    if not iso:
        return None
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except ValueError:
        return None
    if period == "month":
        return f"{dt.year:04d}-{dt.month:02d}"
    if period == "quarter":
        return f"{dt.year:04d}-Q{(dt.month - 1) // 3 + 1}"
    if period == "year":
        return f"{dt.year:04d}"
    return f"{dt.year:04d}-{dt.month:02d}"


def build_timeline(obs: list[dict], tactics: dict, pub: dict,
                   date_source: str, period: str, top: int = 10) -> dict:
    """Aggregate observations into a period-by-period timeline."""
    # Attach a bucket date to every observation. Under the published axis we
    # use only resolved publication dates -- never the observation's ingest
    # date -- so the timeline can't claim "published" while bucketing on
    # observed dates. Observations whose reference has no resolved date drop
    # out (they have no place on a publication axis).
    enriched = []
    for o in obs:
        iso = observation_iso(o, pub, date_source)
        key = bucket_key(iso, period)
        if key:
            enriched.append((key, o))

    # Per-period aggregates.
    by_period: dict[str, dict] = defaultdict(
        lambda: {"techniques": Counter(), "tactics": Counter(), "count": 0}
    )
    for key, o in enriched:
        mid = o.get("mitre_attack_id", "?")
        by_period[key]["techniques"][mid] += 1
        by_period[key]["count"] += 1
        tech1 = (tactics.get(o.get("attack_pattern_uuid", ""))
                 or tactics.get(mid) or ["unknown"])
        for t in tech1:
            by_period[key]["tactics"][t] += 1

    name_of = {o.get("mitre_attack_id"): o.get("display_name") for o in obs}

    # Track first-seen to flag emerging techniques per period.
    seen: set[str] = set()
    periods_out = []
    for key in sorted(by_period):
        bucket = by_period[key]
        techs = bucket["techniques"]
        new = [m for m in techs if m not in seen]
        seen.update(techs)
        periods_out.append({
            "period": key,
            "observation_count": bucket["count"],
            "distinct_techniques": len(techs),
            "tactics": dict(bucket["tactics"].most_common()),
            "top_techniques": [
                {"id": m, "name": name_of.get(m), "count": c}
                for m, c in techs.most_common(max(1, top))
            ],
            "emerging_techniques": [
                {"id": m, "name": name_of.get(m)} for m in new
            ],
        })

    # Cross-period tactic matrix and emergence/decline summary.
    all_tactics = sorted({t for p in periods_out for t in p["tactics"]})
    matrix = {
        t: {p["period"]: p["tactics"].get(t, 0) for p in periods_out}
        for t in all_tactics
    }

    return {
        "period_granularity": period,
        "date_source": date_source,
        "periods": periods_out,
        "tactic_matrix": matrix,
        "tactic_order": all_tactics,
    }


def render_markdown(actor: dict, timeline: dict, total_obs: int, top: int) -> str:
    """Human-readable timeline report."""
    name = actor.get("display_name") or actor.get("name") or "Unknown actor"
    lines = [
        f"# Tactic Evolution: {name}",
        "",
        f"- Observations analyzed: **{total_obs}**",
        f"- Granularity: **{timeline['period_granularity']}**  |  "
        f"Date axis: **{timeline['date_source']}**",
        f"- Periods: **{len(timeline['periods'])}**",
        "",
        "## Tactic emphasis over time",
        "",
    ]
    periods = [p["period"] for p in timeline["periods"]]
    header = "| Tactic | " + " | ".join(periods) + " |"
    sep = "|" + "---|" * (len(periods) + 1)
    lines += [header, sep]
    for tactic in timeline["tactic_order"]:
        row = timeline["tactic_matrix"][tactic]
        cells = " | ".join(str(row.get(p, 0)) for p in periods)
        lines.append(f"| {tactic} | {cells} |")
    lines += ["", "## Period detail", ""]
    for p in timeline["periods"]:
        lines.append(f"### {p['period']}  —  {p['observation_count']} observations, "
                     f"{p['distinct_techniques']} techniques")
        if p["emerging_techniques"]:
            em = ", ".join(
                f"{t['id']} ({t['name']})" for t in p["emerging_techniques"][:top]
            )
            lines.append(f"- **New this period:** {em}")
        top_t = ", ".join(
            f"{t['id']} {t['name']} ×{t['count']}" for t in p["top_techniques"][:top]
        )
        lines.append(f"- **Most observed:** {top_t}")
        lines.append("")
    return "\n".join(lines)


def slugify(name: str | None) -> str:
    """Filesystem-safe slug for an actor name (e.g. 'Scattered Spider')."""
    slug = re.sub(r"[^a-z0-9]+", "_", (name or "actor").lower()).strip("_")
    return slug or "actor"


def observation_iso(o: dict, pub: dict, date_source: str) -> str:
    """The date string an observation should be placed on (published or observed).

    Under the ``published`` axis, return only the resolved publication date for
    the observation's reference. We deliberately do NOT fall back to the
    observation's own ``created_at`` (its ingest time): doing so would bucket a
    record on an observed date while the report still claims ``published``.
    Observations whose reference has no resolved date return "" and are treated
    as undated upstream.
    """
    if date_source == "published":
        return pub.get(o.get("reference_uuid", ""), "")
    return o.get("created_at", "")


def build_heatmap_rows(obs: list[dict], tactics: dict,
                       pub: dict, date_source: str) -> tuple[list[dict], int]:
    """Per-(technique, month) counts for the interactive HTML heatmap.

    Returns (rows, undated) where each row is
    ``{"tid", "name", "tac", "sub", "m": "YYYY-MM", "c"}`` -- the monthly
    granularity the client-side view re-buckets into quarters/months. Undated
    observations (no resolvable date) are excluded and counted separately.
    """
    by_tech: dict[str, dict] = {}
    undated = 0
    for o in obs:
        mid = o.get("mitre_attack_id")
        if not mid:
            # No technique id -> nothing to chart; still an excluded row.
            undated += 1
            continue
        iso = observation_iso(o, pub, date_source)
        # Validate with the same parser the timeline buckets use, so impossible
        # months (e.g. 2024-33) are treated as undated rather than producing
        # bogus periods.
        m = bucket_key(iso, "month")
        if not m:
            undated += 1
            continue
        tech = by_tech.get(mid)
        if tech is None:
            tac_list = (tactics.get(o.get("attack_pattern_uuid", ""))
                        or tactics.get(mid) or ["unknown"])
            tech = by_tech[mid] = {
                "tid": mid,
                "name": o.get("display_name") or mid,
                "tac": tac_list[0] if tac_list else "unknown",
                "sub": "." in mid,
                "by": Counter(),
            }
        tech["by"][m] += 1

    rows = [
        {"tid": t["tid"], "name": t["name"], "tac": t["tac"],
         "sub": t["sub"], "m": m, "c": c}
        for t in by_tech.values()
        for m, c in t["by"].items()
    ]
    return rows, undated


def script_json(value: object) -> str:
    """JSON-encode for safe embedding inside an inline ``<script>`` block.

    ``json.dumps`` does not escape ``<`` / ``>`` / ``&`` or the U+2028/U+2029
    line separators, so a technique/name field from the API containing
    ``</script>`` (or those separators) could break out of the script context
    and inject markup. Escaping them as ``\\uXXXX`` keeps the payload a literal
    JS string while remaining valid JSON.
    """
    return (
        json.dumps(value, separators=(",", ":"))
        .replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace(" ", "\\u2028")
        .replace(" ", "\\u2029")
    )


def render_html(actor: dict, obs: list[dict], tactics: dict, pub: dict,
                date_source: str, period: str, top: int) -> str:
    """Self-contained, interactive HTML report in the Mallory dark-brand style.

    A technique x time heatmap: one row per MITRE technique, colored by its
    kill-chain tactic, each cell's brightness scaled by how often the technique
    was attributed that period. Live controls (Top N, kill-chain vs. volume
    order, quarter vs. month, year range) re-render client-side from an embedded
    monthly dataset. Fully self-contained — the Geist webfont is inlined as
    base64 @font-face (no external requests), so the report is CSP-safe for the
    claude.ai Artifact tool and renders identically offline.
    """
    name = actor.get("display_name") or actor.get("name") or "Unknown actor"
    rows, undated = build_heatmap_rows(obs, tactics, pub, date_source)

    # Headline stats computed server-side for the summary cards.
    totals: Counter = Counter()
    quarters: Counter = Counter()
    tac_seen: set[str] = set()
    for r in rows:
        totals[(r["tid"], r["name"])] += r["c"]
        if r["tac"] != "unknown":
            tac_seen.add(r["tac"])
        q = f'{r["m"][:4]}-Q{(int(r["m"][5:7]) - 1) // 3 + 1}'
        quarters[q] += r["c"]
    n_tech = len({r["tid"] for r in rows})
    evidence = sum(r["c"] for r in rows)
    top_tech = totals.most_common(1)[0][0] if totals else ("--", "")
    peak_q = quarters.most_common(1)[0][0] if quarters else "--"
    has_2022 = any(r["m"][:4] >= "2022" for r in rows)

    # Aliases, if the actor record carries them.
    alias_vals = (actor.get("aliases") or actor.get("aka")
                  or actor.get("alternate_names") or [])
    aliases = [a.get("name") if isinstance(a, dict) else a for a in alias_vals]
    aliases = [a for a in aliases if a and a != name][:6]
    aka_html = ""
    if aliases:
        chips = " · ".join(
            f'<b style="color:#E8EDF5;font-weight:600;">{html.escape(str(a))}</b>'
            for a in aliases
        )
        aka_html = f"aka {chips} &nbsp;—&nbsp; "

    repl = {
        "__FONT_CSS__": load_font_css(),
        "__TITLE__": html.escape(name),
        "__EYEBROW__": "Mallory · Threat Actor Profile",
        "__AKA__": aka_html,
        "__SLUG__": html.escape(slugify(name)),
        "__N_TECH__": f"{n_tech:,}",
        "__EVIDENCE__": f"{evidence:,}",
        "__N_TAC__": str(len(tac_seen)),
        "__TOP_ID__": html.escape(top_tech[0]),
        "__TOP_NAME__": html.escape(top_tech[1] or ""),
        "__PEAK__": html.escape(peak_q),
        "__UNDATED__": f"{undated:,}",
        "__DATE_AXIS__": html.escape(date_source),
        "__TOTAL_LABEL__": f"All {n_tech}",
        "__RAW__": script_json(rows),
        "__BUCKET__": "M" if period == "month" else "Q",
        "__RANGE__": "2022" if has_2022 else "all",
        "__TOPN__": str(max(1, top)),
    }
    out = _HTML_TEMPLATE
    for k, v in repl.items():
        out = out.replace(k, v)
    return out


# Interactive heatmap report, ported from the Mallory Design "Scattered Spider
# Heatmap" component to a standalone page (no DC runtime, data embedded inline).
_HTML_TEMPLATE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Tactic Evolution: __TITLE__</title>
__FONT_CSS__
<style>
  html,body{margin:0;background:#070B14;}
  *{box-sizing:border-box;}
  ::selection{background:rgba(0,102,255,.35);}
</style>
</head>
<body>
<div id="ssp-root" style="min-height:100vh;background:radial-gradient(1100px 560px at 82% -8%, rgba(0,102,255,.12), transparent 60%), #070B14;color:#E8EDF5;font-family:'Geist',system-ui,-apple-system,sans-serif;line-height:1.5;-webkit-font-smoothing:antialiased;">
  <div style="max-width:1180px;margin:0 auto;padding:40px 28px 64px;">

    <p style="font-family:'Geist Mono',ui-monospace,monospace;font-size:11.5px;letter-spacing:.22em;text-transform:uppercase;color:#4DA3FF;margin:0 0 12px;font-weight:500;">__EYEBROW__</p>
    <h1 style="font-size:clamp(28px,4.6vw,46px);line-height:1.04;margin:0;font-weight:700;letter-spacing:-.02em;text-wrap:balance;color:#F4F7FC;">__TITLE__: technique evolution</h1>
    <p style="color:#8A97AD;font-family:'Geist Mono',ui-monospace,monospace;font-size:13px;margin:12px 0 0;">__AKA__<code style="font-family:'Geist Mono',ui-monospace,monospace;background:#151C2A;padding:1px 6px;border-radius:5px;font-size:12px;color:#C2CBDD;">__SLUG__</code></p>
    <p style="max-width:66ch;color:#C2CBDD;margin:16px 0 0;font-size:15.5px;">Every individual MITRE ATT&amp;CK technique attributed to the group, by when each observation is dated. Each row is one technique, colored by its kill-chain tactic; each cell's brightness is how many times it was attributed that period. The bands light up as the playbook shifts.</p>

    <div style="display:grid;grid-template-columns:repeat(5,1fr);gap:1px;background:rgba(140,160,190,.16);border:1px solid rgba(140,160,190,.16);border-radius:12px;overflow:hidden;margin:30px 0 26px;">
      <div style="background:#121A28;padding:16px 18px;"><div style="font-family:'Geist Mono',ui-monospace,monospace;font-size:23px;font-weight:600;font-variant-numeric:tabular-nums;letter-spacing:-.01em;">__N_TECH__</div><div style="font-size:11.5px;color:#8A97AD;margin-top:3px;text-transform:uppercase;letter-spacing:.07em;">techniques</div></div>
      <div style="background:#121A28;padding:16px 18px;"><div style="font-family:'Geist Mono',ui-monospace,monospace;font-size:23px;font-weight:600;font-variant-numeric:tabular-nums;letter-spacing:-.01em;">__EVIDENCE__</div><div style="font-size:11.5px;color:#8A97AD;margin-top:3px;text-transform:uppercase;letter-spacing:.07em;">evidence rows</div></div>
      <div style="background:#121A28;padding:16px 18px;"><div style="font-family:'Geist Mono',ui-monospace,monospace;font-size:23px;font-weight:600;font-variant-numeric:tabular-nums;letter-spacing:-.01em;">__N_TAC__</div><div style="font-size:11.5px;color:#8A97AD;margin-top:3px;text-transform:uppercase;letter-spacing:.07em;">ATT&amp;CK tactics</div></div>
      <div style="background:#121A28;padding:16px 18px;"><div style="font-family:'Geist Mono',ui-monospace,monospace;font-size:23px;font-weight:600;font-variant-numeric:tabular-nums;letter-spacing:-.01em;color:#4DA3FF;">__TOP_ID__</div><div style="font-size:11.5px;color:#8A97AD;margin-top:3px;text-transform:uppercase;letter-spacing:.07em;">top: __TOP_NAME__</div></div>
      <div style="background:#121A28;padding:16px 18px;"><div style="font-family:'Geist Mono',ui-monospace,monospace;font-size:23px;font-weight:600;font-variant-numeric:tabular-nums;letter-spacing:-.01em;">__PEAK__</div><div style="font-size:11.5px;color:#8A97AD;margin-top:3px;text-transform:uppercase;letter-spacing:.07em;">peak quarter</div></div>
    </div>

    <section style="background:linear-gradient(180deg,#141B28,#0F1520);border:1px solid rgba(140,160,190,.16);border-radius:16px;padding:22px 22px 16px;box-shadow:0 1px 3px rgba(0,0,0,.4);">
      <div style="display:flex;flex-wrap:wrap;gap:16px;align-items:flex-end;justify-content:space-between;margin-bottom:18px;">
        <div>
          <h2 style="font-size:16px;margin:0;font-weight:600;letter-spacing:-.01em;color:#E8EDF5;">Technique &times; time heatmap</h2>
          <p id="ssp-subcap" style="margin:4px 0 0;color:#8A97AD;font-size:12.5px;font-family:'Geist Mono',ui-monospace,monospace;"></p>
        </div>
        <div style="display:flex;gap:18px;flex-wrap:wrap;">
          <div style="display:flex;flex-direction:column;gap:5px;"><span style="font-family:'Geist Mono',ui-monospace,monospace;font-size:10px;letter-spacing:.14em;text-transform:uppercase;color:#586780;">Show</span>
            <div id="ssp-topn" style="display:flex;background:#070B14;border:1px solid rgba(140,160,190,.16);border-radius:8px;padding:3px;">
              <button data-v="25" style="appearance:none;border:0;background:transparent;color:#8A97AD;font-family:'Geist Mono',ui-monospace,monospace;font-size:12px;padding:5px 11px;border-radius:6px;cursor:pointer;font-weight:400;">Top 25</button>
              <button data-v="50" style="appearance:none;border:0;background:transparent;color:#8A97AD;font-family:'Geist Mono',ui-monospace,monospace;font-size:12px;padding:5px 11px;border-radius:6px;cursor:pointer;font-weight:400;">Top 50</button>
              <button data-v="999" style="appearance:none;border:0;background:transparent;color:#8A97AD;font-family:'Geist Mono',ui-monospace,monospace;font-size:12px;padding:5px 11px;border-radius:6px;cursor:pointer;font-weight:400;">__TOTAL_LABEL__</button>
            </div></div>
          <div style="display:flex;flex-direction:column;gap:5px;"><span style="font-family:'Geist Mono',ui-monospace,monospace;font-size:10px;letter-spacing:.14em;text-transform:uppercase;color:#586780;">Order</span>
            <div id="ssp-sort" style="display:flex;background:#070B14;border:1px solid rgba(140,160,190,.16);border-radius:8px;padding:3px;">
              <button data-v="killchain" style="appearance:none;border:0;background:transparent;color:#8A97AD;font-family:'Geist Mono',ui-monospace,monospace;font-size:12px;padding:5px 11px;border-radius:6px;cursor:pointer;font-weight:400;">Kill chain</button>
              <button data-v="volume" style="appearance:none;border:0;background:transparent;color:#8A97AD;font-family:'Geist Mono',ui-monospace,monospace;font-size:12px;padding:5px 11px;border-radius:6px;cursor:pointer;font-weight:400;">Volume</button>
            </div></div>
          <div style="display:flex;flex-direction:column;gap:5px;"><span style="font-family:'Geist Mono',ui-monospace,monospace;font-size:10px;letter-spacing:.14em;text-transform:uppercase;color:#586780;">Bucket</span>
            <div id="ssp-bucket" style="display:flex;background:#070B14;border:1px solid rgba(140,160,190,.16);border-radius:8px;padding:3px;">
              <button data-v="Q" style="appearance:none;border:0;background:transparent;color:#8A97AD;font-family:'Geist Mono',ui-monospace,monospace;font-size:12px;padding:5px 11px;border-radius:6px;cursor:pointer;font-weight:400;">Quarter</button>
              <button data-v="M" style="appearance:none;border:0;background:transparent;color:#8A97AD;font-family:'Geist Mono',ui-monospace,monospace;font-size:12px;padding:5px 11px;border-radius:6px;cursor:pointer;font-weight:400;">Month</button>
            </div></div>
          <div style="display:flex;flex-direction:column;gap:5px;"><span style="font-family:'Geist Mono',ui-monospace,monospace;font-size:10px;letter-spacing:.14em;text-transform:uppercase;color:#586780;">Range</span>
            <div id="ssp-range" style="display:flex;background:#070B14;border:1px solid rgba(140,160,190,.16);border-radius:8px;padding:3px;">
              <button data-v="2022" style="appearance:none;border:0;background:transparent;color:#8A97AD;font-family:'Geist Mono',ui-monospace,monospace;font-size:12px;padding:5px 11px;border-radius:6px;cursor:pointer;font-weight:400;">2022+</button>
              <button data-v="all" style="appearance:none;border:0;background:transparent;color:#8A97AD;font-family:'Geist Mono',ui-monospace,monospace;font-size:12px;padding:5px 11px;border-radius:6px;cursor:pointer;font-weight:400;">All</button>
            </div></div>
        </div>
      </div>
      <div style="overflow:auto;max-height:660px;border:1px solid rgba(140,160,190,.16);border-radius:10px;background:#070B14;">
        <div id="ssp-hm" style="display:grid;font-family:'Geist Mono',ui-monospace,monospace;position:relative;width:max-content;min-width:100%;"></div>
      </div>
      <div id="ssp-legend" style="display:flex;flex-wrap:wrap;gap:6px 14px;margin-top:16px;padding-top:14px;border-top:1px solid rgba(140,160,190,.16);"></div>
    </section>

    <footer style="margin-top:30px;color:#8A97AD;font-size:12.5px;max-width:78ch;">
      <div style="display:flex;gap:9px;margin-top:9px;"><span style="color:#4DA3FF;flex:none;">&#9657;</span><span>The time axis is the <b style="color:#C2CBDD;font-weight:600;">__DATE_AXIS__ date</b> of each observation, not necessarily when an intrusion occurred &mdash; one large profile can attribute many techniques at once. Read the <b style="color:#C2CBDD;font-weight:600;">arrival and spread of rows</b>, not absolute cell counts.</span></div>
      <div style="display:flex;gap:9px;margin-top:9px;"><span style="color:#4DA3FF;flex:none;">&#9657;</span><span><b style="color:#C2CBDD;font-weight:600;">__N_TECH__</b> distinct techniques across <b style="color:#C2CBDD;font-weight:600;">__EVIDENCE__</b> evidence rows; <b style="color:#C2CBDD;font-weight:600;">__UNDATED__</b> undated rows excluded. Brightness scales with &radic;count within the chosen bucket.</span></div>
      <div style="display:flex;gap:9px;margin-top:9px;"><span style="color:#4DA3FF;flex:none;">&#9657;</span><span>Source: Mallory <code style="font-family:'Geist Mono',ui-monospace,monospace;background:#151C2A;padding:1px 6px;border-radius:5px;font-size:12px;color:#C2CBDD;">threat_actors.attack_patterns</code> &#8904; <code style="font-family:'Geist Mono',ui-monospace,monospace;background:#151C2A;padding:1px 6px;border-radius:5px;font-size:12px;color:#C2CBDD;">attack_patterns/overview</code>.</span></div>
    </footer>
  </div>
  <div id="ssp-tip" style="position:fixed;pointer-events:none;z-index:30;opacity:0;transform:translateY(-50%);background:#05080F;border:1px solid rgba(140,160,190,.22);border-radius:10px;padding:10px 13px;font-family:'Geist Mono',ui-monospace,monospace;font-size:11.5px;box-shadow:0 12px 40px rgba(0,0,0,.55);max-width:260px;transition:opacity .1s;"></div>
</div>
<script>
(function(){
  var RAW = __RAW__;
  var opt = { topn:__TOPN__, sort:"killchain", bucket:"__BUCKET__", range:"__RANGE__" };
  var C = { GROUND:"#070B14", PANEL:"#121A28", ELEV:"#151C2A",
    BORDER:"rgba(140,160,190,.16)", BFAINT:"rgba(140,160,190,.08)",
    INK:"#E8EDF5", INK2:"#C2CBDD", MUTED:"#8A97AD", FAINT:"#586780" };
  var TAC = [
    ["reconnaissance","Recon"],["resource-development","Resource Dev"],
    ["initial-access","Initial Access"],["execution","Execution"],
    ["persistence","Persistence"],["privilege-escalation","Priv Esc"],
    ["defense-evasion","Defense Evasion"],["credential-access","Cred Access"],
    ["discovery","Discovery"],["lateral-movement","Lateral Move"],
    ["collection","Collection"],["command-and-control","C2"],
    ["exfiltration","Exfiltration"],["impact","Impact"]
  ];
  var RGB={}, COLOR={}, TI={};
  function buildPalette(){
    var A=[3,58,178], B=[120,186,255], n=TAC.length;  // Mono Blue ramp
    TAC.forEach(function(t,i){
      var tt=i/(n-1);
      var rgb=A.map(function(v,k){ return Math.round(v+(B[k]-v)*tt); });
      RGB[t[0]]=rgb; COLOR[t[0]]="rgb("+rgb[0]+","+rgb[1]+","+rgb[2]+")"; TI[t[0]]=i;
    });
  }
  function esc(s){ return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;"); }
  function keyOf(m,b){ return b==="M" ? m : m.slice(0,4)+"-Q"+(Math.floor((+m.slice(5,7)-1)/3)+1); }

  function build(){
    var o=opt, minY = o.range==="2022" ? "2022" : "0000";
    var T=new Map(), pset=new Set();
    for(var i=0;i<RAW.length;i++){
      var r=RAW[i];
      if(r.m.slice(0,4) < minY) continue;
      var id=r.tid+"|"+r.name;
      if(!T.has(id)) T.set(id,{tid:r.tid,name:r.name,tac:r.tac||"reconnaissance",sub:r.sub,total:0,by:{}});
      var x=T.get(id), k=keyOf(r.m,o.bucket);
      x.total+=r.c; x.by[k]=(x.by[k]||0)+r.c; pset.add(k);
    }
    var techs=[...T.values()].sort(function(a,b){return b.total-a.total;});
    if(o.topn!==999) techs=techs.slice(0,o.topn);
    if(o.sort==="killchain")
      techs.sort(function(a,b){ return ((TI[a.tac]||0)-(TI[b.tac]||0)) || (b.total-a.total); });
    var periods=[...pset].sort();
    var maxCell=Math.max(1,...techs.flatMap(function(t){return Object.values(t.by);}));
    var maxTot=Math.max(1,...techs.map(function(t){return t.total;}));
    return {techs:techs,periods:periods,maxCell:maxCell,maxTot:maxTot};
  }

  function renderHeatmap(){
    var hm=document.getElementById("ssp-hm");
    if(!hm) return;
    var r=build(), techs=r.techs, periods=r.periods, maxCell=r.maxCell, maxTot=r.maxTot;
    var cw=opt.bucket==="M" ? 26 : 40;
    var rh=techs.length>70 ? 15 : 19;
    hm.style.gridTemplateColumns="248px repeat("+periods.length+", "+cw+"px) 96px";

    var yearStart={}, py=null;
    periods.forEach(function(p,i){ var y=p.slice(0,4); if(y!==py){ yearStart[i]=y; py=y; } });

    var h="";
    h+='<div style="position:sticky;left:0;top:0;z-index:6;background:'+C.ELEV+';border-right:1px solid '+C.BORDER+';border-bottom:1px solid '+C.BORDER+';display:flex;align-items:flex-end;padding:0 12px 6px;height:34px;font-size:10px;color:'+C.FAINT+';letter-spacing:.06em;text-transform:uppercase">Technique</div>';
    periods.forEach(function(p,i){
      var isY=yearStart[i]!==undefined, lab=p.slice(5);
      var ys=(isY && i>0) ? "box-shadow:inset 1px 0 0 "+C.BORDER+";" : "";
      h+='<div style="position:sticky;top:0;z-index:4;background:'+C.ELEV+';height:34px;display:flex;align-items:flex-end;justify-content:center;padding-bottom:5px;font-size:10px;color:'+(isY?C.INK:C.MUTED)+';'+(isY?"font-weight:600;":"")+'border-bottom:1px solid '+C.BORDER+';'+ys+'">'+(isY?p.slice(0,4)+"·":"")+lab+'</div>';
    });
    h+='<div style="position:sticky;right:0;top:0;z-index:6;background:'+C.ELEV+';border-left:1px solid '+C.BORDER+';border-bottom:1px solid '+C.BORDER+';height:34px;display:flex;align-items:flex-end;padding:0 12px 6px;font-size:10px;color:'+C.FAINT+';text-transform:uppercase;letter-spacing:.06em">Total</div>';

    techs.forEach(function(t){
      var rgb=RGB[t.tac] || [77,140,255];
      var col=COLOR[t.tac] || "#4D8CFF";
      h+='<div style="position:sticky;left:0;z-index:3;background:'+C.PANEL+';display:flex;align-items:center;gap:8px;padding:0 10px 0 12px;height:'+rh+'px;border-right:1px solid '+C.BORDER+';border-bottom:1px solid '+C.BFAINT+';white-space:nowrap">'
        +'<span style="width:7px;height:7px;border-radius:2px;flex:none;background:'+col+'"></span>'
        +'<span style="color:'+C.MUTED+';font-size:10px;width:64px;flex:none">'+esc(t.tid)+'</span>'
        +'<span style="color:'+(t.sub?"#AEB9CD":C.INK)+';font-size:11px;overflow:hidden;text-overflow:ellipsis" title="'+esc(t.name)+'">'+esc(t.name)+'</span></div>';
      periods.forEach(function(p,i){
        var v=t.by[p]||0;
        var ys=(yearStart[i]!==undefined && i>0) ? "box-shadow:inset 1px 0 0 "+C.BORDER+";" : "";
        if(!v){ h+='<div style="height:'+rh+'px;border-bottom:1px solid '+C.BFAINT+';'+ys+'"></div>'; return; }
        var a=(0.16+0.84*Math.sqrt(v/maxCell)).toFixed(3);
        h+='<div style="height:'+rh+'px;display:flex;align-items:center;justify-content:center;font-size:9.5px;color:rgba(255,255,255,.85);font-variant-numeric:tabular-nums;border-bottom:1px solid '+C.BFAINT+';background:rgba('+rgb[0]+','+rgb[1]+','+rgb[2]+','+a+');'+ys+'" data-n="'+esc(t.name)+'" data-id="'+esc(t.tid)+'" data-p="'+esc(p)+'" data-v="'+esc(v)+'">'+esc(v)+'</div>';
      });
      var pct=(t.total/maxTot*100).toFixed(0);
      h+='<div style="position:sticky;right:0;z-index:3;background:'+C.PANEL+';height:'+rh+'px;display:flex;align-items:center;gap:6px;padding:0 12px 0 9px;border-left:1px solid '+C.BORDER+';border-bottom:1px solid '+C.BFAINT+'">'
        +'<span style="flex:1;height:7px;background:'+C.GROUND+';border-radius:4px;overflow:hidden;min-width:42px"><span style="display:block;height:100%;border-radius:4px;width:'+pct+'%;background:'+col+'"></span></span>'
        +'<span style="font-size:10px;color:'+C.INK+';width:24px;text-align:right;font-variant-numeric:tabular-nums">'+t.total+'</span></div>';
    });
    hm.innerHTML=h;
    var sub=document.getElementById("ssp-subcap");
    if(sub) sub.textContent=techs.length+" techniques × "+periods.length+" "+(opt.bucket==="M"?"months":"quarters")+" · cell = times attributed; right bar = all-time total";
    wireCells();
  }

  function wireCells(){
    var tip=document.getElementById("ssp-tip");
    if(!tip) return;
    document.querySelectorAll("#ssp-hm [data-v]").forEach(function(c){
      c.addEventListener("mousemove",function(e){
        tip.innerHTML='<div style="color:#E8EDF5;font-weight:600;margin-bottom:4px">'+esc(c.dataset.id)+' · '+esc(c.dataset.n)+'</div>'
          +'<div style="color:#8A97AD;font-size:10.5px">'+esc(c.dataset.p)+'</div>'
          +'<div style="color:#E8EDF5;font-size:15px;margin-top:6px;font-variant-numeric:tabular-nums">'+esc(c.dataset.v)+' attribution'+(c.dataset.v>1?"s":"")+'</div>';
        tip.style.opacity=1;
        var x=e.clientX+16; if(x>innerWidth-280) x=e.clientX-272;
        tip.style.left=x+"px"; tip.style.top=e.clientY+"px";
      });
      c.addEventListener("mouseleave",function(){ tip.style.opacity=0; });
    });
  }

  function styleBtn(b,on){
    b.style.background=on?"#0066FF":"transparent";
    b.style.color=on?"#fff":"#8A97AD";
    b.style.fontWeight=on?"600":"400";
  }

  function wireControls(){
    var defs=[["ssp-topn","topn",true],["ssp-sort","sort",false],["ssp-bucket","bucket",false],["ssp-range","range",false]];
    defs.forEach(function(d){
      var box=document.getElementById(d[0]); if(!box) return;
      var key=d[1], num=d[2], btns=[...box.querySelectorAll("button")];
      btns.forEach(function(b){
        var val=num?+b.dataset.v:b.dataset.v;
        styleBtn(b, val===opt[key]);
        b.onclick=function(){
          opt[key]=num?+b.dataset.v:b.dataset.v;
          btns.forEach(function(x){ styleBtn(x, x===b); });
          renderHeatmap();
        };
      });
    });
  }

  function renderLegend(){
    var el=document.getElementById("ssp-legend"); if(!el) return;
    var h=TAC.map(function(t,i){
      return '<span style="display:flex;align-items:center;gap:7px;font-size:11.5px;color:#C2CBDD;font-family:\'Geist Mono\',ui-monospace,monospace">'
        +'<span style="width:11px;height:11px;border-radius:3px;flex:none;background:'+COLOR[t[0]]+'"></span>'
        +t[1]+'<span style="color:#586780;font-size:10px">'+String(i+1).padStart(2,"0")+'</span></span>';
    }).join("");
    h+='<span style="margin-left:auto;display:flex;align-items:center;gap:8px;color:#8A97AD;font-size:11px;font-family:\'Geist Mono\',ui-monospace,monospace">less<span style="width:96px;height:9px;border-radius:3px;background:linear-gradient(90deg,rgba(77,140,255,.14),rgba(77,140,255,1))"></span>more</span>';
    el.innerHTML=h;
  }

  buildPalette();
  renderLegend();
  wireControls();
  renderHeatmap();
})();
</script>
</body>
</html>"""


def positive_int(value: str) -> int:
    """argparse type: accept only integers >= 1, with a clear error."""
    try:
        ivalue = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{value!r} is not an integer")
    if ivalue < 1:
        raise argparse.ArgumentTypeError(f"{value!r} must be a positive integer")
    return ivalue


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("actor", help="Threat actor name or UUID")
    ap.add_argument("--period", choices=["month", "quarter", "year"],
                    default="quarter", help="Time bucket granularity (default: quarter)")
    ap.add_argument("--date-source", choices=["observed", "published"],
                    default="observed",
                    help="Date axis: 'observed' = when Mallory recorded the "
                         "observation (fast, default); 'published' = source "
                         "publication date (more accurate but slow -- fetches "
                         "each distinct reference one by one)")
    ap.add_argument("--format", choices=["json", "markdown", "html"],
                    default="json")
    ap.add_argument("--out", metavar="PATH",
                    help="Write the report to this file instead of stdout. "
                         "For --format html, defaults to "
                         "'<actor-slug>_tactics.html' in the current directory.")
    ap.add_argument("--top", type=positive_int, default=10,
                    help="Max techniques to show per period (markdown/html)")
    ap.add_argument("--max-observations", type=int, default=5000,
                    help="Cap on observations pulled (default: 5000)")
    ap.add_argument("--no-tactics", action="store_true",
                    help="Skip tactic enrichment (faster, but no tactic grouping)")
    ap.add_argument("--workers", type=positive_int, default=16,
                    help="Concurrent reference fetches for --date-source "
                         "published (default: 16; plateaus at the server rate "
                         "limit, but cuts wall time vs. serial)")
    ap.add_argument("--no-cache", action="store_true",
                    help="Bypass the on-disk published_at cache (force refetch)")
    args = ap.parse_args()

    # The interactive HTML view only buckets by month/quarter client-side, so a
    # yearly request can't be honored there -- reject it up front rather than
    # silently rendering quarters that contradict --period year.
    if args.format == "html" and args.period == "year":
        raise SystemExit(
            "--format html does not support --period year; use month or quarter"
        )

    client = MalloryApi()

    log(f"Resolving actor '{args.actor}'...")
    actor = resolve_actor(client, args.actor)
    uuid = actor["uuid"]
    name = actor.get("display_name") or actor.get("name")
    log(f"  {name} ({uuid})")

    log("Fetching attack-pattern observations...")
    obs = fetch_observations(client, uuid, args.max_observations)
    if not obs:
        raise SystemExit(f"No attack-pattern observations found for {name}.")
    log(f"  {len(obs)} observations across "
        f"{len({o.get('mitre_attack_id') for o in obs})} distinct techniques")

    tactics: dict[str, list[str]] = {}
    if not args.no_tactics:
        log("Mapping techniques to ATT&CK tactics (overview)...")
        tactics = fetch_tactic_map(client, uuid)

    pub: dict[str, str] = {}
    if args.date_source == "published":
        refs = {o.get("reference_uuid") for o in obs if o.get("reference_uuid")}
        log(f"Enriching {len(refs)} references with publication dates...")
        pub = enrich_published(client, refs, workers=args.workers,
                               use_cache=not args.no_cache)
        if not pub:
            # No reference resolved to a usable publication date. Fall back to
            # the observed axis AND relabel it, so the report never claims
            # "published" while bucketing on ingest dates.
            log("  warning: no publication dates could be resolved; falling "
                "back to the 'observed' date axis")
            args.date_source = "observed"

    timeline = build_timeline(obs, tactics, pub, args.date_source, args.period,
                              args.top)
    if not timeline["periods"]:
        log(f"  warning: none of the {len(obs)} observations could be placed "
            f"on the '{args.date_source}' timeline (missing/invalid dates); "
            f"the report will contain no periods")

    if args.format == "markdown":
        content = render_markdown(actor, timeline, len(obs), args.top)
    elif args.format == "html":
        content = render_html(actor, obs, tactics, pub,
                              args.date_source, args.period, args.top)
    else:
        out = {
            "actor": {"uuid": uuid, "name": name},
            "total_observations": len(obs),
            **timeline,
        }
        content = json.dumps(out, indent=2, default=str)

    out_path = args.out
    if not out_path and args.format == "html":
        out_path = f"{slugify(name)}_tactics.html"
    if out_path:
        with open(out_path, "w") as fh:
            fh.write(content)
        log(f"Wrote {args.format} report to {os.path.abspath(out_path)}")
    else:
        print(content)
    return 0


if __name__ == "__main__":
    sys.exit(main())
