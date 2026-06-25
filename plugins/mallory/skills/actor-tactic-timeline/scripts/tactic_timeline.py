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

try:
    from malloryapi import MalloryApi, NotFoundError
except ImportError:
    sys.stderr.write(
        "malloryapi SDK not installed. Run:\n"
        "  uv pip install --system --upgrade malloryapi\n"
    )
    sys.exit(1)


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
    lock = threading.Lock()

    def fetch(ruuid: str) -> tuple[str, str]:
        try:
            ref = client.references.get(ruuid)
            val = ref.get("published_at") or ref.get("created_at") or ""
        except Exception:
            val = ""
        return ruuid, val

    with ThreadPoolExecutor(max_workers=workers) as ex:
        for ruuid, val in ex.map(fetch, todo):
            pub[ruuid] = val
            cache[ruuid] = val
            with lock:
                done += 1
                progress("publish dates", done, len(todo), start)

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
                   date_source: str, period: str) -> dict:
    """Aggregate observations into a period-by-period timeline."""
    # Attach a bucket date to every observation.
    enriched = []
    for o in obs:
        if date_source == "published" and pub:
            iso = pub.get(o.get("reference_uuid", ""), "") or o.get("created_at", "")
        else:
            iso = o.get("created_at", "")
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
                for m, c in techs.most_common(10)
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


def render_html(actor: dict, timeline: dict, total_obs: int, top: int) -> str:
    """Self-contained HTML report: a heatmap tactic matrix + period detail.

    No external assets (inline CSS, no scripts) so the file opens straight
    from disk. Matrix cells are shaded by observation count relative to the
    busiest cell, so emphasis shifts read at a glance.
    """
    name = actor.get("display_name") or actor.get("name") or "Unknown actor"
    periods = [p["period"] for p in timeline["periods"]]
    matrix = timeline["tactic_matrix"]
    tactics = timeline["tactic_order"]
    peak = max((c for row in matrix.values() for c in row.values()), default=0)

    def cell(count: int) -> str:
        if not count:
            return '<td class="z">·</td>'
        # Perceptual-ish ramp toward Mallory blue; floor keeps low counts legible.
        intensity = 0.12 + 0.88 * (count / peak) if peak else 0.0
        return (f'<td style="background:rgba(0,102,255,{intensity:.3f});'
                f'color:{"#fff" if intensity > 0.55 else "#0a1628"}">{count}</td>')

    rows = []
    for t in tactics:
        cells = "".join(cell(matrix[t].get(p, 0)) for p in periods)
        rows.append(f'<tr><th class="tac">{html.escape(t)}</th>{cells}</tr>')
    head = "".join(f'<th class="per">{html.escape(p)}</th>' for p in periods)

    detail = []
    for p in timeline["periods"]:
        em = ""
        if p["emerging_techniques"]:
            chips = "".join(
                f'<span class="chip new">{html.escape(t["id"])}'
                f'<em>{html.escape(t.get("name") or "")}</em></span>'
                for t in p["emerging_techniques"][:top]
            )
            em = f'<div class="row"><span class="lbl">New</span>{chips}</div>'
        tops = "".join(
            f'<span class="chip">{html.escape(t["id"])}'
            f'<em>{html.escape(t.get("name") or "")}</em>'
            f'<b>×{t["count"]}</b></span>'
            for t in p["top_techniques"][:top]
        )
        detail.append(
            f'<section class="period"><h3>{html.escape(p["period"])}'
            f'<span class="meta">{p["observation_count"]} obs · '
            f'{p["distinct_techniques"]} techniques</span></h3>{em}'
            f'<div class="row"><span class="lbl">Top</span>{tops}</div></section>'
        )

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Tactic Evolution: {html.escape(name)}</title>
<style>
:root{{--blue:#0066FF;--ink:#0a1628;--mut:#5b6b82;--line:#e4e9f0;--bg:#f7f9fc}}
*{{box-sizing:border-box}}
body{{margin:0;font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
color:var(--ink);background:var(--bg)}}
.wrap{{max-width:1200px;margin:0 auto;padding:32px 24px 64px}}
h1{{font-size:26px;margin:0 0 4px}}
.sub{{color:var(--mut);margin:0 0 28px}}
.sub b{{color:var(--ink)}}
h2{{font-size:13px;text-transform:uppercase;letter-spacing:.08em;color:var(--mut);
margin:36px 0 12px;border-bottom:1px solid var(--line);padding-bottom:6px}}
.scroll{{overflow-x:auto;border:1px solid var(--line);border-radius:10px;background:#fff}}
table{{border-collapse:collapse;font-size:13px;width:100%}}
th,td{{padding:6px 8px;text-align:center;white-space:nowrap;border-bottom:1px solid var(--line)}}
th.tac{{text-align:left;position:sticky;left:0;background:#fff;font-weight:600;z-index:1}}
th.per{{color:var(--mut);font-weight:600;font-size:11px}}
td.z{{color:#c2ccdb}}
td{{font-variant-numeric:tabular-nums}}
tr:last-child th,tr:last-child td{{border-bottom:none}}
.period{{background:#fff;border:1px solid var(--line);border-radius:10px;padding:14px 18px;margin:10px 0}}
.period h3{{margin:0 0 10px;font-size:16px;display:flex;align-items:baseline;gap:10px}}
.period h3 .meta{{font-size:12px;color:var(--mut);font-weight:400}}
.row{{display:flex;flex-wrap:wrap;gap:6px;align-items:center;margin:6px 0}}
.lbl{{font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--mut);
width:42px;flex:none}}
.chip{{display:inline-flex;align-items:baseline;gap:5px;background:var(--bg);
border:1px solid var(--line);border-radius:6px;padding:2px 8px;font-size:12px}}
.chip em{{color:var(--mut);font-style:normal}}
.chip b{{color:var(--blue);font-weight:600}}
.chip.new{{background:rgba(0,102,255,.08);border-color:rgba(0,102,255,.25)}}
</style></head><body><div class="wrap">
<h1>Tactic Evolution: {html.escape(name)}</h1>
<p class="sub"><b>{total_obs}</b> observations · granularity <b>{html.escape(timeline['period_granularity'])}</b>
· date axis <b>{html.escape(timeline['date_source'])}</b> · <b>{len(periods)}</b> periods</p>
<h2>Tactic emphasis over time</h2>
<div class="scroll"><table><thead><tr><th class="tac">Tactic</th>{head}</tr></thead>
<tbody>{''.join(rows)}</tbody></table></div>
<h2>Period detail</h2>
{''.join(detail)}
</div></body></html>"""


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
    ap.add_argument("--top", type=int, default=10,
                    help="Max techniques to show per period (markdown/html)")
    ap.add_argument("--max-observations", type=int, default=5000,
                    help="Cap on observations pulled (default: 5000)")
    ap.add_argument("--no-tactics", action="store_true",
                    help="Skip tactic enrichment (faster, but no tactic grouping)")
    ap.add_argument("--workers", type=int, default=16,
                    help="Concurrent reference fetches for --date-source "
                         "published (default: 16; plateaus at the server rate "
                         "limit, but cuts wall time vs. serial)")
    ap.add_argument("--no-cache", action="store_true",
                    help="Bypass the on-disk published_at cache (force refetch)")
    args = ap.parse_args()

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

    timeline = build_timeline(obs, tactics, pub, args.date_source, args.period)

    if args.format == "markdown":
        content = render_markdown(actor, timeline, len(obs), args.top)
    elif args.format == "html":
        content = render_html(actor, timeline, len(obs), args.top)
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
