#!/usr/bin/env python3
"""Build a timeline of a threat actor's observed ATT&CK tactics over time.

Pulls every attack-pattern observation Mallory has attributed to an actor,
enriches each technique with its MITRE ATT&CK tactic(s), buckets the
observations into time periods, and reports how the actor's TTP mix shifts
period to period -- which techniques and tactics emerge, recur, or fade.

Each observation links to the source reference that reported it, so the
timeline is auditable: every technique in a period traces back to citations.

Requires the official SDK and an API key:
    uv pip install --system --upgrade malloryapi
    export MALLORY_API_KEY=sk-...

Usage:
    tactic_timeline.py "ShinyHunters"
    tactic_timeline.py "APT28" --period month --format markdown
    tactic_timeline.py <uuid> --date-source observed --top 12
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
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


def enrich_tactics(client: "MalloryApi", mitre_ids: set) -> dict[str, list[str]]:
    """Map each MITRE technique id to its ATT&CK tactic(s)."""
    tactics: dict[str, list[str]] = {}
    for i, mid in enumerate(sorted(mitre_ids), 1):
        try:
            ap = client.attack_patterns.get(mid)
            tactics[mid] = ap.get("tactics") or ["unknown"]
        except Exception:
            tactics[mid] = ["unknown"]
        if i % 25 == 0:
            log(f"  enriched tactics {i}/{len(mitre_ids)}")
    return tactics


def enrich_published(client: "MalloryApi", ref_uuids: set) -> dict[str, str]:
    """Map each reference UUID to its source publication date (ISO string)."""
    pub: dict[str, str] = {}
    refs = sorted(ref_uuids)
    for i, ruuid in enumerate(refs, 1):
        try:
            ref = client.references.get(ruuid)
            pub[ruuid] = ref.get("published_at") or ref.get("created_at") or ""
        except Exception:
            pub[ruuid] = ""
        if i % 50 == 0:
            log(f"  enriched publish dates {i}/{len(refs)}")
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
        for t in tactics.get(mid, ["unknown"]):
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


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("actor", help="Threat actor name or UUID")
    ap.add_argument("--period", choices=["month", "quarter", "year"],
                    default="quarter", help="Time bucket granularity (default: quarter)")
    ap.add_argument("--date-source", choices=["observed", "published"],
                    default="published",
                    help="Date axis: 'published' = source publication date "
                         "(accurate, slower; default); 'observed' = when Mallory "
                         "recorded it (fast)")
    ap.add_argument("--format", choices=["json", "markdown"], default="json")
    ap.add_argument("--top", type=int, default=10,
                    help="Max techniques to show per period in markdown")
    ap.add_argument("--max-observations", type=int, default=5000,
                    help="Cap on observations pulled (default: 5000)")
    ap.add_argument("--no-tactics", action="store_true",
                    help="Skip tactic enrichment (faster, but no tactic grouping)")
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
        mids = {o.get("mitre_attack_id") for o in obs if o.get("mitre_attack_id")}
        log(f"Enriching {len(mids)} techniques with ATT&CK tactics...")
        tactics = enrich_tactics(client, mids)

    pub: dict[str, str] = {}
    if args.date_source == "published":
        refs = {o.get("reference_uuid") for o in obs if o.get("reference_uuid")}
        log(f"Enriching {len(refs)} references with publication dates...")
        pub = enrich_published(client, refs)

    timeline = build_timeline(obs, tactics, pub, args.date_source, args.period)

    if args.format == "markdown":
        print(render_markdown(actor, timeline, len(obs), args.top))
    else:
        out = {
            "actor": {"uuid": uuid, "name": name},
            "total_observations": len(obs),
            **timeline,
        }
        print(json.dumps(out, indent=2, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
