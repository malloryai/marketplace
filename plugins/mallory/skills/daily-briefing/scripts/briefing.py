#!/usr/bin/env python3
"""Generate a self-contained HTML threat-intelligence daily briefing.

Pulls intelligence from the Mallory API via the official ``malloryapi`` SDK and
renders a single, dependency-free HTML file you can open in a browser, attach to
an email, or pipe into a mail transport later.

Filtering
---------
- ``--topics``       Story topic slugs (server-side filter on ``stories.list``).
                     Run ``malloryapi stories topics`` to see available slugs.
- ``--technologies`` Vendor/product names (e.g. ``cisco,fortinet,winrar``).
                     Keyword-matched across every section's text (CVE titles,
                     descriptions, actor/malware names). Hard filter.
- ``--industry``     GICS sector/industry names or codes. Structured filter on
                     trending actors' ``target_industries``; best-effort keyword
                     refine on story text.
- ``--geo``          ISO country codes (e.g. ``US,UA``). Structured filter on
                     trending actors' ``target_geographies``; best-effort keyword
                     refine on story text.

Requires: MALLORY_API_KEY in the environment and the malloryapi SDK
(``uv pip install --system malloryapi``).
"""
from __future__ import annotations

import argparse
import html
import re
import sys
from datetime import datetime, timedelta, timezone

try:
    from malloryapi import MalloryApi
except ImportError:
    sys.stderr.write(
        "malloryapi SDK not found. Install it with:\n"
        "  uv pip install --system malloryapi\n"
    )
    sys.exit(1)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _split(arg: str | None) -> list[str]:
    if not arg:
        return []
    return [p.strip() for p in arg.split(",") if p.strip()]


def _parse_dt(value) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def _recency(item: dict) -> datetime | None:
    for key in ("updated_content_at", "created_at", "updated_at", "fresh_at"):
        dt = _parse_dt(item.get(key))
        if dt:
            return dt
    return None


def _date(value) -> str:
    dt = _parse_dt(value)
    return dt.strftime("%b %d") if dt else ""


def _esc(value) -> str:
    return html.escape("" if value is None else str(value))


def _md_inline(text: str, limit: int = 320) -> str:
    """Escape, apply minimal inline markdown, collapse to one line, truncate."""
    if not text:
        return ""
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) > limit:
        text = text[: limit - 1].rstrip() + "…"
    out = html.escape(text)
    out = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", out)
    out = re.sub(r"`(.+?)`", r"<code>\1</code>", out)
    return out


def _text_match(item: dict, terms: list[str], fields: list[str]) -> bool:
    if not terms:
        return True
    blob = " ".join(str(item.get(f, "") or "") for f in fields).lower()
    return any(t.lower() in blob for t in terms)


def _resolve_industries(client) -> dict[str, str]:
    lookup: dict[str, str] = {}
    try:
        tax = client.industries.list()
    except Exception:
        return lookup

    def walk(node):
        if isinstance(node, dict):
            code, name = node.get("code"), node.get("name")
            if code and name:
                lookup[str(code)] = name
                lookup[name.lower()] = name
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(tax)
    return lookup


STORY_FIELDS = ["title", "description"]
VULN_FIELDS = [
    "cve_id", "description", "gen_description", "gen_display_name",
    "friendly_name", "gen_cwe_id",
]
ACTOR_FIELDS = ["display_name", "name", "gen_description", "description", "family_name"]
MALWARE_FIELDS = ["display_name", "name", "gen_description", "description"]


# --------------------------------------------------------------------------- #
# Data collection
# --------------------------------------------------------------------------- #
def collect_stories(client, topics, tech, industries, geos, days, limit):
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    seen: dict[str, dict] = {}

    for topic in (topics or [None]):
        kwargs = {"limit": 100}
        if topic:
            kwargs["topic"] = topic
        try:
            page = client.stories.list(**kwargs)
        except Exception as exc:  # noqa: BLE001
            sys.stderr.write(f"warning: stories.list({topic!r}) failed: {exc}\n")
            continue
        for story in page:
            uuid = story.get("uuid")
            if uuid and uuid not in seen:
                seen[uuid] = story

    stories = [s for s in seen.values() if (_recency(s) or cutoff) >= cutoff]

    # Technologies are a hard filter; industry/geo are a softer refine.
    stories = [s for s in stories if _text_match(s, tech, STORY_FIELDS)]

    geo_terms = [g.lower() for g in (industries + geos)]
    if geo_terms:
        refined = [s for s in stories if _text_match(s, geo_terms, STORY_FIELDS)]
        if refined:
            stories = refined

    stories.sort(key=lambda s: _recency(s) or cutoff, reverse=True)
    return stories[:limit]


def collect_vulns(client, accessor_name, tech, period, limit, exploited=False):
    try:
        if exploited:
            items = list(client.vulnerabilities.exploited(limit=100))
        else:
            items = list(client.vulnerabilities.trending(period=period))
    except Exception as exc:  # noqa: BLE001
        sys.stderr.write(f"warning: vulnerabilities {accessor_name} failed: {exc}\n")
        return []
    items = [v for v in items if _text_match(v, tech, VULN_FIELDS)]
    return items[:limit]


def collect_actors(client, tech, industries, geos, period, limit):
    try:
        actors = list(client.threat_actors.trending(period=period))
    except Exception as exc:  # noqa: BLE001
        sys.stderr.write(f"warning: threat_actors.trending failed: {exc}\n")
        return []

    actors = [a for a in actors if _text_match(a, tech, ACTOR_FIELDS)]

    ind_terms = {i.lower() for i in industries}
    geo_terms = {g.upper() for g in geos}
    if not (ind_terms or geo_terms):
        return actors[:limit]

    matched = []
    for actor in actors[: max(limit * 3, 30)]:
        uuid = actor.get("uuid")
        if not uuid:
            continue
        hit = False
        if ind_terms:
            try:
                for row in client.threat_actors.target_industries(uuid):
                    name = str(row.get("gics_name", "")).lower()
                    code = str(row.get("gics_code", ""))
                    if any(t in name or t == code for t in ind_terms):
                        hit = True
                        break
            except Exception:  # noqa: BLE001
                pass
        if not hit and geo_terms:
            try:
                for row in client.threat_actors.target_geographies(uuid):
                    if str(row.get("country_code", "")).upper() in geo_terms:
                        hit = True
                        break
            except Exception:  # noqa: BLE001
                pass
        if hit:
            matched.append(actor)
        if len(matched) >= limit:
            break
    return matched


def collect_malware(client, tech, period, limit):
    try:
        items = list(client.malware.trending(period=period))
    except Exception as exc:  # noqa: BLE001
        sys.stderr.write(f"warning: malware.trending failed: {exc}\n")
        return []
    items = [m for m in items if _text_match(m, tech, MALWARE_FIELDS)]
    return items[:limit]


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #
CSS = """
:root { --blue:#0066FF; --ink:#0d1526; --muted:#64748b; --line:#e6eaf0;
  --bg:#f4f6fa; --card:#ffffff;
  --crit:#b4232a; --high:#d9650a; --med:#b78103; --low:#5b6b82; }
* { box-sizing:border-box; }
body { margin:0; background:var(--bg); color:var(--ink);
  font:14px/1.45 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif; }
.wrap { max-width:880px; margin:0 auto; padding:24px 18px 56px; }
header { border-bottom:3px solid var(--blue); padding-bottom:12px; }
h1 { font-size:21px; margin:0; letter-spacing:-0.02em; text-wrap:balance; }
.date { color:var(--muted); font-size:12.5px; margin-top:2px; }
.filters { margin-top:10px; display:flex; flex-wrap:wrap; gap:5px; }
.chip { background:#e9f0ff; color:var(--blue); border-radius:5px;
  padding:2px 8px; font-size:11px; font-weight:600; }
.summary { display:flex; flex-wrap:wrap; gap:14px; margin:12px 0 4px;
  font-size:12px; color:var(--muted); }
.summary b { color:var(--ink); font-variant-numeric:tabular-nums; }
h2 { font-size:11.5px; text-transform:uppercase; letter-spacing:0.09em;
  color:var(--muted); margin:26px 0 10px; padding-bottom:5px;
  border-bottom:1px solid var(--line); }
h2 span { color:var(--blue); font-weight:700; }
.stories { display:flex; flex-direction:column; gap:8px; }
.grid { display:grid; grid-template-columns:repeat(2,1fr); gap:8px; }
@media (max-width:620px){ .grid { grid-template-columns:1fr; } }
.card { background:var(--card); border:1px solid var(--line); border-radius:8px;
  padding:11px 13px; }
.card h3 { margin:0 0 4px; font-size:15px; line-height:1.3; }
.desc { color:#2b3a52; font-size:13px; }
.desc.c2 { display:-webkit-box; -webkit-line-clamp:2; -webkit-box-orient:vertical;
  overflow:hidden; }
.desc.c3 { display:-webkit-box; -webkit-line-clamp:3; -webkit-box-orient:vertical;
  overflow:hidden; }
code { background:#eef1f6; padding:0 4px; border-radius:4px; font-size:12px; }
.badges { display:flex; flex-wrap:wrap; gap:5px; margin:5px 0; }
.b { font-size:10.5px; font-weight:700; padding:1px 7px; border-radius:4px;
  letter-spacing:0.02em; white-space:nowrap; color:#fff; }
.b.crit{background:var(--crit);} .b.high{background:var(--high);}
.b.med{background:var(--med);} .b.low{background:var(--low);}
.b.kev{background:#7a1020;} .b.epss{background:#1f2a44;}
.b.ghost{background:#eef1f6;color:var(--muted);}
.head { display:flex; justify-content:space-between; align-items:baseline; gap:8px; }
.head h3 { font-size:14px; margin:0; }
.tname { font-weight:700; font-size:14px; }
.topics { margin-top:6px; display:flex; flex-wrap:wrap; gap:4px; }
.topic { background:#eef1f6; color:var(--muted); border-radius:4px;
  padding:1px 6px; font-size:10.5px; }
.meta { color:var(--muted); font-size:11px; margin-top:6px;
  font-variant-numeric:tabular-nums; }
.empty { color:var(--muted); font-style:italic; font-size:13px; }
footer { margin-top:40px; padding-top:12px; border-top:1px solid var(--line);
  color:var(--muted); font-size:11px; text-align:center; }
a { color:var(--blue); text-decoration:none; }
.spotlight { margin-top:14px; border:1px solid #cfe0ff; background:#f2f7ff;
  border-radius:10px; padding:12px 14px; }
.sl-head { font-size:11.5px; text-transform:uppercase; letter-spacing:0.09em;
  color:var(--blue); font-weight:700; margin-bottom:9px;
  display:flex; flex-wrap:wrap; gap:6px; align-items:center; }
.sl-head .for { color:var(--muted); font-weight:600; text-transform:none;
  letter-spacing:0; }
.sgrid { display:grid; grid-template-columns:repeat(2,1fr); gap:7px; }
@media (max-width:620px){ .sgrid { grid-template-columns:1fr; } }
.scard { background:#fff; border:1px solid #d8e3f6; border-left:3px solid var(--blue);
  border-radius:7px; padding:8px 10px; }
.scard.urgent { border-left-color:var(--crit); }
.scard .cat { font-size:9.5px; font-weight:700; letter-spacing:0.05em;
  color:var(--blue); text-transform:uppercase; }
.scard.urgent .cat { color:var(--crit); }
.scard .st { font-size:13px; font-weight:600; line-height:1.3; margin:2px 0 4px; }
.scard .badges { margin:0; }
.scard .meta { margin-top:4px; }
"""


def _sev(score):
    try:
        s = float(score)
    except (TypeError, ValueError):
        return None
    if s >= 9:
        return ("CRIT", "crit", s)
    if s >= 7:
        return ("HIGH", "high", s)
    if s >= 4:
        return ("MED", "med", s)
    return ("LOW", "low", s)


def render_story(s):
    topics = "".join(
        f'<span class="topic">{_esc(t)}</span>' for t in (s.get("topic_labels") or [])[:6]
    )
    dt = _recency(s)
    when = dt.strftime("%b %d") if dt else ""
    refs = s.get("reference_count")
    meta = " · ".join(x for x in [when, f"{refs} src" if refs else ""] if x)
    return (
        '<div class="card">'
        f"<h3>{_esc(s.get('title'))}</h3>"
        f'<div class="desc c3">{_md_inline(s.get("description", ""), 420)}</div>'
        f'<div class="topics">{topics}</div>'
        f'<div class="meta">{meta}</div>'
        "</div>"
    )


def render_vuln(v):
    title = v.get("cve_id") or v.get("gen_display_name") or v.get("friendly_name") or "—"
    name = v.get("gen_display_name") or v.get("friendly_name")
    sub = f' <span class="meta">{_esc(name)}</span>' if name and name != title else ""

    badges = []
    sev = _sev(v.get("cvss_base_score"))
    if sev:
        label, cls, score = sev
        badges.append(f'<span class="b {cls}">{label} {score:g}</span>')
    epss = v.get("epss_percentile")
    if epss is not None:
        try:
            badges.append(f'<span class="b epss">EPSS {float(epss) * 100:.0f}%</span>')
        except (TypeError, ValueError):
            pass
    if v.get("cisa_kev_added_at"):
        badges.append('<span class="b kev">CISA KEV</span>')
    badge_html = f'<div class="badges">{"".join(badges)}</div>' if badges else ""

    meta_bits = []
    if v.get("gen_cwe_id"):
        meta_bits.append(_esc(v["gen_cwe_id"]))
    if v.get("mention_count"):
        meta_bits.append(f'{v["mention_count"]} mentions')
    pub = _date(v.get("published_at"))
    if pub:
        meta_bits.append(pub)
    meta = " · ".join(meta_bits)

    desc = v.get("gen_description") or v.get("description") or ""
    return (
        '<div class="card">'
        f'<div class="head"><h3>{_esc(title)}</h3></div>'
        f"{sub}"
        f"{badge_html}"
        f'<div class="desc c2">{_md_inline(desc, 220)}</div>'
        f'<div class="meta">{meta}</div>'
        "</div>"
    )


def render_actor(a):
    bits = [a.get("motivation"), a.get("family_name")]
    if a.get("mention_count"):
        bits.append(f'{a["mention_count"]} mentions')
    meta = " · ".join(_esc(b) for b in bits if b)
    desc = a.get("gen_description") or a.get("description") or ""
    return (
        '<div class="card">'
        f'<div class="tname">{_esc(a.get("display_name") or a.get("name"))}</div>'
        f'<div class="desc c2">{_md_inline(desc, 200)}</div>'
        f'<div class="meta">{meta}</div>'
        "</div>"
    )


def render_malware(m):
    meta = f'{m["mention_count"]} mentions' if m.get("mention_count") else ""
    desc = m.get("gen_description") or m.get("description") or ""
    return (
        '<div class="card">'
        f'<div class="tname">{_esc(m.get("display_name") or m.get("name"))}</div>'
        f'<div class="desc c2">{_md_inline(desc, 200)}</div>'
        f'<div class="meta">{_esc(meta)}</div>'
        "</div>"
    )


def build_spotlight(stories, vulns, exploited, actors, malware, n):
    """Pick the most relevant tech-matched items across sections for the top.

    Diversity-first: take the highest-ranked item from each category so the
    spotlight reads as a cross-section rather than duplicating one list, then
    fill any remaining slots by urgency (exploited / KEV / high CVSS lead).
    Returns a list of (category, item, urgent) tuples.
    """
    cand = []  # (score, category, item, urgent)
    seen_cve = set()
    for v in exploited:
        cve = v.get("cve_id")
        if cve:
            seen_cve.add(cve)
        cand.append((250 + float(v.get("cvss_base_score") or 0), "Exploited", v, True))
    for v in vulns:
        cve = v.get("cve_id")
        if cve and cve in seen_cve:
            continue
        kev = bool(v.get("cisa_kev_added_at"))
        score = 120 + (80 if kev else 0) + float(v.get("cvss_base_score") or 0)
        cand.append((score, "Vulnerability", v, kev))
    for s in stories:
        cand.append((70, "Story", s, False))
    for a in actors:
        cand.append((40 + min(a.get("mention_count") or 0, 25), "Threat Actor", a, False))
    for m in malware:
        cand.append((35 + min(m.get("mention_count") or 0, 25), "Malware", m, False))

    cand.sort(key=lambda x: x[0], reverse=True)

    picked, used = [], set()
    # Pass 1: best of each category, in urgency order of the categories.
    for category in ("Exploited", "Vulnerability", "Story", "Threat Actor", "Malware"):
        for i, (_, cat, item, urgent) in enumerate(cand):
            if cat == category and i not in used:
                picked.append((i, cat, item, urgent))
                used.add(i)
                break
        if len(picked) >= n:
            break
    # Pass 2: fill remaining slots by global score.
    for i, (_, cat, item, urgent) in enumerate(cand):
        if len(picked) >= n:
            break
        if i not in used:
            picked.append((i, cat, item, urgent))
            used.add(i)

    picked.sort(key=lambda x: x[0])  # restore score order for display
    return [(cat, item, urgent) for _, cat, item, urgent in picked]


def render_spotlight(items, tech):
    cards = []
    for cat, item, urgent in items:
        urgent_cls = " urgent" if urgent else ""
        badges = []
        meta = ""
        if cat in ("Vulnerability", "Exploited"):
            title = item.get("cve_id") or item.get("gen_display_name") or "—"
            name = item.get("gen_display_name") or item.get("friendly_name") or ""
            meta = _esc(name) if name and name != title else ""
            sev = _sev(item.get("cvss_base_score"))
            if sev:
                badges.append(f'<span class="b {sev[1]}">{sev[0]} {sev[2]:g}</span>')
            if cat == "Exploited":
                badges.append('<span class="b kev">EXPLOITED</span>')
            elif item.get("cisa_kev_added_at"):
                badges.append('<span class="b kev">CISA KEV</span>')
        elif cat == "Story":
            title = item.get("title") or "—"
            dt = _recency(item)
            meta = dt.strftime("%b %d") if dt else ""
        else:  # Threat Actor / Malware
            title = item.get("display_name") or item.get("name") or "—"
            if item.get("mention_count"):
                meta = f'{item["mention_count"]} mentions'
        badge_html = f'<div class="badges">{"".join(badges)}</div>' if badges else ""
        meta_html = f'<div class="meta">{meta}</div>' if meta else ""
        cards.append(
            f'<div class="scard{urgent_cls}">'
            f'<div class="cat">{_esc(cat)}</div>'
            f'<div class="st">{_esc(title)}</div>'
            f"{badge_html}{meta_html}"
            "</div>"
        )
    label = ", ".join(tech)
    return (
        '<div class="spotlight">'
        f'<div class="sl-head">Spotlight <span class="for">— matches for {_esc(label)}</span></div>'
        f'<div class="sgrid">{"".join(cards)}</div>'
        "</div>"
    )


def _section(title, items, renderer, layout="grid"):
    head = f'<h2>{_esc(title)} <span>{len(items)}</span></h2>'
    if not items:
        return head + "<p class='empty'>No matching intelligence in this window.</p>"
    inner = "".join(renderer(i) for i in items)
    cls = "stories" if layout == "stories" else "grid"
    return f'{head}<div class="{cls}">{inner}</div>'


def render_html(title, generated, filters, summary, sections, spotlight=""):
    chips = "".join(f'<span class="chip">{_esc(c)}</span>' for c in filters)
    chip_block = f'<div class="filters">{chips}</div>' if chips else ""
    sum_html = "".join(
        f"<span><b>{n}</b> {_esc(label)}</span>" for label, n in summary
    )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{_esc(title)}</title>
<style>{CSS}</style></head>
<body><div class="wrap">
<header>
<h1>{_esc(title)}</h1>
<div class="date">{_esc(generated)}</div>
{chip_block}
</header>
{spotlight}
<div class="summary">{sum_html}</div>
{"".join(sections)}
<footer>Generated by Mallory · threat intelligence by <a href="https://mallory.ai">mallory.ai</a></footer>
</div></body></html>"""


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def main() -> int:
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument("--topics", help="Comma-separated story topic slugs")
    p.add_argument("--technologies", "--tech", dest="technologies",
                   help="Comma-separated vendor/product names (e.g. cisco,fortinet)")
    p.add_argument("--industry", help="Comma-separated GICS sector/industry names or codes")
    p.add_argument("--geo", help="Comma-separated ISO country codes (e.g. US,UA)")
    p.add_argument("--days", type=int, default=1, help="Story freshness window in days (default 1)")
    p.add_argument("--period", default="7d", help="Trending period: 1d/7d/30d (default 7d)")
    p.add_argument("--limit", type=int, default=8, help="Max items per section (default 8)")
    p.add_argument("--title", default="Daily Threat Intelligence Briefing", help="Briefing title")
    p.add_argument("--output", "-o", default="daily-briefing.html", help="Output HTML path")
    p.add_argument("--spotlight", type=int, default=6,
                   help="Items in the top technology spotlight (default 6; 0 to disable)")
    p.add_argument("--no-stories", action="store_true")
    p.add_argument("--no-vulns", action="store_true")
    p.add_argument("--no-exploited", action="store_true")
    p.add_argument("--no-actors", action="store_true")
    p.add_argument("--no-malware", action="store_true")
    args = p.parse_args()

    topics = _split(args.topics)
    tech = _split(args.technologies)
    geos = _split(args.geo)
    raw_industries = _split(args.industry)

    try:
        client = MalloryApi()
    except Exception as exc:  # noqa: BLE001
        sys.stderr.write(f"Failed to init MalloryApi (is MALLORY_API_KEY set?): {exc}\n")
        return 1

    ind_lookup = _resolve_industries(client) if raw_industries else {}
    industries = [ind_lookup.get(t, ind_lookup.get(t.lower(), t)) for t in raw_industries]

    stories = vulns = exploited = actors = malware = []
    sections, summary = [], []
    if not args.no_stories:
        stories = collect_stories(client, topics, tech, industries, geos, args.days, args.limit)
        sections.append(_section("Intelligence Stories", stories, render_story, "stories"))
        summary.append(("stories", len(stories)))
    if not args.no_vulns:
        vulns = collect_vulns(client, "trending", tech, args.period, args.limit)
        sections.append(_section("Trending Vulnerabilities", vulns, render_vuln))
        summary.append(("vulns", len(vulns)))
    if not args.no_exploited:
        exploited = collect_vulns(client, "exploited", tech, args.period, args.limit, exploited=True)
        sections.append(_section("Actively Exploited CVEs", exploited, render_vuln))
        summary.append(("exploited", len(exploited)))
    if not args.no_actors:
        actors = collect_actors(client, tech, industries, geos, args.period, args.limit)
        sections.append(_section("Trending Threat Actors", actors, render_actor))
        summary.append(("actors", len(actors)))
    if not args.no_malware:
        malware = collect_malware(client, tech, args.period, args.limit)
        sections.append(_section("Trending Malware", malware, render_malware))
        summary.append(("malware", len(malware)))

    # When watching specific technologies, surface the highest-priority matches
    # in a spotlight pinned to the top of the page.
    spotlight = ""
    if tech and args.spotlight > 0:
        top = build_spotlight(stories, vulns, exploited, actors, malware, args.spotlight)
        if top:
            spotlight = render_spotlight(top, tech)

    generated = datetime.now(timezone.utc).strftime("%A, %B %d, %Y · %H:%M UTC")
    filters = []
    filters += [f"topic: {t}" for t in topics]
    filters += [f"tech: {t}" for t in tech]
    filters += [f"industry: {i}" for i in industries]
    filters += [f"geo: {g}" for g in geos]
    filters.append(f"window: {args.days}d stories / {args.period} trending")

    doc = render_html(args.title, generated, filters, summary, sections, spotlight)
    with open(args.output, "w", encoding="utf-8") as fh:
        fh.write(doc)

    sys.stderr.write(f"Wrote briefing to {args.output} ({len(doc):,} bytes)\n")
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
