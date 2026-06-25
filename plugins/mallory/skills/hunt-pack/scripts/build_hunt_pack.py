#!/usr/bin/env python3
"""Build a threat-hunt pack scoped to an industry + geography from Mallory data.

Pipeline:
  1. Resolve the requested industry (free text or GICS code) to GICS code(s) via
     the industry taxonomy, and the requested geography to ISO-2 country codes via
     a bundled region map (the API's geography taxonomy is empty).
  2. Build a candidate actor pool from trending activity (recency-weighted).
  3. Score each candidate by how much of its INDUSTRY and GEOGRAPHY targeting
     evidence matches the scope, weighted by recency and mention volume.
  4. Enrich the top actors with their MITRE ATT&CK techniques, malware, IOCs,
     and exploited CVEs.
  5. Emit a hunt pack: hunt_pack.json, report.md, an ATT&CK Navigator layer,
     iocs.csv, cve_watchlist.csv, and hunt_hypotheses.md.

Requires the official SDK:  uv pip install --system malloryapi
Auth:  MALLORY_API_KEY in the environment.
"""
from __future__ import annotations

import argparse
import csv
import json
import math
import os
import sys
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

try:
    from malloryapi import MalloryApi
except ImportError:
    sys.exit("malloryapi not installed. Run: uv pip install --system malloryapi")

HERE = os.path.dirname(os.path.abspath(__file__))
REGIONS_PATH = os.path.join(HERE, "..", "assets", "regions.json")
TRENDING_PERIODS = {"1d", "7d", "30d"}
MAX_WORKERS = 12


# --------------------------------------------------------------------------- #
# Response shape helpers
#
# The SDK wraps endpoints that return an `items` key as PaginatedResponse, but
# passes endpoints that return a `data` key straight through as raw dicts. These
# helpers normalize both so the rest of the script doesn't care.
# --------------------------------------------------------------------------- #
def _rows(resp):
    if isinstance(resp, dict):
        return resp.get("data") or resp.get("items") or []
    try:
        return list(resp)
    except TypeError:
        return []


def _total(resp):
    if isinstance(resp, dict):
        return resp.get("total")
    return getattr(resp, "total", None)


def fetch_all(fn, *args, page=200, cap=2000, **kw):
    """Page through an accessor until exhausted or `cap` rows collected."""
    out, off = [], 0
    while len(out) < cap:
        resp = fn(*args, limit=page, offset=off, **kw)
        batch = _rows(resp)
        if not batch:
            break
        out.extend(batch)
        off += len(batch)
        total = _total(resp)
        if len(batch) < page or (total is not None and off >= total):
            break
    return out[:cap]


# --------------------------------------------------------------------------- #
# Recency
# --------------------------------------------------------------------------- #
def _parse_dt(s):
    """Parse an ISO timestamp to a timezone-aware datetime (assume UTC if naive)."""
    if not s:
        return None
    try:
        dt = datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def recency_weight(dt, now, half_life_days=90.0):
    """Exponential decay in [0, 1]; evidence `half_life_days` old scores 0.5."""
    if dt is None:
        return 0.0
    age = max((now - dt).total_seconds() / 86400.0, 0.0)
    return math.exp(-math.log(2) * age / half_life_days)


def row_recency(row, now):
    dt = _parse_dt(row.get("updated_at")) or _parse_dt(row.get("created_at"))
    return recency_weight(dt, now)


# --------------------------------------------------------------------------- #
# Scope resolution
# --------------------------------------------------------------------------- #
def flatten_industries(tax):
    """Yield (code, name) for every node in the GICS taxonomy tree."""
    for sector in tax.get("sectors", []):
        yield sector["code"], sector["name"]
        for grp in sector.get("industry_groups", []):
            yield grp["code"], grp["name"]
            for ind in grp.get("industries", []):
                yield ind["code"], ind["name"]
                for sub in ind.get("sub_industries", []):
                    yield sub["code"], sub["name"]


def resolve_industry(client, query):
    """Return (codes:set[str], labels:list[str]) matching a name or GICS code."""
    tax = client.industries.list()
    if isinstance(tax, dict):
        nodes = list(flatten_industries(tax))
    else:  # Paginated/ list fallback
        nodes = [(n.get("code"), n.get("name")) for n in _rows(tax)]
    q = query.strip().lower()
    codes, labels = set(), []
    for code, name in nodes:
        if code is None:
            continue
        if q == code.lower() or q in (name or "").lower():
            codes.add(code)
            labels.append(f"{name} ({code})")
    return codes, labels


def industry_match(actor_code, scope_codes):
    """Match when the actor's evidence is the requested GICS code or a descendant.

    Prefix is one-directional on purpose: a sector query ("10") matches its
    sub-industries, but a narrow sub-industry query does NOT match broader
    sector-level evidence — that would widen results exactly when the caller
    asked to narrow them.
    """
    if not actor_code:
        return False
    return any(actor_code.startswith(c) for c in scope_codes)


def load_regions():
    with open(REGIONS_PATH) as fh:
        return json.load(fh)


def _pycountry():
    """Return the pycountry module if installed, else None (cached)."""
    global _PYCOUNTRY
    if _PYCOUNTRY is None:
        try:
            import pycountry
            _PYCOUNTRY = pycountry
        except ImportError:
            _PYCOUNTRY = False
    return _PYCOUNTRY or None


_PYCOUNTRY = None


def _name_to_iso2(token):
    """Resolve a country name to ISO-2 via pycountry (exact, then fuzzy). None if unavailable."""
    pc = _pycountry()
    if not pc:
        return None
    try:
        c = (pc.countries.get(name=token) or pc.countries.get(common_name=token)
             or pc.countries.get(official_name=token))
        if c:
            return c.alpha_2
        res = pc.countries.search_fuzzy(token)
        return res[0].alpha_2 if res else None
    except LookupError:
        return None


def resolve_geo(query):
    """Return (country_codes:set[str], labels:list[str]) from codes, region names, or country names.

    Country-name/code resolution prefers pycountry (full ISO 3166 coverage); the
    bundled regions.json supplies analyst region groupings and a colloquial-alias
    fallback so the skill still works without pycountry installed.
    """
    if not query:
        return set(), []
    data = load_regions()
    regions = {k.lower(): v for k, v in data.get("regions", {}).items()}
    aliases = {k.lower(): v.upper() for k, v in data.get("countries", {}).items()}
    pc = _pycountry()

    # Accept any code that is a valid ISO-2 (pycountry), a bundled alias target,
    # or appears in a region list — so e.g. `--geo PE` works without an alias entry.
    valid_codes = {c.alpha_2 for c in pc.countries} if pc else set()
    valid_codes |= set(aliases.values())
    for lst in regions.values():
        valid_codes |= {c.upper() for c in lst}

    codes, labels = set(), []
    for token in [t.strip() for t in query.split(",") if t.strip()]:
        tl, tu = token.lower(), token.upper()
        if tl in regions:
            cs = {c.upper() for c in regions[tl]}
            codes |= cs
            labels.append(f"{token} ({len(cs)} countries)")
        elif len(token) == 2 and tu in valid_codes:
            codes.add(tu)
            labels.append(tu)
        elif len(token) == 3 and pc and pc.countries.get(alpha_3=tu):
            iso = pc.countries.get(alpha_3=tu).alpha_2
            codes.add(iso)
            labels.append(f"{token} ({iso})")
        elif tl in aliases:
            codes.add(aliases[tl])
            labels.append(f"{token} ({aliases[tl]})")
        else:
            iso = _name_to_iso2(token)
            if iso:
                codes.add(iso)
                labels.append(f"{token} ({iso})")
            else:
                labels.append(f"{token} (UNRESOLVED)")
    return codes, labels


# --------------------------------------------------------------------------- #
# Candidate pool + scoring
# --------------------------------------------------------------------------- #
def build_pool(client, window, pool_size, industry_labels):
    """Trending actors (recency) + a name search seed, merged by uuid."""
    pool = {}
    for a in fetch_all(client.threat_actors.trending, period=window, cap=pool_size * 2):
        pool[a["uuid"]] = a
    # Seed with a search on the primary industry term, in case it isn't trending.
    if industry_labels:
        term = industry_labels[0].split(" (")[0]
        try:
            for a in _rows(client.search.query(q=term, types="threat_actor")):
                pool.setdefault(a["uuid"], a)
        except Exception:
            pass
    actors = sorted(pool.values(), key=lambda a: a.get("mention_count") or 0, reverse=True)
    return actors[:pool_size]


def score_actor(client, actor, scope_codes, geo_codes, now):
    """Pull targeting evidence and compute a relevance score. Returns dict or None."""
    ind_rows = fetch_all(client.threat_actors.target_industries, actor["uuid"], cap=400)
    geo_rows = (
        fetch_all(client.threat_actors.target_geographies, actor["uuid"], cap=400)
        if geo_codes else []
    )

    ind_matches = [r for r in ind_rows if industry_match(r.get("gics_code"), scope_codes)]
    geo_matches = [r for r in geo_rows if (r.get("country_code") or "").upper() in geo_codes]

    if scope_codes and not ind_matches:
        return None
    if geo_codes and not geo_matches:
        return None

    ind_rec = max((row_recency(r, now) for r in ind_matches), default=0.0)
    geo_rec = max((row_recency(r, now) for r in geo_matches), default=0.0)
    mentions = actor.get("mention_count") or 0

    score = (
        2.0 * math.log1p(len(ind_matches))
        + 1.5 * math.log1p(len(geo_matches))
        + 2.5 * max(ind_rec, geo_rec)
        + 1.0 * math.log1p(mentions)
    )
    return {
        "actor": actor,
        "score": round(score, 4),
        "industry_match_count": len(ind_matches),
        "geo_match_count": len(geo_matches),
        "industry_evidence": ind_matches,
        "geo_evidence": geo_matches,
    }


# --------------------------------------------------------------------------- #
# Enrichment
# --------------------------------------------------------------------------- #
def enrich_actor(client, scored):
    a = scored["actor"]
    uuid = a["uuid"]

    ap_rows = fetch_all(client.threat_actors.attack_patterns, uuid, cap=2000)
    freq = Counter()
    tech_name, tech_uuid = {}, {}
    for r in ap_rows:
        tid = r.get("mitre_attack_id")
        if not tid:
            continue
        freq[tid] += 1
        tech_name.setdefault(tid, r.get("display_name") or r.get("name"))
        if r.get("attack_pattern_uuid"):
            tech_uuid.setdefault(tid, r["attack_pattern_uuid"])

    malware = [
        {"name": m.get("display_name") or m.get("name"), "uuid": m.get("malware_uuid") or m.get("uuid")}
        for m in fetch_all(client.threat_actors.malware, uuid, cap=200)
    ]

    iocs = [
        {
            "type": o.get("type"),
            "value": o.get("name"),
            "uuid": o.get("uuid"),
            "latest_opinion": o.get("latest_opinion_published_at"),
            "created_at": o.get("created_at"),
        }
        for o in fetch_all(client.threat_actors.observables, uuid, cap=500)
    ]

    cves = {}
    for e in fetch_all(client.threat_actors.exploitations, uuid, cap=300):
        cve = e.get("cve_id")
        if not cve:
            continue
        cur = cves.setdefault(cve, {
            "cve_id": cve, "vulnerability_uuid": e.get("vulnerability_uuid"),
            "exploited_in_the_wild": False, "reference_url": e.get("reference_url"),
        })
        cur["exploited_in_the_wild"] |= bool(e.get("exploited_in_the_wild"))

    scored.update({
        "technique_freq": dict(freq), "technique_name": tech_name,
        "technique_uuid": tech_uuid, "malware": malware, "iocs": iocs,
        "cves": cves,
    })
    return scored


def hydrate_techniques(client, scored_list):
    """Resolve unique technique UUIDs -> MITRE id + tactics (for the Navigator layer)."""
    want = {}
    for s in scored_list:
        for tid, uuid in s.get("technique_uuid", {}).items():
            want.setdefault(tid, uuid)
    tactics = {}

    def _one(item):
        tid, uuid = item
        try:
            ap = client.attack_patterns.get(uuid)
            return tid, (ap.get("tactics") or [])
        except Exception:
            return tid, []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        for tid, tacs in pool.map(_one, want.items()):
            tactics[tid] = tacs
    return tactics


def hydrate_cves(client, scored_list):
    """Resolve unique CVE UUIDs -> CVSS/EPSS once each."""
    want = {}
    for s in scored_list:
        for cve, rec in s.get("cves", {}).items():
            if rec.get("vulnerability_uuid"):
                want.setdefault(cve, rec["vulnerability_uuid"])
    details = {}

    def _one(item):
        cve, uuid = item
        try:
            v = client.vulnerabilities.get(uuid)
            return cve, {
                "cvss": v.get("cvss_base_score"), "epss": v.get("epss_score"),
                "state": v.get("state"),
            }
        except Exception:
            return cve, {}

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        for cve, det in pool.map(_one, want.items()):
            details[cve] = det
    return details


# --------------------------------------------------------------------------- #
# Output builders
# --------------------------------------------------------------------------- #
# --------------------------------------------------------------------------- #
# Per-actor hunting guidance (deterministic; no model needed)
# --------------------------------------------------------------------------- #
# Where each IOC type is most likely to surface in defender telemetry. Mallory
# observable types are dotted (e.g. "ip.v4", "hash.sha256"); ioc_log_source()
# falls back to the prefix before the dot, so new subtypes still resolve.
IOC_SOURCE = {
    "domain": "DNS and web-proxy logs", "hostname": "DNS and web-proxy logs",
    "fqdn": "DNS and web-proxy logs", "uri": "web-proxy / URL-filtering logs",
    "url": "web-proxy / URL-filtering logs",
    "ip": "firewall, NetFlow, and VPN logs",
    "hash": "EDR/AV file-hash telemetry",
    "email": "email-gateway logs",
    "file": "EDR file/process telemetry", "filename": "EDR file/process telemetry",
    "mutex": "EDR process telemetry", "registry": "EDR registry telemetry",
    "user_agent": "web-proxy / WAF logs", "ssl": "TLS/JA3 network telemetry",
}


def ioc_log_source(ioc_type):
    t = (ioc_type or "").lower()
    return IOC_SOURCE.get(t) or IOC_SOURCE.get(t.split(".")[0]) or "the relevant logs"

# Tactic-level fallback guidance — always applies when a technique has no override.
TACTIC_GUIDANCE = {
    "reconnaissance": "Review perimeter/WAF and external-scan logs for enumeration against your assets.",
    "resource-development": "Watch for newly-registered lookalike domains and staging infrastructure tied to this actor.",
    "initial-access": "Audit external-facing services (VPN, email gateway, web apps, RDP) for exploitation and anomalous auth; confirm patch status of the CVEs above.",
    "execution": "Hunt EDR process-creation telemetry for script interpreters and signed-binary proxy execution.",
    "persistence": "Audit autoruns: scheduled tasks, services, run keys, WMI subscriptions, and new account creation.",
    "privilege-escalation": "Review token manipulation, UAC bypass, vulnerable-driver (BYOVD) loads, and sudo/SUID abuse.",
    "defense-evasion": "Look for log clearing, security-tool tampering, masquerading, and signed-binary proxy execution.",
    "credential-access": "Hunt for LSASS access, credential dumping, Kerberoasting, and access to credential stores.",
    "discovery": "Review host/network discovery commands run in rapid succession from a single host.",
    "lateral-movement": "Inspect remote-service auth (SMB, WMI, RDP, WinRM) and admin-share use between hosts.",
    "collection": "Look for data staging/archiving and access to file shares, mailboxes, and cloud storage.",
    "command-and-control": "Inspect egress, proxy, and DNS logs for beaconing; pivot on this actor's IOC domains/IPs below.",
    "exfiltration": "Watch for large or anomalous outbound transfers to web services and cloud storage.",
    "impact": "Monitor for mass file modification, shadow-copy deletion, service stop, and encryption activity.",
}

# Technique-level overrides for high-signal, common techniques (matched on full id, then base id).
TECHNIQUE_GUIDANCE = {
    "T1190": "Confirm patch status and external exposure of the CVEs in this pack; review WAF/app logs for exploitation of public-facing apps.",
    "T1133": "Review external remote services (VPN/RDP gateways, Citrix) for unauthorized or anomalous access.",
    "T1566": "Check the email gateway for spearphishing; detonate suspicious attachments and links; hunt for macro/child-process execution.",
    "T1078": "Review auth logs for valid-account abuse: impossible travel, MFA fatigue, and dormant-account logons.",
    "T1059": "Hunt command/script interpreter execution for encoded or obfuscated commands and download cradles.",
    "T1059.001": "Hunt PowerShell logs (4104 script-block, 4103 module) for encoded commands and download cradles.",
    "T1059.003": "Hunt cmd.exe child processes and suspicious batch execution chains.",
    "T1105": "Inspect proxy/EDR for ingress tool transfer via LOLBins (certutil, bitsadmin, curl, mshta).",
    "T1003": "Hunt for LSASS access and credential dumping (comsvcs.dll, procdump, Mimikatz, NTDS extraction).",
    "T1068": "Check for privilege-escalation CVE exploitation and vulnerable-driver (BYOVD) loads.",
    "T1112": "Audit registry-modification telemetry for persistence and defense-evasion changes.",
    "T1486": "Hunt ransomware encryption: rapid file renames, ransom notes, and shadow-copy deletion (vssadmin/wmic).",
    "T1490": "Alert on inhibition of recovery: vssadmin/wbadmin delete, bcdedit recovery changes.",
    "T1090": "Inspect proxy/connection-relay and anonymization traffic (Tor, multi-hop proxies) in egress logs.",
    "T1567": "Watch for exfiltration over web services (cloud storage, paste sites, code repos).",
    "T1071": "Baseline application-layer C2 over HTTP/S and DNS; hunt for beaconing intervals and rare destinations.",
    "T1053": "Audit scheduled task/cron creation and modification for persistence.",
    "T1204": "Hunt user-execution chains: office apps spawning interpreters, LNK/ISO/container delivery.",
    "T1021": "Inspect lateral movement over RDP/SMB/WMI/WinRM and remote-service creation.",
    "T1547": "Audit boot/logon autostart entries (run keys, startup folder, services).",
}


def technique_instruction(tid, tactics):
    base = tid.split(".")[0]
    g = TECHNIQUE_GUIDANCE.get(tid) or TECHNIQUE_GUIDANCE.get(base)
    if g:
        return g
    for t in tactics:
        if t in TACTIC_GUIDANCE:
            return TACTIC_GUIDANCE[t]
    return "Map this technique to your telemetry and hunt for its known procedures."


def build_checklist(a):
    """Turn an assembled actor entry into concrete 'what to check' guidance."""
    itw = [c for c in a["cves"] if c.get("exploited_in_the_wild")]
    other = [c for c in a["cves"] if not c.get("exploited_in_the_wild")]
    exposure = []
    for c in (itw + other)[:10]:
        cvss = f" (CVSS {c['cvss']})" if c.get("cvss") else ""
        tail = " — actively exploited in the wild, prioritize." if c.get("exploited_in_the_wild") else "."
        exposure.append({
            "cve_id": c["cve_id"], "cvss": c.get("cvss"),
            "exploited_in_the_wild": bool(c.get("exploited_in_the_wild")),
            "action": f"Confirm patch status and external exposure to {c['cve_id']}{cvss}{tail}",
        })

    by_type = defaultdict(list)
    for ioc in a["iocs"]:
        if ioc.get("value"):
            by_type[(ioc.get("type") or "other").lower()].append(ioc["value"])
    ioc_sweeps = []
    for typ, vals in sorted(by_type.items(), key=lambda kv: -len(kv[1])):
        src = ioc_log_source(typ)
        sample = vals[:8]
        more = f" (+{len(vals) - len(sample)} more in iocs.csv)" if len(vals) > len(sample) else ""
        ioc_sweeps.append({
            "ioc_type": typ, "count": len(vals), "log_source": src, "sample": sample,
            "action": f"Search {src} for these {typ} indicators: " + ", ".join(sample) + more,
        })

    behavioral = [
        {
            "mitre_attack_id": t["mitre_attack_id"], "name": t["name"], "tactics": t["tactics"],
            "action": technique_instruction(t["mitre_attack_id"], t["tactics"]),
        }
        for t in a["top_techniques"][:6]
    ]

    malware = [m["name"] for m in a["malware"][:10] if m.get("name")]
    return {
        "exposure_checks": exposure,
        "ioc_sweeps": ioc_sweeps,
        "behavioral_hunts": behavioral,
        "malware_watch": malware,
    }


def _ev_dt(r):
    return _parse_dt(r.get("updated_at")) or _parse_dt(r.get("created_at"))


def _ev_ts(r):
    dt = _ev_dt(r)  # _parse_dt guarantees tz-aware
    return dt.timestamp() if dt else 0.0


def why_relevant(scored, limit=3):
    """Most-recent matching evidence first, dated, drawing from both industry and geo."""
    def mk(r, kind, label):
        dt = _ev_dt(r)
        return {
            "kind": kind, "label": label,
            "date": dt.date().isoformat() if dt else None,
            "context": (r.get("context") or "").strip()[:300],
            "reference_url": r.get("reference_url"), "source": r.get("reference_source"),
        }
    ind = sorted(scored["industry_evidence"], key=_ev_ts, reverse=True)[:limit]
    geo = sorted(scored["geo_evidence"], key=_ev_ts, reverse=True)[:limit]
    items = ([mk(r, "industry", r.get("gics_name")) for r in ind]
             + [mk(r, "geography", r.get("country_code")) for r in geo])
    items.sort(key=lambda x: x["date"] or "", reverse=True)
    return items


def build_pack(scope, scored_list, tactics, cve_details, now):
    actors = []
    for s in scored_list:
        a = s["actor"]
        # Enrichment fields default to empty: enrich_actor may have failed for
        # this actor (the _enrich wrapper returns the un-enriched dict), and one
        # bad actor must not crash the whole pack.
        technique_name = s.get("technique_name", {})
        techs = sorted(s.get("technique_freq", {}).items(), key=lambda kv: kv[1], reverse=True)
        cves = []
        for cve, rec in sorted(s.get("cves", {}).items()):
            d = cve_details.get(cve, {})
            cves.append({**rec, **d})
        cves.sort(key=lambda c: (c.get("cvss") or 0), reverse=True)
        iocs = s.get("iocs", [])
        entry = {
            "uuid": a["uuid"],
            "name": a.get("display_name") or a.get("name"),
            "aliases": a.get("family_name"),
            "motivation": a.get("motivation"),
            "mention_count": a.get("mention_count"),
            "score": s["score"],
            "industry_match_count": s["industry_match_count"],
            "geo_match_count": s["geo_match_count"],
            "why_relevant": why_relevant(s),
            "summary": (a.get("gen_description") or "").strip()[:600] or None,
            "top_techniques": [
                {"mitre_attack_id": t, "name": technique_name.get(t),
                 "tactics": tactics.get(t, []), "count": c}
                for t, c in techs[:15]
            ],
            "malware": s.get("malware", [])[:15],
            "ioc_count": len(iocs),
            "iocs": iocs,               # full set — display limits applied in renderers
            "cve_count": len(cves),
            "cves": cves,               # full set — display limits applied in renderers
        }
        entry["hunt_checklist"] = build_checklist(entry)
        actors.append(entry)
    return {
        "meta": {
            "generated_at": now.isoformat(),
            "scope": scope,
            "actor_count": len(actors),
        },
        "actors": actors,
    }


def write_navigator_layer(path, pack):
    agg = Counter()
    comments = defaultdict(set)
    for actor in pack["actors"]:
        for t in actor["top_techniques"]:
            agg[t["mitre_attack_id"]] += t["count"]
            comments[t["mitre_attack_id"]].add(actor["name"])
    techniques = [
        {
            "techniqueID": tid, "score": cnt,
            "comment": "Used by: " + ", ".join(sorted(comments[tid])),
            "enabled": True,
        }
        for tid, cnt in agg.items()
    ]
    scope = pack["meta"]["scope"]
    layer = {
        "name": f"Hunt Pack — {scope['industry']} / {scope.get('geo') or 'global'}",
        "versions": {"attack": "14", "navigator": "4.9.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": f"Generated by Mallory hunt-pack from {pack['meta']['actor_count']} actors.",
        "techniques": techniques,
        "gradient": {
            "colors": ["#0b1b3a", "#0066ff", "#3fe0f0"],
            "minValue": 0,
            "maxValue": max([t["score"] for t in techniques], default=1),
        },
        "sorting": 3,
    }
    with open(path, "w") as fh:
        json.dump(layer, fh, indent=2)


def write_iocs_csv(path, pack):
    with open(path, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["ioc_type", "ioc_value", "actor", "actor_uuid",
                    "latest_opinion_published_at", "first_seen"])
        for actor in pack["actors"]:
            for ioc in actor["iocs"]:
                w.writerow([ioc.get("type"), ioc.get("value"), actor["name"],
                            actor["uuid"], ioc.get("latest_opinion"), ioc.get("created_at")])


def write_cve_csv(path, pack):
    with open(path, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["cve_id", "cvss", "epss", "exploited_in_the_wild", "state",
                    "actor", "reference_url"])
        for actor in pack["actors"]:
            for c in actor["cves"]:
                w.writerow([c.get("cve_id"), c.get("cvss"), c.get("epss"),
                            c.get("exploited_in_the_wild"), c.get("state"),
                            actor["name"], c.get("reference_url")])


def write_report_md(path, pack):
    m = pack["meta"]
    s = m["scope"]
    lines = [
        f"# Threat Hunt Pack — {s['industry']} / {s.get('geo') or 'Global'}",
        "",
        f"_Generated {m['generated_at']} from Mallory · window {s['window']} · "
        f"{m['actor_count']} prioritized actors._",
        "",
        f"**Scope:** industry `{', '.join(s['industry_codes'])}`"
        + (f" · geography `{', '.join(s['geo_codes'])}`" if s.get("geo_codes") else ""),
        "",
        "## Prioritized actors",
        "",
    ]
    for i, a in enumerate(pack["actors"], 1):
        lines += [
            f"### {i}. {a['name']}"
            + (f" ({a['aliases']})" if a.get("aliases") else ""),
            "",
            f"- **Relevance score:** {a['score']} · "
            f"industry evidence: {a['industry_match_count']} · "
            f"geo evidence: {a['geo_match_count']} · mentions: {a['mention_count']}",
            f"- **Motivation:** {a.get('motivation') or 'unknown'}",
            f"- **Arsenal:** {a['cve_count']} CVEs · {a['ioc_count']} IOCs · "
            f"{len(a['malware'])} malware families",
        ]
        if a.get("summary"):
            lines += ["", a["summary"], ""]
        if a["why_relevant"]:
            lines.append("- **Why relevant** (most recent first):")
            for w in a["why_relevant"]:
                ctx = w["context"] or ""
                date = f"`{w['date']}` " if w.get("date") else ""
                url = (w.get("reference_url") or "").strip()
                src = (f" ([{w.get('source') or 'source'}]({url}))"
                       if url.lower().startswith(("http://", "https://")) else "")
                lines.append(f"  - {date}_{w['kind']} · {w['label']}_: {ctx}{src}")

        # What to check — concrete, actor-specific hunting guidance
        hc = a.get("hunt_checklist", {})
        lines += ["", "**What to check:**", ""]
        if hc.get("exposure_checks"):
            lines.append("- _Exposure / patch:_")
            for e in hc["exposure_checks"]:
                lines.append(f"  - {e['action']}")
        if hc.get("ioc_sweeps"):
            lines.append("- _IOC sweeps:_")
            for sw in hc["ioc_sweeps"]:
                lines.append(f"  - {sw['action']}")
        if hc.get("behavioral_hunts"):
            lines.append("- _Behavioral hunts:_")
            for b in hc["behavioral_hunts"]:
                tac = f" [{', '.join(b['tactics'])}]" if b.get("tactics") else ""
                lines.append(f"  - **{b['mitre_attack_id']} {b['name']}**{tac}: {b['action']}")
        if hc.get("malware_watch"):
            lines.append(f"- _Malware to watch:_ verify EDR/AV detections for {', '.join(hc['malware_watch'])}.")
        lines.append("")
    with open(path, "w") as fh:
        fh.write("\n".join(lines))


def _esc(s):
    return (str(s) if s is not None else "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _safe_url(u):
    """Return an attribute-safe http(s) URL, or '' if the scheme is not allowed.

    reference_url is third-party data; rejecting non-http(s) schemes blocks
    `javascript:`/`data:` hrefs, and escaping quotes/angle brackets prevents
    breaking out of the href attribute.
    """
    if not u:
        return ""
    u = str(u).strip()
    if not u.lower().startswith(("http://", "https://")):
        return ""
    return (u.replace("&", "&amp;").replace('"', "&quot;")
            .replace("<", "&lt;").replace(">", "&gt;"))


# Mallory dark design tokens (ported from the ttp-heatmap design system).
BRIEF_CSS = """
:root{--ground:#070B14;--panel:#121A28;--elev:#151C2A;--bd:rgba(140,160,190,.16);
--bd2:rgba(140,160,190,.08);--ink:#E8EDF5;--ink2:#C2CBDD;--muted:#8A97AD;--faint:#586780;
--accent:#0066FF;--link:#4DA3FF;--cyan:#3FE0F0;}
*{box-sizing:border-box}
.hp{background:var(--ground);color:var(--ink);font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
padding:32px;max-width:1100px;margin:0 auto}
.hp h1{font-size:26px;margin:0 0 4px;letter-spacing:-.01em}
.hp .eyebrow{color:var(--link);font-size:12px;text-transform:uppercase;letter-spacing:.12em;font-weight:600}
.hp .sub{color:var(--muted);font-size:13px;margin:6px 0 0}
.hp .scopebar{display:flex;flex-wrap:wrap;gap:8px;margin:18px 0 26px}
.hp .chip{background:var(--panel);border:1px solid var(--bd);border-radius:999px;padding:5px 12px;font-size:12px;color:var(--ink2)}
.hp .chip b{color:var(--ink);font-weight:600}
.hp .actor{background:var(--panel);border:1px solid var(--bd);border-radius:14px;padding:20px 22px;margin:0 0 16px}
.hp .actor h2{margin:0;font-size:19px;display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.hp .rank{display:inline-flex;align-items:center;justify-content:center;min-width:26px;height:26px;border-radius:8px;
background:var(--accent);color:#fff;font-size:13px;font-weight:700;padding:0 6px}
.hp .alias{color:var(--muted);font-size:13px;font-weight:400}
.hp .metrics{display:flex;flex-wrap:wrap;gap:18px;margin:12px 0;color:var(--ink2);font-size:12.5px}
.hp .metrics span b{color:var(--ink);font-variant-numeric:tabular-nums}
.hp .desc{color:var(--ink2);font-size:13.5px;margin:8px 0 14px}
.hp .label{color:var(--faint);font-size:11px;text-transform:uppercase;letter-spacing:.1em;font-weight:600;margin:14px 0 7px}
.hp .tags{display:flex;flex-wrap:wrap;gap:6px}
.hp .tag{font-size:11.5px;border:1px solid var(--bd2);border-radius:6px;padding:3px 8px;color:var(--ink2);
font-family:ui-monospace,SFMono-Regular,Menlo,monospace;background:var(--elev)}
.hp .tag .n{color:var(--cyan)}
.hp .tag.itw{border-color:rgba(255,90,90,.4)}
.hp .tag.itw .w{color:#ff6b6b}
.hp .why{margin:0;padding:0;list-style:none}
.hp .why li{font-size:12.5px;color:var(--ink2);padding:6px 0 6px 14px;border-left:2px solid var(--bd);margin:0 0 2px}
.hp .why .k{color:var(--link);font-weight:600}
.hp .why .d{color:var(--cyan);font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:11.5px;font-variant-numeric:tabular-nums}
.hp .why a{color:var(--faint);text-decoration:none}
.hp .why a:hover{color:var(--link)}
.hp .label .lt{color:var(--faint);font-weight:400;text-transform:none;letter-spacing:0}
.hp .check{display:grid;grid-template-columns:1fr;gap:12px;background:var(--elev);border:1px solid var(--bd2);border-radius:10px;padding:14px 16px;margin-top:8px}
.hp .check .gt{color:var(--accent);font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.09em;margin-bottom:5px}
.hp .check ul{margin:0;padding-left:18px}
.hp .check li{font-size:12.5px;color:var(--ink2);margin:0 0 4px}
.hp .check li b{color:var(--ink);font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px}
.hp .check .tac{color:var(--faint);font-size:11px}
.hp .check .mw{margin:0;font-size:12.5px;color:var(--ink2)}
.hp .foot{color:var(--faint);font-size:11.5px;margin-top:24px;border-top:1px solid var(--bd2);padding-top:14px}
.hp a.src{color:var(--faint)}
"""


def render_brief_html(pack):
    m, s = pack["meta"], pack["meta"]["scope"]
    parts = [f"<style>{BRIEF_CSS}</style>", '<div class="hp">']
    parts.append('<div class="eyebrow">Mallory Threat Hunt Pack</div>')
    parts.append(f"<h1>{_esc(s['industry'])} &middot; {_esc(s.get('geo') or 'Global')}</h1>")
    parts.append(f'<p class="sub">{m["actor_count"]} prioritized actors &middot; trending window '
                 f'{_esc(s["window"])} &middot; generated {_esc(m["generated_at"][:10])}</p>')
    parts.append('<div class="scopebar">')
    parts.append(f'<span class="chip">Industry (GICS): <b>{_esc(", ".join(s["industry_codes"]))}</b></span>')
    if s.get("geo_codes"):
        parts.append(f'<span class="chip">Geography: <b>{_esc(", ".join(s["geo_codes"]))}</b></span>')
    tot_cve = sum(a["cve_count"] for a in pack["actors"])
    tot_ioc = sum(a["ioc_count"] for a in pack["actors"])
    parts.append(f'<span class="chip"><b>{tot_cve}</b> CVEs</span>')
    parts.append(f'<span class="chip"><b>{tot_ioc}</b> IOCs</span>')
    parts.append("</div>")

    for i, a in enumerate(pack["actors"], 1):
        parts.append('<div class="actor">')
        alias = f'<span class="alias">{_esc(a["aliases"])}</span>' if a.get("aliases") else ""
        parts.append(f'<h2><span class="rank">{i}</span>{_esc(a["name"])} {alias}</h2>')
        parts.append('<div class="metrics">'
                     f'<span>Relevance <b>{a["score"]}</b></span>'
                     f'<span>Industry evidence <b>{a["industry_match_count"]}</b></span>'
                     f'<span>Geo evidence <b>{a["geo_match_count"]}</b></span>'
                     f'<span>Mentions <b>{a["mention_count"] or 0}</b></span>'
                     f'<span>Motivation <b>{_esc(a.get("motivation") or "unknown")}</b></span>'
                     "</div>")
        if a.get("summary"):
            parts.append(f'<div class="desc">{_esc(a["summary"])}</div>')
        if a["why_relevant"]:
            parts.append('<div class="label">Why relevant <span class="lt">— most recent first</span></div><ul class="why">')
            for w in a["why_relevant"]:
                href = _safe_url(w.get("reference_url"))
                src = (f' <a class="src" href="{href}" rel="noopener noreferrer">[{_esc(w.get("source") or "source")}]</a>'
                       if href else "")
                date = f'<span class="d">{_esc(w["date"])}</span> ' if w.get("date") else ""
                parts.append(f'<li>{date}<span class="k">{_esc(w["kind"])} &middot; {_esc(w["label"])}</span> '
                             f'{_esc(w["context"])}{src}</li>')
            parts.append("</ul>")
        if a["top_techniques"]:
            parts.append('<div class="label">Top ATT&amp;CK techniques</div><div class="tags">')
            for t in a["top_techniques"][:12]:
                parts.append(f'<span class="tag">{_esc(t["mitre_attack_id"])} '
                             f'<span class="n">{t["count"]}</span></span>')
            parts.append("</div>")
        if a["cves"]:
            parts.append('<div class="label">Exploited CVEs</div><div class="tags">')
            for c in a["cves"][:12]:
                itw = " itw" if c.get("exploited_in_the_wild") else ""
                cvss = f' <span class="n">{c["cvss"]}</span>' if c.get("cvss") else ""
                w = '<span class="w">⚠</span>' if c.get("exploited_in_the_wild") else ""
                parts.append(f'<span class="tag{itw}">{w}{_esc(c["cve_id"])}{cvss}</span>')
            parts.append("</div>")

        hc = a.get("hunt_checklist", {})
        if any(hc.get(k) for k in ("exposure_checks", "ioc_sweeps", "behavioral_hunts", "malware_watch")):
            parts.append('<div class="label">What to check</div><div class="check">')
            if hc.get("exposure_checks"):
                parts.append('<div class="grp"><div class="gt">Exposure / patch</div><ul>')
                for e in hc["exposure_checks"]:
                    parts.append(f'<li>{_esc(e["action"])}</li>')
                parts.append("</ul></div>")
            if hc.get("ioc_sweeps"):
                parts.append('<div class="grp"><div class="gt">IOC sweeps</div><ul>')
                for sw in hc["ioc_sweeps"]:
                    parts.append(f'<li>{_esc(sw["action"])}</li>')
                parts.append("</ul></div>")
            if hc.get("behavioral_hunts"):
                parts.append('<div class="grp"><div class="gt">Behavioral hunts</div><ul>')
                for b in hc["behavioral_hunts"]:
                    tac = f' <span class="tac">{_esc(", ".join(b["tactics"]))}</span>' if b.get("tactics") else ""
                    parts.append(f'<li><b>{_esc(b["mitre_attack_id"])} {_esc(b["name"])}</b>{tac} — {_esc(b["action"])}</li>')
                parts.append("</ul></div>")
            if hc.get("malware_watch"):
                parts.append('<div class="grp"><div class="gt">Malware to watch</div>'
                             f'<p class="mw">Verify EDR/AV detections for {_esc(", ".join(hc["malware_watch"]))}.</p></div>')
            parts.append("</div>")
        parts.append("</div>")

    parts.append('<p class="foot">Generated by the Mallory <code>hunt-pack</code> skill. '
                 'Targeting evidence is attributed from open-source reporting; publication date '
                 'may differ from intrusion date. Cross-reference against your own telemetry before acting.</p>')
    parts.append("</div>")
    return "\n".join(parts)


def write_brief_html(path, pack):
    with open(path, "w") as fh:
        fh.write(render_brief_html(pack))


def write_hypotheses_md(path, pack):
    lines = ["# Hunt Hypotheses", "",
             "One hypothesis per high-frequency technique across the prioritized actors.", ""]
    agg = Counter()
    tac = {}
    actors_by_tech = defaultdict(set)
    for a in pack["actors"]:
        for t in a["top_techniques"]:
            agg[t["mitre_attack_id"]] += t["count"]
            tac[t["mitre_attack_id"]] = (t["name"], t["tactics"])
            actors_by_tech[t["mitre_attack_id"]].add(a["name"])
    for tid, cnt in agg.most_common(20):
        name, tactics = tac.get(tid, (tid, []))
        actors = ", ".join(sorted(actors_by_tech[tid]))
        tactic_str = ", ".join(tactics) if tactics else "n/a"
        lines += [
            f"## {tid} — {name}",
            f"- **Tactic(s):** {tactic_str} · **Evidence weight:** {cnt} · **Actors:** {actors}",
            f"- **Hypothesis:** Activity consistent with `{tid}` ({name}) is present in the "
            f"environment, attributable to the scoped actors targeting this sector.",
            "- **Where to look:** map the technique to your telemetry (EDR/SIEM/network) and "
            "hunt for the associated procedures; pivot on the IOCs in `iocs.csv`.",
            "",
        ]
    with open(path, "w") as fh:
        fh.write("\n".join(lines))


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def main():
    ap = argparse.ArgumentParser(description="Build an industry/geo threat-hunt pack from Mallory.")
    ap.add_argument("--industry", required=True, help="Industry name or GICS code (e.g. 'Energy' or '10').")
    ap.add_argument("--geo", default=None, help="Country codes / names / region (e.g. 'US', 'Europe').")
    ap.add_argument("--window", default="30d", choices=sorted(TRENDING_PERIODS),
                    help="Trending window for the candidate pool (default 30d).")
    ap.add_argument("--pool-size", type=int, default=120, help="Max candidate actors to score.")
    ap.add_argument("--top-actors", type=int, default=10, help="Actors to keep in the pack.")
    ap.add_argument("--out", required=True, help="Output directory.")
    args = ap.parse_args()

    now = datetime.now(timezone.utc)
    client = MalloryApi()

    scope_codes, industry_labels = resolve_industry(client, args.industry)
    if not scope_codes:
        sys.exit(f"No GICS industry matched '{args.industry}'. Try a sector name like 'Energy' or a code like '10'.")
    geo_codes, geo_labels = resolve_geo(args.geo)
    if args.geo and not geo_codes:
        sys.exit(f"No countries resolved from --geo '{args.geo}'. Use ISO-2 codes, country names, or a region.")

    print(f"[*] Industry scope: {industry_labels}", file=sys.stderr)
    if args.geo:
        print(f"[*] Geography scope: {geo_labels}", file=sys.stderr)

    pool = build_pool(client, args.window, args.pool_size, industry_labels)
    print(f"[*] Scoring {len(pool)} candidate actors ({args.window} trending + search seed)...", file=sys.stderr)

    def _score(a):
        try:
            return score_actor(client, a, scope_codes, geo_codes, now)
        except Exception as e:
            print(f"    ! score failed for {a.get('display_name')}: {e}", file=sys.stderr)
            return None

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool_ex:
        scored = [s for s in pool_ex.map(_score, pool) if s]
    scored.sort(key=lambda s: s["score"], reverse=True)
    scored = scored[:args.top_actors]
    if not scored:
        sys.exit("No actors matched the requested industry/geography scope in this window.")
    print(f"[*] {len(scored)} actors matched. Enriching...", file=sys.stderr)

    def _enrich(s):
        try:
            return enrich_actor(client, s)
        except Exception as e:
            print(f"    ! enrich failed for {s['actor'].get('display_name')}: {e}", file=sys.stderr)
            return s
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool_ex:
        scored = list(pool_ex.map(_enrich, scored))

    print("[*] Resolving technique tactics and CVE scores...", file=sys.stderr)
    tactics = hydrate_techniques(client, scored)
    cve_details = hydrate_cves(client, scored)

    scope = {
        "industry": args.industry, "industry_codes": sorted(scope_codes),
        "industry_labels": industry_labels,
        "geo": args.geo, "geo_codes": sorted(geo_codes), "geo_labels": geo_labels,
        "window": args.window,
    }
    pack = build_pack(scope, scored, tactics, cve_details, now)

    os.makedirs(args.out, exist_ok=True)
    json_path = os.path.join(args.out, "hunt_pack.json")
    with open(json_path, "w") as fh:
        json.dump(pack, fh, indent=2)
    write_report_md(os.path.join(args.out, "report.md"), pack)
    write_navigator_layer(os.path.join(args.out, "attack_navigator_layer.json"), pack)
    write_iocs_csv(os.path.join(args.out, "iocs.csv"), pack)
    write_cve_csv(os.path.join(args.out, "cve_watchlist.csv"), pack)
    write_hypotheses_md(os.path.join(args.out, "hunt_hypotheses.md"), pack)
    write_brief_html(os.path.join(args.out, "brief.html"), pack)

    print(f"[+] Hunt pack written to {args.out}", file=sys.stderr)
    print(f"    actors={pack['meta']['actor_count']} "
          f"techniques={sum(len(a['top_techniques']) for a in pack['actors'])} "
          f"iocs={sum(a['ioc_count'] for a in pack['actors'])} "
          f"cves={sum(a['cve_count'] for a in pack['actors'])}", file=sys.stderr)
    print(json_path)  # stdout = path to the pack, for the skill to pick up


if __name__ == "__main__":
    main()
