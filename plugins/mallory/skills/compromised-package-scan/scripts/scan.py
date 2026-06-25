#!/usr/bin/env python3
"""Cross-reference GitHub SBOMs against Mallory's latest compromised packages.

Subcommands
-----------
  compromised   Pull the latest compromised packages (+ compromised versions) from Mallory.
  sbom          Pull and pre-process GitHub SBOM(s) into a normalized package/version list.
  crossref      Join a compromised feed against a pre-processed SBOM and report matches.
  run           End-to-end: compromised -> sbom -> crossref for one or more repos.

The Mallory feed comes from the official `malloryapi` SDK (reads MALLORY_API_KEY).
SBOMs come from GitHub's Dependency Graph SBOM API via the `gh` CLI (uses your gh auth),
or from a local SPDX JSON file.

Accuracy note
-------------
GitHub SBOMs frequently report *declared version ranges* (e.g. "^2.0.0") taken from
manifests rather than pinned, resolved versions. We therefore separate two outcomes:

  CONFIRMED  pinned SBOM version exactly matches a known compromised version.
  REVIEW     the package (name + ecosystem) is known-compromised, but the SBOM version
             is a range / could not be matched exactly. The declared range may resolve
             to a compromised version -- verify against a lockfile / resolved version.

Output is JSON by default; pass --output table for a human-readable summary.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import unquote


# ----------------------------------------------------------------------------
# Ecosystem normalization (PURL type -> Mallory ecosystem string)
# ----------------------------------------------------------------------------
ECOSYSTEM_ALIASES = {
    "go": "golang",
    "golang": "golang",
    "rubygems": "gem",
    "gem": "gem",
    "npm": "npm",
    "pypi": "pypi",
    "cargo": "cargo",
    "maven": "maven",
    "composer": "composer",
    "nuget": "nuget",
}


def norm_ecosystem(eco: str | None) -> str | None:
    if not eco:
        return None
    eco = eco.strip().lower()
    return ECOSYSTEM_ALIASES.get(eco, eco)


def norm_name(name: str | None) -> str | None:
    if not name:
        return None
    return name.strip().lower()


# Range / non-pinned version indicators. If a version matches, it is NOT a single
# pinned version and cannot be used for an exact compromised-version match. A
# leading "=" is an exact-pin marker (handled in is_pinned), so it is not listed
# here -- only true range operators (>= <= > <) are.
_RANGE_RE = re.compile(r"^[\^~]|(?:>=|<=|>|<)|\s|\bx\b|\*|\|\||,| - ", re.IGNORECASE)


def is_pinned(version: str | None) -> bool:
    if not version:
        return False
    v = version.strip()
    if not v:
        return False
    # A leading "=" pins an exact version (e.g. "=1.2.3"); strip it before the
    # range check so it stays consistent with clean_version's normalization.
    if v.startswith("="):
        v = v[1:].lstrip()
    return _RANGE_RE.search(v) is None


def clean_version(version: str | None) -> str | None:
    """Strip a leading 'v' / '=' for comparison, leave the rest intact."""
    if version is None:
        return None
    v = version.strip()
    v = re.sub(r"^[=v]+", "", v)
    return v or None


# ----------------------------------------------------------------------------
# PURL parsing
# ----------------------------------------------------------------------------
def parse_purl(purl: str) -> dict | None:
    """Parse pkg:type/namespace/name@version into ecosystem/name/version."""
    if not purl or not purl.startswith("pkg:"):
        return None
    body = purl[len("pkg:") :]
    # drop qualifiers / subpath
    body = body.split("?", 1)[0].split("#", 1)[0]
    if "/" not in body:
        return None
    ptype, rest = body.split("/", 1)
    version = None
    if "@" in rest:
        rest, version = rest.rsplit("@", 1)
        version = unquote(version)
    # namespace/name -> keep namespace for scoped packages (e.g. @babel/core)
    parts = [unquote(p) for p in rest.split("/") if p]
    if not parts:
        return None
    if ptype.lower() == "npm" and len(parts) >= 2:
        name = "/".join(parts)  # @scope/name or namespace/name
        if not name.startswith("@") and rest.startswith("%40"):
            name = "@" + name
    else:
        name = "/".join(parts)
    return {
        "ecosystem": norm_ecosystem(ptype),
        "name": name,
        "version": version,
    }


# ----------------------------------------------------------------------------
# Mallory: latest compromised packages
# ----------------------------------------------------------------------------
def fetch_compromised(limit: int, ecosystem: str | None, workers: int) -> dict:
    try:
        from malloryapi import MalloryApi
    except ImportError:
        sys.exit(
            "malloryapi SDK not installed. Run: uv pip install --system malloryapi"
        )

    client = MalloryApi()

    # Page through packages sorted by most-recent compromise. Packages with no
    # compromise sort last, so we stop once we have `limit` with a compromise date.
    pkgs: list[dict] = []
    offset = 0
    page = min(100, max(limit, 1))
    filt = f"ecosystem:{norm_ecosystem(ecosystem)}" if ecosystem else None
    while len(pkgs) < limit:
        resp = client.packages.list(
            sort="last_compromised_at",
            order="desc",
            offset=offset,
            limit=page,
            filter=filt,
        )
        items = list(resp)
        if not items:
            break
        for it in items:
            if not it.get("last_compromised_at"):
                items = []  # reached packages with no compromise -> done
                break
            pkgs.append(it)
            if len(pkgs) >= limit:
                break
        if not items:
            break
        offset += page

    def _versions(pkg: dict) -> dict:
        versions: set[str] = set()
        ctypes: set[str] = set()
        sources: set[str] = set()
        try:
            for c in client.packages.compromises(pkg["uuid"], limit=100):
                for v in c.get("compromised_versions") or []:
                    if v:
                        versions.add(str(v))
                if c.get("compromise_type"):
                    ctypes.add(c["compromise_type"])
                if c.get("source"):
                    sources.add(c["source"])
        except Exception as e:  # noqa: BLE001 - best-effort enrichment
            sys.stderr.write(f"warn: compromises({pkg.get('name')}): {e}\n")
        return {
            "uuid": pkg["uuid"],
            "name": pkg.get("name"),
            "ecosystem": norm_ecosystem(pkg.get("ecosystem")),
            "last_compromised_at": pkg.get("last_compromised_at"),
            "compromise_evidence_count": pkg.get("compromise_evidence_count"),
            "compromised_versions": sorted(versions),
            "compromise_types": sorted(ctypes),
            "sources": sorted(sources),
        }

    out: list[dict] = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = [ex.submit(_versions, p) for p in pkgs]
        for f in as_completed(futs):
            out.append(f.result())

    out.sort(key=lambda x: x.get("last_compromised_at") or "", reverse=True)
    return {"count": len(out), "limit": limit, "packages": out}


# ----------------------------------------------------------------------------
# GitHub SBOM -> normalized package list
# ----------------------------------------------------------------------------
def _load_sbom_json(repo: str | None, sbom_file: str | None) -> dict:
    if sbom_file:
        with open(sbom_file) as fh:
            return json.load(fh)
    if not repo:
        raise ValueError("either repo or sbom_file is required")
    try:
        res = subprocess.run(
            ["gh", "api", f"repos/{repo}/dependency-graph/sbom"],
            capture_output=True,
            text=True,
            check=True,
        )
    except FileNotFoundError:
        sys.exit("gh CLI not found. Install GitHub CLI or pass --sbom-file.")
    except subprocess.CalledProcessError as e:
        sys.exit(f"gh api failed for {repo}: {e.stderr.strip()}")
    return json.loads(res.stdout)


def preprocess_sbom(repo: str | None, sbom_file: str | None) -> dict:
    raw = _load_sbom_json(repo, sbom_file)
    sbom = raw.get("sbom", raw)
    source = repo or sbom_file or sbom.get("name", "sbom")
    seen: set[tuple] = set()
    pkgs: list[dict] = []
    for p in sbom.get("packages", []):
        purl = None
        for ref in p.get("externalRefs", []) or []:
            if ref.get("referenceType") == "purl":
                purl = ref.get("referenceLocator")
                break
        parsed = parse_purl(purl) if purl else None
        if parsed and parsed.get("name"):
            ecosystem = parsed["ecosystem"]
            name = parsed["name"]
            version = parsed.get("version") or p.get("versionInfo")
        else:
            # Fallback: SPDX name may be "npm:foo" / "pip:foo"; otherwise bare.
            # Only treat the prefix as an ecosystem when it is a recognized one --
            # a bare "groupId:artifactId" Maven name must stay intact, not be split
            # into ecosystem="org.springframework", name="spring-core".
            raw_name = p.get("name") or ""
            ecosystem, name = None, raw_name
            if ":" in raw_name:
                pre, rest = raw_name.split(":", 1)
                normalized_pre = norm_ecosystem(pre)
                if normalized_pre in ECOSYSTEM_ALIASES.values():
                    ecosystem, name = normalized_pre, rest
            version = p.get("versionInfo")
        if not name:
            continue
        key = (norm_ecosystem(ecosystem), norm_name(name), (version or "").strip())
        if key in seen:
            continue
        seen.add(key)
        pkgs.append(
            {
                "ecosystem": norm_ecosystem(ecosystem),
                "name": name,
                "version": version,
                "pinned": is_pinned(version),
                "purl": purl,
            }
        )
    pkgs.sort(key=lambda x: (x.get("ecosystem") or "", x.get("name") or ""))
    return {"source": source, "count": len(pkgs), "packages": pkgs}


# ----------------------------------------------------------------------------
# Cross-reference
# ----------------------------------------------------------------------------
def crossref(feed: dict, sboms: list[dict]) -> dict:
    # Index compromised packages by (ecosystem, name).
    index: dict[tuple, dict] = {}
    for c in feed.get("packages", []):
        index[(c.get("ecosystem"), norm_name(c.get("name")))] = c

    findings: list[dict] = []
    for sb in sboms:
        for p in sb.get("packages", []):
            key = (p.get("ecosystem"), norm_name(p.get("name")))
            comp = index.get(key)
            if not comp:
                continue
            comp_versions = set(comp.get("compromised_versions") or [])
            sbom_v = clean_version(p.get("version"))
            cmp_clean = {clean_version(v) for v in comp_versions}
            confirmed = bool(
                p.get("pinned") and sbom_v and sbom_v in cmp_clean
            )
            findings.append(
                {
                    "status": "CONFIRMED" if confirmed else "REVIEW",
                    "sbom_source": sb.get("source"),
                    "ecosystem": p.get("ecosystem"),
                    "name": p.get("name"),
                    "sbom_version": p.get("version"),
                    "pinned": p.get("pinned"),
                    "compromised_versions": sorted(comp_versions),
                    "compromise_types": comp.get("compromise_types"),
                    "last_compromised_at": comp.get("last_compromised_at"),
                    "sources": comp.get("sources"),
                    "package_uuid": comp.get("uuid"),
                }
            )
    findings.sort(key=lambda f: (f["status"] != "CONFIRMED", f["name"] or ""))
    confirmed = [f for f in findings if f["status"] == "CONFIRMED"]
    review = [f for f in findings if f["status"] == "REVIEW"]
    return {
        "feed_packages": feed.get("count"),
        "sbom_sources": [sb.get("source") for sb in sboms],
        "summary": {"confirmed": len(confirmed), "review": len(review)},
        "findings": findings,
    }


def print_table(report: dict) -> None:
    s = report["summary"]
    print(
        f"Compromised feed: {report['feed_packages']} pkgs  |  "
        f"SBOM sources: {', '.join(map(str, report['sbom_sources']))}"
    )
    print(f"CONFIRMED: {s['confirmed']}   REVIEW: {s['review']}\n")
    if not report["findings"]:
        print("No known-compromised packages found in the SBOM(s). ✓")
        return
    for f in report["findings"]:
        mark = "✗" if f["status"] == "CONFIRMED" else "⚠"
        cv = ", ".join(f["compromised_versions"]) or "(unspecified)"
        ct = ", ".join(f.get("compromise_types") or []) or "?"
        print(f"{mark} [{f['status']}] {f['ecosystem']}/{f['name']}")
        print(f"    sbom version: {f['sbom_version']}  (pinned={f['pinned']})")
        print(f"    compromised:  {cv}   type: {ct}")
        print(f"    last seen:    {f['last_compromised_at']}  src: {f['sbom_source']}")
    print()


# ----------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------
def positive_int(value: str) -> int:
    """argparse type: reject non-positive integers (e.g. --workers 0 crashes
    ThreadPoolExecutor; a negative --limit silently yields no results)."""
    ivalue = int(value)
    if ivalue <= 0:
        raise argparse.ArgumentTypeError(f"must be a positive integer, got {value}")
    return ivalue


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("compromised", help="Pull latest compromised packages from Mallory")
    c.add_argument("--limit", type=positive_int, default=100)
    c.add_argument("--ecosystem", help="Restrict to one ecosystem (npm, pypi, gem, golang, ...)")
    c.add_argument("--workers", type=positive_int, default=8)
    c.add_argument("-o", "--output-file")

    s = sub.add_parser("sbom", help="Pull + preprocess GitHub SBOM(s)")
    s.add_argument("repos", nargs="*", help="owner/repo (one or more)")
    s.add_argument("--sbom-file", action="append", default=[], help="Local SPDX JSON file(s)")
    s.add_argument("-o", "--output-file")

    x = sub.add_parser("crossref", help="Cross-reference a feed against preprocessed SBOM(s)")
    x.add_argument("--feed", required=True)
    x.add_argument("--sbom", required=True, action="append", help="Preprocessed SBOM JSON (repeatable)")
    x.add_argument("--output", choices=["json", "table"], default="json")

    r = sub.add_parser("run", help="End-to-end scan for one or more repos")
    r.add_argument("repos", nargs="*", help="owner/repo (one or more)")
    r.add_argument("--sbom-file", action="append", default=[], help="Local SPDX JSON file(s)")
    r.add_argument("--limit", type=positive_int, default=100)
    r.add_argument("--ecosystem")
    r.add_argument("--workers", type=positive_int, default=8)
    r.add_argument("--output", choices=["json", "table"], default="table")

    args = ap.parse_args()

    def emit(obj, output_file=None, fmt="json"):
        if fmt == "table":
            print_table(obj)
            return
        text = json.dumps(obj, indent=2)
        if output_file:
            with open(output_file, "w") as fh:
                fh.write(text)
            sys.stderr.write(f"wrote {output_file}\n")
        else:
            print(text)

    if args.cmd == "compromised":
        emit(fetch_compromised(args.limit, args.ecosystem, args.workers), args.output_file)

    elif args.cmd == "sbom":
        sboms = [preprocess_sbom(repo, None) for repo in args.repos]
        sboms += [preprocess_sbom(None, f) for f in args.sbom_file]
        if not sboms:
            ap.error("provide at least one owner/repo or --sbom-file")
        result = sboms[0] if len(sboms) == 1 else {"sboms": sboms}
        emit(result, args.output_file)

    elif args.cmd == "crossref":
        feed = json.load(open(args.feed))
        sboms = []
        for path in args.sbom:
            data = json.load(open(path))
            sboms.extend(data["sboms"] if "sboms" in data else [data])
        emit(crossref(feed, sboms), fmt=args.output)

    elif args.cmd == "run":
        if not args.repos and not args.sbom_file:
            ap.error("provide at least one owner/repo or --sbom-file")
        feed = fetch_compromised(args.limit, args.ecosystem, args.workers)
        sboms = [preprocess_sbom(repo, None) for repo in args.repos]
        sboms += [preprocess_sbom(None, f) for f in args.sbom_file]
        emit(crossref(feed, sboms), fmt=args.output)


if __name__ == "__main__":
    main()
