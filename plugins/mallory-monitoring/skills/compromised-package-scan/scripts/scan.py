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
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import unquote

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "scripts"))
from workflow_support import CoverageError, collect_pages

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


def norm_name(name: str | None, ecosystem: str | None = None) -> str | None:
    if not name:
        return None
    name = name.strip()
    if ecosystem == "pypi":
        return re.sub(r"[-_.]+", "-", name).lower()
    if ecosystem in {"npm", "nuget", "gem"}:
        return name.lower()
    return name


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
def fetch_compromised(limit: int | None, ecosystem: str | None, workers: int) -> dict:
    from malloryapi import MalloryApi

    client = MalloryApi()
    gaps = []
    params = {
        "compromise_evidence_count__gt": 0,
        "sort": "name" if limit is None else "last_compromised_at",
        "order": "asc" if limit is None else "desc",
    }
    if ecosystem:
        params["filter"] = f"ecosystem:{norm_ecosystem(ecosystem)}"
    try:
        try:
            pkgs = collect_pages(client.packages.list, max_items=limit, **params)
        except CoverageError as exc:
            pkgs = exc.items
            gaps.append(str(exc))

        def evidence(pkg):
            errors = []
            rows = []
            if not pkg.get("uuid"):
                errors.append("Package missing UUID")
            else:
                try:
                    rows = collect_pages(
                        lambda **kw: client.packages.compromises(
                            pkg["uuid"], sort="updated_at", order="desc", **kw
                        )
                    )
                except CoverageError as exc:
                    rows = exc.items
                    errors.append(str(exc))
            versions = set()
            for row in rows:
                values = row.get("compromised_versions") or []
                if not isinstance(values, list):
                    errors.append("Malformed compromised_versions")
                    continue
                versions.update(str(v) for v in values if v)
            return {
                "uuid": pkg.get("uuid"),
                "name": pkg.get("name"),
                "ecosystem": norm_ecosystem(pkg.get("ecosystem")),
                "last_compromised_at": pkg.get("last_compromised_at"),
                "compromise_evidence_count": pkg.get("compromise_evidence_count"),
                "compromised_versions": sorted(versions),
                "compromise_types": sorted(
                    {
                        str(x["compromise_type"])
                        for x in rows
                        if x.get("compromise_type")
                    }
                ),
                "sources": sorted(
                    {
                        str(
                            x.get("source_url")
                            or x.get("reference_url")
                            or x.get("source")
                        )
                        for x in rows
                        if x.get("source_url")
                        or x.get("reference_url")
                        or x.get("source")
                    }
                ),
                "evidence": rows,
                "coverage_gaps": errors,
            }

        with ThreadPoolExecutor(max_workers=workers) as pool:
            out = list(pool.map(evidence, pkgs))
        for row in out:
            gaps.extend(f"{row['uuid']}: {gap}" for gap in row["coverage_gaps"])
        out.sort(key=lambda x: x.get("last_compromised_at") or "", reverse=True)
        return {
            "count": len(out),
            "limit": limit,
            "packages": out,
            "coverage": {
                "mode": "all_known_compromises" if limit is None else "latest_n",
                "gaps": gaps,
            },
        }
    finally:
        client.close()


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
        raise RuntimeError("gh CLI not found; supply an SBOM file")
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"GitHub SBOM unavailable for {repo}") from e
    return json.loads(res.stdout)


def preprocess_sbom(repo: str | None, sbom_file: str | None) -> dict:
    """Normalize one SPDX/CycloneDX inventory; reject malformed source shapes.

    ValueError lets the CLI report a source-level coverage gap while retaining
    valid inventories from the other inputs.
    """
    raw = _load_sbom_json(repo, sbom_file)
    if not isinstance(raw, dict):
        raise ValueError("SBOM must be an object")
    sbom = raw.get("sbom", raw)
    if not isinstance(sbom, dict):
        raise ValueError("SBOM must be an object")
    observed_at = None
    if sbom.get("bomFormat") == "CycloneDX":
        if not isinstance(sbom.get("components"), list):
            raise ValueError("CycloneDX components are missing")
        metadata = sbom.get("metadata", {})
        if not isinstance(metadata, Mapping):
            raise ValueError("CycloneDX metadata must be an object")
        observed_at = metadata.get("timestamp")

        def components(rows, location="components"):
            """Walk nested components, naming malformed fields in source errors."""
            if not isinstance(rows, list):
                raise ValueError(f"CycloneDX {location} must be a list")
            for index, row in enumerate(rows):
                item = f"{location}[{index}]"
                if not isinstance(row, Mapping):
                    raise ValueError(f"CycloneDX {item} must be an object")
                for field in ("name", "version", "purl"):
                    value = row.get(field)
                    if value is not None and not isinstance(value, str):
                        raise ValueError(f"CycloneDX {item}.{field} must be a string")
                yield row
                yield from components(row.get("components", []), f"{item}.components")

        converted = []
        for row in components(sbom["components"]):
            converted.append(
                {
                    "name": row.get("name"),
                    "versionInfo": row.get("version"),
                    "externalRefs": [
                        {"referenceType": "purl", "referenceLocator": row.get("purl")}
                    ],
                    "evidence": row.get("evidence"),
                    "bom_ref": row.get("bom-ref"),
                    "hashes": row.get("hashes", []),
                }
            )
        sbom = {**sbom, "packages": converted}
    elif not isinstance(sbom.get("packages"), list):
        raise ValueError(
            "Unrecognized SBOM: expected SPDX packages or CycloneDX components"
        )
    else:
        observed_at = (sbom.get("creationInfo") or {}).get("created")
    source = repo or sbom_file or sbom.get("name", "sbom")
    seen: set[tuple] = set()
    pkgs: list[dict] = []
    gaps = []
    for p in sbom.get("packages", []):
        if not isinstance(p, dict):
            gaps.append("Malformed component record")
            continue
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
            gaps.append("Component has no resolvable name")
            continue
        key = (
            norm_ecosystem(ecosystem),
            norm_name(name, norm_ecosystem(ecosystem)),
            (version or "").strip(),
            purl,
        )
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
                "evidence": p.get("evidence"),
                "hashes": p.get("hashes", []),
            }
        )
    pkgs.sort(key=lambda x: (x.get("ecosystem") or "", x.get("name") or ""))
    return {
        "source": source,
        "count": len(pkgs),
        "packages": pkgs,
        "observed_at": observed_at,
        "coverage_gaps": gaps
        + (
            ["One or more component ecosystems are unknown"]
            if any(not p["ecosystem"] for p in pkgs)
            else []
        ),
    }


# ----------------------------------------------------------------------------
# Cross-reference
# ----------------------------------------------------------------------------
def crossref(feed: dict, sboms: list[dict]) -> dict:
    # Index compromised packages by (ecosystem, name).
    index: dict[tuple, dict] = {}
    for c in feed.get("packages", []):
        index[(c.get("ecosystem"), norm_name(c.get("name"), c.get("ecosystem")))] = c

    findings: list[dict] = []
    for sb in sboms:
        for p in sb.get("packages", []):
            key = (p.get("ecosystem"), norm_name(p.get("name"), p.get("ecosystem")))
            comp = index.get(key)
            if not comp:
                continue
            comp_versions = set(comp.get("compromised_versions") or [])
            sbom_v = clean_version(p.get("version"))
            cmp_clean = {clean_version(v) for v in comp_versions}
            confirmed = bool(
                p.get("pinned")
                and sbom_v
                and sbom_v in cmp_clean
                and "?" not in (p.get("purl") or "")
                and not comp.get("coverage_gaps")
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
                    "component_purl": p.get("purl"),
                    "observed_at": sb.get("observed_at"),
                    "evidence": comp.get("evidence", []),
                    "execution": "unknown",
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
        "coverage": {
            "mode": feed.get("coverage", {}).get("mode", "unknown"),
            "gaps": list(feed.get("coverage", {}).get("gaps", []))
            + [
                f"{sb.get('source')}: {gap}"
                for sb in sboms
                for gap in sb.get("coverage_gaps", [])
            ],
        },
        "inventory": [
            {
                "source": sb.get("source"),
                "observed_at": sb.get("observed_at"),
                "components": sb.get("count", 0),
            }
            for sb in sboms
        ],
    }


def print_table(report: dict) -> None:
    s = report["summary"]
    for gap in report.get("coverage", {}).get("gaps", []):
        print(f"Coverage gap: {gap}")
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
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser(
        "compromised", help="Pull latest compromised packages from Mallory"
    )
    c.add_argument("--limit", type=positive_int, default=100)
    c.add_argument(
        "--ecosystem", help="Restrict to one ecosystem (npm, pypi, gem, golang, ...)"
    )
    c.add_argument("--workers", type=positive_int, default=8)
    c.add_argument("-o", "--output-file")

    s = sub.add_parser("sbom", help="Pull + preprocess GitHub SBOM(s)")
    s.add_argument("repos", nargs="*", help="owner/repo (one or more)")
    s.add_argument(
        "--sbom-file",
        action="append",
        default=[],
        help="Local SPDX or CycloneDX JSON exports (including GitLab)",
    )
    s.add_argument("-o", "--output-file")

    x = sub.add_parser(
        "crossref", help="Cross-reference a feed against preprocessed SBOM(s)"
    )
    x.add_argument("--feed", required=True)
    x.add_argument(
        "--sbom",
        required=True,
        action="append",
        help="Preprocessed SBOM JSON (repeatable)",
    )
    x.add_argument("--output", choices=["json", "table"], default="json")

    r = sub.add_parser("run", help="End-to-end scan for one or more repos")
    r.add_argument("repos", nargs="*", help="owner/repo (one or more)")
    r.add_argument(
        "--sbom-file",
        action="append",
        default=[],
        help="Local SPDX or CycloneDX JSON exports (including GitLab)",
    )
    r.add_argument("--limit", type=positive_int, default=100)
    r.add_argument("--ecosystem")
    r.add_argument("--workers", type=positive_int, default=8)
    r.add_argument("--output", choices=["json", "table"], default="table")

    c.add_argument(
        "--all", action="store_true", help="Exhaust all known compromise packages"
    )
    r.add_argument(
        "--all", action="store_true", help="Exhaust all known compromise packages"
    )
    args = ap.parse_args()

    def read_inputs():
        result = []
        for repo, filename in [(repo, None) for repo in args.repos] + [
            (None, filename) for filename in args.sbom_file
        ]:
            try:
                result.append(preprocess_sbom(repo, filename))
            except (OSError, ValueError, RuntimeError) as exc:
                result.append(
                    {
                        "source": repo or filename,
                        "count": 0,
                        "packages": [],
                        "coverage_gaps": [str(exc)],
                    }
                )
        return result

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
        emit(
            fetch_compromised(
                None if args.all else args.limit, args.ecosystem, args.workers
            ),
            args.output_file,
        )

    elif args.cmd == "sbom":
        sboms = read_inputs()
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
        feed = fetch_compromised(
            None if args.all else args.limit, args.ecosystem, args.workers
        )
        sboms = read_inputs()
        emit(crossref(feed, sboms), fmt=args.output)


if __name__ == "__main__":
    main()
