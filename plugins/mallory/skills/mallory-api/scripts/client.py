#!/usr/bin/env python3
"""Mallory API CLI — thin wrapper around the malloryapi SDK.

Install:
    pip install malloryapi

Usage:
    python client.py vulnerabilities list --limit 10
    python client.py vulnerabilities get CVE-2024-1234
    python client.py threat_actors trending --period 7d
    python client.py search query --q "APT28"
    python client.py vulnerabilities exploits CVE-2024-1234
"""
from __future__ import annotations

import argparse
import json
import sys


def main() -> int:
    try:
        from malloryapi import MalloryApi  # noqa: E402
    except ImportError:
        sys.stderr.write(
            "malloryapi is not installed. Run: pip install malloryapi\n"
        )
        return 1

    parser = argparse.ArgumentParser(
        description="Mallory API CLI (powered by malloryapi SDK)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python client.py vulnerabilities list --limit 5\n"
            "  python client.py vulnerabilities get CVE-2024-1234\n"
            "  python client.py threat_actors trending --period 30d\n"
            "  python client.py malware list --limit 10\n"
            "  python client.py search query --q ransomware\n"
            "  python client.py vulnerabilities exploits CVE-2024-1234\n"
        ),
    )
    parser.add_argument(
        "resource",
        help="SDK resource (e.g. vulnerabilities, threat_actors, malware)",
    )
    parser.add_argument(
        "method",
        help="Method to call (e.g. list, get, trending, exploits)",
    )
    parser.add_argument(
        "identifier",
        nargs="?",
        default=None,
        help="Identifier (CVE ID, UUID, etc.) for get/export/sub-resource methods",
    )
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--offset", type=int, default=None)
    parser.add_argument("--period", default=None)
    parser.add_argument("--q", default=None, help="Search query string")
    parser.add_argument("--types", default=None, help="Search types filter")
    parser.add_argument(
        "--api-key", default=None, help="API key (or set MALLORY_API_KEY env var)"
    )

    args = parser.parse_args()

    client = MalloryApi(api_key=args.api_key) if args.api_key else MalloryApi()

    resource = getattr(client, args.resource, None)
    if resource is None:
        sys.stderr.write(
            f"Unknown resource: {args.resource}\n"
            f"Available: vulnerabilities, threat_actors, malware, exploits, "
            f"exploitations, organizations, products, attack_patterns, "
            f"breaches, detection_signatures, advisories, weaknesses, "
            f"stories, references, sources, content_chunks, mentions, "
            f"search\n"
        )
        return 1

    method_fn = getattr(resource, args.method, None)
    if method_fn is None:
        sys.stderr.write(
            f"Unknown method '{args.method}' on resource '{args.resource}'\n"
        )
        return 1

    kwargs: dict = {}
    if args.limit is not None:
        kwargs["limit"] = args.limit
    if args.offset is not None:
        kwargs["offset"] = args.offset
    if args.period is not None:
        kwargs["period"] = args.period
    if args.q is not None:
        kwargs["q"] = args.q
    if args.types is not None:
        kwargs["types"] = args.types

    try:
        if args.identifier:
            result = method_fn(args.identifier, **kwargs)
        else:
            result = method_fn(**kwargs)
    except Exception as exc:
        sys.stderr.write(f"Error: {exc}\n")
        return 1

    if hasattr(result, "items"):
        output = {
            "total": getattr(result, "total", None),
            "offset": getattr(result, "offset", None),
            "limit": getattr(result, "limit", None),
            "has_more": getattr(result, "has_more", None),
            "items": list(result),
        }
    elif isinstance(result, (dict, list)):
        output = result
    else:
        output = str(result)

    print(json.dumps(output, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
