#!/usr/bin/env python3
"""Bundle canonical support into independent plugin installs; --check detects drift."""

import argparse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PLUGINS = ("mallory", "mallory-monitoring", "mallory-investigations")


def files():
    """Yield canonical source/destination pairs for standalone plugin installs."""
    for name in PLUGINS:
        plugin = ROOT / "plugins" / name
        for source in (ROOT / "shared").iterdir():
            if source.suffix == ".md":
                yield source, plugin / "references" / source.name
            elif source.name == "workflow_support.py":
                yield source, plugin / "scripts" / source.name
    source = ROOT / "plugins/mallory/skills/compromised-package-scan"
    for file in source.rglob("*"):
        if file.is_file() and "__pycache__" not in file.parts:
            yield (
                file,
                ROOT
                / "plugins/mallory-monitoring/skills/compromised-package-scan"
                / file.relative_to(source),
            )


def owned_files():
    """Only these mirror destinations are managed by this synchronizer.

    Plugin references are generated Markdown; plugin scripts may contain
    unrelated code, so only the known workflow helper is owned there.
    The monitoring scanner directory is a complete mirror of its canonical skill.
    """
    for name in PLUGINS:
        plugin = ROOT / "plugins" / name
        yield from (
            file for file in (plugin / "references").rglob("*.md") if file.is_file()
        )
        helper = plugin / "scripts/workflow_support.py"
        if helper.is_file():
            yield helper
    scanner = ROOT / "plugins/mallory-monitoring/skills/compromised-package-scan"
    yield from (
        file
        for file in scanner.rglob("*")
        if file.is_file() and "__pycache__" not in file.parts
    )


def main():
    """Check drift without writes, or synchronize copies and remove owned orphans."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    mismatches = []
    copies = list(files())
    orphans = set(owned_files()) - {target for _, target in copies}
    for source, target in copies:
        data = source.read_bytes()
        if not target.exists() or target.read_bytes() != data:
            if args.check:
                mismatches.append(str(target.relative_to(ROOT)))
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
    for target in sorted(orphans):
        if args.check:
            mismatches.append(f"{target.relative_to(ROOT)} (orphaned)")
        else:
            target.unlink()
    if mismatches:
        print("Bundle drift:\n" + "\n".join(mismatches))
        return 1
    print("Bundles are current." if args.check else "Bundles synchronized.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
