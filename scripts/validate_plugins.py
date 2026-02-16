#!/usr/bin/env python3
"""
Plugin Marketplace Validator

Validates the marketplace structure, plugin manifests, and SKILL.md files
for Claude Code marketplace compatibility.

You can also use the built-in validator: `claude plugin validate .` (or
/plugin validate . from within Claude Code).

Checks:
- marketplace.json exists and is valid
- Each plugin has .claude-plugin/plugin.json
- Each plugin has at least one skill with SKILL.md
- SKILL.md frontmatter has required fields (name, description)
- Directory names match name fields
- Names follow naming convention (lowercase, hyphens only)
- Description length within bounds (1-1024 chars)
- No secrets committed (.api_key files)

Usage:
    python scripts/validate_plugins.py
    python scripts/validate_plugins.py --verbose
"""

import argparse
import json
import re
import sys
from pathlib import Path

# Naming convention: lowercase alphanumeric with single hyphen separators
NAME_PATTERN = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")

MAX_DESCRIPTION_LENGTH = 1024
MIN_DESCRIPTION_LENGTH = 1

# Files that should not be committed (potential secrets)
SECRET_PATTERNS = [
    ".api_key",
    ".env",
    "*.key",
    "*.pem",
    "credentials.json",
    "secrets.json",
]


def parse_frontmatter(content: str) -> dict | None:
    """Parse YAML frontmatter from SKILL.md content."""
    if not content.startswith("---"):
        return None

    end_idx = content.find("---", 3)
    if end_idx == -1:
        return None

    frontmatter_text = content[3:end_idx].strip()

    result = {}
    for line in frontmatter_text.split("\n"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" in line:
            key, value = line.split(":", 1)
            result[key.strip()] = value.strip()

    return result


def validate_marketplace(marketplace_path: Path, verbose: bool = False) -> list[str]:
    """Validate the marketplace.json file."""
    errors = []

    if not marketplace_path.exists():
        errors.append(
            f"Missing marketplace manifest: {marketplace_path}"
        )
        return errors

    try:
        data = json.loads(marketplace_path.read_text())
    except json.JSONDecodeError as e:
        errors.append(f"Invalid JSON in marketplace.json: {e}")
        return errors

    # Check required fields
    for field in ["name", "owner", "plugins"]:
        if field not in data:
            errors.append(
                f"marketplace.json: Missing required field '{field}'"
            )

    if "owner" in data and "name" not in data["owner"]:
        errors.append("marketplace.json: owner.name is required")

    if "plugins" in data:
        if not isinstance(data["plugins"], list):
            errors.append("marketplace.json: 'plugins' must be an array")
        else:
            names_seen = set()
            for i, plugin in enumerate(data["plugins"]):
                if "name" not in plugin:
                    errors.append(
                        f"marketplace.json: plugins[{i}] missing 'name'"
                    )
                else:
                    name = plugin["name"]
                    if name in names_seen:
                        errors.append(
                            f"marketplace.json: Duplicate plugin name '{name}'"
                        )
                    names_seen.add(name)

                    if not NAME_PATTERN.match(name):
                        errors.append(
                            f"marketplace.json: Plugin name '{name}' doesn't "
                            "follow naming convention"
                        )

                if "source" not in plugin:
                    errors.append(
                        f"marketplace.json: plugins[{i}] missing 'source'"
                    )

    if verbose and not errors:
        plugin_count = len(data.get("plugins", []))
        print(f"  marketplace.json: OK ({plugin_count} plugins listed)")

    return errors


def validate_plugin(plugin_dir: Path, verbose: bool = False) -> list[str]:
    """Validate a single plugin directory."""
    errors = []
    plugin_name = plugin_dir.name

    if verbose:
        print(f"  Checking plugin: {plugin_name}")

    # Check plugin.json exists
    manifest_path = plugin_dir / ".claude-plugin" / "plugin.json"
    if not manifest_path.exists():
        errors.append(
            f"{plugin_name}: Missing .claude-plugin/plugin.json"
        )
    else:
        try:
            manifest = json.loads(manifest_path.read_text())
        except json.JSONDecodeError as e:
            errors.append(
                f"{plugin_name}: Invalid JSON in plugin.json: {e}"
            )
            manifest = {}

        if "name" in manifest and manifest["name"] != plugin_name:
            errors.append(
                f"{plugin_name}: plugin.json name '{manifest['name']}' "
                f"doesn't match directory name '{plugin_name}'"
            )

        if "description" not in manifest:
            errors.append(
                f"{plugin_name}: plugin.json missing 'description'"
            )

    # Check for skills
    skills_dir = plugin_dir / "skills"
    if not skills_dir.exists():
        errors.append(f"{plugin_name}: Missing skills/ directory")
        return errors

    skill_count = 0
    for skill_dir in sorted(skills_dir.iterdir()):
        if not skill_dir.is_dir() or skill_dir.name.startswith("."):
            continue

        skill_count += 1
        skill_errors = validate_skill(skill_dir, plugin_name, verbose)
        errors.extend(skill_errors)

    if skill_count == 0:
        errors.append(f"{plugin_name}: No skills found in skills/")

    # Check for potential secrets
    for pattern in SECRET_PATTERNS:
        if "*" in pattern:
            matches = list(plugin_dir.rglob(pattern))
        else:
            matches = list(plugin_dir.rglob(pattern))

        for match in matches:
            if match.exists():
                rel = match.relative_to(plugin_dir)
                errors.append(
                    f"{plugin_name}: Potential secret file: {rel} "
                    "(should be in .gitignore)"
                )

    return errors


def validate_skill(
    skill_dir: Path, plugin_name: str, verbose: bool = False
) -> list[str]:
    """Validate a single skill directory within a plugin."""
    errors = []
    skill_name = skill_dir.name
    skill_md = skill_dir / "SKILL.md"

    if verbose:
        print(f"    Checking skill: {skill_name}")

    if not skill_md.exists():
        errors.append(
            f"{plugin_name}/{skill_name}: Missing SKILL.md file"
        )
        return errors

    content = skill_md.read_text()
    frontmatter = parse_frontmatter(content)

    if frontmatter is None:
        errors.append(
            f"{plugin_name}/{skill_name}: Missing YAML frontmatter "
            "(must start with ---)"
        )
        return errors

    # Check required fields
    if "name" not in frontmatter:
        errors.append(
            f"{plugin_name}/{skill_name}: Missing 'name' in frontmatter"
        )
    else:
        fm_name = frontmatter["name"]

        if fm_name != skill_name:
            errors.append(
                f"{plugin_name}/{skill_name}: Name mismatch - "
                f"frontmatter says '{fm_name}' but directory is "
                f"'{skill_name}'"
            )

        if not NAME_PATTERN.match(fm_name):
            errors.append(
                f"{plugin_name}/{skill_name}: Name '{fm_name}' doesn't "
                "follow naming convention (lowercase alphanumeric "
                "with hyphens)"
            )

    if "description" not in frontmatter:
        errors.append(
            f"{plugin_name}/{skill_name}: Missing 'description' in "
            "frontmatter"
        )
    else:
        desc = frontmatter["description"]
        desc_len = len(desc)

        if desc_len < MIN_DESCRIPTION_LENGTH:
            errors.append(
                f"{plugin_name}/{skill_name}: Description is empty"
            )
        elif desc_len > MAX_DESCRIPTION_LENGTH:
            errors.append(
                f"{plugin_name}/{skill_name}: Description too long "
                f"({desc_len} chars, max {MAX_DESCRIPTION_LENGTH})"
            )

    if verbose and not errors:
        print(f"      OK")

    return errors


def main():
    parser = argparse.ArgumentParser(
        description="Validate Claude Code plugin marketplace structure"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Show detailed output"
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=None,
        help="Path to marketplace root (default: auto-detect)",
    )
    args = parser.parse_args()

    # Find marketplace root
    if args.root:
        root = args.root
    else:
        script_dir = Path(__file__).parent.parent
        root = script_dir
        if not (root / ".claude-plugin" / "marketplace.json").exists():
            root = Path.cwd()

    print(f"Validating marketplace at: {root}")
    print()

    all_errors = []

    # Validate marketplace.json
    print("Checking marketplace.json...")
    marketplace_path = root / ".claude-plugin" / "marketplace.json"
    marketplace_errors = validate_marketplace(marketplace_path, args.verbose)
    all_errors.extend(marketplace_errors)

    # Validate plugins
    plugins_dir = root / "plugins"
    if not plugins_dir.exists():
        all_errors.append("Missing plugins/ directory")
    else:
        print("Checking plugins...")
        total_plugins = 0
        passed_plugins = 0

        for plugin_dir in sorted(plugins_dir.iterdir()):
            if not plugin_dir.is_dir() or plugin_dir.name.startswith("."):
                continue

            total_plugins += 1
            plugin_errors = validate_plugin(plugin_dir, args.verbose)

            if plugin_errors:
                all_errors.extend(plugin_errors)
            else:
                passed_plugins += 1

        print()
        print(
            f"Results: {passed_plugins}/{total_plugins} plugins passed "
            "validation"
        )

    if all_errors:
        print()
        print("Errors:")
        for error in all_errors:
            print(f"  - {error}")
        print()
        print(
            "Fix these issues to ensure Claude Code marketplace "
            "compatibility."
        )
        return 1
    else:
        print("All plugins are valid!")
        return 0


if __name__ == "__main__":
    sys.exit(main())
