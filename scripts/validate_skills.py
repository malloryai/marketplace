#!/usr/bin/env python3
"""
Skill Validator - Validates SKILL.md files for Claude Code/OpenCode compatibility.

Checks:
- Required frontmatter fields (name, description)
- Directory name matches name field
- Name follows OpenCode naming convention (lowercase, hyphens only)
- Description length within bounds (1-1024 chars)
- No secrets committed (.api_key files)

Usage:
    pdm run python scripts/validate_skills.py
    pdm run python scripts/validate_skills.py --verbose
    pdm run python scripts/validate_skills.py --fix  # Auto-fix some issues
"""

import argparse
import re
import sys
from pathlib import Path

# OpenCode-compatible name pattern: lowercase alphanumeric with single hyphen separators
NAME_PATTERN = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")

# Max description length per OpenCode spec
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

    # Find the closing ---
    end_idx = content.find("---", 3)
    if end_idx == -1:
        return None

    frontmatter_text = content[3:end_idx].strip()

    # Simple YAML parsing for key: value pairs
    result = {}
    for line in frontmatter_text.split("\n"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" in line:
            key, value = line.split(":", 1)
            result[key.strip()] = value.strip()

    return result


def validate_skill(skill_dir: Path, verbose: bool = False) -> list[str]:
    """Validate a single skill directory. Returns list of errors."""
    errors = []
    skill_name = skill_dir.name
    skill_md = skill_dir / "SKILL.md"

    if verbose:
        print(f"  Checking {skill_name}...")

    # Check SKILL.md exists
    if not skill_md.exists():
        errors.append(f"{skill_name}: Missing SKILL.md file")
        return errors

    # Read and parse frontmatter
    content = skill_md.read_text()
    frontmatter = parse_frontmatter(content)

    if frontmatter is None:
        errors.append(f"{skill_name}: Missing YAML frontmatter (must start with ---)")
        return errors

    # Check required fields
    if "name" not in frontmatter:
        errors.append(f"{skill_name}: Missing required 'name' field in frontmatter")
    else:
        fm_name = frontmatter["name"]

        # Check name matches directory
        if fm_name != skill_name:
            errors.append(
                f"{skill_name}: Name mismatch - frontmatter says '{fm_name}' "
                f"but directory is '{skill_name}'"
            )

        # Check name follows OpenCode convention
        if not NAME_PATTERN.match(fm_name):
            errors.append(
                f"{skill_name}: Name '{fm_name}' doesn't follow OpenCode convention "
                "(lowercase alphanumeric with hyphens, e.g., 'my-skill-name')"
            )

    if "description" not in frontmatter:
        errors.append(
            f"{skill_name}: Missing required 'description' field in frontmatter"
        )
    else:
        desc = frontmatter["description"]
        desc_len = len(desc)

        if desc_len < MIN_DESCRIPTION_LENGTH:
            errors.append(f"{skill_name}: Description is empty")
        elif desc_len > MAX_DESCRIPTION_LENGTH:
            errors.append(
                f"{skill_name}: Description too long ({desc_len} chars, "
                f"max {MAX_DESCRIPTION_LENGTH})"
            )

    # Check for potential secrets
    for pattern in SECRET_PATTERNS:
        if "*" in pattern:
            # Glob pattern
            matches = list(skill_dir.glob(pattern))
        else:
            # Exact match
            matches = [skill_dir / pattern] if (skill_dir / pattern).exists() else []

        for match in matches:
            if match.exists():
                errors.append(
                    f"{skill_name}: Potential secret file found: {match.name} "
                    "(should be in .gitignore)"
                )

    return errors


def validate_all_skills(
    skills_dir: Path, verbose: bool = False
) -> tuple[int, int, list[str]]:
    """Validate all skills in the skills directory.

    Returns: (total_skills, passed_skills, all_errors)
    """
    all_errors = []
    total = 0
    passed = 0

    if not skills_dir.exists():
        return 0, 0, [f"Skills directory not found: {skills_dir}"]

    for skill_dir in sorted(skills_dir.iterdir()):
        if not skill_dir.is_dir():
            continue
        if skill_dir.name.startswith("."):
            continue

        total += 1
        errors = validate_skill(skill_dir, verbose)

        if errors:
            all_errors.extend(errors)
        else:
            passed += 1
            if verbose:
                print(f"    OK")

    return total, passed, all_errors


def main():
    parser = argparse.ArgumentParser(
        description="Validate SKILL.md files for Claude Code/OpenCode compatibility"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Show detailed output"
    )
    parser.add_argument(
        "--skills-dir",
        type=Path,
        default=None,
        help="Path to skills directory (default: .claude/skills)",
    )
    args = parser.parse_args()

    # Find skills directory
    if args.skills_dir:
        skills_dir = args.skills_dir
    else:
        # Try to find .claude/skills relative to script or cwd
        script_dir = Path(__file__).parent.parent
        skills_dir = script_dir / ".claude" / "skills"
        if not skills_dir.exists():
            skills_dir = Path.cwd() / ".claude" / "skills"

    print(f"Validating skills in: {skills_dir}")
    print()

    total, passed, errors = validate_all_skills(skills_dir, args.verbose)

    print()
    print(f"Results: {passed}/{total} skills passed validation")

    if errors:
        print()
        print("Errors:")
        for error in errors:
            print(f"  - {error}")
        print()
        print("Fix these issues to ensure Claude Code/OpenCode compatibility.")
        return 1
    else:
        print("All skills are valid!")
        return 0


if __name__ == "__main__":
    sys.exit(main())
