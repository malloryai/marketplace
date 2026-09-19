import json
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class PackagingTests(unittest.TestCase):
    def test_independent_plugins_render_artifacts_without_repo_shared_directory(self):
        report = {
            "schema_version": 1,
            "skill": "demo",
            "scope": {},
            "window": None,
            "status": "complete",
            "summary": "Synthetic example",
            "results": [],
            "coverage": {"examined": 0, "requested": 0, "gaps": []},
            "finding_actions": [],
        }
        for plugin in (ROOT / "plugins").iterdir():
            if not plugin.is_dir():
                continue
            with (
                self.subTest(plugin=plugin.name),
                tempfile.TemporaryDirectory() as directory,
            ):
                isolated = Path(directory) / "installed-plugin"
                shutil.copytree(
                    plugin, isolated, ignore=shutil.ignore_patterns("__pycache__")
                )
                data = Path(directory) / "input.json"
                data.write_text(json.dumps(report))
                result = subprocess.run(
                    [
                        sys.executable,
                        str(isolated / "scripts/workflow_support.py"),
                        str(data),
                        "--output-prefix",
                        str(Path(directory) / "report"),
                        "--html",
                    ],
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertTrue(Path(json.loads(result.stdout)["html"]).is_file())
                scanner = isolated / "skills/compromised-package-scan/scripts/scan.py"
                if scanner.exists():
                    result = subprocess.run(
                        [sys.executable, str(scanner), "run", "--help"],
                        capture_output=True,
                        text=True,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn("--all", result.stdout)

    def test_catalog_paths_and_manifests_agree(self):
        claude = json.loads((ROOT / ".claude-plugin/marketplace.json").read_text())
        codex = json.loads((ROOT / ".agents/plugins/marketplace.json").read_text())
        self.assertEqual(
            [x["name"] for x in claude["plugins"]],
            [x["name"] for x in codex["plugins"]],
        )
        for catalog, manifest_directory in (
            (claude, ".claude-plugin"),
            (codex, ".codex-plugin"),
        ):
            for entry in catalog["plugins"]:
                with self.subTest(catalog=manifest_directory, plugin=entry["name"]):
                    source = entry["source"]
                    if manifest_directory == ".codex-plugin":
                        self.assertIsInstance(source, dict)
                        path = source["path"]
                    else:
                        self.assertIsInstance(source, str)
                        path = source
                    plugin = (ROOT / path).resolve()
                    self.assertTrue(plugin.is_relative_to((ROOT / "plugins").resolve()))
                    self.assertEqual(plugin.name, entry["name"])
                    manifest = plugin / manifest_directory / "plugin.json"
                    self.assertEqual(
                        json.loads(manifest.read_text())["name"], entry["name"]
                    )

    def test_new_workflow_markdown_links_stay_inside_the_installed_plugin(self):
        for plugin in (ROOT / "plugins").iterdir():
            paths = list((plugin / "references").glob("*.md"))
            for name in (
                "story-based-tabletop-exercise",
                "third-party-breach-monitor",
                "technology-advisory-monitor",
                "supply-chain-compromise-monitor",
                "exposure-validation",
                "observable-investigation",
            ):
                path = plugin / "skills" / name / "SKILL.md"
                if path.exists():
                    paths.append(path)
            for path in paths:
                for target in re.findall(r"\]\(([^)]+)\)", path.read_text()):
                    if "://" in target or target.startswith("#"):
                        continue
                    linked = (path.parent / target.split("#")[0]).resolve()
                    self.assertTrue(
                        linked.is_relative_to(plugin.resolve()), f"{path}: {target}"
                    )
                    self.assertTrue(linked.exists(), f"{path}: {target}")


if __name__ == "__main__":
    unittest.main()
