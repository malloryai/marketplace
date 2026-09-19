import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class BundleSyncTests(unittest.TestCase):
    def test_deleted_sources_are_reported_and_removed_only_from_owned_destinations(
        self,
    ):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            script = root / "scripts/sync_bundles.py"
            script.parent.mkdir()
            shutil.copyfile(ROOT / "scripts/sync_bundles.py", script)
            source_paths = (
                "shared/retired.md",
                "shared/workflow_support.py",
                "plugins/mallory/skills/compromised-package-scan/scripts/retired.py",
            )
            for relative in source_paths:
                source = root / relative
                source.parent.mkdir(parents=True, exist_ok=True)
                source.write_text("formerly generated\n")

            def run(*args):
                return subprocess.run(
                    [sys.executable, str(script), *args], capture_output=True, text=True
                )

            first = run()
            self.assertEqual(first.returncode, 0, first.stderr)
            unrelated = root / "plugins/mallory/scripts/custom.py"
            unrelated.write_text("do not remove\n")
            for relative in source_paths:
                (root / relative).unlink()
            stale_paths = (
                "plugins/mallory/references/retired.md",
                "plugins/mallory/scripts/workflow_support.py",
                "plugins/mallory-monitoring/skills/compromised-package-scan/scripts/retired.py",
            )
            check = run("--check")
            self.assertEqual(check.returncode, 1, check.stdout + check.stderr)
            for relative in stale_paths:
                self.assertIn(relative, check.stdout)
                self.assertTrue((root / relative).exists(), "--check must not delete")
            sync = run()
            self.assertEqual(sync.returncode, 0, sync.stderr)
            for relative in stale_paths:
                self.assertFalse((root / relative).exists(), relative)
            self.assertEqual(unrelated.read_text(), "do not remove\n")
            self.assertEqual(run("--check").returncode, 0)


if __name__ == "__main__":
    unittest.main()
