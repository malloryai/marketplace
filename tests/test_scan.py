import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from malloryapi._types import PaginatedResponse

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "scan", ROOT / "plugins/mallory/skills/compromised-package-scan/scripts/scan.py"
)
scan = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scan)


class ScannerTests(unittest.TestCase):
    def test_malformed_cyclonedx_shapes_raise_value_error(self):
        cases = [
            ([], "SBOM"),
            (
                {"bomFormat": "CycloneDX", "components": [], "metadata": None},
                "metadata",
            ),
            ({"bomFormat": "CycloneDX", "components": [], "metadata": []}, "metadata"),
            ({"bomFormat": "CycloneDX", "components": [None]}, "components\\[0\\]"),
            ({"bomFormat": "CycloneDX", "components": ["pkg"]}, "components\\[0\\]"),
            (
                {"bomFormat": "CycloneDX", "components": [{"components": None}]},
                "components\\[0\\].components",
            ),
            (
                {"bomFormat": "CycloneDX", "components": [{"components": {}}]},
                "components\\[0\\].components",
            ),
            ({"bomFormat": "CycloneDX", "components": [{"purl": 42}]}, "purl"),
            ({"bomFormat": "CycloneDX", "components": [{"name": {}}]}, "name"),
            (
                {
                    "bomFormat": "CycloneDX",
                    "components": [{"name": "pkg", "version": 1}],
                },
                "version",
            ),
        ]
        for raw, error in cases:
            with (
                self.subTest(raw=raw),
                patch.object(scan, "_load_sbom_json", return_value=raw),
            ):
                with self.assertRaisesRegex(ValueError, error):
                    scan.preprocess_sbom(None, "fixture.json")

    def test_cli_retains_other_sources_when_cyclonedx_is_malformed(self):
        with tempfile.TemporaryDirectory() as directory:
            good = Path(directory) / "good.json"
            good.write_text(
                json.dumps(
                    {
                        "bomFormat": "CycloneDX",
                        "components": [
                            {
                                "name": "parent",
                                "purl": "pkg:npm/parent@1.0.0",
                                "components": [
                                    {"name": "child", "purl": "pkg:npm/child@2.0.0"}
                                ],
                            }
                        ],
                    }
                )
            )
            bad = Path(directory) / "bad.json"
            bad.write_text(
                json.dumps(
                    {"bomFormat": "CycloneDX", "components": [{"components": None}]}
                )
            )
            result = subprocess.run(
                [
                    sys.executable,
                    scan.__file__,
                    "sbom",
                    "--sbom-file",
                    str(good),
                    "--sbom-file",
                    str(bad),
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            sources = json.loads(result.stdout)["sboms"]
            self.assertEqual(sources[0]["count"], 2)
            self.assertEqual(sources[1]["source"], str(bad))
            self.assertEqual(sources[1]["count"], 0)
            self.assertTrue(sources[1]["coverage_gaps"])

    def test_gitlab_cyclonedx_preserves_component_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "gitlab.json"
            path.write_text(
                json.dumps(
                    {
                        "bomFormat": "CycloneDX",
                        "specVersion": "1.5",
                        "metadata": {"timestamp": "2026-01-01T12:00:00Z"},
                        "components": [
                            {
                                "name": "@example/pkg",
                                "version": "1.2.3",
                                "purl": "pkg:npm/%40example/pkg@1.2.3",
                            }
                        ],
                    }
                )
            )
            result = scan.preprocess_sbom(None, str(path))
        self.assertEqual(result["count"], 1)
        self.assertEqual(result["packages"][0]["name"], "@example/pkg")
        self.assertEqual(result["observed_at"], "2026-01-01T12:00:00Z")

    def test_distinct_registry_provenance_is_not_deduplicated(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sbom.json"
            path.write_text(
                json.dumps(
                    {
                        "bomFormat": "CycloneDX",
                        "components": [
                            {
                                "name": "pkg",
                                "version": "1.0.0",
                                "purl": "pkg:npm/pkg@1.0.0",
                            },
                            {
                                "name": "pkg",
                                "version": "1.0.0",
                                "purl": "pkg:npm/pkg@1.0.0?repository_url=private.example.test",
                            },
                        ],
                    }
                )
            )
            result = scan.preprocess_sbom(None, str(path))
        self.assertEqual(result["count"], 2)

    def test_nameless_component_is_reported_as_coverage_gap(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sbom.json"
            path.write_text(json.dumps({"packages": [{"versionInfo": "1.0.0"}]}))
            result = scan.preprocess_sbom(None, str(path))
        self.assertTrue(result["coverage_gaps"])

    def test_unknown_format_is_not_empty_inventory(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "invalid.json"
            path.write_text('{"error":"forbidden"}')
            with self.assertRaises(ValueError):
                scan.preprocess_sbom(None, str(path))

    def test_pypi_names_normalize_but_go_case_remains(self):
        self.assertEqual(scan.norm_name("Build.Helper", "pypi"), "build-helper")
        self.assertNotEqual(
            scan.norm_name("Example/Lib", "golang"),
            scan.norm_name("example/lib", "golang"),
        )

    def test_ranges_and_unverified_registry_are_review(self):
        feed = {
            "count": 1,
            "packages": [
                {"name": "pkg", "ecosystem": "npm", "compromised_versions": ["1.2.3"]}
            ],
        }
        report = scan.crossref(
            feed,
            [
                {
                    "source": "repo",
                    "packages": [
                        {
                            "name": "pkg",
                            "ecosystem": "npm",
                            "version": "^1.2.0",
                            "pinned": False,
                        },
                        {
                            "name": "pkg",
                            "ecosystem": "npm",
                            "version": "1.2.3",
                            "pinned": True,
                            "purl": "pkg:npm/pkg@1.2.3?repository_url=private.example.test",
                        },
                    ],
                }
            ],
        )
        self.assertEqual(
            [x["status"] for x in report["findings"]], ["REVIEW", "REVIEW"]
        )

    def test_complete_feed_pages_compromise_evidence(self):
        class Packages:
            def list(self, **kw):
                return PaginatedResponse(
                    items=[{"uuid": "pkg", "name": "pkg", "ecosystem": "npm"}], total=1
                )

            def compromises(self, uuid, **kw):
                off = kw["offset"]
                return PaginatedResponse(
                    items=[{"uuid": str(off), "compromised_versions": [f"1.0.{off}"]}],
                    total=2,
                    offset=off,
                    limit=1,
                )

        class Client:
            packages = Packages()

            def close(self):
                pass

        with patch("malloryapi.MalloryApi", return_value=Client()):
            result = scan.fetch_compromised(None, None, 1)
        self.assertEqual(
            result["packages"][0]["compromised_versions"], ["1.0.0", "1.0.1"]
        )
        self.assertEqual(result["coverage"]["mode"], "all_known_compromises")
        self.assertEqual(result["coverage"]["gaps"], [])


if __name__ == "__main__":
    unittest.main()
