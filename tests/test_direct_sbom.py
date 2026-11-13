"""No-install direct dependency inventory contract tests."""
import json
import tempfile
import unittest
from pathlib import Path

from scripts.generate_direct_sbom import direct_inventory

ROOT = Path(__file__).resolve().parents[1]


class DeclaredSbomTests(unittest.TestCase):
    def test_real_project_declared_inventory_is_deterministic_and_unresolved(self):
        first = direct_inventory(ROOT / "pyproject.toml")
        second = direct_inventory(ROOT / "pyproject.toml")
        self.assertEqual(first, second)
        self.assertEqual(first["bomFormat"], "CycloneDX")
        self.assertEqual(first["specVersion"], "1.5")
        self.assertTrue(len(first["components"]) >= 8)
        self.assertIn("camel-ai", {item["name"] for item in first["components"]})
        for item in first["components"]:
            self.assertNotIn("version", item, "do not fabricate resolved versions")
            self.assertIn(
                {"name": "tinkerforge:resolution-status", "value": "unresolved"},
                item["properties"],
            )
        self.assertIn(
            {"name": "tinkerforge:vulnerability-audit", "value": "not-run"},
            first["metadata"]["properties"],
        )

    def test_duplicate_direct_dependencies_fail_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            config = Path(temp) / "pyproject.toml"
            config.write_text('[project]\nname="fixture"\nversion="0.1"\n'
                              'dependencies=["My_Package>=1","my-package==2"]\n')
            with self.assertRaisesRegex(ValueError, "Duplicate"):
                direct_inventory(config)

    def test_malformed_requirements_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            config = Path(temp) / "pyproject.toml"
            config.write_text('[project]\nname="fixture"\nversion="0.1"\n'
                              'dependencies=["!invalid"]\n')
            with self.assertRaisesRegex(ValueError, "Malformed"):
                direct_inventory(config)


if __name__ == "__main__":
    unittest.main()
