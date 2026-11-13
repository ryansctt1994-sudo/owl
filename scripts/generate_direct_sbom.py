#!/usr/bin/env python3
"""Export declared direct OWL dependencies as an UNRESOLVED CycloneDX 1.5 inventory.

This is not a resolved dependency SBOM, vulnerability scan, or installed-package
attestation. Version constraints may resolve differently by platform/time.
No package installers, providers, or network requests are invoked.
"""
from __future__ import annotations

import argparse
import json
import re
import tomllib
from pathlib import Path

NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]+\])?")
NORMALIZE = re.compile(r"[-_.]+")


def direct_inventory(path: Path) -> dict:
    document = tomllib.loads(path.read_text(encoding="utf-8"))
    project = document["project"]
    requirements = project["dependencies"]
    if not isinstance(requirements, list) or not requirements:
        raise ValueError("No declared dependencies")
    components = []
    seen = set()
    for spec in requirements:
        if not isinstance(spec, str) or not (match := NAME.match(spec)):
            raise ValueError(f"Malformed requirement: {spec!r}")
        name = NORMALIZE.sub("-", match.group(1)).lower()
        if name in seen:
            raise ValueError(f"Duplicate direct dependency: {name}")
        seen.add(name)
        components.append({
            "type": "library",
            "name": name,
            "purl": f"pkg:pypi/{name}",
            "scope": "required",
            "properties": [
                {"name": "tinkerforge:declared-requirement", "value": spec},
                {"name": "tinkerforge:resolution-status", "value": "unresolved"},
            ],
        })
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": project["name"],
                "version": project["version"],
            },
            "properties": [
                {"name": "tinkerforge:scope", "value": "direct-declarations-only"},
                {"name": "tinkerforge:transitive-dependencies", "value": "not-included"},
                {"name": "tinkerforge:vulnerability-audit", "value": "not-run"},
            ],
        },
        "components": sorted(components, key=lambda x: x["name"]),
    }


def main() -> int:
    cli = argparse.ArgumentParser()
    cli.add_argument("--project", type=Path, default=Path("pyproject.toml"))
    cli.add_argument("--output", type=Path, default=Path("direct-dependency-inventory.cdx.json"))
    args = cli.parse_args()
    args.output.write_text(json.dumps(direct_inventory(args.project), indent=2, sort_keys=True) + "\n",
                           encoding="utf-8")
    print(f"Exported UNRESOLVED direct dependency declarations to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
