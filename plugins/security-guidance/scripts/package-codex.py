#!/usr/bin/env python3
"""Build a standalone Codex package without changing the Claude distribution."""

import argparse
import json
from pathlib import Path
import shutil


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path, help="New security-guidance-codex directory")
    args = parser.parse_args()
    source = Path(__file__).resolve().parents[1]
    destination = args.destination.expanduser().resolve()
    if destination.name != "security-guidance-codex":
        parser.error("destination directory must be named security-guidance-codex")
    if destination.exists():
        parser.error("destination already exists; package into a new directory first")
    destination.mkdir(parents=True)
    for folder in ("hooks", "tests"):
        shutil.copytree(source / folder, destination / folder,
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    shutil.copy2(source / "hooks/codex-hooks.json", destination / "hooks/hooks.json")
    (destination / ".codex-plugin").mkdir()
    manifest = json.loads((source / "codex-plugin.json").read_text())
    (destination / ".codex-plugin/plugin.json").write_text(json.dumps(manifest, indent=2) + "\n")
    for name in ("README.md", "CODEX_COMPATIBILITY.md", "LICENSE"):
        shutil.copy2(source / name, destination / name)
    print(destination)


if __name__ == "__main__":
    main()
