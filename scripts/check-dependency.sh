#!/usr/bin/env bash
# The BLAKE2b dependency is exactly version 0.1.2, from the Alire index: no
# other version range, and no pin of any crate (a local path or a commit
# would stand in for the release).
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
python3 - "$root/alire.toml" <<'PYTHON'
import pathlib
import sys
import tomllib


def collect(node):
    """Every value of a key "blake2b", at any depth of node."""
    found = []
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "blake2b":
                found.append(value)
            found.extend(collect(value))
    elif isinstance(node, list):
        for value in node:
            found.extend(collect(value))
    return found


manifest = tomllib.loads(pathlib.Path(sys.argv[1]).read_text())
# Every blake2b key anywhere in the dependencies, conditional tables
# (depends-on.'case(os)'.windows) included, must be the one unconditional
# "=0.1.2", directly in a [[depends-on]] entry.
depends = manifest.get("depends-on", [])
if not isinstance(depends, list):
    raise SystemExit("depends-on must be an array of tables")
direct = [dep["blake2b"] for dep in depends if "blake2b" in dep]
if direct != ["=0.1.2"] or collect(depends) != direct:
    raise SystemExit("BLAKE2b dependency must be exactly version 0.1.2, "
                     "once, unconditionally")
if "pins" in manifest:
    raise SystemExit("The library manifest must pin nothing")
print("BLAKE2b dependency is 0.1.2, from the index, and nothing is pinned")
PYTHON
