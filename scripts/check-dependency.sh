#!/usr/bin/env bash
# The BLAKE2b dependency is exactly version 0.1.2, pinned to one commit of
# its repository until that release is in the Alire index: no other
# version range, no other pin (a local path or another commit would stand
# in for the release), and no pin of any other crate.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
python3 - "$root/alire.toml" <<'PYTHON'
import pathlib
import sys
import tomllib

URL = "https://github.com/m-doughty/blake2b"
COMMIT = "fec91ab72758a7c5d1d06450f78615c793352440"


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
pins = manifest.get("pins", [])
expected = {"blake2b": {"url": URL, "commit": COMMIT}}
if pins != [expected]:
    raise SystemExit("The library manifest must pin blake2b to "
                     f"{URL} at commit {COMMIT}, and pin nothing else")
print(f"BLAKE2b dependency is 0.1.2, pinned to commit {COMMIT}")
PYTHON
