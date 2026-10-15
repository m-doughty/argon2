#!/usr/bin/env bash
# The BLAKE2b dependency comes from the Alire index at exactly version 0.1.1:
# no pin of any kind (a commit pin or a local path would stand in for the
# release), and no other version range.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
python3 - "$root/alire.toml" <<'PYTHON'
import pathlib
import sys
import tomllib

manifest = tomllib.loads(pathlib.Path(sys.argv[1]).read_text())
if manifest.get("pins"):
    raise SystemExit("The library manifest must not contain pins")
dependencies = [dep["blake2b"] for dep in manifest.get("depends-on", [])
                if "blake2b" in dep]
if dependencies != ["=0.1.1"]:
    raise SystemExit("BLAKE2b dependency must be exactly version 0.1.1")
print("BLAKE2b dependency is the index release 0.1.1, unpinned")
PYTHON
