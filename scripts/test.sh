#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
bash "$root/scripts/check-dependency.sh"
bash "$root/scripts/check-sources.sh"
cd "$root/tests"
alr -n build --validation --profiles=argon2=validation
./bin/test_main
