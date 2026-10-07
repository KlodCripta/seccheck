#!/usr/bin/env bash
# Development tests use temporary fixture directories; never root or real scanners.
set -uo pipefail
script_dir=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
exec python3 -m unittest discover -s "$script_dir/tests" -v "$@"
