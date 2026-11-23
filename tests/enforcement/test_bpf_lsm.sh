#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# Backward-compatible entry point. The Python runner creates/cleans its own fixture.
exec python3 "$SCRIPT_DIR/test_bpf_lsm.py" --loopback "$@"
