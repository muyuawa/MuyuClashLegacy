#!/bin/bash
set -euo pipefail
task_root="$(cd "$(dirname "$0")/.." && pwd)"
exec python3 -B "$task_root/protocols/build_senko.py" "$@"
