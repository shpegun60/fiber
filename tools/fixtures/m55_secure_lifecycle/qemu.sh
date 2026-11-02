#!/usr/bin/env bash
set -euo pipefail
root=$1
export LD_LIBRARY_PATH="$root/usr/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export PYTHONDONTWRITEBYTECODE=1
test -x "$root/usr/bin/qemu-system-arm"
ulimit -c 0
exec python3 "$(dirname "$0")/run.py" "$@"
