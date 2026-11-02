#!/usr/bin/env bash
set -euo pipefail
root=$1
secure=$2
nonsecure=$3
seconds=$4
ulimit -c 0
export LD_LIBRARY_PATH="$root/usr/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
if [[ $# == 5 ]]; then
    exec python3 "$(dirname "$0")/aircr_rsp.py" "$root" "$secure" "$nonsecure" "$seconds" "$5"
fi
exec timeout --signal=TERM --kill-after=2s "${seconds}s" "$root/usr/bin/qemu-system-arm" \
    -machine mps2-an505 -accel tcg -display none -serial none -monitor none \
    -no-reboot -semihosting-config enable=on,target=native -L "$root/usr/share/qemu" \
    -kernel "$secure" -device "loader,file=$nonsecure"
