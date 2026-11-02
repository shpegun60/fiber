#!/usr/bin/env bash
set -euo pipefail
action=$1
root=$2
out=$3
export LC_ALL=C
export LD_LIBRARY_PATH="$root/usr/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
qemu="$root/usr/bin/qemu-system-arm"
[[ -x $qemu ]] || { echo 'Existing isolated QemuRoot required; no provisioning'; exit 1; }
if [[ $action == inspect ]]; then
    exec bash "$(dirname "$0")/../cm33f_mpu_first_start_execution/qemu.sh" "$@"
elif [[ $action == run ]]; then
    secure=$4
    nonsecure=$5
    seconds=$6
    ulimit -c 0
    trace="$(dirname "$secure")/qemu-exceptions.log"
    args=(-machine mps2-an505 -accel tcg -display none -serial none -monitor none
        -no-reboot -semihosting-config enable=on,target=native -L "$root/usr/share/qemu"
        -kernel "$secure")
    if [[ $nonsecure != none ]]; then
        args+=(-device "loader,file=$nonsecure")
        trace="$(dirname "$nonsecure")/qemu-exceptions.log"
    fi
    args+=(-d int -D "$trace")
    exec timeout --signal=TERM --kill-after=2s "${seconds}s" "$qemu" "${args[@]}"
else
    echo "Unsupported action (no provisioning): $action" >&2
    exit 1
fi
