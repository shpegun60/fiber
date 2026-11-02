#!/usr/bin/env bash
set -euo pipefail
action=$1
root=$2
out=$3
export LC_ALL=C
export LD_LIBRARY_PATH="$root/usr/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
qemu="$root/usr/bin/qemu-system-arm"
[[ -x $qemu ]] || { echo 'Explicit existing QemuRoot required; no provisioning'; exit 1; }
if [[ $action == inspect ]]; then
    bash "$(dirname "$0")/../../arm_control/qemu.sh" inspect "$root" "$out"
    mapfile -t dependencies < <(awk '/=> \/[^ ]+/ {print $3} /^[[:space:]]*\// {print $1}' "$out/qemu-ldd.txt" | sort -u)
    [[ ${#dependencies[@]} -gt 0 ]] || { echo 'Missing actual QEMU runtime dependency inventory'; exit 1; }
    sha256sum "$qemu" "${dependencies[@]}" > "$out/runtime-dependencies.sha256"
elif [[ $action == run ]]; then
    secure=$4
    nonsecure=$5
    seconds=$6
    ulimit -c 0
    exec timeout --signal=TERM --kill-after=2s "${seconds}s" "$qemu" \
        -machine mps2-an505 -accel tcg -display none -serial none -monitor none -no-reboot \
        -semihosting-config enable=on,target=native -L "$root/usr/share/qemu" \
        -kernel "$secure" -device "loader,file=$nonsecure" \
        -d int -D "$out/qemu-exceptions.log"
else
    echo "Unsupported action (no provisioning): $action" >&2
    exit 1
fi
