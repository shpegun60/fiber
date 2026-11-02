#!/usr/bin/env bash
set -euo pipefail
action=$1
root=$2
out=$3
export LC_ALL=C
export LD_LIBRARY_PATH="$root/usr/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
qemu="$root/usr/bin/qemu-system-arm"
[[ -x $qemu ]] || { echo 'Existing isolated QemuRoot is required; no provisioning'; exit 1; }
if [[ $action == inspect ]]; then
    "$qemu" --version > "$out/qemu-version.txt"
    "$qemu" -machine help > "$out/qemu-machines.txt"
    ldd "$qemu" > "$out/qemu-ldd.txt"
    if grep -q 'not found' "$out/qemu-ldd.txt"; then cat "$out/qemu-ldd.txt"; exit 1; fi
    sha256sum "$qemu" > "$out/qemu-sha256.txt"
    printf '%s\n' "$root" > "$out/qemu-root.txt"
    uname -a > "$out/wsl-system.txt"
    id > "$out/wsl-user.txt"
elif [[ $action == run ]]; then
    secure=$4
    nonsecure=$5
    seconds=$6
    ulimit -c 0
    args=(-machine mps2-an505 -accel tcg -display none -serial none -monitor none
        -no-reboot -semihosting-config enable=on,target=native -L "$root/usr/share/qemu"
        -kernel "$secure")
    if [[ $nonsecure != none ]]; then args+=(-device "loader,file=$nonsecure"); fi
    exec timeout --signal=TERM --kill-after=2s "${seconds}s" "$qemu" "${args[@]}"
else
    echo "Unsupported action (provisioning is never supported): $action" >&2
    exit 1
fi
