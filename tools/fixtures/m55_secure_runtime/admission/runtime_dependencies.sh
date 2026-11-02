#!/usr/bin/env bash
set -euo pipefail
root=$1
out=$2
export LC_ALL=C
export LD_LIBRARY_PATH="$root/usr/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
qemu="$root/usr/bin/qemu-system-arm"
[[ -x $qemu ]] || { echo 'Explicit existing QemuRoot required; no provisioning'; exit 1; }
bash "$(dirname "$0")/../../arm_control/qemu.sh" inspect "$root" "$out"
mapfile -t dependencies < <(awk '/=> \/[^ ]+/ {print $3} /^[[:space:]]*\// {print $1}' "$out/qemu-ldd.txt" | sort -u)
[[ ${#dependencies[@]} -gt 0 ]] || { echo 'Missing actual QEMU dependency inventory'; exit 1; }
sha256sum "$qemu" "${dependencies[@]}" > "$out/runtime-dependencies.sha256"
