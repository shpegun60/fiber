#!/usr/bin/env bash
set -euo pipefail
action=$1
root=$2
out=$3
export LC_ALL=C
export LD_LIBRARY_PATH="$root/usr/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
qemu="$root/usr/bin/qemu-system-arm"
[[ -x $qemu ]] || { echo 'Existing isolated QemuRoot required; no provisioning'; exit 1; }
hash_dependencies() {
    { printf '%s\n' "$qemu"; ldd "$qemu" | awk '$3 ~ /^\// {print $3} $1 ~ /^\// {print $1}'; } |
        sort -u | while IFS= read -r path; do sha256sum "$path"; done
}
if [[ $action == inspect ]]; then
    "$qemu" --version > "$out/qemu-version.txt"
    "$qemu" -machine help > "$out/qemu-machines.txt"
    ldd "$qemu" > "$out/qemu-ldd.txt"
    if grep -q 'not found' "$out/qemu-ldd.txt"; then cat "$out/qemu-ldd.txt"; exit 1; fi
    sha256sum "$qemu" > "$out/qemu-sha256.txt"
    printf '%s\n' "$root" > "$out/qemu-root.txt"
    uname -a > "$out/wsl-system.txt"
    id > "$out/wsl-user.txt"
    hash_dependencies > "$out/qemu-inputs-before.sha256"
elif [[ $action == verify ]]; then
    hash_dependencies > "$out/qemu-inputs-after.sha256"
    cmp "$out/qemu-inputs-before.sha256" "$out/qemu-inputs-after.sha256"
elif [[ $action == run ]]; then
    elf=$4
    seconds=$5
    ulimit -c 0
    exec timeout --signal=TERM --kill-after=2s "${seconds}s" "$qemu" \
        -machine mps3-an547 -accel tcg -display none -serial none -monitor none \
        -no-reboot -semihosting-config enable=on,target=native -L "$root/usr/share/qemu" \
        -kernel "$elf" -d int -D "$(dirname "$elf")/qemu-exceptions.log"
else
    echo "Unsupported action (no provisioning): $action" >&2
    exit 1
fi
