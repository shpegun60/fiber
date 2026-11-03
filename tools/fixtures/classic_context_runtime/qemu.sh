#!/usr/bin/env bash
set -euo pipefail

action=$1
root=$2
out=$3
export LC_ALL=C
[[ $root == /* ]] || { echo 'Expected absolute existing QEMU prefix' >&2; exit 1; }
[[ $(uname -m) == x86_64 ]] || { echo 'Qualified QEMU prefix requires x86_64 WSL' >&2; exit 1; }
export LD_LIBRARY_PATH="$root/usr/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
qemu="$root/usr/bin/qemu-system-arm"
[[ -x $qemu ]] || { echo 'Existing QEMU executable missing; no provisioning attempted' >&2; exit 1; }

if [[ $action == inspect ]]; then
    "$qemu" --version > "$out/qemu-version.txt"
    "$qemu" -machine help > "$out/qemu-machines.txt"
    "$qemu" -cpu help > "$out/qemu-cpus.txt"
    ldd "$qemu" > "$out/qemu-ldd.txt"
    if grep -q 'not found' "$out/qemu-ldd.txt"; then
        cat "$out/qemu-ldd.txt" >&2
        exit 1
    fi
    sha256sum "$(realpath "$qemu")" > "$out/qemu-sha256.txt"
    mapfile -t libraries < <(awk '
        /=>/ && $3 ~ /^\// { print $3 }
        $1 ~ /^\// { print $1 }
    ' "$out/qemu-ldd.txt" | sort -u)
    (( ${#libraries[@]} > 0 )) || { echo 'Missing dynamic-library closure' >&2; exit 1; }
    for library in "${libraries[@]}"; do
        sha256sum "$(realpath "$library")"
    done | sort > "$out/qemu-libraries-sha256.txt"
    for tool in bash timeout ldd awk sort realpath sha256sum; do
        sha256sum "$(realpath "$(command -v "$tool")")"
    done | sort -u > "$out/wsl-tools-sha256.txt"
    id > "$out/wsl-user.txt"
    uname -a > "$out/wsl-system.txt"
    cat /etc/os-release > "$out/wsl-os-release.txt"
    if [[ -d $root/debs ]]; then
        find "$root/debs" -maxdepth 1 -type f -name '*.deb' -print0 |
            sort -z | xargs -0 -r sha256sum > "$out/deb-sha256.txt"
        for deb in "$root"/debs/*.deb; do
            [[ -f $deb ]] || continue
            dpkg-deb -f "$deb" Package Version
        done > "$out/deb-versions.txt"
    else
        printf '%s\n' 'No package archives retained in prefix' > "$out/deb-sha256.txt"
        printf '%s\n' 'Package archive identity unavailable' > "$out/deb-versions.txt"
    fi
    printf '%s\n' "$root" > "$out/qemu-root.txt"
elif [[ $action == run ]]; then
    machine=$4
    image=$5
    seconds=$6
    [[ $machine == microbit ]] || { echo 'Unadmitted classic runtime machine' >&2; exit 1; }
    ulimit -c 0
    exec timeout --signal=TERM --kill-after=2s "${seconds}s" "$qemu" \
        -machine "$machine" -accel tcg -display none -serial none -monitor none \
        -no-reboot -semihosting-config enable=on,target=native \
        -L "$root/usr/share/qemu" -kernel "$image"
else
    echo "Unknown action: $action" >&2
    exit 1
fi
