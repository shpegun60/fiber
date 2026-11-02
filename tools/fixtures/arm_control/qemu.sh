#!/usr/bin/env bash
set -euo pipefail

action=$1
root=$2
out=$3
export LC_ALL=C
[[ $(uname -m) == x86_64 ]] || { echo 'This isolated package recipe requires x86_64 WSL'; exit 1; }
export LD_LIBRARY_PATH="$root/usr/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
qemu="$root/usr/bin/qemu-system-arm"

if [[ $action == provision || $action == inspect ]]; then
    if [[ $action == provision ]]; then
        [[ $(id -u) != 0 ]] || { echo 'Refusing root provisioning'; exit 1; }
        mkdir -p "$root/debs"
    fi
    if [[ $action == provision && ! -x $qemu ]]; then
        cd "$root/debs"
        # Query/download/extract only: no apt install, sudo, dpkg registration,
        # apt update, or writes to the distribution's package database.
        apt-cache depends --recurse --no-recommends --no-suggests \
            --no-conflicts --no-breaks --no-replaces --no-enhances qemu-system-arm \
            > "$out/apt-dependencies.txt"
        mapfile -t packages < <(awk '/^[a-z0-9][a-z0-9+.-]*(:[a-z0-9]+)?$/ {print $1}' \
            "$out/apt-dependencies.txt" | sort -u)
        for package in "${packages[@]}"; do
            if [[ $package == qemu-system-* ]] || \
                [[ $(dpkg-query -W -f='${db:Status-Status}' "$package" 2>/dev/null || true) != installed ]]; then
                apt-get download "$package"
            fi
        done
        for deb in ./*.deb; do dpkg-deb -x "$deb" "$root"; done
    fi
    [[ -x $qemu ]] || { echo 'Extracted qemu-system-arm missing'; exit 1; }
    "$qemu" --version > "$out/qemu-version.txt"
    "$qemu" -machine help > "$out/qemu-machines.txt"
    ldd "$qemu" > "$out/qemu-ldd.txt"
    if grep -q 'not found' "$out/qemu-ldd.txt"; then cat "$out/qemu-ldd.txt"; exit 1; fi
    sha256sum "$qemu" > "$out/qemu-sha256.txt"
    id > "$out/wsl-user.txt"
    uname -a > "$out/wsl-system.txt"
    if [[ -d $root/debs ]]; then
        find "$root/debs" -maxdepth 1 -name '*.deb' -print0 | sort -z | \
            xargs -0 -r sha256sum > "$out/deb-sha256.txt"
    fi
    for deb in "$root"/debs/*.deb; do
        [[ -f $deb ]] || continue
        dpkg-deb -f "$deb" Package Version
    done > "$out/deb-versions.txt"
    printf '%s\n' "$root" > "$out/qemu-root.txt"
elif [[ $action == run ]]; then
    machine=$4
    image=$5
    seconds=$6
    [[ -x $qemu ]] || { echo 'Extracted qemu-system-arm missing'; exit 1; }
    ulimit -c 0
    exec timeout --signal=TERM --kill-after=2s "${seconds}s" "$qemu" \
        -machine "$machine" -accel tcg -display none -serial none -monitor none \
        -no-reboot -semihosting-config enable=on,target=native \
        -L "$root/usr/share/qemu" -kernel "$image"
else
    echo "Unknown action: $action" >&2
    exit 1
fi
