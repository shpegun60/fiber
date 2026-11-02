"""One structured source for compiled NS requests and debugger expectations."""
import json
from pathlib import Path
import sys

A, B, C, D = 0xA101, 0xB202, 0xC303, 0xD404
STEPS = []


def add(name, op, arg=0, owner=A, expected=0, mode=11, **extra):
    STEPS.append(dict(name=name, op=op, arg=arg, owner=owner, expected=expected, mode=mode, **extra))


def ptr(handle, field, delta=0):
    return dict(handle=handle, field=field, delta=delta)


add("unready-allocate", 1, 64)
add("unready-load", 2)
add("unready-save", 3, mode=14)
add("initialize", 0, expected=1)
for mode, label in ((0, "thread"), (15, "systick")):
    for op, name in ((1, "allocate"), (2, "load"), (3, "save")):
        add("wrong-" + label + "-" + name, op, 64 if op == 1 else 0, mode=mode)
add("wrong-svc-save", 3)
add("direct-svc", 2, expected=1, direct=True)
add("direct-pendsv", 3, expected=1, mode=14, direct=True)
for op, name in ((1, "allocate"), (2, "load"), (3, "save")):
    for bad in (0, 1, 3, 6, 10, 14):
        add(f"control-{name}-{bad}", op, 64 if op == 1 else 0,
            mode=14 if op == 3 else 11, control_read=bad)
for seed, label in (([0, 0x30006000], "pointer"), ([0x30005000, 0], "limit")):
    for op, name in ((1, "allocate"), (2, "load")):
        add("partial-empty-" + label + "-" + name, op, 64 if op == 1 else 0, seed=seed)
add("empty-reset", 2, expected=1, seed=[0, 0])
for size in (0, 7, 9, 136, 0xFFFFFFFF):
    add(f"invalid-size-{size}", 1, size)
add("invalid-allocate-owner", 1, 64, owner=0)
add("allocate-a", 1, 64, expected=1)
add("duplicate-owner", 1, 64)
add("unallocated-load", 2, 2, owner=B)
add("unallocated-save", 3, 2, owner=B, mode=14)
add("allocate-b", 1, 96, owner=B, expected=2, mode=14)
add("allocate-c", 1, 128, owner=C, expected=3)
add("exhaustion", 1, 48, owner=D)
for op, name in ((2, "load"), (3, "save")):
    for handle in (4, 0xFFFFFFFF):
        add(f"invalid-{name}-{handle}", op, handle, mode=14 if op == 3 else 11)
    add("foreign-" + name, op, 1, owner=B, mode=14 if op == 3 else 11)
    add("zero-owner-" + name, op, mode=14 if op == 3 else 11, owner=0)
add("unattached-load", 2, expected=1)
add("unattached-save", 3, expected=1, mode=14)
add("load-a-first", 2, 1, expected=1)
add("loaded-allocate", 1, 64, owner=D)
add("loaded-load", 2, 1)
add("loaded-zero-load", 2)
add("loaded-zero-save", 3, mode=14)
add("loaded-foreign-save", 3, 1, owner=B, mode=14)
add("loaded-wrong-svc-save", 3, 1)
for label, limit, pointer in (
        ("unaligned", ptr(1, "limit"), ptr(1, "top", -4)),
        ("below", ptr(1, "limit"), ptr(1, "limit", -8)),
        ("above", ptr(1, "limit"), ptr(1, "top", 8)),
        ("wrong-limit", ptr(1, "limit", 8), ptr(1, "top", -8)),
        ("zero-pointer", ptr(1, "limit"), 0)):
    add("live-save-" + label, 3, 1, mode=14, seed=[limit, pointer])
add("save-at-limit", 3, 1, expected=1, mode=14, seed=[ptr(1, "limit"), ptr(1, "limit")])
add("reload-at-limit", 2, 1, expected=1, mode=14)
add("save-a-first", 3, 1, expected=1, mode=14, seed=[ptr(1, "limit"), ptr(1, "top", -16)])
for cycle in range(3):
    for handle, owner in ((1, A), (2, B), (3, C)):
        add(f"cycle-{cycle}-load-{handle}", 2, handle, owner=owner, expected=1,
            mode=11 if cycle % 2 == 0 else 14)
        add(f"cycle-{cycle}-save-{handle}", 3, handle, owner=owner, expected=1, mode=14,
            seed=[ptr(handle, "limit"), ptr(handle, "top", -8 * (cycle + 1))])
add("unattached-final-load", 2, expected=1)
add("unattached-final-save", 3, expected=1, mode=14)


if __name__ == "__main__":
    header, manifest = map(Path, sys.argv[1:])
    rows = ["static const Step steps[]={"]
    rows += ["    {%du,%du,%du,%du,%du}," % tuple(s[k] for k in ("mode", "op", "arg", "owner", "expected")) for s in STEPS]
    rows.append("};\n")
    header.write_text("\n".join(rows))
    manifest.write_text(json.dumps(STEPS, indent=2) + "\n")
