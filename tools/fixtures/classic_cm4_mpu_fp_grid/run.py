"""Closed-input, opt-in CM4 MPU FP grid; never provisions tools."""
from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import importlib.util
import json
import os
from pathlib import Path
import sys

sys.dont_write_bytecode = True
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
HERE = Path(__file__).resolve().parent
RELATIVE = "tools/fixtures/classic_cm4_mpu_fp_grid"
PILOT = "tools/fixtures/classic_cm4_mpu_fp_pilot"
BASIC = "tools/fixtures/classic_cm4_mpu_basic_grid"
PIN = "a50edad08b29052631aa469d4df6e6ec7ff68878"


def need(condition, message):
    if not condition:
        raise RuntimeError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest().upper()


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="ascii")


def capture(args):
    repo = Path(args.repo).resolve(strict=True)
    need(HERE == repo / RELATIVE, "Runner must belong to the selected source tree")
    root = Path(args.build_root).resolve()
    need(not root.exists() and not root.is_relative_to(repo), "Use a fresh external build root")
    root.mkdir(parents=True)
    target = root / "source"
    originals = dict(Repository=str(repo), Cmsis=str(Path(args.cmsis).resolve(strict=True)),
                     FreeRTOS=str(Path(args.freertos).resolve(strict=True)))
    names = {p.relative_to(repo).as_posix() for p in repo.glob("*.h")}
    for directory in ("context", "fiber", "fiber/port", "fiber/lifecycle", "fiber/port/ARM_CM4_MPU"):
        for suffix in ("*.h", "*.c"):
            names.update(p.relative_to(repo).as_posix() for p in (repo / directory).glob(suffix))
    names.update(("tools/runtime_sources.py", "tools/runtime_sources.ps1", "tools/runtime_sources.json",
                  "tools/freertos_asm_parity.ps1", "FREERTOS_ASM_PARITY.md",
                  "tools/test_classic_cm4_mpu_fp_pilot.ps1", "tools/test_classic_cm4_mpu_fp_grid.ps1",
                  "tools/fixtures/classic_cm4_mpu_context_runtime/run.py",
                  "tools/fixtures/classic_fp_context_runtime/run.py",
                  "tools/fixtures/classic_context_runtime/run.py",
                  "tools/fixtures/classic_context_runtime/qemu.sh", "tools/fixtures/arm_control/qemu.sh"))
    for directory in (repo / BASIC, repo / PILOT, HERE):
        for path in directory.rglob("*"):
            if not path.is_file() or "__pycache__" in path.parts:
                continue
            need(path.suffix in (".py", ".ps1", ".c", ".h", ".S", ".ld", ".json", ".md"),
                 "Unexpected fixture input: " + str(path))
            names.add(path.relative_to(repo).as_posix())
    records = []

    def copy(source, destination, role, expected=None):
        need(source.is_file() and not source.is_symlink(), "Missing/reparse input: " + str(source))
        data = source.read_bytes()
        value = digest(data)
        need(expected is None or value == expected, "Pinned input mismatch: " + str(source))
        destination.parent.mkdir(parents=True, exist_ok=True)
        need(not destination.exists(), "Duplicate captured path")
        destination.write_bytes(data)
        need(digest(source.read_bytes()) == digest(destination.read_bytes()) == value, "Capture-time drift")
        records.append(dict(Original=str(source.resolve()), Captured=str(destination.resolve()),
                            Sha256=value, Role=role))

    for name in sorted(names):
        copy(repo / name, target / name, "SelectedRepositorySource")
    pinned = json.loads((target / BASIC / "pinned_reference.json").read_text())
    need(pinned["ExpectedCommit"] == PIN and len(pinned["Files"]) == 26 and
         len({row["Path"] for row in pinned["Files"]}) == 26, "Exact selected FreeRTOS pin inventory")
    reference = root / "reference"
    for row in pinned["Files"]:
        name = Path(row["Path"])
        need(not name.is_absolute() and ".." not in name.parts, "Unsafe reference path")
        copy(Path(originals["FreeRTOS"]) / name, reference / name, "PinnedReference", row["Sha256"])
    cmsis = root / "cmsis"
    headers = sorted(Path(originals["Cmsis"]).rglob("*.h"))
    need(headers, "Missing CMSIS headers")
    for path in headers:
        copy(path, cmsis / path.relative_to(originals["Cmsis"]), "CMSIS")
    need(not any(n == "elftools" or n.startswith("elftools.") for n in sys.modules), "Preloaded ELF package")
    package = importlib.metadata.distribution("pyelftools")
    need(package.version == "0.33" and package.files, "Existing pyelftools 0.33 required")
    python_copy = root / "python"
    selected = []
    for item in package.files:
        name = Path(str(item))
        need(not name.is_absolute() and ".." not in name.parts, "Unsafe package path")
        if ((name.parts[0] == "elftools" and name.suffix == ".py") or
                (name.parts[0].endswith(".dist-info") and name.name in ("METADATA", "WHEEL", "RECORD"))):
            copy(Path(package.locate_file(item)).resolve(strict=True), python_copy / name, "PythonPackage")
            selected.append(name.as_posix())
    need("elftools/__init__.py" in selected and "elftools/elf/elffile.py" in selected, "Incomplete ELF package")
    sys.path.insert(0, str(python_copy))
    manifest = root / "capture.json"
    save(manifest, dict(SchemaVersion=1, Originals=originals, Files=records,
                       Attribution="Fresh selected byte capture; not a clean Git or board claim"))
    args.repo, args.cmsis, args.freertos = str(target), str(cmsis), str(reference)
    args.build_root = str(root / "evidence")
    args.capture_manifest = str(manifest)
    args.output_root = str(root)
    for row in records:
        need(digest(Path(row["Captured"]).read_bytes()) == row["Sha256"], "Pre-import capture drift")
    return target, records


def load(name, path, records):
    need(name not in sys.modules, "Preloaded local module: " + name)
    row = next((r for r in records if r["Captured"] == str(path.resolve())), None)
    need(row is not None, "Uncaptured helper: " + str(path))
    data = path.read_bytes()
    need(digest(data) == row["Sha256"], "Local helper changed before import")
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    exec(compile(data, str(path), "exec"), module.__dict__)
    return module


def main():
    parser = argparse.ArgumentParser(allow_abbrev=False)
    for key in ("repo", "gcc", "cmsis", "freertos", "build-root"):
        parser.add_argument("--" + key, required=True)
    parser.add_argument("--qemu-root")
    parser.add_argument("--wsl-distro", default="Ubuntu-24.04")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--execute-grid", action="store_true")
    mode.add_argument("--compile-only", action="store_true")
    args = parser.parse_args()
    need(__debug__ and not sys.flags.optimize, "Disable Python optimization")
    if args.execute_grid:
        need(type(args.qemu_root) is str and args.qemu_root.startswith("/") and args.wsl_distro,
             "Execution requires an explicit existing QEMU prefix; never provisions")
    args.execute_pilot = args.execute_grid
    root, records = capture(args)
    for name, relative in (("cm4_mpu_basic_engine", BASIC + "/engine.py"),
                           ("cm4_mpu_basic_builds", BASIC + "/build.py"),
                           ("cm4_mpu_basic_contracts", BASIC + "/contracts.py"),
                           ("cm4_mpu_basic_suite", BASIC + "/suite.py"),
                           ("cm4_mpu_fp_checks", PILOT + "/check_fp.py"),
                           ("cm4_mpu_fp_contracts", PILOT + "/contracts.py"),
                           ("cm4_mpu_fp_suite", PILOT + "/suite.py"),
                           ("cm4_mpu_fp_grid_contracts", RELATIVE + "/contracts.py"),
                           ("cm4_mpu_fp_grid_builds", RELATIVE + "/build.py")):
        load(name, root / relative, records)
    module = load("cm4_mpu_fp_grid_suite", root / RELATIVE / "suite.py", records)
    suite = module.FpGrid(args)
    error = None
    try:
        suite.run()
    except Exception as failure:
        error = type(failure).__name__ + ": " + str(failure)
    if not suite.finish(error):
        raise RuntimeError("Preserve failed FP grid: " + str(suite.build) + ": " + str(suite.report["Error"]))
    print(suite.report["Verdict"] + " " + str(suite.build), flush=True)


if __name__ == "__main__":
    main()
