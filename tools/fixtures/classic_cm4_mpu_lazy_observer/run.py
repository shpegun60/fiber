"""Closed-input, opt-in lazy observer of four existing FP pilot images."""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import importlib.metadata
import importlib.util
import json
import os
from pathlib import Path
import re
import sys

sys.dont_write_bytecode = True
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
HERE = Path(__file__).resolve().parent
RELATIVE = "tools/fixtures/classic_cm4_mpu_lazy_observer"
BASIC = "tools/fixtures/classic_cm4_mpu_basic_grid"
FP_PILOT = "tools/fixtures/classic_cm4_mpu_fp_pilot"
IMAGE_KEYS = (("context", False, "context-eager"), ("context", True, "context-lazy"),
              ("fiber", False, "fiber-eager"), ("fiber", True, "fiber-lazy"))


def need(condition, message):
    if not condition:
        raise RuntimeError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest().upper()


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="ascii")


def read_json(path):
    def pairs(items):
        result = {}
        for name, value in items:
            need(name not in result, "Duplicate JSON property: " + name)
            result[name] = value
        return result
    return json.loads(path.read_text(encoding="utf-8-sig"), object_pairs_hook=pairs)


def regular(path):
    def allowed(value):
        parts = {part.casefold() for part in value.parts}
        need(not parts.intersection(("cm33f_secure_transfer_reference", "m55_secure_closed_parity",
                 "test_cm33f_secure_transfer_reference.ps1", "test_m55_secure_closed_parity.ps1")),
             "Protected stopped input is not admissible")
    allowed(path)
    need(path.is_file() and not path.is_symlink() and
         not (getattr(path.stat(follow_symlinks=False), "st_file_attributes", 0) & 0x400),
         "Missing/reparse input: " + str(path))
    resolved = path.resolve(strict=True)
    allowed(resolved)
    return resolved


def image_rows(receipt, artifacts, origin):
    need(type(receipt) is dict and receipt.get("Verdict") == "FP-PILOT-PASS" and
         receipt.get("Execution") == "FP_ACTIVE_PILOT" and "Error" in receipt and receipt["Error"] is None,
         "An executed FP pilot receipt is required")
    need(type(artifacts) is dict and type(artifacts.get("Artifacts")) is dict,
         "Pilot artifact manifest grammar")
    for name, value in artifacts["Artifacts"].items():
        path = Path(name)
        need(type(name) is str and name and not path.drive and not path.is_absolute() and
             ".." not in path.parts and path.as_posix() == name and
             type(value) is str and re.fullmatch(r"[0-9A-F]{64}", value) is not None,
             "Unsafe/malformed pilot artifact identity")
    need(artifacts.get("ResultsSha256") == digest(origin.read_bytes()) ==
         artifacts["Artifacts"].get(origin.name), "Pilot receipt/manifest identity")
    rows = receipt.get("Rows")
    need(type(rows) is list and len(rows) == 4, "Exactly four positive pilot images required")
    for row, (consumer, lazy, name) in zip(rows, IMAGE_KEYS):
        need(type(row) is dict and type(row.get("Consumer")) is str and row["Consumer"] == consumer and
             type(row.get("Lazy")) is bool and row["Lazy"] is lazy and row.get("Name") == name and
             row.get("Model") is False and "Mutation" in row and row["Mutation"] is None and
             type(row.get("Case")) is int and row["Case"] == 0 and row.get("Optimization") == "O2" and
             row.get("LTO") is False and row.get("Archive") is False and row.get("Executed") is True and
             row.get("Status") == "PASS" and type(row.get("Elf")) is str and
             type(row.get("ElfSha256")) is str and re.fullmatch(r"[0-9A-F]{64}", row["ElfSha256"]) is not None,
             "Wrong/missing positive pilot key: " + name)
        expected = origin.parent / name / "runtime.elf"
        actual = regular(expected)
        need(row["Elf"] == str(actual) and actual == expected and
             artifacts["Artifacts"].get(name + "/runtime.elf") == row["ElfSha256"] == digest(actual.read_bytes()),
             "Pilot positive ELF/path/manifest mismatch: " + name)
    return rows


def capture(args):
    repo = Path(args.repo).resolve(strict=True)
    need(HERE == repo / RELATIVE, "Runner must belong to the selected source tree")
    origin = regular(Path(args.pilot_receipt))
    root = Path(args.build_root).resolve()
    need(not root.exists() and not root.is_relative_to(repo) and
         not root.is_relative_to(origin.parent.parent), "Use a fresh root outside sources and qualified pilot artifacts")
    root.mkdir(parents=True)
    args.output_root = str(root)
    save(root / "bootstrap-result.json", dict(Verdict="FAIL", Stage="CAPTURE", CompilerInvocations=0))
    target = root / "source"
    artifact_origin = regular(origin.parent / "artifacts.json")
    capture_origin = regular(origin.parent.parent / "capture.json")
    originals = dict(Repository=str(repo), PilotReceipt=str(origin),
                     PilotArtifacts=str(artifact_origin), PilotCapture=str(capture_origin))
    names = {"tools/test_classic_cm4_mpu_lazy_observer.ps1", BASIC + "/engine.py",
             "tools/fixtures/classic_cm4_mpu_context_runtime/run.py",
             "tools/fixtures/classic_fp_context_runtime/run.py",
             "tools/fixtures/classic_context_runtime/run.py",
             "tools/fixtures/classic_context_runtime/qemu.sh",
             FP_PILOT + "/check_fp.py", FP_PILOT + "/contracts.py", FP_PILOT + "/check_receipt.ps1"}
    for directory, directories, filenames in os.walk(HERE, followlinks=False):
        for name in directories:
            path = Path(directory) / name
            need(not path.is_symlink() and not
                 (getattr(path.stat(follow_symlinks=False), "st_file_attributes", 0) & 0x400),
                 "Reparse observer source directory")
        directories[:] = [name for name in directories if name != "__pycache__"]
        for name in filenames:
            path = Path(directory) / name
            if path.suffix in (".py", ".md", ".sh"):
                names.add(path.relative_to(repo).as_posix())
    need(all(RELATIVE + "/" + name in names for name in ("run.py", "image.py", "contracts.py", "suite.py")),
         "Missing observer module source")
    records = []

    def copy(source, destination, role, expected=None):
        source = regular(source)
        data = source.read_bytes()
        value = digest(data)
        need(expected is None or value == expected, "Input hash mismatch: " + str(source))
        destination.parent.mkdir(parents=True, exist_ok=True)
        need(not destination.exists(), "Duplicate captured path")
        destination.write_bytes(data)
        need(digest(source.read_bytes()) == digest(destination.read_bytes()) == value, "Capture-time drift")
        records.append(dict(Original=str(source), Captured=str(destination.resolve()), Sha256=value, Role=role))

    for name in sorted(names):
        source = repo / name
        need(source.resolve(strict=True) == source, "Selected source must not alias a different path")
        copy(source, target / name, "SelectedRepositorySource")
    copied_receipt = root / "inputs/pilot-receipt.json"
    copy(origin, copied_receipt, "PilotReceipt")
    copy(artifact_origin, root / "inputs/pilot-artifacts.json", "PilotArtifacts")
    copy(capture_origin, root / "inputs/pilot-capture.json", "PilotCapture")
    receipt = read_json(copied_receipt)
    artifacts = read_json(root / "inputs/pilot-artifacts.json")
    identity = receipt.get("SourceIdentity") if type(receipt) is dict else None
    need(type(identity) is dict and identity.get("Manifest") == str(capture_origin) and
         identity.get("ManifestSha256") == digest((root / "inputs/pilot-capture.json").read_bytes()),
         "Pilot capture manifest/receipt identity")
    for row in image_rows(receipt, artifacts, origin):
        copy(Path(row["Elf"]), root / "images" / row["Name"] / "runtime.elf", "PilotElf", row["ElfSha256"])
    need(not any(name == "elftools" or name.startswith("elftools.") for name in sys.modules),
         "ELF package loaded before capture")
    package = importlib.metadata.distribution("pyelftools")
    need(package.version == "0.33" and package.files, "Existing pyelftools 0.33 required")
    python_copy = root / "python"
    selected = []
    for item in package.files:
        name = Path(str(item))
        need(not name.is_absolute() and ".." not in name.parts and name.parts, "Unsafe package path")
        if ((name.parts[0] == "elftools" and name.suffix == ".py") or
                (name.parts[0].endswith(".dist-info") and name.name in ("METADATA", "WHEEL", "RECORD"))):
            copy(Path(package.locate_file(item)), python_copy / name, "PythonPackage")
            selected.append(name.as_posix())
    need("elftools/__init__.py" in selected and "elftools/elf/elffile.py" in selected, "Incomplete ELF package")
    manifest = root / "capture.json"
    save(manifest, dict(SchemaVersion=1, Originals=originals, Files=records,
        Attribution="Fresh observer/helper and supplied pilot byte capture; no C compilation or new reference qualification"))
    inputs = []
    for row in records:
        for field, prefix in (("Original", "Original:"), ("Captured", "Captured:")):
            inputs.append(dict(Path=row[field], Sha256=row["Sha256"], Role=prefix + row["Role"]))
    inputs.append(dict(Path=str(manifest), Sha256=digest(manifest.read_bytes()), Role="CaptureManifest"))
    gcc = regular(Path(args.gcc))
    if os.name == "nt":
        buffer = ctypes.create_unicode_buffer(32768)
        need(0 < ctypes.windll.kernel32.GetModuleFileNameW(None, buffer, len(buffer)) < len(buffer),
             "Cannot identify Python executable")
        python = Path(buffer.value)
    else:
        python = Path(sys.executable)
    for path, role in ((gcc, "ArmToolchainLocatorNotExecuted"),
                       (regular(gcc.parent / "arm-none-eabi-objdump.exe"), "NativeInspectionTool"),
                       (regular(gcc.parent / "arm-none-eabi-readelf.exe"), "NativeInspectionTool"),
                       (regular(python), "Python")):
        inputs.append(dict(Path=str(path), Sha256=digest(path.read_bytes()), Role=role))
    need(len({row["Path"].casefold() for row in inputs}) == len(inputs), "Duplicate opening input identity")
    inputs_manifest = root / "inputs.before.json"
    save(inputs_manifest, inputs)
    args.repo, args.gcc = str(target), str(gcc)
    args.build_root, args.capture_manifest = str(root / "evidence"), str(manifest)
    args.pilot_receipt, args.pilot_origin = str(copied_receipt), str(origin)
    args.inputs_manifest = str(inputs_manifest)
    for row in inputs:
        need(digest(Path(row["Path"]).read_bytes()) == row["Sha256"], "Pre-import input drift")
    sys.path.insert(0, str(python_copy))
    return target, records


def load(name, path, records):
    need(name not in sys.modules, "Preloaded local module: " + name)
    canonical = str(path.resolve(strict=True))
    record = next((row for row in records if row["Captured"] == canonical), None)
    need(record is not None, "Uncaptured local module: " + str(path))
    data = path.read_bytes()
    need(digest(data) == record["Sha256"], "Local module changed before import")
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    exec(compile(data, str(path), "exec"), module.__dict__)
    return module


def main():
    parser = argparse.ArgumentParser(allow_abbrev=False)
    for key in ("repo", "gcc", "pilot-receipt", "build-root", "qemu-root"):
        parser.add_argument("--" + key, required=True)
    parser.add_argument("--wsl-distro", default="Ubuntu-24.04")
    args = parser.parse_args()
    need(__debug__ and not sys.flags.optimize, "Disable Python optimization")
    need(args.qemu_root.startswith("/") and args.wsl_distro and
         not any(c in args.qemu_root + args.wsl_distro for c in "\r\n\0"),
         "Explicit existing QEMU prefix/distro required; never provisions")
    suite = None
    try:
        root, records = capture(args)
        for name, relative in (("cm4_mpu_basic_engine", BASIC + "/engine.py"),
                               ("cm4_mpu_fp_checks", FP_PILOT + "/check_fp.py"),
                               ("cm4_mpu_fp_contracts", FP_PILOT + "/contracts.py"),
                               ("cm4_mpu_lazy_image", RELATIVE + "/image.py"),
                               ("cm4_mpu_lazy_contracts", RELATIVE + "/contracts.py")):
            load(name, root / relative, records)
        module = load("cm4_mpu_lazy_suite", root / RELATIVE / "suite.py", records)
        suite = module.LazyObserver(args)
        error = None
        try:
            suite.run()
        except Exception as failure:
            error = type(failure).__name__ + ": " + str(failure)
        need(suite.finish(error), "Preserve failed lazy observer: " + str(suite.build))
        save(Path(args.output_root) / "bootstrap-result.json", dict(Verdict="PASS", Stage="SUITE_FINISHED",
             SuiteVerdict=suite.report["Verdict"], CompilerInvocations=0))
        print(suite.report["Verdict"] + " " + str(suite.build), flush=True)
    except Exception as failure:
        if hasattr(args, "output_root"):
            save(Path(args.output_root) / "bootstrap-result.json", dict(Verdict="FAIL", Stage="BOOTSTRAP_OR_SUITE",
                 Error=type(failure).__name__ + ": " + str(failure), CompilerInvocations=0))
        raise


if __name__ == "__main__":
    main()
