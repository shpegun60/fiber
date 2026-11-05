"""Seven guarded real-CLI admission refusals; no positive, parser or tool run."""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import traceback
import uuid

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
WITNESS = HERE / "witness.py"
EXPECTED_CASES = 7
TIMEOUT_SECONDS = 300
PROTECTED = frozenset(("cm33f_secure_transfer_reference", "m55_secure_closed_parity",
    "test_cm33f_secure_transfer_reference.ps1", "test_m55_secure_closed_parity.ps1"))
SOURCE_PATHS = (Path(__file__).resolve(), WITNESS,
    HERE.with_name("cm3_lto_transport") / "probe.py",
    HERE.with_name("cm3_lto_link_contract") / "witness.py",
    HERE.with_name("cm3_lto_roots") / "witness.py")
GUARD = r'''import hashlib
import os
from pathlib import Path
import sys

sys.dont_write_bytecode = True
source_path, expected, arguments = sys.argv[1], sys.argv[2], sys.argv[3:]
forbidden = {"cm33f_secure_transfer_reference", "m55_secure_closed_parity",
    "test_cm33f_secure_transfer_reference.ps1", "test_m55_secure_closed_parity.ps1"}
write_flags = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND
mutations = {"os.mkdir", "os.remove", "os.rmdir", "os.rename", "os.link", "os.symlink",
    "os.truncate", "os.chmod", "os.chown", "os.utime", "shutil.copyfile"}

def guard(event, values):
    if event == "open":
        target, mode, flags = values
        if isinstance(target, (str, bytes, os.PathLike)):
            parts = os.fsdecode(target).replace("\\", "/").casefold().split("/")
            if forbidden.intersection(parts):
                raise RuntimeError("TEST-GUARD: protected input")
        if (isinstance(mode, str) and any(c in mode for c in "wax+")) or (isinstance(flags, int) and flags & write_flags):
            raise RuntimeError("TEST-GUARD: filesystem write")
    if event in mutations:
        raise RuntimeError("TEST-GUARD: filesystem mutation")
    if event == "subprocess.Popen" or event == "os.system" or event.startswith(("os.exec", "os.spawn")):
        raise RuntimeError("TEST-GUARD: descendant or tool process")
    if event == "import" and (values[0] == "elftools" or values[0].startswith("elftools.")):
        raise RuntimeError("TEST-GUARD: qualified parser import")
    if event == "exec":
        filename = values[0].co_filename.replace("\\", "/").casefold()
        if "/elftools/" in filename:
            raise RuntimeError("TEST-GUARD: qualified parser execution")

sys.addaudithook(guard)
data = Path(source_path).read_bytes()
if hashlib.sha256(data).hexdigest().upper() != expected:
    raise RuntimeError("TEST-GUARD: witness source hash")
sys.argv = [source_path, *arguments]
namespace = {"__name__": "__main__", "__file__": source_path,
    "__package__": None, "__spec__": None, "__cached__": None}
exec(compile(data, source_path, "exec"), namespace)
'''


def sha(data):
    return hashlib.sha256(data).hexdigest().upper()


def need(condition, message):
    if not condition:
        raise ValueError("cm3-override-refusal-controls: " + message)


def digest(value):
    need(type(value) is str and re.fullmatch(r"[A-F0-9]{64}", value) is not None, "uppercase SHA256 required")
    return value


def stable(path):
    path = Path(os.path.abspath(os.fspath(path)))
    need(not PROTECTED.intersection(part.casefold() for part in path.parts), "protected input/output")
    for ancestor in (path, *path.parents):
        if ancestor.exists() or ancestor.is_symlink():
            stat = ancestor.lstat()
            need(not ancestor.is_symlink() and not getattr(stat, "st_file_attributes", 0) & 0x400,
                 "symlink/reparse path")
    return path


def interpreter_path():
    if os.name != "nt":
        return stable(sys.executable)
    buffer = ctypes.create_unicode_buffer(32768)
    get_module_filename = ctypes.WinDLL("kernel32", use_last_error=True).GetModuleFileNameW
    get_module_filename.argtypes = (ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_uint32)
    get_module_filename.restype = ctypes.c_uint32
    length = get_module_filename(None, buffer, len(buffer))
    need(0 < length < len(buffer), "actual loaded Python executable path")
    return stable(buffer.value)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def read_bound(path, hashes, expected=None):
    path = stable(path)
    need(path.is_file(), "regular input required: " + str(path))
    data = path.read_bytes()
    value = sha(data)
    need(expected is None or value == digest(expected), "runner input hash mismatch: " + str(path))
    need(path not in hashes or hashes[path] == value, "runner input changed: " + str(path))
    hashes[path] = value
    return data


def structured(path, hashes, expected):
    result = json.loads(read_bound(path, hashes, expected), object_pairs_hook=unique_object)
    need(type(result) is dict, "JSON object required")
    return result


def snapshot(path):
    path = stable(path)
    if not path.exists():
        return None
    need(path.is_dir(), "expected output-directory role")
    result = {}
    for directory, names, files in os.walk(path):
        for name in names:
            stable(Path(directory) / name)
        for name in files:
            item = stable(Path(directory) / name)
            need(item.is_file(), "nonregular existing-output file")
            result[item.relative_to(path).as_posix()] = sha(item.read_bytes())
    return result


def changed_digest(value):
    return ("0" if value[0] != "0" else "1") + value[1:]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--controls-build", type=Path, required=True)
    parser.add_argument("--controls-receipt-sha256", required=True)
    parser.add_argument("--controls-artifacts-sha256", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    need(not sys.flags.optimize and __debug__, "unoptimized interpreter required")
    output, temporary = stable(args.output_dir), stable(tempfile.gettempdir())
    need(not output.exists() and output.is_relative_to(temporary) and not output.is_relative_to(REPO)
         and not REPO.is_relative_to(output), "fresh external TEMP output directory required")
    hashes = {}
    source_hashes = {str(item): sha(read_bound(item, hashes)) for item in SOURCE_PATHS}
    interpreter = interpreter_path()
    read_bound(interpreter, hashes)
    controls = stable(args.controls_build)
    receipt_hash, manifest_hash = digest(args.controls_receipt_sha256), digest(args.controls_artifacts_sha256)
    capture = structured(controls / "results.json", hashes, receipt_hash)
    artifacts = structured(controls / "artifacts.json", hashes, manifest_hash)
    need(type(artifacts.get("Artifacts")) is dict and artifacts["Artifacts"].get("results.json") == receipt_hash,
         "caller-bound controls receipt/manifest")
    need(capture.get("Status") == "CM3-LTO-FRESH-LINK-CAPTURE-PASS-NOT-QUALIFIED",
         "successful fresh-link capture required")
    base = stable(capture["CaptureBuild"])
    base_receipt = structured(base / "results.json", hashes, digest(capture["CaptureReceiptSha256"]))
    base_manifest = structured(base / "artifacts.json", hashes, digest(capture["CaptureArtifactsSha256"]))
    need(type(base_manifest.get("Artifacts")) is dict
         and base_manifest["Artifacts"].get("results.json") == capture["CaptureReceiptSha256"],
         "caller-bound base receipt/manifest")
    seed = stable(base_receipt["SeedBuild"])
    need(all(root.is_dir() for root in (controls, base, seed)), "existing controls/base/seed roots")
    denied = (REPO, controls, base, seed, *(item.parent for item in hashes))
    need(all(not output.is_relative_to(root) and not root.is_relative_to(output) for root in denied),
         "runner output must not overlap admitted inputs")
    token = "__cm3_override_refusal_" + uuid.uuid4().hex
    targets = {name: root / token for name, root in (("repo", REPO), ("controls", controls), ("base", base), ("seed", seed))}
    need(all(not stable(target).exists() for target in targets.values()), "unused overlap-test output paths")
    output.mkdir(parents=True, exist_ok=False)
    existing = output / "existing-output"
    existing.mkdir()
    (existing / "untouched.txt").write_bytes(b"existing output must remain unchanged\n")
    (output / "child_guard.py").write_text(GUARD, encoding="ascii")
    report = dict(Status="FAIL", Scope="CM3_LTO_OVERRIDE_GUARDED_REAL_CLI_ADMISSION_REFUSALS_ONLY",
        ExpectedCases=EXPECTED_CASES, Tests=0, Passed=0, Failures=0, Errors=0, Cases=[],
        SourceHashes=source_hashes, SourceDrift=[], InputDrift=[], SourceClosureVerified=False,
        InputClosureVerified=False, ClosingFilesVerified=0, PythonCommandsExecuted=0,
        NativeCommandsExecuted=0, ToolInvocations=0, NoOutputCreated=False, ExistingOutputUnchanged=False,
        ChildGuardSha256=sha(GUARD.encode("ascii")), Interpreter=str(interpreter),
        ControlsBuild=str(controls), ControlsReceiptSha256=receipt_hash, ControlsArtifactsSha256=manifest_hash,
        PositiveReplay=False, SyntheticInputs=False, ActualELFTested=False, ActualMachineDecoderTested=False,
        ActualWitnessAdmissionTested=False, CapturedSourcesSemanticMutationTested=False,
        CommandRecordMutationTested=False, Qualification=False, FullABIProof=False, SourceIRProof=False,
        SourceToMachineSemanticProof=False, OriginalTranslationUnitOwnership=False, CanonicalProtocolValidated=False,
        FinalReferenceParity=False, InstructionEquivalence=False, PolicyEquivalence=False, CompleteObjectProof=False,
        KernelRuntimeProof=False, CpuExecution=False, BoardExecution=False, GlobalFreezeQualified=False,
        RequiredCellSatisfied=False, RequiredCellsSatisfied=0)
    root_diagnostic = "ValueError: cm3-lto-root-witness: fresh output outside all authenticated input roots"
    controls_diagnostic = "ValueError: cm3-lto-override-witness: fresh output outside all newly admitted input roots"
    cases = [
        ("wrong-receipt", output / "wrong-receipt-output", changed_digest(receipt_hash), manifest_hash,
         {"ValueError: cm3-lto-probe: input hash mismatch: " + str(controls / "results.json")}),
        ("wrong-manifest", output / "wrong-manifest-output", receipt_hash, changed_digest(manifest_hash),
         {"ValueError: cm3-lto-probe: input hash mismatch: " + str(controls / "artifacts.json")}),
        ("repo-overlap", targets["repo"], receipt_hash, manifest_hash, {root_diagnostic}),
        ("controls-overlap", targets["controls"], receipt_hash, manifest_hash, {root_diagnostic, controls_diagnostic}),
        ("base-overlap", targets["base"], receipt_hash, manifest_hash, {root_diagnostic}),
        ("seed-overlap", targets["seed"], receipt_hash, manifest_hash, {root_diagnostic}),
        ("existing-output", existing, receipt_hash, manifest_hash, {root_diagnostic}),
    ]
    try:
        need(len(cases) == EXPECTED_CASES, "exact seven refusal cases")
        for index, (name, target, supplied_receipt, supplied_manifest, expected) in enumerate(cases):
            before = snapshot(target)
            if name != "existing-output":
                need(before is None, "negative output must be absent before command")
            arguments = ["--controls-build", str(controls), "--controls-receipt-sha256", supplied_receipt,
                "--controls-artifacts-sha256", supplied_manifest, "--output-dir", str(target)]
            command = [str(interpreter), "-I", "-B", "-c", GUARD, str(WITNESS), source_hashes[str(WITNESS)], *arguments]
            record = dict(Name=name, Status="FAIL", Argv=command, Cwd=str(output), Exit=None,
                TimedOut=False, ExpectedDiagnostics=sorted(expected), Output=str(target), Error=None)
            stdout, stderr = b"", b""
            report["PythonCommandsExecuted"] += 1
            try:
                completed = subprocess.run(command, cwd=output, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    stdin=subprocess.DEVNULL, timeout=TIMEOUT_SECONDS, check=False)
                record["Exit"] = completed.returncode
                stdout, stderr = completed.stdout, completed.stderr
            except subprocess.TimeoutExpired as error:
                record.update(TimedOut=True, Error="TimeoutExpired")
                stdout, stderr = error.stdout or b"", error.stderr or b""
            except OSError as error:
                record["Error"] = type(error).__name__ + ": " + str(error)
            stdout_path, stderr_path = output / ("case-%02d.stdout" % index), output / ("case-%02d.stderr" % index)
            stdout_path.write_bytes(stdout)
            stderr_path.write_bytes(stderr)
            record.update(Stdout=str(stdout_path), Stderr=str(stderr_path), StdoutSha256=sha(stdout), StderrSha256=sha(stderr))
            lines = stderr.decode("utf-8", "replace").splitlines()
            diagnostic = next((line for line in reversed(lines) if line.strip()), "")
            after = snapshot(target)
            unchanged = before == after
            record.update(ActualDiagnostic=diagnostic, NoUnexpectedOutput=unchanged,
                GuardTriggered=b"TEST-GUARD:" in stderr or b"TEST-GUARD:" in stdout)
            if (record["Exit"] == 1 and not record["TimedOut"] and record["Error"] is None
                    and diagnostic in expected and not stdout and unchanged and not record["GuardTriggered"]):
                record["Status"] = "PASS"
            report["Cases"].append(record)
            report["Tests"] += 1
            report["Passed"] += int(record["Status"] == "PASS")
            report["Failures"] += int(record["Status"] != "PASS")
            (output / ("case-%02d.json" % index)).write_text(json.dumps(record, sort_keys=True, indent=2) + "\n", encoding="ascii")
        report["NoOutputCreated"] = all(case["NoUnexpectedOutput"] for case in report["Cases"] if case["Name"] != "existing-output")
        report["ExistingOutputUnchanged"] = report["Cases"][-1]["NoUnexpectedOutput"]
        report["ActualWitnessAdmissionTested"] = report["Tests"] == EXPECTED_CASES
        if report["Passed"] == EXPECTED_CASES and report["Tests"] == EXPECTED_CASES:
            report["Status"] = "PASS"
    except Exception:
        report.update(Status="FAIL", Error=traceback.format_exc(), Errors=report["Errors"] + 1)
    finally:
        for item, expected in hashes.items():
            try:
                matches = sha(stable(item).read_bytes()) == expected
            except OSError:
                matches = False
            if matches:
                report["ClosingFilesVerified"] += 1
            else:
                report["InputDrift"].append(str(item))
                if str(item) in source_hashes:
                    report["SourceDrift"].append(str(item))
        report["InputHashes"] = {str(item): value for item, value in hashes.items()}
        report["InputClosureVerified"] = not report["InputDrift"]
        report["SourceClosureVerified"] = len(source_hashes) == len(SOURCE_PATHS) and not report["SourceDrift"]
        if not report["InputClosureVerified"] or not report["SourceClosureVerified"]:
            report["Status"] = "FAIL"
    target = output / "results.json"
    target.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="ascii")
    print("Receipt:", target, sha(target.read_bytes()))
    return 0 if report["Status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
