"""Bounded read-only observations of four already-qualified immutable ELFs."""
from __future__ import annotations

import ctypes
import json
import os
from pathlib import Path
import re
import sys

from cm4_mpu_basic_engine import common, fp, need, save, digest, load
import cm4_mpu_fp_contracts as pilot_contracts
import cm4_mpu_lazy_contracts as contracts
import cm4_mpu_lazy_image as image_plan

HERE = Path(__file__).resolve().parent
QEMU_FILES = ("qemu-version.txt", "qemu-machines.txt", "qemu-cpus.txt", "qemu-ldd.txt",
              "qemu-sha256.txt", "qemu-libraries-sha256.txt", "wsl-tools-sha256.txt",
              "wsl-user.txt", "wsl-system.txt", "wsl-os-release.txt", "deb-sha256.txt",
              "deb-versions.txt", "qemu-root.txt")
KEYS = (("context", False, "context-eager"), ("context", True, "context-lazy"),
        ("fiber", False, "fiber-eager"), ("fiber", True, "fiber-lazy"))


def read_json(path):
    def pairs(items):
        result, names = {}, set()
        for name, value in items:
            need(name.casefold() not in names, "Duplicate/case-aliased JSON property: " + name)
            names.add(name.casefold())
            result[name] = value
        return result
    return json.loads(Path(path).read_text(encoding="utf-8-sig"), object_pairs_hook=pairs)


def regular(path):
    path = Path(path)
    need(path.is_file() and not path.is_symlink() and
         not getattr(path.stat(follow_symlinks=False), "st_file_attributes", 0) & 0x400,
         "Missing/reparse input: " + str(path))
    return path.resolve(strict=True)


def inventory(root):
    root = Path(root).resolve(strict=True)
    result = {}
    for directory, directories, files in os.walk(root, followlinks=False):
        for name in directories:
            path = Path(directory) / name
            need(not path.is_symlink() and not
                 getattr(path.stat(follow_symlinks=False), "st_file_attributes", 0) & 0x400,
                 "Reparse artifact directory")
        for name in files:
            path = regular(Path(directory) / name)
            result[path.relative_to(root).as_posix()] = digest(path)
    return result


class LazyObserver:
    command = common.Suite.command
    wsl_path = common.Suite.wsl_path

    def __init__(self, args):
        self.a = args
        self.repo = Path(args.repo).resolve(strict=True)
        self.build = Path(args.build_root).resolve()
        need(not self.build.exists(), "Fresh observer evidence directory required")
        self.build.mkdir(parents=True)
        self.commands, self.rows = [], []
        self.inputs = {}
        self.qemu_before = None
        self.origin = regular(args.pilot_origin)
        self.old_root = self.origin.parent
        self.old_inventory = None
        self.report = dict(SchemaVersion=1, Verdict="FAIL", Error=None, CompleteSuite=False,
            RequestedInventoryComplete=False, Execution="NOT_RUN", Rows=self.rows, Commands=self.commands,
            Repository=str(self.repo), BuildRoot=str(self.build), CaptureManifest=args.capture_manifest,
            PilotReceipt=dict(Path=str(self.origin), Sha256=digest(self.origin)),
            Scope="Four immutable CM4/AN386 MPU8 O2/native/direct pilot ELFs; bounded FP-copy interval only",
            NoCompilation=True, CompilerInvocations=0, TargetElfModified=False,
            ReferenceExecuted=False, NewFinalReferenceParity=False, HardwareValidated=False,
            PreSaveLspactObserved=False, ArtifactsVerifiedBeforePass=False)
        save(self.build / "results.json", self.report)

    def enroll(self, path, role, expected=None):
        path = regular(path)
        value = digest(path)
        need(expected is None or value == expected, "Input hash mismatch: " + str(path))
        key = str(path)
        if key in self.inputs:
            need(self.inputs[key]["Sha256"] == value, "Input enrollment drift")
        else:
            need(not any(k.casefold() == key.casefold() for k in self.inputs), "Case-aliased input")
            self.inputs[key] = dict(Path=key, Sha256=value, Role=role)

    def inspect(self, name):
        directory = self.build / name
        directory.mkdir()
        self.command(["wsl.exe", "-d", self.a.wsl_distro, "--", "bash",
            self.wsl_path(self.repo / "tools/fixtures/classic_context_runtime/qemu.sh"),
            "inspect", self.a.qemu_root, self.wsl_path(directory)], "existing QEMU identity", timeout=45)
        result = {}
        for name in QEMU_FILES:
            path = regular(directory / name)
            need(path.stat().st_size, "Empty QEMU identity file")
            if name != "qemu-ldd.txt":
                result[name] = digest(path)
        need(re.search(r"(?m)^mps2-an386\s", (directory / "qemu-machines.txt").read_text()),
             "QEMU lacks qualified AN386")
        return result

    def admit_pilot(self):
        capture = read_json(self.a.capture_manifest)
        need(type(capture) is dict and type(capture.get("Files")) is list, "Capture grammar")
        self.capture = capture
        for row in read_json(self.a.inputs_manifest):
            self.enroll(row["Path"], row["Role"], row["Sha256"])
        self.enroll(self.a.inputs_manifest, "BootstrapOpeningManifest")
        for row in capture["Files"]:
            for field in ("Original", "Captured"):
                self.enroll(row[field], field + ":" + row["Role"], row["Sha256"])
        supplied = read_json(self.a.pilot_receipt)
        need(supplied == read_json(self.origin), "Supplied receipt changed during capture")
        pilot_contracts.validate(supplied, True)
        old_manifest = read_json(self.old_root / "artifacts.json")
        actual = inventory(self.old_root)
        need(type(old_manifest.get("Artifacts")) is dict and
             old_manifest.get("ResultsSha256") == digest(self.origin) and
             {k: v for k, v in actual.items() if k != "artifacts.json"} == old_manifest["Artifacts"],
             "Pilot artifact bytes or inventory differ from supplied receipt")
        self.old_inventory = actual
        for name, value in actual.items():
            self.enroll(self.old_root / name, "SuppliedPilotArtifact", value)
        self.enroll(self.old_root.parent / "capture.json", "SuppliedPilotCapture")
        for row, (consumer, lazy, name) in zip(supplied["Rows"], KEYS):
            need((row["Consumer"], row["Lazy"], row["Name"]) == (consumer, lazy, name), "Ordered pilot keys")
        self.pilot = supplied
        self.report["AdmittedPilot"] = dict(PositiveImages=4, OriginalReceiptSha256=digest(self.origin),
            ArtifactsSha256=digest(self.old_root / "artifacts.json"), Artifacts=len(actual) - 1,
            PriorProofOnly=True, NewReferenceExecution=False)

    def preflight(self):
        self.admit_pilot()
        from elftools.elf.elffile import ELFFile
        self.ELFFile = ELFFile
        observer = load("cm4_mpu_lazy_producer_controls", HERE / "observer.py")
        self.report["ProducerCompatibilityControls"] = contracts.producer_controls(observer)
        self.report["TransportControls"] = observer.self_controls()
        self.tools = {name: regular(Path(self.a.gcc).parent / ("arm-none-eabi-" + name + ".exe"))
                      for name in ("objdump", "readelf")}
        self.tools["powershell"] = regular(Path(os.environ["SystemRoot"]) /
            "System32/WindowsPowerShell/v1.0/powershell.exe")
        for path in self.tools.values():
            self.enroll(path, "ActualHostInspectionTool")
        for path in Path(self.a.gcc).parent.glob("*.dll"):
            self.enroll(path, "NativeInspectionLibrary")
        buffer = ctypes.create_unicode_buffer(32768)
        need(0 < ctypes.windll.kernel32.GetModuleFileNameW(None, buffer, len(buffer)) < len(buffer),
             "Cannot identify actual host Python executable")
        self.enroll(buffer.value, "ActualHostPythonExecutable")
        for module in tuple(sys.modules.values()):
            for field in ("__file__", "__cached__"):
                path = getattr(module, field, None)
                if path and Path(path).is_file():
                    self.enroll(path, "LoadedHostPythonModule")
        for name in ("objdump", "readelf"):
            self.command([self.tools[name], "--version"], "inspection tool identity")
        checker = self.repo / "tools/fixtures/classic_cm4_mpu_fp_pilot/check_receipt.ps1"
        driver = self.build / "admit-pilot.ps1"
        driver.write_text("""param([string]$Receipt,[string]$Checker,[string]$Root)
$ErrorActionPreference='Stop'
Set-StrictMode -Version 2.0
. $Checker
$parsed=Get-Content -LiteralPath $Receipt -Raw | ConvertFrom-Json
Assert-Cm4MpuFpPilotEvidence -Receipt $parsed -Execute $true -BuildRoot $Root
Write-Output 'SUPPLIED_PILOT_EVIDENCE_PASS'
""", encoding="ascii")
        self.enroll(driver, "GeneratedAdmissionDriver")
        self.command([self.tools["powershell"], "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", driver,
            "-Receipt", self.origin, "-Checker", checker, "-Root", self.old_root],
            "independent captured pilot evidence admission", timeout=90)
        self.report["ContractControls"] = contracts.control_tests()
        self.qemu_before = self.inspect("qemu-before")
        expected = {name: digest(self.old_root / "qemu-before" / name) for name in self.qemu_before}
        need(self.qemu_before == expected, "Observer QEMU differs from supplied qualified pilot cohort")
        self.report["QemuIdentityMatchesPilot"] = True
        self.report["QemuIdentity"] = self.qemu_before
        save(self.build / "inputs.before.json", list(self.inputs.values()))

    def observe(self, original):
        matches = [r for r in self.capture["Files"] if r["Role"] == "PilotElf" and r["Original"] == original["Elf"]]
        need(len(matches) == 1, "Exactly one captured pilot ELF")
        captured = regular(matches[0]["Captured"])
        need(digest(captured) == original["ElfSha256"], "Captured ELF identity")
        directory = self.build / original["Name"]
        directory.mkdir()
        for tool, flags, suffix in (("objdump", ("-d",), ".dis"),
                                     ("readelf", ("-h", "-A", "-S", "-W"), ".readelf.txt")):
            value = self.command([self.tools[tool], *flags, captured], "inspect immutable " + original["Name"])
            captured.with_suffix(suffix).write_text(value["Stdout"], encoding="ascii")
            self.enroll(captured.with_suffix(suffix), "GeneratedElfInspection")
        row = dict(original, Elf=str(captured))
        image = fp.Image(captured, self.ELFFile)
        planner_controls = image_plan.control_tests(image, row)
        plan = image_plan.plan(image, row)
        save(directory / "static-plan.json", plan)
        manifest = {key: plan[key] for key in ("ElfSha256", "Consumer", "Lazy", "Pre", "Post",
                    "CurrentSlot", "Workers", "Stacks", "ReturnPC")}
        manifest.update(SchemaVersion=1, Elf=self.wsl_path(captured))
        manifest_path = directory / "manifest.json"
        save(manifest_path, manifest)
        self.enroll(manifest_path, "ReadonlyObserverPlan")
        out = directory / "observation"
        actual = self.command(["wsl.exe", "-d", self.a.wsl_distro, "--", "/usr/bin/python3", "-B",
            self.wsl_path(HERE / "observer.py"), "--manifest", self.wsl_path(manifest_path),
            "--qemu-root", self.a.qemu_root, "--output-dir", self.wsl_path(out), "--seconds", "45"],
            "read-only pre/post observer " + original["Name"], timeout=65, expected=None)
        trace_path = out / "trace.json"
        record = dict(Name=original["Name"], Consumer=original["Consumer"], Lazy=original["Lazy"],
            OriginalElf=original["Elf"], Elf=str(captured), ElfSha256=digest(captured),
            Plan=str(directory / "static-plan.json"), PlanSha256=digest(directory / "static-plan.json"),
            Manifest=str(manifest_path), ManifestSha256=digest(manifest_path),
            Trace=str(trace_path), Actual=actual, PlannerControls=planner_controls, Status="FAIL", Executed=False)
        self.rows.append(record)
        need(not actual["TimedOut"] and actual["Exit"] == 0, "Observer helper failed: " + original["Name"])
        trace = read_json(trace_path)
        for role, path in (("ObserverScript", HERE / "observer.py"), ("Manifest", manifest_path),
                           ("Elf", captured)):
            entries = [entry for entry in trace.get("InputsBefore", []) if entry.get("Role") == role]
            need(len(entries) == 1 and entries[0]["Path"] == self.wsl_path(path) and
                 entries[0]["Sha256"] == digest(path), "Actual Linux input binding: " + role)
        qemu = [entry for entry in trace.get("InputsBefore", []) if entry.get("Role") == "QemuExecutable"]
        expected_qemu = (self.build / "qemu-before/qemu-sha256.txt").read_text().split()[0].upper()
        need(len(qemu) == 1 and qemu[0]["Sha256"] == expected_qemu,
             "Actual observer QEMU binary differs from inspected qualified binary")
        observed = contracts.validate_trace(manifest, trace)
        need(tuple(observed[k] for k in ("Pairs", "Extended", "Basic", "PreSnapshots", "PostSnapshots")) ==
             (22, 15, 7, 22, 22), "Exact validated observation counts")
        record.update(TraceSha256=digest(trace_path), Observed=observed, Status="PASS", Executed=True)
        need(digest(captured) == original["ElfSha256"], "Observer changed target ELF")
        save(directory / "result.json", record)
        print("OBSERVED " + original["Name"], flush=True)

    def run(self):
        self.preflight()
        for row in self.pilot["Rows"]:
            self.observe(row)
        need(len(self.rows) == 4 and all(row["Status"] == "PASS" for row in self.rows), "Four successful observations")

    def finish(self, error):
        closing = []
        try:
            if self.qemu_before is not None:
                after = self.inspect("qemu-after")
                self.report["QemuDrift"] = [k for k in self.qemu_before if self.qemu_before[k] != after.get(k)]
                need(not self.report["QemuDrift"], "Closing QEMU identity drift")
            if self.old_inventory is not None:
                need(inventory(self.old_root) == self.old_inventory, "Supplied evidence changed during observation")
            for row in self.inputs.values():
                path = Path(row["Path"])
                closing.append(dict(row, Sha256=digest(regular(path)) if path.is_file() else None))
            drift = [row["Path"] for row in closing if row["Sha256"] != self.inputs[row["Path"]]["Sha256"]]
            self.report["InputDrift"] = drift
            need(not drift, "Closing observer input drift")
        except Exception as failure:
            error = error or type(failure).__name__ + ": " + str(failure)
        save(self.build / "inputs.after.json", closing)
        self.report["Error"] = error
        if error is None:
            need(len(self.rows) == 4 and all(row["Status"] == "PASS" for row in self.rows), "Incomplete observer inventory")
            counts = {key: sum(row["Observed"][field] for row in self.rows) for key, field in
                      (("PairedSaves", "Pairs"), ("ExtendedPairs", "Extended"), ("BasicPairs", "Basic"))}
            counts["Snapshots"] = sum(row["Observed"][field] for row in self.rows
                                      for field in ("PreSnapshots", "PostSnapshots"))
            need(counts == dict(PairedSaves=88, ExtendedPairs=60, BasicPairs=28, Snapshots=176),
                 "Aggregate exact observation inventory")
            self.report.update(Verdict="LAZY-OBSERVER-PASS", Execution="BOUNDED_LAZY_OBSERVER",
                RequestedInventoryComplete=True, PreSaveLspactObserved=True,
                Executions=len(self.rows), ArtifactsVerifiedBeforePass=True, **counts)
        try:
            save(self.build / "results.json", self.report)
            artifacts = inventory(self.build)
            artifacts.pop("artifacts.json", None)
            save(self.build / "artifacts.json", dict(ResultsSha256=digest(self.build / "results.json"), Artifacts=artifacts))
            need({k: v for k, v in inventory(self.build).items() if k != "artifacts.json"} == artifacts,
                 "Closing observer artifact inventory drift")
        except Exception as failure:
            error = error or type(failure).__name__ + ": " + str(failure)
            self.report.update(Verdict="FAIL", Error=error, RequestedInventoryComplete=False,
                               ArtifactsVerifiedBeforePass=False)
            save(self.build / "results.json", self.report)
            artifacts = inventory(self.build)
            artifacts.pop("artifacts.json", None)
            save(self.build / "artifacts.json", dict(ResultsSha256=digest(self.build / "results.json"), Artifacts=artifacts))
        return error is None
