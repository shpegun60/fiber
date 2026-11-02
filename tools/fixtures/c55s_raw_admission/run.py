"""Actual C55S raw admission, standard cohort TU and causal missing-operation proof."""
import sys

if not __debug__ or sys.flags.optimize:
    raise SystemExit("C55S raw admission requires ordinary Python without -O/-OO")
sys.dont_write_bytecode = True

import argparse
import csv
import difflib
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import traceback
from types import SimpleNamespace

PORT = Path("fiber/port/ARM_CM55/non_secure")
FIXTURE = Path("tools/fixtures/c55s_raw_admission")
SHARED = Path("tools/fixtures/sensitive_port_closure/run.py")
EXPECTED_SOURCES = sorted(("fiber_port.c", "fiber_port_boot.c", "fiber_port_secure_context.c",
                           "fiber_port_svc.c", "fiber_port_runtime.c", "fiber_port_pendsv.c"))
FORWARD = set("fiber_port_context_init fiber_port_runtime_memory_barrier fiber_port_panic_wait "
              "fiber_port_require_scheduler_configuration_environment fiber_port_runtime_prepare_start "
              "fiber_port_runtime_select_first fiber_port_runtime_start_first fiber_port_runtime_schedule".split())
MISSING = "fiber_port_runtime_schedule"
RENAMED = "fiber_c55s_missing_schedule_control"
DIAGNOSTIC = "Actual forward ABI functions missing"
LAYOUTS = ((False, "sectioned"), (True, "sectioned"), (True, "unsectioned"))


def require(value, message):
    if not value:
        raise RuntimeError(message)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest().upper()


def write(path, value):
    Path(path).write_text(json.dumps(value, indent=2) + "\n", encoding="ascii")


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def capture(args):
    repo, cmsis, build = (Path(p).resolve() for p in (args.repo, args.cmsis_core, args.build))
    root = build / "immutable-inputs"

    def inventory():
        files = {p for directory in (repo, repo / "fiber", repo / "fiber/port")
                 for p in directory.iterdir() if p.is_file() and p.suffix.lower() in (".c", ".h", ".inc")}
        reader = load(repo / "tools/runtime_sources.py", "c55s_snapshot_runtime_sources")
        files.update(reader.get_runtime_source_inputs(repo,
                     ("engine", "state", "panic", "optional_configuration", "legacy_compat", "facade_bridge")))
        files.update((repo / "context").glob("*.h"))
        files.update(p for p in (repo / "fiber/port/ARM_CM55").rglob("*")
                     if p.is_file() and p.suffix.lower() in (".c", ".h", ".ld"))
        for directory in (repo / FIXTURE, repo / SHARED.parent):
            files.update(p for p in directory.rglob("*")
                         if p.is_file() and p.suffix.lower() in (".c", ".h", ".py", ".md", ".ps1"))
        files.add(repo / "tools/test_sensitive_port_closure.ps1")
        files.update(p for p in cmsis.rglob("*") if p.is_file())
        return files

    files = inventory()
    before = {p: sha(p) for p in files}
    rows = []
    for path in sorted(files):
        target = (root / "cmsis" / path.relative_to(cmsis) if path.is_relative_to(cmsis)
                  else root / "repo" / path.relative_to(repo))
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(path.read_bytes())
        require(sha(target) == before[path], "Input changed during immutable capture: " + str(path))
        rows.append(dict(original=str(path), copy=str(target), sha256=before[path]))
    require(inventory() == files and all(sha(p) == value for p, value in before.items()),
            "Input inventory/bytes changed during immutable capture")
    manifest = root / "manifest.json"
    write(manifest, dict(files=rows, policy="Only captured bytes are proof inputs; copied but unconsumed files are not compiled claims"))
    command = list(map(str, (sys.executable, "-B", root / "repo" / FIXTURE / "run.py",
                            "--repo", root / "repo", "--arm-gcc", args.arm_gcc,
                            "--cmsis-core", root / "cmsis", "--build", build,
                            "--input-snapshot", manifest)))
    write(root / "child-command.json", command)
    print("Verified immutable C55S raw-admission inputs: " + str(root), flush=True)
    return subprocess.run(command).returncode


def options(args, build):
    return SimpleNamespace(**dict(vars(args), build=str(build), profiles="C55S", optimizations="O2,Os",
                                  bundles="baseline,raw", native_lto_sections="sectioned,unsectioned",
                                  all_profiles=False, audit_only=False, cm7_prefix_root=None, cm0_vtor="0"))


def native_state(module, directory):
    elf = module.Elf(directory / "port-native.o")
    elf.native()
    present = {f["name"] for f in elf.functions}
    report = module.inspect(elf.path, elf.path.with_suffix(".dis").read_text(encoding="ascii"))
    require(not report["defects"], "Missing-operation control has independent native classifier defects")
    require(FORWARD - present == {MISSING} and RENAMED in present,
            "Compiled mutation did not remove exactly the required schedule definition")
    return dict(Missing=sorted(FORWARD - present), Renamed=RENAMED, NativeSha256=sha(elf.path),
                Defects=report["defects"])


def cohort_state(module, directory):
    port = module.Elf(directory / "port-native.o")
    cohorts = [s["name"] for s in port.objects if s["name"].startswith("fiber_port_context_cohort_armv81m_mainline_")]
    require(len(cohorts) == 1, "Actual C55S port has no unique exact context cohort")
    rows = []
    for group in ("common", "whole"):
        elf = module.Elf(directory / (group + "-native.o"))
        objects = [s for s in elf.objects if s["name"] == "fiber_port_context_cohort_build_expectation"]
        require(len(objects) == 1 and objects[0]["size"] == 4,
                "Actual native group lost the four-byte build expectation: " + group)
        obj = objects[0]
        require(elf.sections[obj["section"]]["name"] == ".fiber_port_context_cohort_expectation",
                "Build expectation left its retained section")
        rels = [r for r in elf.relocations if r["section"] == obj["section"] and
                obj["value"] <= r["offset"] < obj["value"] + obj["size"]]
        require(len(rels) == 1 and rels[0]["type"] == 2 and
                rels[0]["offset"] == obj["value"] and elf.targets(rels[0]) == cohorts,
                "Build expectation does not retain exactly the actual C55S cohort")
        rows.append(dict(Group=group, Symbol=cohorts[0], Relocation=rels[0]["type"]))
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("repo", "arm-gcc", "cmsis-core", "build"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--input-snapshot", help=argparse.SUPPRESS)
    args = parser.parse_args()
    repo, build = Path(args.repo).resolve(), Path(args.build).resolve()
    build.mkdir(parents=True, exist_ok=True)
    if not args.input_snapshot:
        require(not any(build.iterdir()), "Use a fresh evidence directory")
        return capture(args)

    module = load(repo / SHARED, "c55s_current_raw_gate")
    profile = next(p for p in module.profiles() if p["name"] == "C55S")
    report = dict(Status="FAIL", CompleteSuite=False,
                  Scope="C55S native compiler admission only; staged RuntimeSelectable remains zero",
                  Limits=["No CPU, Secure gateway or board execution", "No global raw closure claim",
                          "Only primary scalar manifest and O2/Os; external memory/callback bodies remain outside this gate"])
    audits = []
    failure = None
    try:
        require(module.FORWARD == FORWARD, "Shared forward requirement is not the frozen eight-operation ABI")
        require(profile["sources"] == EXPECTED_SOURCES and profile["kind"] == "paired-staged",
                "Exact staged C55S source inventory/role changed")
        positive = module.Audit(options(args, build / "positive"))
        positive.build.mkdir()
        positive.planned_cells = 12
        audits.append(positive)
        positive.preflight()
        positive.track(Path(__file__))
        positive.track(Path(__file__).with_name("README.md"))
        port_sources, common_sources = positive.source_paths(profile)
        expectation = repo / "fiber/port/fiber_port_context_cohort_expectation.c"
        reader = load(repo / "tools/runtime_sources.py", "c55s_selected_runtime_sources")
        selected_common = list(reader.get_runtime_source_paths(repo,
                              ("engine", "state", "optional_configuration", "panic", "legacy_compat")))
        require([p.name for p in port_sources] == EXPECTED_SOURCES and
                common_sources == selected_common + [expectation],
                "Actual C55S common source inventory omits/adds a required TU")
        macros = positive.run([positive.gcc, *positive.flags(profile, "O2", False, "baseline"),
                               "-E", "-dM", expectation], "actual C55S manifest preprocessing")
        (positive.build / "manifest.macros").write_text(macros, encoding="ascii")
        require(re.search(r"^#define FIBER_PORT_RUNTIME_SELECTABLE 0\s*$", macros, re.M),
                "C55S runtime selection policy changed")
        positives = []
        for opt in ("O2", "Os"):
            for lto, sections in LAYOUTS:
                for bundle in ("baseline", "raw"):
                    positive.case(profile, opt, lto, bundle, sections)
                    cell = positive.cases[-1]
                    require(cell["status"] == "PASS", "Actual C55S raw admission failed: " + cell["name"])
                    directory = positive.build / cell["name"]
                    present = {f["name"] for f in module.Elf(directory / "port-native.o").functions}
                    require(FORWARD <= present, "Positive lost a required forward definition")
                    require((directory / "common-fiber_port_context_cohort_expectation.o").is_file(),
                            "Standard expectation TU was not compiled")
                    positives.append(dict(Case=cell["name"], Forward=sorted(FORWARD),
                                          Cohort=cohort_state(module, directory)))
        require(positive.finish(True) == 0, "Positive source/tool/snapshot drift or incomplete inventory")

        # Restore only the two obsolete exemptions in the captured real runner.
        fixed = (repo / SHARED).read_bytes()
        changes = ((b'        common += [self.repo / "fiber/port/fiber_port_context_cohort_expectation.c"]',
                    b'        # C55S has a private staged cohort, not the complete generic storage ABI.\n'
                    b'        if p["kind"] != "paired-staged":\n'
                    b'            common += [self.repo / "fiber/port/fiber_port_context_cohort_expectation.c"]'),
                   (b'            if group == "port" and p["kind"] != "companion":',
                    b'            if group == "port" and p["kind"] not in ("companion", "paired-staged"):'))
        legacy = fixed
        for new, old in changes:
            require(legacy.count(new) == 1, "Exact two-exemption historical control anchor changed")
            legacy = legacy.replace(new, old)
        legacy_dir = build / "legacy-runner"
        legacy_dir.mkdir()
        legacy_path = legacy_dir / "run.py"
        legacy_path.write_bytes(legacy)
        (legacy_dir / "two-exemptions.diff").write_text("".join(difflib.unified_diff(
            fixed.decode("ascii").splitlines(True), legacy.decode("ascii").splitlines(True),
            fromfile="repaired-captured-runner", tofile="restored-two-exemptions")), encoding="ascii")
        old_module = load(legacy_path, "c55s_legacy_raw_gate")

        def mutant_audit(implementation, path):
            class MissingSchedule(implementation.Audit):
                def compile(self, source, target, flags, extra=()):
                    if Path(source) == repo / PORT / "fiber_port.c":
                        extra = [*extra, "-D" + MISSING + "=" + RENAMED]
                    return super().compile(source, target, flags, extra)
            audit = MissingSchedule(options(args, path))
            audit.build.mkdir()
            audit.fixture = positive.fixture
            audit.planned_cells = 12
            audit.preflight()
            audit.track(legacy_path)
            audits.append(audit)
            return audit

        old = mutant_audit(old_module, build / "old-exemptions-mutant")
        current = mutant_audit(module, build / "repaired-mutant")
        negatives = []
        for opt in ("O2", "Os"):
            for lto, sections in LAYOUTS:
                for bundle in ("baseline", "raw"):
                    old.case(profile, opt, lto, bundle, sections)
                    cell = old.cases[-1]
                    require(cell["status"] == "PASS" and not cell["defects"],
                            "Historical gate did not reproduce the missing-operation false PASS")
                    old_state = native_state(module, old.build / cell["name"])
                    whole = module.Elf(old.build / cell["name"] / "whole-native.o")
                    require(any(s["name"] == MISSING and s["section"] == 0 for s in whole.symbols),
                            "Common no longer imports the missing actual operation")
                    try:
                        current.case(profile, opt, lto, bundle, sections)
                    except RuntimeError as error:
                        require(str(error) == DIAGNOSTIC,
                                "Missing-operation mutation rejected for an unrelated reason: " + str(error))
                        current.errors.append(dict(case=cell["name"], profile="C55S", error=str(error)))
                    else:
                        raise RuntimeError("Repaired gate accepted a compiled missing required operation")
                    current_state = native_state(module, current.build / cell["name"])
                    require((current.build / cell["name"] / "common-fiber_port_context_cohort_expectation.o").is_file(),
                            "Repaired mutant did not compile the actual expectation TU")
                    row = dict(Case=cell["name"], OldFalsePass=old_state, RepairedReject=current_state,
                               Diagnostic=DIAGNOSTIC)
                    write(current.build / cell["name"] / "expected-rejection.json", row)
                    negatives.append(row)
                    print("PASS causal missing-operation rejection " + cell["name"], flush=True)
        require(len(negatives) == 12 and old.finish(True) == 0 and current.finish(True) == 1,
                "Exact historical false-PASS/repaired-FAIL receipt inventory changed")
        report.update(Status="PASS", CompleteSuite=True, PositiveCells=positives, MutationCells=negatives,
                      PositiveReceipt=str(positive.build / "results.json"),
                      OldFalsePassReceipt=str(old.build / "results.json"),
                      ExpectedFailureReceipt=str(current.build / "results.json"),
                      CapturedFixedRunnerSha256=sha(repo / SHARED),
                      RestoredHistoricalRunnerSha256=sha(legacy_path),
                      Mutation="Actual port fiber_port.c compiled with -D" + MISSING + "=" + RENAMED,
                      RuntimeSelectable=0)
    except Exception as error:
        failure = error
        report.update(Error=str(error), Traceback=traceback.format_exc())
    finally:
        drift = []
        inputs = {}
        for audit in audits:
            inputs.update(audit.inputs)
        for path, value in inputs.items():
            if not Path(path).is_file() or sha(path) != value:
                drift.append(path)
        snapshot = json.loads(Path(args.input_snapshot).read_text(encoding="ascii"))
        snapshot_drift = [row["copy"] for row in snapshot["files"]
                          if not Path(row["copy"]).is_file() or sha(row["copy"]) != row["sha256"]]
        report.update(InputDrift=drift, SnapshotDrift=snapshot_drift,
                      Snapshot=str(args.input_snapshot), Inputs=len(inputs),
                      Commands=sum(len(a.commands) for a in audits))
        if drift or snapshot_drift:
            report.update(Status="FAIL", CompleteSuite=False)
        write(build / "results.json", report)
        with (build / "inputs.sha256.csv").open("w", encoding="ascii", newline="") as stream:
            writer = csv.writer(stream)
            writer.writerow(("path", "sha256"))
            writer.writerows(sorted(inputs.items()))
        with (build / "artifacts.sha256.csv").open("w", encoding="ascii", newline="") as stream:
            writer = csv.writer(stream)
            writer.writerow(("path", "sha256"))
            writer.writerows((str(p.relative_to(build)), sha(p)) for p in sorted(build.rglob("*"))
                             if p.is_file() and p != build / "artifacts.sha256.csv")
    print("%s C55S raw admission: %s" % (report["Status"], build / "results.json"), flush=True)
    if failure is not None:
        raise failure
    return 0 if report["Status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
