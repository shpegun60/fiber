"""Exact-cohort native compile preflight; not assembly parity or final-ELF proof."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time

sys.dont_write_bytecode = True
LOADED = {}


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    data = Path(path).read_bytes()
    LOADED[str(Path(path).resolve())] = hashlib.sha256(data).hexdigest().upper()
    exec(compile(data, str(path), "exec"), module.__dict__)
    return module


HERE = Path(__file__).resolve().parent
inventory = load("freeze_compile_inventory", HERE / "freeze_cohorts.py")
recipe = load("freeze_compile_recipe", HERE / "fixtures/freeze_cohorts/build_recipe.py")
closure = load("freeze_compile_native_objects", HERE / "fixtures/sensitive_port_closure/run.py")
need, regular, sha, save = inventory.need, inventory.regular, inventory.sha, inventory.save


def verify_inventory(root, repo, freertos):
    """Verify the explicit receipt and original source binding before ARM tools."""
    artifacts = inventory.read_json(regular(root / "artifacts.json").read_bytes())["Artifacts"]
    actual = {p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()
              and p != root / "artifacts.json"}
    need(set(artifacts) == actual, "inventory-artifact-set")
    for name, expected in artifacts.items():
        inventory.relative(name)
        need(sha(regular(root / name).read_bytes()) == expected, "inventory-artifact-bytes")
    result = inventory.read_json((root / "results.json").read_bytes())
    need(result["Verdict"] == "INVENTORY-PLAN-PASS" and result["GlobalFreezeQualified"] is False and
         result["ReferenceIdentityVerified"] is True and result["ReferenceCommit"] == inventory.PIN and
         result["ProofScope"] == "DECLARED_INVENTORY_AND_PLAN_ONLY" and result["Error"] is None and
         result["CompilerDependenciesCaptured"] is False and result["InputDrift"] == [] and
         all(type(result[key]) is int and result[key] == 0 for key in ("CompilerInvocations", "TargetExecutions")),
         "inventory-receipt-scope")
    inputs = inventory.read_json((root / "capture.json").read_bytes())["Files"]
    names = {}
    for row in inputs:
        copy = regular(row["Captured"])
        need(copy.is_relative_to(root / "inputs"), "inventory-capture-containment")
        name = inventory.relative(copy.relative_to(root / "inputs").as_posix())
        need(name not in names and sha(copy.read_bytes()) == row["Sha256"], "inventory-capture-binding")
        names[name] = row["Sha256"]
        original = regular(row["Original"])
        if name.startswith("pinned-reference/"):
            expected = freertos / name[len("pinned-reference/"):]
        elif name.startswith("host-git/"):
            # This compiler-only phase never invokes the previously recorded Git file.
            continue
        else:
            expected = repo / name
        need(original == regular(expected) and sha(original.read_bytes()) == row["Sha256"],
             "inventory-original-source-drift")
    need(sha(inventory.encoded(dict(sorted(names.items())))) == result["SourceInventorySha256"],
         "inventory-source-fingerprint")
    manifest = inventory.read_json((root / "inputs/tools/freeze_cohorts.json").read_bytes())
    registry = inventory.read_registry((root / "inputs/tools/fixtures/sensitive_port_closure/run.py").read_bytes())
    groups = inventory.validate_manifest(manifest, registry)
    required_sources = {source for group in groups.values() for source in group["sources"]}
    required_sources.update("pinned-reference/" + source for cohort in manifest["cohorts"]
                            for artifact in cohort["artifacts"] for source in artifact["upstream_sources"])
    required_sources.update(("tools/freeze_cohorts.py", "tools/freeze_cohorts.json", "tools/runtime_sources.json",
                             "tools/runtime_sources.py", "tools/runtime_sources.ps1",
                             "tools/fixtures/sensitive_port_closure/run.py"))
    need(required_sources <= set(names), "inventory-declared-source-coverage")
    required = inventory.read_json((root / "required-cells.json").read_bytes())
    need(required == inventory.plan(manifest), "inventory-required-plan-binding")
    return result, manifest, groups


class Compile(closure.Audit):
    def __init__(self, args, report):
        super().__init__(args)
        self.report = report
        self.tools = {name: regular(self.gcc.with_name("arm-none-eabi-" + name + ".exe"))
                      for name in ("objdump", "readelf")}
        self.allowed = {str(regular(self.gcc)), *(str(path) for path in self.tools.values())}
        self.inputs = {}
        self.commands = []
        self.environment = dict(os.environ, LC_ALL="C", LANG="C", GCC_COLORS="")
        for key in ("GCC_EXEC_PREFIX", "COMPILER_PATH", "LIBRARY_PATH", "CPATH", "C_INCLUDE_PATH",
                    "CPLUS_INCLUDE_PATH", "OBJC_INCLUDE_PATH", "GCC_SPECS"):
            need(not self.environment.get(key), "ambient-compiler-path-override-" + key)

    def track(self, path):
        path = regular(path)
        data = path.read_bytes()
        key, digest = str(path), sha(data)
        if key in self.inputs:
            need(self.inputs[key]["Sha256"] == digest, "compiler-input-drift")
        else:
            copy = self.build / "input-bytes" / (digest + "-" + path.name)
            copy.parent.mkdir(exist_ok=True)
            if copy.exists():
                need(copy.read_bytes() == data, "compiler-capture-alias")
            else:
                copy.write_bytes(data)
            self.inputs[key] = dict(Original=key, Captured=str(copy), Sha256=digest)

    def run(self, argv, label, timeout=120):
        argv = [str(value) for value in argv]
        need(argv[0] in self.allowed, "unapproved-compiler-command")
        self.track(argv[0])
        start = time.monotonic()
        process = subprocess.run(argv, cwd=self.build, env=self.environment, capture_output=True,
                                 text=True, errors="replace", timeout=timeout)
        row = dict(label=label, command=argv, exit=process.returncode, stdout=process.stdout,
                   stderr=process.stderr, seconds=round(time.monotonic() - start, 3))
        save(self.build / ("command-%05d.json" % len(self.commands)), row)
        self.commands.append(row)
        need(process.returncode == 0, "native-command-failed: " + label + ": " + process.stderr[-2000:])
        return process.stdout

    def preflight(self):
        for path in (Path(__file__), HERE / "freeze_cohorts.py", Path(recipe.__file__), Path(closure.__file__),
                     self.gcc, *self.tools.values()):
            self.track(path)
        for path, expected in LOADED.items():
            need(self.inputs[path]["Sha256"] == expected, "loaded-helper-source-drift")
        need(self.run([self.gcc, "-dumpfullversion"], "compiler version").strip() == "14.3.1",
             "compiler-version")
        workers = {}
        for program in ("cc1", "collect2", "as", "ld", "lto1", "lto-wrapper", "liblto_plugin.dll"):
            path = Path(self.run([self.gcc, "-print-prog-name=" + program], "query worker " + program).strip())
            if not path.is_file():
                path = Path(self.run([self.gcc, "-print-file-name=" + program], "query file " + program).strip())
            self.track(path)
            workers[program] = str(regular(path))
        self.report["CompilerWorkers"] = workers
        self.run([self.gcc, "-dumpspecs"], "compiler builtin specs")
        specs = self.run([self.gcc, "-print-file-name=specs"], "query external specs").strip()
        if specs != "specs":
            self.track(specs)

    def build_cell(self, cohort, artifact, group, mode):
        directory = self.build / "cells" / cohort["id"] / artifact["role"] / mode
        directory.mkdir(parents=True)
        header = directory / "main.h"
        header.write_text(recipe.cmsis_main(artifact["target"]), encoding="ascii")
        self.track(header)
        port = self.repo / Path(group["sources"][0]).parent
        flags = recipe.native_flags(artifact, mode, directory, port, self.repo, Path(self.a.cmsis_core))
        row = dict(Cohort=cohort["id"], ArtifactRole=artifact["role"], SourceGroup=group["id"], Mode=mode,
                   Representation="object", Linkage="none", CohortSha256=inventory.cohort_fingerprint(cohort),
                   Status="FAIL", RequiredCellSatisfied=False, GeneratedAssemblyParity=False,
                   FinalElfProof=False, CpuExecution=False, Objects=[])
        self.report["Cells"].append(row)
        objects = []
        for index, source in enumerate(group["sources"]):
            source = regular(self.repo / source)
            self.track(source)
            target = directory / ("source-%02d.o" % index)
            self.compile(source, target, flags)
            objects.append(target)
            row["Objects"].append(dict(Source=str(source), Path=str(target), Sha256=sha(target.read_bytes())))
        target = directory / "native-group.o"
        profile = dict(architecture=artifact["target"]["architecture"])
        self.lower(profile, objects, target, flags, False)
        row.update(Status="COMPILE-PREFLIGHT-PASS", NativeGroup=str(target), NativeGroupSha256=sha(target.read_bytes()))
        print("COMPILED " + cohort["id"] + "/" + artifact["role"] + "/" + mode, flush=True)


def main():
    parser = argparse.ArgumentParser(allow_abbrev=False)
    for option in ("repo", "inventory", "freertos", "arm-gcc", "cmsis-core", "output-dir"):
        parser.add_argument("--" + option, required=True)
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument("--cohort", action="append")
    selection.add_argument("--all-cohorts", action="store_true")
    parser.add_argument("--mode", choices=inventory.OBJECT_MODES, action="append")
    args = parser.parse_args()
    args.repo = str(Path(args.repo).resolve(strict=True))
    out = Path(args.output_dir).resolve()
    receipt = Path(args.inventory).resolve(strict=True)
    readonly_roots = (Path(args.repo), receipt, Path(args.freertos).resolve(strict=True),
                      Path(args.cmsis_core).resolve(strict=True), regular(args.arm_gcc).parent)
    need(not out.exists() and not any(out.is_relative_to(root) for root in readonly_roots),
         "fresh-external-output-required")
    out.mkdir(parents=True)
    args.build, args.cm7_prefix_root = str(out), None
    report = dict(Verdict="FAIL", Error=None, GlobalFreezeQualified=False, GeneratedAssemblyParity=False,
                  FinalElfProof=False, CpuExecution=False, BoardExecution=False, TransitiveHostClosure=False,
                  RequiredCellsSatisfied=0, ProofScope="NATIVE_COMPILE_PREFLIGHT_ONLY", Cells=[])
    save(out / "results.json", report)
    audit = None
    try:
        source, manifest, groups = verify_inventory(receipt, Path(args.repo), Path(args.freertos).resolve(strict=True))
        selected = args.cohort or [row["id"] for row in manifest["cohorts"]]
        need(len(set(selected)) == len(selected), "duplicate-selected-cohort")
        cohorts = {row["id"]: row for row in manifest["cohorts"]}
        need(set(selected) <= set(cohorts), "unknown-selected-cohort")
        need(all(cohorts[name]["compiler_admission"] == "Admitted" for name in selected), "unadmitted-compile-selection")
        modes = args.mode or list(inventory.OBJECT_MODES)
        need(len(set(modes)) == len(modes), "duplicate-selected-mode")
        report.update(SourceInventorySha256=source["SourceInventorySha256"], SourceInventoryReceipt=str(receipt),
                      SelectedCohorts=selected, Modes=modes,
                      ExpectedCompileCells=sum(len(cohorts[name]["artifacts"]) for name in selected) * len(modes))
        audit = Compile(args, report)
        audit.preflight()
        for name in selected:
            for artifact in cohorts[name]["artifacts"]:
                for mode in modes:
                    audit.build_cell(cohorts[name], artifact, groups[artifact["source_group_id"]], mode)
        need(len(report["Cells"]) == report["ExpectedCompileCells"] and
             all(row["Status"] == "COMPILE-PREFLIGHT-PASS" for row in report["Cells"]), "incomplete-native-compile")
        for row in audit.inputs.values():
            need(sha(regular(row["Original"]).read_bytes()) == row["Sha256"] and
                 sha(regular(row["Captured"]).read_bytes()) == row["Sha256"], "closing-native-input-drift")
        verify_inventory(receipt, Path(args.repo), Path(args.freertos).resolve(strict=True))
        report.update(Verdict="COMPILE-PREFLIGHT-PASS", InputDrift=[])
    except Exception as failure:
        report.update(Verdict="FAIL", Error=type(failure).__name__ + ": " + str(failure))
    try:
        if audit is not None:
            report.update(RecordedCommands=len(audit.commands),
                          SourceCompileCommands=sum("-c" in row["command"] for row in audit.commands),
                          RelocatableGroupCommands=sum("-r" in row["command"] for row in audit.commands),
                          FinalExecutableLinks=0,
                          CompilerInputSha256=sha(inventory.encoded({k: v["Sha256"]
                              for k, v in sorted(audit.inputs.items())})))
            save(out / "inputs.json", dict(Files=list(audit.inputs.values())))
            save(out / "commands.json", audit.commands)
        save(out / "results.json", report)
        artifacts = {p.relative_to(out).as_posix(): sha(regular(p).read_bytes())
                     for p in sorted(out.rglob("*")) if p.is_file() and p != out / "artifacts.json"}
        save(out / "artifacts.json", dict(Artifacts=artifacts))
        measured = {p.relative_to(out).as_posix(): sha(regular(p).read_bytes())
                    for p in sorted(out.rglob("*")) if p.is_file() and p != out / "artifacts.json"}
        need(measured == artifacts, "closing-native-artifact-drift")
    except Exception as failure:
        report.update(Verdict="FAIL", Error=type(failure).__name__ + ": " + str(failure))
        save(out / "results.json", report)
    print(report["Verdict"] + " " + str(out), flush=True)
    return 0 if report["Verdict"] == "COMPILE-PREFLIGHT-PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
