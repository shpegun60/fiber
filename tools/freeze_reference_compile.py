"""Compile pinned reference recipes; never promote compilation to CPU parity."""
from __future__ import annotations

import argparse
from collections import Counter
from pathlib import Path
import sys
import time

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import freeze_compile as native

inventory = native.inventory
recipe = native.load("freeze_reference_recipe", native.HERE / "fixtures/freeze_cohorts/reference_recipe.py")
need, regular, sha, save = native.need, native.regular, native.sha, native.save
TFM_COMMIT = "9ca8a5eb3c85eecee1303dffa262800ea0385584"
TFM_FILES = {
    "interface/include/os_wrapper/mutex.h": "321A599838EE95A3FAF75BAFF57D2DB1BD3770824BE467DDC24870744831D705",
    "interface/include/os_wrapper/common.h": "AD83089404AADC15A130378EE69AB096436A60F6AADC45D899ECBEAA77D7C048",
    "license.rst": "C16DF600171BFDAE60D22A01F046D742F89BA1046E2E5ED135BBF091B21BE34F",
}


def tfm_provider(include):
    """Require unchanged pinned TF-M headers/license, not a typed test stub."""
    include = Path(include).resolve(strict=True)
    root = include.parent.parent
    need(root / "interface/include" == include, "tfm-provider-layout")
    rows = []
    for name, expected in TFM_FILES.items():
        path = regular(root / name)
        data = path.read_bytes()
        # Git's normal Windows checkout expansion is the only permitted change.
        canonical = data.replace(b"\r\n", b"\n")
        need(b"\r" not in canonical and sha(canonical) == expected and
             data in (canonical, canonical.replace(b"\n", b"\r\n")), "tfm-pinned-provider-bytes")
        rows.append(dict(Path=str(path), WorktreeSha256=sha(data), GitBlobSha256=expected,
                         ByteComparison="exact" if data == canonical else "git-lf-worktree-crlf"))
    return rows


def tfm_include_for(artifact, include):
    return include if "portable/ThirdParty/GCC/ARM_TFM/os_wrapper_freertos.c" in artifact["upstream_sources"] else None


class Reference(native.Compile):
    def __init__(self, args, report):
        super().__init__(args, report)
        self.reference = Path(args.freertos).resolve(strict=True)
        self.git = regular(args.git)
        need(not self.git.is_relative_to(self.reference), "git-tool-inside-reference")
        self.bindings = {}
        self.cell_inputs = None
        self.allowed.add(str(self.git))

    def git_bytes(self, *arguments):
        self.track(self.git)
        argv = [str(self.git), "--no-optional-locks", "-c", "core.fsmonitor=false",
                "-C", str(self.reference), *arguments]
        started = time.monotonic()
        row = dict(label="pinned reference " + arguments[0], command=argv,
                   exit=None, stdout_sha256=None, stderr="", timed_out=False, Error=None, seconds=None)
        record = self.build / ("command-%05d.json" % len(self.commands))
        self.commands.append(row)
        save(record, row)
        try:
            process = native.process_runner.run(argv, cwd=self.build, env=self.environment, timeout=30)
            row.update(exit=process.returncode, stdout_sha256=sha(process.stdout),
                       stderr=process.stderr.decode("utf-8", "replace"), timed_out=process.timed_out)
        except BaseException as failure:
            row["Error"] = type(failure).__name__ + ": " + str(failure)
            raise
        finally:
            row["seconds"] = round(time.monotonic() - started, 3)
            save(record, row)
        need(not row["timed_out"] and row["exit"] == 0, "reference-git-command")
        return process.stdout

    def track(self, path):
        logical = Path(path).absolute()
        path = regular(path)
        need(not logical.is_relative_to(self.reference) or path.is_relative_to(self.reference),
             "reference-dependency-escaped")
        super().track(path)
        if self.cell_inputs is not None:
            self.cell_inputs.add(path)
        if path.is_relative_to(self.reference):
            name = inventory.relative(path.relative_to(self.reference).as_posix())
            if name not in self.bindings:
                data = path.read_bytes()
                blob = self.git_bytes("show", inventory.PIN + ":" + name)
                comparison = inventory.reference_bytes_match(data, blob)
                target = self.build / "reference-blobs" / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(blob)
                self.bindings[name] = dict(Path=name, WorktreeSha256=sha(data),
                                          GitBlobSha256=sha(blob), ByteComparison=comparison)

    def reference_identity(self):
        need(self.git_bytes("rev-parse", "HEAD").decode("ascii").strip() == inventory.PIN,
             "actual-reference-pin")
        need(not self.git_bytes("status", "--porcelain=v1", "--untracked-files=all", "--ignored=matching"),
             "reference-worktree-drift")

    def preflight(self):
        self.track(Path(recipe.__file__))
        super().preflight()
        self.track(Path(__file__))
        self.track(native.HERE / "fixtures/freertos_asm_parity/FreeRTOSConfig.h")
        self.reference_identity()
        if self.a.tfm_include:
            rows = tfm_provider(self.a.tfm_include)
            for row in rows:
                self.track(row["Path"])
            self.report.update(TfmReferenceCommit=TFM_COMMIT, TfmProviderFiles=rows)

    def build_cell(self, cohort, artifact, mode):
        directory = self.build / "cells" / cohort["id"] / artifact["role"] / mode
        directory.mkdir(parents=True)
        binding = recipe.reference_recipe(artifact, mode, directory, self.reference,
                                          tfm_include_for(artifact, self.a.tfm_include))
        base = native.HERE / "fixtures/freertos_asm_parity/FreeRTOSConfig.h"
        self.track(base)
        (directory / "freeze_base_FreeRTOSConfig.h").write_bytes(base.read_bytes())
        (directory / "FreeRTOSConfig.h").write_text(binding["ConfigText"], encoding="ascii")
        self.track(directory / "freeze_base_FreeRTOSConfig.h")
        self.track(directory / "FreeRTOSConfig.h")
        flags = binding["Flags"]
        row = dict(Cohort=cohort["id"], ArtifactRole=artifact["role"],
                   SourceGroup=artifact["source_group_id"], Mode=mode,
                   Representation="reference-object", Linkage="none",
                   CohortSha256=inventory.cohort_fingerprint(cohort),
                   Recipe=binding, Status="FAIL", RequiredCellSatisfied=False,
                   GeneratedAssemblyParity=False, FinalElfProof=False, CpuExecution=False, Objects=[])
        self.report["Cells"].append(row)
        objects = []
        for index, source_name in enumerate(artifact["upstream_sources"]):
            self.track(self.reference / source_name)
            source = regular(self.reference / source_name)
            target = directory / ("reference-%02d.o" % index)
            self.cell_inputs = set()
            self.compile(source, target, flags)
            dependencies = self.cell_inputs
            self.cell_inputs = None
            providers = {path for path in dependencies if path.name.lower() == "portmacro.h"}
            expected = ({regular(self.reference / binding["PortmacroProvider"])}
                        if artifact["role"] == "runtime" else set())
            need(providers == expected, "actual-reference-portmacro-provider")
            # Pinned secure_init.c has no configuration include or config use.
            expected_config = (set() if artifact["role"] == "secure_companion" and
                               Path(source_name).name == "secure_init.c" else
                               {regular(directory / "FreeRTOSConfig.h")})
            need({path for path in dependencies if path.name == "FreeRTOSConfig.h"} == expected_config,
                 "actual-reference-config-provider")
            tfm_headers = {path for path in dependencies if path.parent.name == "os_wrapper"}
            expected_tfm = ({regular(Path(self.a.tfm_include) / "os_wrapper" / name)
                             for name in ("mutex.h", "common.h")}
                            if source_name == "portable/ThirdParty/GCC/ARM_TFM/os_wrapper_freertos.c" else set())
            need(tfm_headers == expected_tfm, "actual-pinned-tfm-provider")
            native.closure.Elf(target).native()
            objects.append(target)
            row["Objects"].append(dict(Source=source_name, Path=str(target), Sha256=sha(target.read_bytes()),
                TrackedCompileInputs={str(path): self.inputs[str(path)]["Sha256"] for path in sorted(dependencies)}))
        target = directory / "native-reference-group.o"
        self.lower(dict(architecture=artifact["target"]["architecture"]), objects, target, flags, False)
        row.update(Status="REFERENCE-COMPILE-PREFLIGHT-PASS", NativeGroup=str(target),
                   NativeGroupSha256=sha(target.read_bytes()))
        print("REFERENCE-COMPILED " + cohort["id"] + "/" + artifact["role"] + "/" + mode, flush=True)


def main():
    parser = argparse.ArgumentParser(allow_abbrev=False)
    for option in ("repo", "inventory", "freertos", "arm-gcc", "git", "output-dir"):
        parser.add_argument("--" + option, required=True)
    parser.add_argument("--tfm-include", default=str(native.HERE / "fixtures/freeze_cohorts/tfm_v2/interface/include"))
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument("--cohort", action="append")
    selection.add_argument("--all-cohorts", action="store_true")
    parser.add_argument("--mode", choices=inventory.OBJECT_MODES, action="append")
    args = parser.parse_args()
    args.repo = str(Path(args.repo).resolve(strict=True))
    args.freertos = str(Path(args.freertos).resolve(strict=True))
    receipt = Path(args.inventory).resolve(strict=True)
    out = Path(args.output_dir).resolve()
    roots = [Path(args.repo), Path(args.freertos), receipt, regular(args.arm_gcc).parent, regular(args.git).parent]
    if args.tfm_include:
        args.tfm_include = str(Path(args.tfm_include).resolve(strict=True))
        roots.append(Path(args.tfm_include))
    need(not out.exists() and not any(out.is_relative_to(root) for root in roots), "fresh-external-output-required")
    out.mkdir(parents=True)
    args.build, args.cm7_prefix_root = str(out), None
    report = dict(Verdict="FAIL", Error=None, GlobalFreezeQualified=False,
                  GeneratedAssemblyParity=False, FinalElfProof=False, CpuExecution=False,
                  BoardExecution=False, TransitiveHostClosure=False, RequiredCellsSatisfied=0,
                  ProofScope="REFERENCE_COMPILE_PREFLIGHT_ONLY", Cells=[])
    save(out / "results.json", report)
    audit = None
    try:
        source, manifest, _ = native.verify_inventory(receipt, Path(args.repo), Path(args.freertos))
        selected = args.cohort or [row["id"] for row in manifest["cohorts"]]
        cohorts = {row["id"]: row for row in manifest["cohorts"]}
        modes = args.mode or list(inventory.OBJECT_MODES)
        need(len(selected) == len(set(selected)) and set(selected) <= set(cohorts), "selected-cohorts")
        need(len(modes) == len(set(modes)), "duplicate-selected-mode")
        need(all(cohorts[name]["compiler_admission"] == "Admitted" for name in selected), "unadmitted-selection")
        report.update(SourceInventorySha256=source["SourceInventorySha256"],
                      SourceInventoryReceipt=str(receipt), ReferenceCommit=inventory.PIN,
                      SelectedCohorts=selected, Modes=modes,
                      ExpectedCompileCells=sum(len(cohorts[name]["artifacts"]) for name in selected) * len(modes))
        audit = Reference(args, report)
        # Reject every missing/unsupported recipe before the first compiler query.
        for name in selected:
            for artifact in cohorts[name]["artifacts"]:
                recipe.reference_recipe(artifact, modes[0], out, audit.reference, tfm_include_for(artifact, args.tfm_include))
        tfm_provider(args.tfm_include)
        audit.preflight()
        for name in selected:
            for artifact in cohorts[name]["artifacts"]:
                for mode in modes:
                    audit.build_cell(cohorts[name], artifact, mode)
        need(len(report["Cells"]) == report["ExpectedCompileCells"] and
             all(row["Status"] == "REFERENCE-COMPILE-PREFLIGHT-PASS" for row in report["Cells"]),
             "incomplete-reference-compile")
        audit.reference_identity()
        for row in audit.inputs.values():
            need(sha(regular(row["Original"]).read_bytes()) == row["Sha256"] and
                 sha(regular(row["Captured"]).read_bytes()) == row["Sha256"], "closing-reference-input-drift")
        native.verify_inventory(receipt, Path(args.repo), Path(args.freertos))
        report.update(Verdict="REFERENCE-COMPILE-PREFLIGHT-PASS", InputDrift=[])
    except Exception as failure:
        report.update(Verdict="FAIL", Error=type(failure).__name__ + ": " + str(failure))
    try:
        if audit is not None:
            report.update(RecordedCommands=len(audit.commands),
                SourceCompileCommands=sum(row["command"][0] == str(audit.gcc) and "-c" in row["command"]
                                          for row in audit.commands),
                RelocatableGroupCommands=sum(row["command"][0] == str(audit.gcc) and "-r" in row["command"]
                                             for row in audit.commands),
                FinalExecutableLinks=0, ReferenceFileBindings=list(audit.bindings.values()),
                DifferenceCells=dict(Counter(d["Kind"] for row in report["Cells"] for d in row["Recipe"]["Differences"])),
                CompilerInputSha256=sha(inventory.encoded({k: v["Sha256"] for k, v in sorted(audit.inputs.items())})))
            save(out / "inputs.json", dict(Files=list(audit.inputs.values())))
            save(out / "commands.json", audit.commands)
        save(out / "results.json", report)
        artifacts = {p.relative_to(out).as_posix(): sha(regular(p).read_bytes())
                     for p in sorted(out.rglob("*")) if p.is_file() and p != out / "artifacts.json"}
        save(out / "artifacts.json", dict(Artifacts=artifacts))
        need(artifacts == {p.relative_to(out).as_posix(): sha(regular(p).read_bytes())
             for p in sorted(out.rglob("*")) if p.is_file() and p != out / "artifacts.json"}, "closing-artifact-drift")
    except Exception as failure:
        report.update(Verdict="FAIL", Error=type(failure).__name__ + ": " + str(failure))
        save(out / "results.json", report)
    print(report["Verdict"] + " " + str(out), flush=True)
    return 0 if report["Verdict"] == "REFERENCE-COMPILE-PREFLIGHT-PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
