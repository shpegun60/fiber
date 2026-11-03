"""Separate bounded FP grid; qualified pilot and basic sources stay immutable."""
import json
from pathlib import Path

from cm4_mpu_basic_engine import need, save, digest, fp
from cm4_mpu_fp_grid_builds import GridBuilds
from cm4_mpu_fp_grid_contracts import KEYS, REF_KEYS, CONTROL_KEYS, validate, control_tests
import cm4_mpu_fp_checks as checks


class FpGrid(GridBuilds):
    def __init__(self, args):
        super().__init__(args)
        self.report.update(Verdict="FAIL", Execution="NOT_RUN", CompileOnly=not args.execute_grid,
            Scope="CM4/AN386 MPU8 hard-FP eager/lazy O2/Os ordinary/final-LTO direct/archive bounded FP grid",
            CompleteSuite=False, RequestedInventoryComplete=False)

    def preflight(self):
        super().preflight()
        self.report["GridContractControls"] = control_tests()

    def run(self):
        self.preflight()
        for opt, lto, archive in REF_KEYS:
            reference = self.build_reference(opt, lto, archive)
            reference["FpMechanisms"] = checks.check_reference(fp.Image(reference["Elf"], self.ELFFile))
            self.references.append(reference)
        refs = {(r["Optimization"], r["LTO"], r["Archive"]): r for r in self.references}
        self.report["ModelProbe"] = self.build_subject("context", False, "O2", False, False, model=True)
        for consumer, lazy, opt, lto, archive in KEYS:
            row = self.build_subject(consumer, lazy, opt, lto, archive)
            self.rows.append(row)
            reference = refs[(opt, lto, archive)]
            path = Path(row["Elf"]).parent / "reference-association.json"
            paired = self.pair(row, reference, path)
            self.associations.append(dict(Consumer=consumer, Lazy=lazy, Optimization=opt, LTO=lto, Archive=archive,
                SubjectElf=row["Elf"], SubjectSha256=row["ElfSha256"], ReferenceElf=reference["Elf"],
                ReferenceSha256=reference["ElfSha256"], Evidence=str(path), EvidenceSha256=digest(path),
                NamedMechanismResults=len(paired["Checks"]), SubjectFp=row["Mechanism"],
                ReferenceFp=reference["FpMechanisms"], Executed=False))
        for consumer, lazy, opt, lto, archive, mutation in CONTROL_KEYS:
            self.controls.append(self.build_subject(consumer, lazy, opt, lto, archive, mutation=mutation))
        if self.a.execute_grid:
            for row in [self.report["ModelProbe"], *self.rows, *self.controls]:
                self.execute(row)

    def bind_artifacts(self):
        manifest = json.loads((self.build / "artifacts.json").read_text())
        rows = [self.report["ModelProbe"], *self.rows, *self.controls, *self.references]
        need(len(rows) == 61 and len({r["Elf"] for r in rows}) == 61, "Sixty-one distinct ELF bindings")
        for row in rows:
            path = Path(row["Elf"]).resolve(strict=True)
            need(str(path) == row["Elf"] and path.is_relative_to(self.build) and path.is_file() and
                 digest(path) == row["ElfSha256"] == manifest["Artifacts"].get(path.relative_to(self.build).as_posix()),
                 "Actual grid ELF bytes/manifest binding")
        model = self.report["ModelProbe"]
        need(Path(model["Elf"]) == self.build / "model/runtime.elf", "Exact grid model path")
        self.report["ModelArtifactBinding"] = dict(Verified=True, ArtifactRelative="model/runtime.elf",
            Elf=model["Elf"], ElfSha256=model["ElfSha256"], ManifestEntrySha256=model["ElfSha256"])
        for row in self.associations:
            path = Path(row["Evidence"]).resolve(strict=True)
            need(path.is_relative_to(self.build) and digest(path) == row["EvidenceSha256"] ==
                 manifest["Artifacts"].get(path.relative_to(self.build).as_posix()), "Grid association artifact drift")

    def finish(self, error):
        self.report.update(Error=error, Verdict="FAIL", RequestedInventoryComplete=False,
                           ArtifactsVerifiedBeforePass=False, InputCount=len(self.inputs))
        try:
            save(self.build / "results.json", self.report)
            if error is not None:
                raise RuntimeError("Prior failure: " + repr(error))
            self.close_identity()
            self.report["InputDrift"] = self.input_drift()
            need(not self.report["InputDrift"], "Grid input drift")
            save(self.build / "inputs.after.json", [dict(Path=p, Sha256=digest(p)) for p in self.inputs])
            save(self.build / "dependencies.json", self.dependencies)
            save(self.build / "generated-inputs.json", list(self.generated.values()))
            save(self.build / "results.json", self.report)
            self.artifact_manifest(verify=True)
            self.bind_artifacts()
            candidate = dict(self.report, Verdict="FP-GRID-PASS" if self.a.execute_grid else "COMPILE-PREFLIGHT-PASS",
                Execution="BOUNDED_FP_GRID" if self.a.execute_grid else "NOT_RUN",
                RequestedInventoryComplete=True, ArtifactsVerifiedBeforePass=True)
            validate(candidate, self.a.execute_grid)
            self.report.update(candidate)
            save(self.build / "results.json", self.report)
            self.artifact_manifest(verify=True)
            self.bind_artifacts()
            need(not self.input_drift(), "Late grid input drift")
            return True
        except Exception as failure:
            self.report.update(Verdict="FAIL", RequestedInventoryComplete=False, ArtifactsVerifiedBeforePass=False,
                Error=error if error is not None else "finalizer: " + type(failure).__name__ + ": " + str(failure))
            save(self.build / "results.json", self.report)
            try:
                self.artifact_manifest(verify=False)
            except Exception as manifest_failure:
                self.report["FailureManifestError"] = str(manifest_failure)
                save(self.build / "results.json", self.report)
            return False
