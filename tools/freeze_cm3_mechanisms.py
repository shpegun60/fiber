"""Compare closed CM3 roots from captured preflights; never a full freeze gate."""
from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path
import re
import sys

if sys.flags.optimize or not __debug__:
    raise SystemExit("REJECT:PYTHON:optimization is unsupported")

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent


def load(name, path, data):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    exec(compile(data, str(path), "exec"), module.__dict__)
    return module


INVENTORY_BYTES = (HERE / "freeze_cohorts.py").read_bytes()
inventory = load("freeze_cm3_inventory", HERE / "freeze_cohorts.py", INVENTORY_BYTES)
COHORT = "cm3-cortex-m3-soft-nofpu-none-v1-mpu0-p4-b16-aapcs-default"
need, sha, save, regular = inventory.need, inventory.sha, inventory.save, inventory.regular
ROOTS = {"Native": ("fiber_port_start_first_context", "SVC_Handler", "PendSV_Handler"),
         "Reference": ("prvPortStartFirstTask", "vPortSVCHandler", "xPortPendSVHandler")}
DIFFERENCES = {"FAP-COMMON-START", "FAP-COMMON-PROVENANCE", "FAP-COMMON-MASK-RESTORE",
               "FAP-COMMON-SCHEDULER", "FAP-CM3-EXC-RETURN", "FAP-CM3-LOCAL-LITERAL-POOLS"}


def digest(value):
    need(type(value) is str and re.fullmatch(r"[0-9A-F]{64}", value), "comparison-sha256")
    return value


class Bundle:
    """Closed captured bytes, not a claim that today's working tree is identical."""

    def __init__(self, root):
        self.root = Path(root).resolve(strict=True)
        need(self.root.is_dir(), "comparison-receipt-directory")
        need(regular(self.root / "artifacts.json") == self.root / "artifacts.json",
             "comparison-manifest-alias")
        self.manifest_bytes = (self.root / "artifacts.json").read_bytes()
        self.files = inventory.read_json(self.manifest_bytes)["Artifacts"]
        need(type(self.files) is dict and self.files, "comparison-empty-artifact-map")
        self.verify()
        self.result = inventory.read_json(self.read("results.json"))

    def path(self, name):
        inventory.relative(name)
        need(name in self.files, "comparison-unbound-artifact")
        path = self.root / name
        need(regular(path) == path, "comparison-artifact-alias")
        return path

    def read(self, name):
        data = self.path(name).read_bytes()
        need(sha(data) == digest(self.files[name]), "comparison-artifact-drift")
        return data

    def bound_path(self, value, expected_hash):
        path = Path(value)
        need(path.is_absolute() and path.is_relative_to(self.root), "comparison-path-escape")
        name = path.relative_to(self.root).as_posix()
        need(sha(self.read(name)) == digest(expected_hash), "comparison-row-hash")
        return self.path(name)

    def verify(self):
        need(regular(self.root / "artifacts.json").read_bytes() == self.manifest_bytes,
             "comparison-artifact-manifest-drift")
        actual = {p.relative_to(self.root).as_posix() for p in self.root.rglob("*")
                  if p.is_file() and p != self.root / "artifacts.json"}
        need(actual == set(self.files), "comparison-artifact-membership")
        for name in self.files:
            self.read(name)


def captured_inventory(bundle):
    result = bundle.result
    need(result["Verdict"] == "INVENTORY-PLAN-PASS" and result["Error"] is None and
         result["GlobalFreezeQualified"] is False and result["InputDrift"] == [] and
         result["ReferenceIdentityVerified"] is True and result["ReferenceCommit"] == inventory.PIN and
         result["ProofScope"] == "DECLARED_INVENTORY_AND_PLAN_ONLY" and
         result["CompilerDependenciesCaptured"] is False,
         "comparison-inventory-scope")
    need(all(type(result[k]) is int and result[k] == 0 for k in
             ("CompilerInvocations", "TargetExecutions")), "comparison-inventory-execution")
    captured = inventory.read_json(bundle.read("capture.json"))["Files"]
    names = {}
    for row in captured:
        path = bundle.bound_path(row["Captured"], row["Sha256"])
        need(path.is_relative_to(bundle.root / "inputs"), "comparison-capture-location")
        name = path.relative_to(bundle.root / "inputs").as_posix()
        need(name not in names, "comparison-duplicate-capture")
        names[name] = row["Sha256"]
    need(sha(inventory.encoded(dict(sorted(names.items())))) == result["SourceInventorySha256"],
         "comparison-inventory-fingerprint")
    need({"inputs/" + name for name in names} == {n for n in bundle.files if n.startswith("inputs/")},
         "comparison-capture-membership")
    manifest = inventory.read_json(bundle.read("inputs/tools/freeze_cohorts.json"))
    registry = inventory.read_registry(bundle.read("inputs/tools/fixtures/sensitive_port_closure/run.py"))
    inventory.validate_manifest(manifest, registry)
    need(inventory.read_json(bundle.read("required-cells.json")) == inventory.plan(manifest),
         "comparison-required-plan")
    return manifest


def compiler_inputs(bundle):
    files = inventory.read_json(bundle.read("inputs.json"))["Files"]
    need(type(files) is list and files, "comparison-empty-compiler-inputs")
    names = {}
    for row in files:
        name = row["Original"]
        need(type(name) is str and Path(name).is_absolute() and name not in names,
             "comparison-compiler-input-name")
        path = bundle.bound_path(row["Captured"], row["Sha256"])
        need(path.is_relative_to(bundle.root / "input-bytes"), "comparison-compiler-capture-location")
        names[name] = row["Sha256"]
    need(sha(inventory.encoded(dict(sorted(names.items())))) == bundle.result["CompilerInputSha256"],
         "comparison-compiler-input-fingerprint")
    return names


def bind_source_inputs(source, compiler, required):
    captures = inventory.read_json(source.read("capture.json"))["Files"]
    found = set()
    for row in captures:
        name = Path(row["Captured"]).relative_to(source.root / "inputs").as_posix()
        if row["Original"] in compiler:
            need(compiler[row["Original"]] == row["Sha256"], "comparison-source-snapshot-drift")
            found.add(name)
    need(set(required) <= found, "comparison-required-source-binding")


def cells_for(result, manifest, source_sha, reference, *, cohort=COHORT, source_group="CM3"):
    status = "REFERENCE-COMPILE-PREFLIGHT-PASS" if reference else "COMPILE-PREFLIGHT-PASS"
    scope = "REFERENCE_COMPILE_PREFLIGHT_ONLY" if reference else "NATIVE_COMPILE_PREFLIGHT_ONLY"
    need(result["Verdict"] == status and result["ProofScope"] == scope and result["Error"] is None and
         result["InputDrift"] == [] and result["SourceInventorySha256"] == source_sha,
         "comparison-preflight-scope")
    for key in ("GlobalFreezeQualified", "GeneratedAssemblyParity", "FinalElfProof", "CpuExecution",
                "BoardExecution", "TransitiveHostClosure"):
        need(result[key] is False, "comparison-preflight-promotion")
    for key in ("RequiredCellsSatisfied", "FinalExecutableLinks"):
        need(type(result[key]) is int and result[key] == 0, "comparison-preflight-execution")
    if reference:
        need(result["ReferenceCommit"] == inventory.PIN, "comparison-reference-pin")
    cohorts = {row["id"]: row for row in manifest["cohorts"]}
    selected, modes = result["SelectedCohorts"], result["Modes"]
    need(type(selected) is list and len(selected) == len(set(selected)) and
         set(selected) <= set(cohorts) and cohort in selected, "comparison-selected-cohorts")
    need(type(modes) is list and len(modes) == len(set(modes)) and
         set(modes) == set(inventory.OBJECT_MODES), "comparison-five-modes-required")
    expected = {(name, a["role"], a["source_group_id"], mode,
                 inventory.cohort_fingerprint(cohorts[name]))
                for name in selected for a in cohorts[name]["artifacts"] for mode in modes}
    found = {}
    for row in result["Cells"]:
        key = tuple(row[n] for n in ("Cohort", "ArtifactRole", "SourceGroup", "Mode", "CohortSha256"))
        need(key in expected and key not in found, "comparison-cell-identity")
        need(row["Status"] == status and row["Linkage"] == "none" and
             row["Representation"] == ("reference-object" if reference else "object") and
             all(row[n] is False for n in
                 ("RequiredCellSatisfied", "GeneratedAssemblyParity", "FinalElfProof", "CpuExecution")),
             "comparison-cell-scope")
        if reference and row["Cohort"] == cohort:
            need(row["Recipe"]["ExactTargetRecipe"] is True and row["Recipe"]["WitnessKind"] == "none",
                 "comparison-reference-witness")
        found[key] = row
    need(set(found) == expected and type(result["ExpectedCompileCells"]) is int and
         result["ExpectedCompileCells"] == len(expected), "comparison-cell-completeness")
    return {row["Mode"]: row for row in found.values()
            if row["Cohort"] == cohort and row["ArtifactRole"] == "runtime" and row["SourceGroup"] == source_group}


def require_cm3_attributes(attributes):
    rows = re.findall(r'^\s*(Tag_[A-Za-z0-9_]+):[^\S\r\n]*(.*?)\s*$', attributes, re.MULTILINE)
    need(len(rows) == len({name for name, _ in rows}), "comparison-duplicate-codegen-attribute")
    fields = dict(rows)
    need(all(fields.get(key) == value for key, value in {
             "Tag_CPU_name": '"7-M"', "Tag_CPU_arch": "v7",
             "Tag_CPU_arch_profile": "Microcontroller", "Tag_THUMB_ISA_use": "Thumb-2"}.items()) and
         not {"Tag_FP_arch", "Tag_MVE_arch", "Tag_Advanced_SIMD_arch", "Tag_ABI_VFP_args",
              "Tag_PAC_extension", "Tag_BTI_extension"} & set(fields), "comparison-cm3-codegen-attributes")


def object_for(bundle, row, decoder):
    path = bundle.bound_path(row["NativeGroup"], row["NativeGroupSha256"])
    disassembly = path.with_suffix(".dis")
    for auxiliary in (disassembly, path.with_suffix(".attributes")):
        bundle.read(auxiliary.relative_to(bundle.root).as_posix())
    for obj in row["Objects"]:
        bundle.bound_path(obj["Path"], obj["Sha256"])
    image = decoder.Object(path, disassembly)
    need(not any(name.startswith(".gnu.lto_") for name in image.names), "comparison-non-native-lto-group")
    attributes = bundle.read(path.with_suffix(".attributes").relative_to(bundle.root).as_posix()).decode("ascii")
    require_cm3_attributes(attributes)
    return image


def require_proof(proof, mode):
    need(type(proof) is dict and proof["Verdict"] == "CM3-CLOSED-ROOTS-PASS" and
         proof["ProofScope"] == "CM3_P4_B16_SIX_CLOSED_ROOT_PROTOCOLS_ONLY" and
         proof["Roots"] == list(ROOTS["Native"]) and type(proof["ClosedBodies"]) is int and
         proof["ClosedBodies"] == 6, "comparison-checker-completeness")
    need(all(proof[key] is False for key in ("RequiredCellSatisfied", "CompleteObjectProof",
             "InstructionEquivalence", "CpuExecution", "FinalElfProof", "GlobalFreezeQualified")),
         "comparison-checker-promotion")
    differences = proof["DifferenceIds"]
    need(type(differences) is list and len(differences) == len(set(differences)) and
         set(differences) == DIFFERENCES, "comparison-difference-ledger")
    expected = {(side, name) for side, names in ROOTS.items() for name in names}
    evidence, found = proof["RootEvidence"], set()
    need(type(evidence) is list and len(evidence) == 6, "comparison-root-evidence")
    for root in evidence:
        identity = (root["Side"], root["Name"])
        need(identity in expected and identity not in found and
             type(root["Tokens"]) is int and root["Tokens"] > 0 and
             type(root["LiteralIslands"]) is int and root["LiteralIslands"] == 1 and
             type(root["TailNops"]) is int and root["TailNops"] == (1 if mode == "O0" else 0),
             "comparison-root-layout")
        digest(root["BodySha256"])
        found.add(identity)
    obligation = proof["ReferenceSvcObligation"]
    need(obligation == dict(StartRoot=ROOTS["Reference"][0], RestoreRoot=ROOTS["Reference"][1],
             FirstContextExcReturnProtocolMatched=True, HandlerRoutingProven=False, UnreachabilityProven=False),
         "comparison-svc-obligation-scope")


def output_files(out):
    return {p.relative_to(out).as_posix(): sha(regular(p).read_bytes())
            for p in sorted(out.rglob("*")) if p.is_file() and p != out / "artifacts.json"}


def verify_output(out, artifacts):
    need(inventory.read_json(regular(out / "artifacts.json").read_bytes()) == dict(Artifacts=artifacts)
         and output_files(out) == artifacts, "comparison-closing-output-drift")


def main():
    parser = argparse.ArgumentParser(allow_abbrev=False)
    for option in ("inventory", "native", "reference", "output-dir"):
        parser.add_argument("--" + option, required=True)
    args = parser.parse_args()
    roots = [Path(getattr(args, name)).resolve(strict=True) for name in ("inventory", "native", "reference")]
    out = Path(args.output_dir).resolve()
    repo = HERE.parent
    need(not out.exists() and not any(out.is_relative_to(r) or r.is_relative_to(out) for r in roots + [repo]),
         "comparison-fresh-external-output")
    out.mkdir(parents=True)
    report = dict(Verdict="FAIL", Error=None, ProofScope="CM3_CLOSED_ROOT_MECHANISMS_ONLY",
                  GlobalFreezeQualified=False, RequiredCellsSatisfied=0, FinalElfProof=False,
                  CpuExecution=False, BoardExecution=False, CompilerInvocations=0, Cells=[])
    save(out / "results.json", report)
    bundles, readers, reader_bytes = [], {}, {}
    try:
        for path in (Path(__file__), HERE / "freeze_cohorts.py", HERE / "fixtures/cm3_freeze_parity/check.py",
                     HERE / "fixtures/cm55_tfm_parity/elf.py", HERE / "freertos_asm_parity.ps1",
                     repo / "FREERTOS_ASM_PARITY.md"):
            data = regular(path).read_bytes()
            if path == HERE / "freeze_cohorts.py":
                need(data == INVENTORY_BYTES, "comparison-loaded-inventory-drift")
            readers[str(path)] = sha(data)
            reader_bytes[path] = data
            copy = out / "reader-bytes" / path.relative_to(repo)
            copy.parent.mkdir(parents=True, exist_ok=True)
            copy.write_bytes(data)
        ledger = reader_bytes[repo / "FREERTOS_ASM_PARITY.md"].decode("utf-8-sig")
        need(all(re.search(r"^### " + re.escape(name) + r"\s*$", ledger, re.MULTILINE)
                 for name in DIFFERENCES), "comparison-missing-difference-rationale")
        checker_path = HERE / "fixtures/cm3_freeze_parity/check.py"
        decoder_path = HERE / "fixtures/cm55_tfm_parity/elf.py"
        checker = load("freeze_cm3_check", checker_path, reader_bytes[checker_path])
        decoder = load("freeze_cm3_decoder", decoder_path, reader_bytes[decoder_path])
        bundles = [Bundle(root) for root in roots]
        source, native, reference = bundles
        manifest = captured_inventory(source)
        native_inputs, reference_inputs = compiler_inputs(native), compiler_inputs(reference)
        group = next(g for g in manifest["source_groups"] if g["id"] == "CM3")
        artifact = next(c for c in manifest["cohorts"] if c["id"] == COHORT)["artifacts"][0]
        bind_source_inputs(source, native_inputs, group["sources"])
        bind_source_inputs(source, reference_inputs,
                           ["pinned-reference/" + name for name in artifact["upstream_sources"]])
        source_sha = source.result["SourceInventorySha256"]
        native_cells = cells_for(native.result, manifest, source_sha, False)
        reference_cells = cells_for(reference.result, manifest, source_sha, True)
        need(set(native_cells) == set(reference_cells) == set(inventory.OBJECT_MODES), "comparison-cm3-join")
        report.update(SourceInventorySha256=source_sha, CapturedInputsOnly=True,
                      Receipts=[dict(Path=str(b.root), ArtifactManifestSha256=sha(b.manifest_bytes),
                                     ResultSha256=sha(b.read("results.json"))) for b in bundles])
        for mode in inventory.OBJECT_MODES:
            proof = checker.check_pair(object_for(native, native_cells[mode], decoder),
                                       object_for(reference, reference_cells[mode], decoder))
            require_proof(proof, mode)
            report["Cells"].append(dict(Cohort=COHORT, Mode=mode, SourceGroup="CM3", ArtifactRole="runtime",
                                        CohortSha256=native_cells[mode]["CohortSha256"], Proof=proof,
                                        RequiredCellSatisfied=False, FinalElfProof=False))
        for bundle in bundles:
            bundle.verify()
        need(all(sha(regular(path).read_bytes()) == expected for path, expected in readers.items()),
             "comparison-reader-drift")
        report["Verdict"] = "CM3-MECHANISMS-PASS"
    except Exception as failure:
        report["Error"] = type(failure).__name__ + ": " + str(failure)
    save(out / "readers.json", readers)
    save(out / "results.json", report)
    try:
        artifacts = output_files(out)
        save(out / "artifacts.json", dict(Artifacts=artifacts))
        verify_output(out, artifacts)
    except Exception as failure:
        report.update(Verdict="FAIL", Error=type(failure).__name__ + ": " + str(failure))
        save(out / "results.json", report)
    print(report["Verdict"] + " " + str(out), flush=True)
    return 0 if report["Verdict"] == "CM3-MECHANISMS-PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
