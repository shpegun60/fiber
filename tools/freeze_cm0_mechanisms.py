"""Captured CM0/M0+ p2 roots; not full object, final ELF or CPU equivalence."""
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
COHORTS = {
    "cm0-cortex-m0-soft-nofpu-none-v0-mpu0-p2-b0-aapcs-default": ("cortex-m0", False),
    "cm0-cortex-m0plus-soft-nofpu-none-v0-mpu0-p2-b0-aapcs-default": ("cortex-m0plus", False),
    "cm0-cortex-m0plus-soft-nofpu-none-v1-mpu0-p2-b0-aapcs-default": ("cortex-m0plus", True),
}
ROOTS = {"Native": ("fiber_port_start_first_context", "SVC_Handler", "PendSV_Handler"),
         "Reference": ("vStartFirstTask", "SVC_Handler", "vPortSVCHandler_C",
                       "vRestoreContextOfFirstTask", "PendSV_Handler")}
DIFFERENCES = {"FAP-COMMON-START", "FAP-COMMON-PROVENANCE", "FAP-COMMON-MASK-RESTORE",
               "FAP-COMMON-SCHEDULER", "FAP-CM0-STAGED-FRAME"}


def load(name, path, data):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    exec(compile(data, str(path), "exec"), module.__dict__)
    return module


SHARED_BYTES = (HERE / "freeze_cm3_mechanisms.py").read_bytes()
shared = load("cm0_receipt_helpers", HERE / "freeze_cm3_mechanisms.py", SHARED_BYTES)
need, sha, save, regular = shared.need, shared.sha, shared.save, shared.regular


def require_cohort(artifact, identity):
    need(identity in COHORTS, "cm0-profile")
    cpu, vtor = COHORTS[identity]
    target = dict(cpu=cpu, architecture="ARMV6M", float_abi="soft", fpu_present=False,
                  fpu_used=False, fpu_unit="", fp_stacking="none", vtor=vtor, mpu_regions=0,
                  security_role="classic", psplim_slot=False, psplim_register=False, mve="none",
                  pac=False, bti=False, errata_policy="none", r9_abi="aapcs",
                  nvic_priority_bits=2, scheduler_basepri=0)
    need(artifact["role"] == "runtime" and artifact["source_group_id"] == "CM0" and
         artifact["abi_contract"] == "forward8" and
         shared.inventory.encoded(artifact["target"]) == shared.inventory.encoded(target) and
         artifact["compile_flags"] == ["-mcpu=" + cpu, "-mthumb", "-mfloat-abi=soft"],
         "cm0-selected-cohort")


def require_attributes(attributes):
    rows = re.findall(r'^\s*(Tag_[A-Za-z0-9_]+):[^\S\r\n]*(.*?)\s*$', attributes, re.MULTILINE)
    need(len(rows) == len({key for key, _ in rows}), "cm0-duplicate-attribute")
    fields = dict(rows)
    expected = {"Tag_CPU_name": '"6S-M"', "Tag_CPU_arch": "v6S-M",
                "Tag_CPU_arch_profile": "Microcontroller", "Tag_THUMB_ISA_use": "Thumb-1"}
    need(all(fields.get(key) == value for key, value in expected.items()) and
         not {"Tag_FP_arch", "Tag_ABI_VFP_args", "Tag_MVE_arch", "Tag_Advanced_SIMD_arch",
              "Tag_PAC_extension", "Tag_BTI_extension"} & set(fields), "cm0-codegen-attributes")


def object_for(bundle, row, decoder):
    path = bundle.bound_path(row["NativeGroup"], row["NativeGroupSha256"])
    disassembly = path.with_suffix(".dis")
    bundle.read(disassembly.relative_to(bundle.root).as_posix())
    require_attributes(bundle.read(path.with_suffix(".attributes").relative_to(bundle.root).as_posix()).decode("ascii"))
    for obj in row["Objects"]:
        bundle.bound_path(obj["Path"], obj["Sha256"])
    image = decoder.Object(path, disassembly)
    need(not any(name.startswith(".gnu.lto_") for name in image.names), "cm0-native-group-required")
    return image


def require_proof(proof, mode):
    need(type(proof) is dict and proof["Verdict"] == "CM0-CLOSED-ROOTS-PASS" and
         proof["Mode"] == mode and proof["Roots"] == {key: list(value) for key, value in ROOTS.items()} and
         proof["ProofScope"] == "CM0_P2_NO_MPU_EIGHT_CLOSED_ROOT_PROTOCOLS_ONLY" and
         type(proof["ClosedBodies"]) is int and proof["ClosedBodies"] == 8, "cm0-checker-completeness")
    need(all(proof[key] is False for key in ("RequiredCellSatisfied", "CompleteObjectProof",
             "InstructionEquivalence", "CpuExecution", "BoardExecution", "FinalElfProof", "GlobalFreezeQualified",
             "PolicyEquivalence", "CSourceSemanticProof")),
         "cm0-checker-promotion")
    need(type(proof["RequiredCellsSatisfied"]) is int and proof["RequiredCellsSatisfied"] == 0,
         "cm0-zero-proof-counter")
    actual = proof["DifferenceIds"]
    need(type(actual) is list and len(actual) == len(set(actual)) and set(actual) == DIFFERENCES,
         "cm0-difference-ledger")
    obligation = proof["ReferenceSvcObligation"]
    need(obligation["DispatcherRoot"] == "SVC_Handler" and obligation["CHandlerRoot"] == "vPortSVCHandler_C" and
         obligation["RestoreRoot"] == "vRestoreContextOfFirstTask" and
         obligation["DispatchChainProtocolsMatched"] is True and
         obligation["FirstContextExcReturnProtocolMatched"] is True and
         obligation["HandlerRoutingProven"] is False and obligation["UnreachabilityProven"] is False,
         "cm0-svc-obligation-scope")
    difference = proof["FirstRestoreDifference"]
    need(difference["DifferenceId"] == "FAP-CM0-STAGED-FRAME" and
         difference["InitialRegisterValueEquivalenceProven"] is False and
         proof["SchedulerThreshold"] == "BASEPRI-NOT-APPLICABLE;PRIMASK-ENVELOPE", "cm0-restore-difference-scope")
    evidence, found = proof["RootEvidence"], set()
    expected = {(side, name) for side, names in ROOTS.items() for name in names}
    need(type(evidence) is list and len(evidence) == 8, "cm0-root-evidence")
    for root in evidence:
        identity = (root["Side"], root["Name"])
        need(identity in expected and identity not in found and type(root["Tokens"]) is int and root["Tokens"] > 0 and
             type(root["LiteralIslands"]) is int and root["LiteralIslands"] >= 0 and
             type(root["TailNops"]) is int and root["TailNops"] >= 0, "cm0-root-layout")
        shared.digest(root["BodySha256"])
        found.add(identity)


def main():
    parser = argparse.ArgumentParser(allow_abbrev=False)
    for option in ("inventory", "native", "reference", "output-dir"):
        parser.add_argument("--" + option, required=True)
    args = parser.parse_args()
    roots = [Path(getattr(args, name)).resolve(strict=True) for name in ("inventory", "native", "reference")]
    out, repo = Path(args.output_dir).resolve(), HERE.parent
    need(not out.exists() and not any(out.is_relative_to(root) or root.is_relative_to(out) for root in roots + [repo]),
         "cm0-fresh-external-output")
    out.mkdir(parents=True)
    report = dict(Verdict="FAIL", Error=None, ProofScope="CM0_CLOSED_ROOT_MECHANISMS_ONLY",
                  GlobalFreezeQualified=False, RequiredCellsSatisfied=0, FinalElfProof=False,
                  CpuExecution=False, BoardExecution=False, CompilerInvocations=0, Cells=[])
    save(out / "results.json", report)
    readers, reader_bytes, bundles = {}, {}, []
    checker_path = HERE / "fixtures/cm0_freeze_parity/closed_roots.py"
    decoder_path = HERE / "fixtures/cm55_tfm_parity/elf.py"
    try:
        for path in (Path(__file__), HERE / "freeze_cm3_mechanisms.py", HERE / "freeze_cohorts.py",
                     checker_path, decoder_path, HERE / "freertos_asm_parity.ps1", repo / "FREERTOS_ASM_PARITY.md"):
            data = regular(path).read_bytes()
            readers[str(path)], reader_bytes[path] = sha(data), data
            copy = out / "reader-bytes" / path.relative_to(repo)
            copy.parent.mkdir(parents=True, exist_ok=True)
            copy.write_bytes(data)
        need(reader_bytes[HERE / "freeze_cm3_mechanisms.py"] == SHARED_BYTES and
             reader_bytes[HERE / "freeze_cohorts.py"] == shared.INVENTORY_BYTES, "cm0-loaded-helper-drift")
        checker = load("cm0_closed_roots", checker_path, reader_bytes[checker_path])
        decoder = load("cm0_closed_decoder", decoder_path, reader_bytes[decoder_path])
        bundles = [shared.Bundle(root) for root in roots]
        source, native, reference = bundles
        manifest = shared.captured_inventory(source)
        native_inputs, reference_inputs = shared.compiler_inputs(native), shared.compiler_inputs(reference)
        source_sha = source.result["SourceInventorySha256"]
        group = next(group for group in manifest["source_groups"] if group["id"] == "CM0")
        shared.bind_source_inputs(source, native_inputs, group["sources"])
        ledger = reader_bytes[repo / "FREERTOS_ASM_PARITY.md"].decode("utf-8-sig")
        need(all(re.search(r"^### " + re.escape(name) + r"\s*$", ledger, re.MULTILINE) for name in DIFFERENCES),
             "cm0-missing-difference-rationale")
        report.update(SourceInventorySha256=source_sha, CapturedInputsOnly=True,
             Receipts=[dict(Path=str(bundle.root), ArtifactManifestSha256=sha(bundle.manifest_bytes),
                            ResultSha256=sha(bundle.read("results.json"))) for bundle in bundles])
        for identity in COHORTS:
            cohort = next(cohort for cohort in manifest["cohorts"] if cohort["id"] == identity)
            need(len(cohort["artifacts"]) == 1, "cm0-selected-artifact-count")
            artifact = cohort["artifacts"][0]
            require_cohort(artifact, identity)
            shared.bind_source_inputs(source, reference_inputs,
                                      ["pinned-reference/" + name for name in artifact["upstream_sources"]])
            native_cells, reference_cells = [shared.cells_for(bundle.result, manifest, source_sha, is_reference,
                 cohort=identity, source_group="CM0") for bundle, is_reference in ((native, False), (reference, True))]
            need(set(native_cells) == set(reference_cells) == set(shared.inventory.OBJECT_MODES), "cm0-mode-join")
            for mode in shared.inventory.OBJECT_MODES:
                proof = checker.check_pair(object_for(native, native_cells[mode], decoder),
                                           object_for(reference, reference_cells[mode], decoder), mode)
                require_proof(proof, mode)
                report["Cells"].append(dict(Cohort=identity, Mode=mode, SourceGroup="CM0", ArtifactRole="runtime",
                     CohortSha256=native_cells[mode]["CohortSha256"], Proof=proof,
                     ReferenceRecipe=reference_cells[mode]["Recipe"], RequiredCellSatisfied=False, FinalElfProof=False))
        for bundle in bundles:
            bundle.verify()
        need(all(sha(regular(path).read_bytes()) == expected for path, expected in readers.items()), "cm0-reader-drift")
        report["Verdict"] = "CM0-MECHANISMS-PASS"
    except Exception as failure:
        report["Error"] = type(failure).__name__ + ": " + str(failure)
    save(out / "readers.json", readers)
    save(out / "results.json", report)
    try:
        artifacts = shared.output_files(out)
        save(out / "artifacts.json", dict(Artifacts=artifacts))
        shared.verify_output(out, artifacts)
    except Exception as failure:
        report.update(Verdict="FAIL", Error=type(failure).__name__ + ": " + str(failure))
        save(out / "results.json", report)
    print(report["Verdict"] + " " + str(out), flush=True)
    return 0 if report["Verdict"] == "CM0-MECHANISMS-PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
