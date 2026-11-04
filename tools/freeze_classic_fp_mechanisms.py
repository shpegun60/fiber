"""Captured CM4/CM7 hard-FP closed roots, not full object/policy/CPU equivalence."""
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
PROFILES = {
    "CM4": ("cm4-cortex-m4-hard-fpu-eager-v1-mpu0-p4-b16-aapcs-default", "VFPv4-D16"),
    "CM7": ("cm7-cortex-m7-hard-fpu-eager-v1-mpu0-p4-b16-aapcs-default", "FPv5/FP-D16 for ARMv8"),
}
BASE_DIFFERENCES = {"FAP-COMMON-START", "FAP-COMMON-PROVENANCE", "FAP-COMMON-MASK-RESTORE",
                    "FAP-COMMON-SCHEDULER", "FAP-FP-VALIDATION"}


def load(name, path, data):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    exec(compile(data, str(path), "exec"), module.__dict__)
    return module


SHARED_BYTES = (HERE / "freeze_cm3_mechanisms.py").read_bytes()
shared = load("classic_fp_receipt_helpers", HERE / "freeze_cm3_mechanisms.py", SHARED_BYTES)
need, sha, save, regular = shared.need, shared.sha, shared.save, shared.regular


def require_attributes(attributes, profile):
    need(profile in PROFILES, "classic-fp-profile")
    rows = re.findall(r'^\s*(Tag_[A-Za-z0-9_]+):[^\S\r\n]*(.*?)\s*$', attributes, re.MULTILINE)
    need(len(rows) == len({name for name, _ in rows}), "classic-fp-duplicate-attribute")
    fields = dict(rows)
    expected = {"Tag_CPU_name": '"7E-M"', "Tag_CPU_arch": "v7E-M",
                "Tag_CPU_arch_profile": "Microcontroller", "Tag_THUMB_ISA_use": "Thumb-2",
                "Tag_FP_arch": PROFILES[profile][1], "Tag_ABI_VFP_args": "VFP registers"}
    need(all(fields.get(key) == value for key, value in expected.items()) and
         not {"Tag_MVE_arch", "Tag_Advanced_SIMD_arch", "Tag_PAC_extension", "Tag_BTI_extension"} & set(fields),
         "classic-fp-codegen-attributes")


def object_for(bundle, row, decoder, profile):
    path = bundle.bound_path(row["NativeGroup"], row["NativeGroupSha256"])
    disassembly = path.with_suffix(".dis")
    bundle.read(disassembly.relative_to(bundle.root).as_posix())
    attributes = bundle.read(path.with_suffix(".attributes").relative_to(bundle.root).as_posix()).decode("ascii")
    require_attributes(attributes, profile)
    for obj in row["Objects"]:
        bundle.bound_path(obj["Path"], obj["Sha256"])
    image = decoder.Object(path, disassembly)
    need(not any(name.startswith(".gnu.lto_") for name in image.names), "classic-fp-native-group-required")
    return image


def require_cohort(artifact, profile):
    need(profile in PROFILES, "classic-fp-profile")
    cpu, fpu, errata = (("cortex-m4", "fpv4-sp-d16", "none") if profile == "CM4" else
                        ("cortex-m7", "fpv5-d16", "837070-primask-preserving"))
    target = dict(cpu=cpu, architecture="ARMV7EM", float_abi="hard", fpu_present=True,
                  fpu_used=True, fpu_unit=fpu, fp_stacking="eager", vtor=True, mpu_regions=0,
                  security_role="classic", psplim_slot=False, psplim_register=False, mve="none",
                  pac=False, bti=False, errata_policy=errata, r9_abi="aapcs",
                  nvic_priority_bits=4, scheduler_basepri=16)
    need(artifact["role"] == "runtime" and artifact["source_group_id"] == profile and
         artifact["abi_contract"] == "forward8" and
         shared.inventory.encoded(artifact["target"]) == shared.inventory.encoded(target) and
         artifact["compile_flags"] == ["-mcpu=" + cpu, "-mthumb", "-mfloat-abi=hard", "-mfpu=" + fpu],
         "classic-fp-selected-cohort")


def require_proof(proof, profile, mode):
    need(type(proof) is dict and proof["Verdict"] == "CLASSIC-FP-CLOSED-ROOTS-PASS" and
         proof["Profile"] == profile and proof["Roots"] == list(shared.ROOTS["Native"]) and
         proof["ProofScope"] == "CLASSIC_FP_P4_B16_SIX_CLOSED_ROOT_PROTOCOLS_ONLY" and
         type(proof["ClosedBodies"]) is int and proof["ClosedBodies"] == 6, "classic-fp-checker-completeness")
    need(all(proof[key] is False for key in ("RequiredCellSatisfied", "CompleteObjectProof",
             "InstructionEquivalence", "CpuExecution", "BoardExecution", "FinalElfProof", "GlobalFreezeQualified")),
         "classic-fp-checker-promotion")
    need(type(proof["RequiredCellsSatisfied"]) is int and proof["RequiredCellsSatisfied"] == 0,
         "classic-fp-zero-proof-counter")
    policy = proof["FPCCRPolicy"]
    need(policy["Status"] == "UNRESOLVED-BY-THREE-ROOTS" and policy["NativePolicy"] == "eager" and
         policy["ReferencePolicy"] == "ASPEN=1,LSPEN=1" and policy["PolicyEquivalenceProven"] is False,
         "classic-fp-unresolved-policy")
    obligation = proof["ReferenceSvcObligation"]
    need(obligation["StartRoot"] == shared.ROOTS["Reference"][0] and
         obligation["RestoreRoot"] == shared.ROOTS["Reference"][1] and
         obligation["FirstContextExcReturnProtocolMatched"] is True and
         obligation["HandlerRoutingProven"] is False and obligation["UnreachabilityProven"] is False,
         "classic-fp-svc-obligation-scope")
    differences = BASE_DIFFERENCES | ({"FAP-CM7-ERRATA-PRIMASK"} if profile == "CM7" else set())
    actual = proof["DifferenceIds"]
    need(type(actual) is list and len(actual) == len(set(actual)) and set(actual) == differences,
         "classic-fp-difference-ledger")
    expected = {(side, name) for side, names in shared.ROOTS.items() for name in names}
    evidence, found = proof["RootEvidence"], set()
    need(type(evidence) is list and len(evidence) == 6, "classic-fp-root-evidence")
    for root in evidence:
        identity = (root["Side"], root["Name"])
        need(identity in expected and identity not in found and type(root["Tokens"]) is int and root["Tokens"] > 0 and
             type(root["LiteralIslands"]) is int and root["LiteralIslands"] == 1 and
             type(root["TailNops"]) is int and root["TailNops"] == (1 if mode == "O0" else 0),
             "classic-fp-root-layout")
        shared.digest(root["BodySha256"])
        found.add(identity)


def require_setup_proof(proof, profile, mode):
    need(type(proof) is dict and proof["Verdict"] == "FP-SETUP-CLOSED-ROOTS-PASS" and
         proof["Profile"] == profile and proof["Mode"] == mode and proof["Cohort"] == PROFILES[profile][0] and
         proof["ProofScope"] == "CM4_CM7_HARD_EAGER_P4_B16_THREE_COMPLETE_SETUP_PROTOCOLS_ONLY" and
         type(proof["ClosedBodies"]) is int and proof["ClosedBodies"] == 3 and
         proof["DistinctContractsChecked"] is True and proof["ReferencePin"] == shared.inventory.PIN,
         "classic-fp-setup-completeness")
    need(all(proof[key] is False for key in ("RequiredCellSatisfied", "CompleteObjectProof",
             "InstructionEquivalence", "CpuExecution", "BoardExecution", "FinalElfProof", "GlobalFreezeQualified",
             "StartupRoutingProven", "CalleeBodiesProven", "UnreachabilityProven")), "classic-fp-setup-promotion")
    need(type(proof["RequiredCellsSatisfied"]) is int and proof["RequiredCellsSatisfied"] == 0,
         "classic-fp-setup-zero-counter")
    need(proof["DifferenceIds"] == ["fpccr-eager-vs-lazy", "native-conditional-stores-barriers-readbacks"],
         "classic-fp-setup-differences")
    need(shared.inventory.encoded(proof["CPACR"]) == shared.inventory.encoded(
         dict(Address=0xE000ED88, AccessMask=0x00F00000)), "classic-fp-setup-cpacr")
    need(shared.inventory.encoded(proof["FPCCR"]) == shared.inventory.encoded(dict(
         Address=0xE000EF34, PolicyMask=0xC0000000, NativeBits=0x80000000, ReferenceBits=0xC0000000,
         NativePolicy="eager", ReferencePolicy="lazy", PolicyEquivalenceProven=False,
         HardwareReadbackProven=False, LspactHandlingProven=False)), "classic-fp-setup-policy")
    evidence, found = proof["RootEvidence"], set()
    expected = {("Native", "fiber_port_runtime_prepare"), ("Reference", "vPortEnableVFP"),
                ("Reference", "xPortStartScheduler")}
    need(type(evidence) is list and len(evidence) == 3, "classic-fp-setup-root-evidence")
    for root in evidence:
        identity = (root["Side"], root["Name"])
        need(identity in expected and identity not in found and type(root["Tokens"]) is int and root["Tokens"] > 0 and
             type(root["LiteralIslands"]) is int and root["LiteralIslands"] == 1, "classic-fp-setup-root-layout")
        shared.digest(root["BodySha256"])
        found.add(identity)


def main():
    parser = argparse.ArgumentParser(allow_abbrev=False)
    for option in ("inventory", "native", "reference", "output-dir"):
        parser.add_argument("--" + option, required=True)
    parser.add_argument("--profile", choices=tuple(PROFILES), required=True)
    parser.add_argument("--kind", choices=("transfer", "setup"), default="transfer")
    args = parser.parse_args()
    roots = [Path(getattr(args, name)).resolve(strict=True) for name in ("inventory", "native", "reference")]
    out = Path(args.output_dir).resolve()
    repo = HERE.parent
    need(not out.exists() and not any(out.is_relative_to(r) or r.is_relative_to(out) for r in roots + [repo]),
         "classic-fp-fresh-external-output")
    out.mkdir(parents=True)
    report = dict(Verdict="FAIL", Error=None,
                  ProofScope=("CLASSIC_FP_CLOSED_ROOT_MECHANISMS_ONLY" if args.kind == "transfer" else
                              "CLASSIC_FP_DISTINCT_SETUP_PROTOCOLS_ONLY"), ProofKind=args.kind,
                  Profile=args.profile, GlobalFreezeQualified=False, RequiredCellsSatisfied=0, FinalElfProof=False,
                  CpuExecution=False, BoardExecution=False, CompilerInvocations=0, PolicyEquivalence=False, Cells=[])
    save(out / "results.json", report)
    readers, reader_bytes, bundles = {}, {}, []
    checker_path = HERE / "fixtures/cm4_cm7_freeze_parity" / ("check.py" if args.kind == "transfer" else "check_setup.py")
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
             reader_bytes[HERE / "freeze_cohorts.py"] == shared.INVENTORY_BYTES, "classic-fp-loaded-helper-drift")
        checker = load("classic_fp_closed_roots", checker_path, reader_bytes[checker_path])
        decoder = load("classic_fp_decoder", decoder_path, reader_bytes[decoder_path])
        bundles = [shared.Bundle(root) for root in roots]
        source, native, reference = bundles
        manifest = shared.captured_inventory(source)
        identity = PROFILES[args.profile][0]
        cohort = next(c for c in manifest["cohorts"] if c["id"] == identity)
        artifact = cohort["artifacts"][0]
        need(len(cohort["artifacts"]) == 1, "classic-fp-selected-artifact-count")
        require_cohort(artifact, args.profile)
        group = next(g for g in manifest["source_groups"] if g["id"] == args.profile)
        shared.bind_source_inputs(source, shared.compiler_inputs(native), group["sources"])
        shared.bind_source_inputs(source, shared.compiler_inputs(reference),
                                  ["pinned-reference/" + name for name in artifact["upstream_sources"]])
        source_sha = source.result["SourceInventorySha256"]
        native_cells, reference_cells = [shared.cells_for(bundle.result, manifest, source_sha, is_reference,
             cohort=identity, source_group=args.profile) for bundle, is_reference in ((native, False), (reference, True))]
        need(set(native_cells) == set(reference_cells) == set(shared.inventory.OBJECT_MODES), "classic-fp-mode-join")
        differences = (BASE_DIFFERENCES | ({"FAP-CM7-ERRATA-PRIMASK"} if args.profile == "CM7" else set())
                       if args.kind == "transfer" else {"FAP-FP-SETUP-POLICY", "FAP-FP-SETUP-READBACK"})
        ledger = reader_bytes[repo / "FREERTOS_ASM_PARITY.md"].decode("utf-8-sig")
        need(all(re.search(r"^### " + re.escape(name) + r"\s*$", ledger, re.MULTILINE) for name in differences),
             "classic-fp-missing-difference-rationale")
        report.update(SourceInventorySha256=source_sha, CapturedInputsOnly=True,
             Receipts=[dict(Path=str(b.root), ArtifactManifestSha256=sha(b.manifest_bytes),
                            ResultSha256=sha(b.read("results.json"))) for b in bundles])
        for mode in shared.inventory.OBJECT_MODES:
            pair = (object_for(native, native_cells[mode], decoder, args.profile),
                    object_for(reference, reference_cells[mode], decoder, args.profile))
            if args.kind == "transfer":
                proof = checker.check_pair(*pair, args.profile)
                require_proof(proof, args.profile, mode)
            else:
                proof = checker.check_pair(*pair, args.profile, mode)
                require_setup_proof(proof, args.profile, mode)
            report["Cells"].append(dict(Cohort=identity, Mode=mode, SourceGroup=args.profile, ArtifactRole="runtime",
                 CohortSha256=native_cells[mode]["CohortSha256"], Proof=proof,
                 ReferenceRecipe=reference_cells[mode]["Recipe"], RequiredCellSatisfied=False, FinalElfProof=False))
        for bundle in bundles:
            bundle.verify()
        need(all(sha(regular(path).read_bytes()) == expected for path, expected in readers.items()),
             "classic-fp-reader-drift")
        report["Verdict"] = "CLASSIC-FP-MECHANISMS-PASS"
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
    return 0 if report["Verdict"] == "CLASSIC-FP-MECHANISMS-PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
