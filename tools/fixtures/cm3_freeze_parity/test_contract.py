"""Synthetic receipt-join controls, not ELF, compiler or processor proof."""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
from types import SimpleNamespace

sys.dont_write_bytecode = True
TOOLS = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("freeze_cm3_contract_subject", TOOLS / "freeze_cm3_mechanisms.py")
f = importlib.util.module_from_spec(spec)
spec.loader.exec_module(f)


def main():
    records = []
    manifest = f.inventory.read_json((TOOLS / "freeze_cohorts.json").read_bytes())
    cohort = next(row for row in manifest["cohorts"] if row["id"] == f.COHORT)
    source_sha = "A" * 64

    def test(name, action, accept):
        reason = None
        try:
            action()
        except (RuntimeError, ValueError, KeyError, TypeError) as failure:
            reason = str(failure)
        f.need((reason is None) is accept, "comparison-control-" + name + ": " + str(reason))
        records.append(dict(Name=name, Accepted=reason is None, Rejection=reason))

    for reference in (False, True):
        prefix = "reference-" if reference else "native-"
        status = "REFERENCE-COMPILE-PREFLIGHT-PASS" if reference else "COMPILE-PREFLIGHT-PASS"
        result = dict(Verdict=status, ProofScope="REFERENCE_COMPILE_PREFLIGHT_ONLY" if reference else
                      "NATIVE_COMPILE_PREFLIGHT_ONLY", Error=None, InputDrift=[], SourceInventorySha256=source_sha,
                      GlobalFreezeQualified=False, GeneratedAssemblyParity=False, FinalElfProof=False,
                      CpuExecution=False, BoardExecution=False, TransitiveHostClosure=False,
                      RequiredCellsSatisfied=0, FinalExecutableLinks=0, ReferenceCommit=f.inventory.PIN,
                      SelectedCohorts=[f.COHORT], Modes=list(f.inventory.OBJECT_MODES), ExpectedCompileCells=5)
        result["Cells"] = [dict(Cohort=f.COHORT, ArtifactRole="runtime", SourceGroup="CM3", Mode=mode,
            CohortSha256=f.inventory.cohort_fingerprint(cohort), Status=status, Linkage="none",
            Representation="reference-object" if reference else "object", RequiredCellSatisfied=False,
            GeneratedAssemblyParity=False, FinalElfProof=False, CpuExecution=False,
            Recipe=dict(ExactTargetRecipe=True, WitnessKind="none")) for mode in f.inventory.OBJECT_MODES]
        test(prefix + "complete-five", lambda: f.cells_for(result, manifest, source_sha, reference), True)
        mutations = [
            ("failed-receipt", lambda r: r.update(Verdict="FAIL")),
            ("error", lambda r: r.update(Error="synthetic")),
            ("drift", lambda r: r.update(InputDrift=["synthetic"])),
            ("mixed-snapshot", lambda r: r.update(SourceInventorySha256="B" * 64)),
            ("promoted-global", lambda r: r.update(GlobalFreezeQualified=True)),
            ("bool-zero-counter", lambda r: r.update(RequiredCellsSatisfied=False)),
            ("final-link", lambda r: r.update(FinalExecutableLinks=1)),
            ("missing-mode", lambda r: r["Modes"].pop()),
            ("duplicate-mode", lambda r: r["Modes"].append("O2")),
            ("unknown-cohort", lambda r: r["SelectedCohorts"].append("foreign")),
            ("duplicate-cohort", lambda r: r["SelectedCohorts"].append(f.COHORT)),
            ("missing-cell", lambda r: r["Cells"].pop()),
            ("duplicate-cell", lambda r: r["Cells"].append(deepcopy(r["Cells"][0]))),
            ("wrong-context", lambda r: r["Cells"][0].update(CohortSha256="C" * 64)),
            ("foreign-group", lambda r: r["Cells"][0].update(SourceGroup="CM4")),
            ("failed-cell", lambda r: r["Cells"][0].update(Status="FAIL")),
            ("promoted-cell", lambda r: r["Cells"][0].update(RequiredCellSatisfied=True)),
            ("bool-cell-flag", lambda r: r["Cells"][0].update(CpuExecution=0)),
            ("wrong-representation", lambda r: r["Cells"][0].update(Representation="final")),
            ("wrong-count", lambda r: r.update(ExpectedCompileCells=4)),
        ]
        if reference:
            mutations += [("wrong-pin", lambda r: r.update(ReferenceCommit="0" * 40)),
                          ("limited-witness", lambda r: r["Cells"][0]["Recipe"].update(WitnessKind="softfp")),
                          ("inexact-target", lambda r: r["Cells"][0]["Recipe"].update(ExactTargetRecipe=False))]
        for name, change in mutations:
            altered = deepcopy(result)
            change(altered)
            test(prefix + name, lambda r=altered: f.cells_for(r, manifest, source_sha, reference), False)

    with TemporaryDirectory(prefix="cm3-receipt-controls-") as temporary:
        root = Path(temporary)
        (root / "results.json").write_text("{}", encoding="ascii")
        (root / "payload.bin").write_bytes(b"synthetic-not-an-ELF")

        def seal(mapping=None):
            files = mapping or {p.name: f.sha(p.read_bytes()) for p in root.iterdir() if p.name != "artifacts.json"}
            f.save(root / "artifacts.json", dict(Artifacts=files))

        seal()
        bundle = f.Bundle(root)
        test("bound-payload", lambda: bundle.bound_path(str(root / "payload.bin"), f.sha(b"synthetic-not-an-ELF")), True)
        test("escaped-payload", lambda: bundle.bound_path(str(root.parent / "payload.bin"), "D" * 64), False)
        test("wrong-row-hash", lambda: bundle.bound_path(str(root / "payload.bin"), "D" * 64), False)
        (root / "payload.bin").write_bytes(b"changed")
        test("changed-payload", bundle.verify, False)
        seal()
        test("changed-manifest", bundle.verify, False)
        bundle = f.Bundle(root)
        (root / "extra.bin").write_bytes(b"extra")
        test("extra-artifact", bundle.verify, False)
        files = dict(bundle.files)
        files["../escaped.bin"] = "E" * 64
        seal(files)
        test("unsafe-member", lambda: f.Bundle(root), False)
    with TemporaryDirectory(prefix="cm3-input-controls-") as temporary:
        root = Path(temporary)
        payload = root / "input-bytes" / "source.c"
        payload.parent.mkdir()
        payload.write_bytes(b"synthetic source")
        original = str(root / "original.c")
        item = dict(Original=original, Captured=str(payload), Sha256=f.sha(payload.read_bytes()))
        f.save(root / "inputs.json", dict(Files=[item]))
        f.save(root / "results.json", dict(CompilerInputSha256=f.sha(f.inventory.encoded({original: item["Sha256"]}))))
        f.save(root / "artifacts.json", dict(Artifacts={p.relative_to(root).as_posix(): f.sha(p.read_bytes())
               for p in root.rglob("*") if p.is_file()}))
        bundle = f.Bundle(root)
        test("valid-compiler-capture", lambda: f.compiler_inputs(bundle), True)
        bundle.result["CompilerInputSha256"] = "D" * 64
        test("wrong-compiler-fingerprint", lambda: f.compiler_inputs(bundle), False)
        bundle.result["CompilerInputSha256"] = f.sha(f.inventory.encoded({original: item["Sha256"]}))
        source = SimpleNamespace(root=root, read=lambda name: f.inventory.encoded(dict(Files=[
            dict(item, Captured=str(root / "inputs" / "source.c"))])))
        test("matching-source-snapshot", lambda: f.bind_source_inputs(source, {original: item["Sha256"]}, ["source.c"]), True)
        test("missing-required-source", lambda: f.bind_source_inputs(source, {}, ["source.c"]), False)
        test("mixed-source-snapshot", lambda: f.bind_source_inputs(source, {original: "E" * 64}, ["source.c"]), False)
        payload.write_bytes(b"changed")
        test("changed-compiler-capture", lambda: f.compiler_inputs(bundle), False)
    with TemporaryDirectory(prefix="cm3-reader-controls-") as temporary:
        root = Path(temporary)
        script = root / "module.py"
        captured = b"VALUE = 'captured'\n"
        script.write_bytes(b"raise RuntimeError('changed bytes must not execute')\n")
        module = f.load("cm3_synthetic_captured_module", script, captured)
        test("execute-captured-not-reread-bytes", lambda: f.need(module.VALUE == "captured", "loader-control"), True)
        artifacts = f.output_files(root)
        f.save(root / "artifacts.json", dict(Artifacts=artifacts))
        test("closed-output", lambda: f.verify_output(root, artifacts), True)
        script.write_bytes(b"changed again")
        test("output-drift", lambda: f.verify_output(root, artifacts), False)
        f.save(root / "artifacts.json", dict(Artifacts={}))
        test("output-manifest-drift", lambda: f.verify_output(root, artifacts), False)
    proof = dict(Verdict="CM3-CLOSED-ROOTS-PASS", ProofScope="CM3_P4_B16_SIX_CLOSED_ROOT_PROTOCOLS_ONLY",
        Roots=list(f.ROOTS["Native"]), ClosedBodies=6, DifferenceIds=sorted(f.DIFFERENCES),
        RequiredCellSatisfied=False, CompleteObjectProof=False, InstructionEquivalence=False,
        CpuExecution=False, FinalElfProof=False, GlobalFreezeQualified=False,
        RootEvidence=[dict(Side=side, Name=name, Tokens=10, LiteralIslands=1, TailNops=1,
                           BodySha256="A" * 64) for side, names in f.ROOTS.items() for name in names],
        ReferenceSvcObligation=dict(StartRoot=f.ROOTS["Reference"][0], RestoreRoot=f.ROOTS["Reference"][1],
            FirstContextExcReturnProtocolMatched=True, HandlerRoutingProven=False, UnreachabilityProven=False))
    test("complete-checker-result", lambda: f.require_proof(proof, "O0"), True)
    test("checker-cannot-return-none", lambda: f.require_proof(None, "O0"), False)
    test("mode-specific-tail-count", lambda: f.require_proof(proof, "O2"), False)
    mutations = [
        ("partial-root-list", lambda p: p["Roots"].pop()),
        ("partial-body-count", lambda p: p.update(ClosedBodies=5)),
        ("promoted-checker", lambda p: p.update(GlobalFreezeQualified=True)),
        ("missing-difference", lambda p: p["DifferenceIds"].pop()),
        ("duplicate-difference", lambda p: p["DifferenceIds"].append(p["DifferenceIds"][0])),
        ("missing-root-evidence", lambda p: p["RootEvidence"].pop()),
        ("duplicate-root-evidence", lambda p: p["RootEvidence"].__setitem__(0, deepcopy(p["RootEvidence"][1]))),
        ("foreign-root", lambda p: p["RootEvidence"][0].update(Name="foreign")),
        ("missing-tokens", lambda p: p["RootEvidence"][0].update(Tokens=0)),
        ("bad-body-sha", lambda p: p["RootEvidence"][0].update(BodySha256="fake")),
        ("mode-layout-mix", lambda p: p["RootEvidence"][0].update(TailNops=0)),
        ("invented-routing-proof", lambda p: p["ReferenceSvcObligation"].update(HandlerRoutingProven=True)),
    ]
    for name, change in mutations:
        altered = deepcopy(proof)
        change(altered)
        test(name, lambda p=altered: f.require_proof(p, "O0"), False)
    attributes = 'Tag_CPU_name: "7-M"\nTag_CPU_arch: v7\nTag_CPU_arch_profile: Microcontroller\nTag_THUMB_ISA_use: Thumb-2\n'
    test("cm3-codegen-attributes", lambda: f.require_cm3_attributes(attributes), True)
    for name, value in [
        ("foreign-arch", attributes.replace("v7\n", "v7E-M\n")),
        ("foreign-cpu", attributes.replace('"7-M"', '"7E-M"')),
        ("thumb1", attributes.replace("Thumb-2", "Thumb-1")),
        ("missing-attributes", ""),
        ("duplicate-arch", attributes + "Tag_CPU_arch: v7\n"),
        ("fp-arch", attributes + "Tag_FP_arch: VFPv4\n"),
        ("fp-abi", attributes + "Tag_ABI_VFP_args: VFP registers\n"),
        ("mve-arch", attributes + "Tag_MVE_arch: MVE Integer and FP\n"),
    ]:
        test(name, lambda a=value: f.require_cm3_attributes(a), False)
    print(json.dumps(dict(Verdict="PASS", Controls=len(records), CompilerInvocations=0,
                          CpuExecution=False, Records=records), indent=2))


if __name__ == "__main__":
    main()
