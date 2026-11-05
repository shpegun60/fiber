"""Pure CM3 join contract controls; synthetic recipes, not ELF or CPU proof."""
import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("cm3_join_contract_controls", HERE / "join.py")
join = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = join
SOURCE_BYTES = (HERE / "join.py").read_bytes()
exec(compile(SOURCE_BYTES, str(HERE / "join.py"), "exec"), join.__dict__)
MODES = ("O0", "Og", "O2", "Os", "O3")


def mechanisms():
    return [
        dict(Name="first-start", NativeRoot="fiber_port_start_first_context", ReferenceRoot="prvPortStartFirstTask",
             DifferenceIds=["FAP-COMMON-START", "FAP-COMMON-PROVENANCE", "FAP-CM3-LOCAL-LITERAL-POOLS"]),
        dict(Name="first-restore", NativeRoot="SVC_Handler", ReferenceRoot="vPortSVCHandler",
             DifferenceIds=["FAP-COMMON-PROVENANCE", "FAP-COMMON-MASK-RESTORE", "FAP-CM3-EXC-RETURN",
                            "FAP-CM3-LOCAL-LITERAL-POOLS"]),
        dict(Name="PendSV", NativeRoot="PendSV_Handler", ReferenceRoot="xPortPendSVHandler",
             DifferenceIds=["FAP-COMMON-SCHEDULER", "FAP-COMMON-PROVENANCE", "FAP-CM3-EXC-RETURN",
                            "FAP-CM3-LOCAL-LITERAL-POOLS"]),
    ]


def compile_fixture(mode="O2"):
    artifact = dict(compile_flags=["-mcpu=cortex-m3", "-mthumb", "-mfloat-abi=soft"])
    sources, commands = [], []
    for index, name in enumerate(("port.c", "startup.S")):
        flags = [*artifact["compile_flags"], "-" + mode, "-g0"]
        if name.endswith(".c"):
            flags += ["-std=gnu11", "-ffreestanding"]
        row = dict(Source=name, Object=name + ".o", CompileFlags=flags, CompileDependencyFile=name + ".d")
        sources.append(row)
        commands.append(dict(Label="compile " + name, Argv=["synthetic-gcc", *flags, "-MD", "-MF", row["CompileDependencyFile"],
            "-MT", "pilot-source-" + str(index), "-c", name, "-o", row["Object"]]))
    return dict(Sources=sources, Commands=commands), artifact


def link_fixture(root, side="Native", mode="O2"):
    result, artifact = compile_fixture(mode)
    # Only command/recipe metadata is synthetic; none of these files are created.
    directory = "classic_final_image" if side == "Native" else "cm3_final_image/reference"
    script = root / "source/tools/fixtures" / directory / "link.ld"
    result["Links"] = []
    for kind in ("ordinary", "emit-relocs"):
        path, link_map = root / (kind + ".elf"), root / (kind + ".map")
        link = dict(Kind=kind, Path=str(path), Map=str(link_map))
        result["Links"].append(link)
        argv = ["synthetic-gcc", *artifact["compile_flags"], "-" + mode, "-nostdlib",
            "-Wl,--gc-sections,--no-undefined,--fatal-warnings,--build-id=none,-z,noexecstack",
            "-T", str(script), *(row["Object"] for row in result["Sources"])]
        if kind == "emit-relocs":
            argv.append("-Wl,--emit-relocs")
        argv += ["-Wl,-Map=" + str(link_map), "-o", str(path)]
        result["Commands"].append(dict(Label="link " + kind, Argv=argv))
    return result, artifact


class MechanismControls(unittest.TestCase):
    def test_fixed_profile_modes_pin(self):
        self.assertEqual(join.PROFILES, ("CM3",))
        self.assertEqual(join.MODES, MODES)
        self.assertEqual(join.PIN, "a50edad08b29052631aa469d4df6e6ec7ff68878")

    def test_exact_six_body_three_mechanism_mapping(self):
        join.require_mechanisms(dict(Mechanisms=mechanisms()))

    def test_missing_extra_duplicate_reordered_rows_reject(self):
        rows = mechanisms()
        for changed in (rows[:2], rows + rows[:1], [rows[0], rows[0], rows[2]], rows[::-1]):
            with self.subTest(rows=changed), self.assertRaises(ValueError):
                join.require_mechanisms(dict(Mechanisms=changed))

    def test_foreign_name_and_each_owner_reject(self):
        for index in range(3):
            for key in ("Name", "NativeRoot", "ReferenceRoot"):
                rows = mechanisms()
                rows[index][key] = "foreign"
                with self.subTest(index=index, key=key), self.assertRaises(ValueError):
                    join.require_mechanisms(dict(Mechanisms=rows))

    def test_cm0_chain_not_substituted_for_cm3_root(self):
        rows = mechanisms()
        rows[1]["ReferenceRoots"] = ["SVC_Handler", "vPortSVCHandler_C", "vRestoreContextOfFirstTask"]
        del rows[1]["ReferenceRoot"]
        with self.assertRaises(ValueError):
            join.require_mechanisms(dict(Mechanisms=rows))

    def test_exact_difference_assignment_order_and_membership(self):
        for index in range(3):
            original = mechanisms()[index]["DifferenceIds"]
            for changed in (original[:-1], original + ["UNREVIEWED"], original + original[:1], original[::-1]):
                rows = mechanisms()
                rows[index]["DifferenceIds"] = changed
                with self.subTest(index=index, ids=changed), self.assertRaises(ValueError):
                    join.require_mechanisms(dict(Mechanisms=rows))

    def test_mechanism_extra_field_rejected(self):
        rows = mechanisms()
        rows[0]["InstructionEquivalence"] = True
        with self.assertRaises(ValueError):
            join.require_mechanisms(dict(Mechanisms=rows))

    def test_scope_does_not_promote(self):
        for mode in MODES:
            report = join.scope_report("CM3", mode)
            for key in ("FinalReferenceParity", "InstructionEquivalence", "PolicyEquivalence", "CompleteObjectProof",
                        "ArchiveExtraction", "LTO", "CpuExecution", "BoardExecution", "GlobalFreezeQualified"):
                self.assertIs(report[key], False, key)
            for key in ("RequiredCellsSatisfied", "NativeCommandsExecuted"):
                self.assertIs(type(report[key]), int)
                self.assertEqual(report[key], 0)


class CodegenControls(unittest.TestCase):
    def test_all_five_three_flag_recipes(self):
        for mode in MODES:
            result, artifact = compile_fixture(mode)
            join.require_codegen_records(result, artifact, mode)

    def test_wrong_target_mode_or_abi_reject(self):
        for index, flag in ((0, "-mcpu=cortex-m4"), (2, "-mfloat-abi=hard"), (3, "-O3")):
            result, artifact = compile_fixture()
            result["Sources"][0]["CompileFlags"][index] = flag
            with self.subTest(index=index), self.assertRaises(ValueError):
                join.require_codegen_records(result, artifact, "O2")

    def test_recorded_codegen_overrides_reject(self):
        for flag in ("-O0", "-O2", "-O3", "-flto", "-flto=auto", "-march=armv7-m", "-mabi=aapcs-linux",
                     "-mcpu=cortex-m33", "-mfpu=fpv4-sp-d16", "-mfloat-abi=softfp"):
            result, artifact = compile_fixture()
            result["Sources"][0]["CompileFlags"].append(flag)
            with self.subTest(flag=flag), self.assertRaises(ValueError):
                join.require_codegen_records(result, artifact, "O2")

    def test_extra_actual_compiler_argument_reject(self):
        for flag in ("-O3", "-flto", "-mfloat-abi=hard", "-DUNREVIEWED=1"):
            result, artifact = compile_fixture()
            result["Commands"][0]["Argv"].insert(-2, flag)
            with self.subTest(flag=flag), self.assertRaises(ValueError):
                join.require_codegen_records(result, artifact, "O2")

    def test_actual_source_object_dependency_tail_reject(self):
        for field in ("Source", "Object", "CompileDependencyFile"):
            result, artifact = compile_fixture()
            result["Sources"][0][field] = "not-the-actual-command"
            with self.subTest(field=field), self.assertRaises(ValueError):
                join.require_codegen_records(result, artifact, "O2")

    def test_duplicate_actual_compile_reject(self):
        result, artifact = compile_fixture()
        result["Commands"].append(copy.deepcopy(result["Commands"][0]))
        with self.assertRaises(ValueError):
            join.require_codegen_records(result, artifact, "O2")

    def test_git_configuration_argument_not_compiler(self):
        result, artifact = compile_fixture()
        result["Commands"].append(dict(Argv=["synthetic-git", "-c", "core.fsmonitor=false", "status"]))
        join.require_codegen_records(result, artifact, "O2")


class LinkControls(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="cm3-link-contract-")
        self.root = Path(self.temporary.name).resolve()
        self.addCleanup(self.temporary.cleanup)

    def test_both_sides_all_five_modes(self):
        for side in ("Native", "Reference"):
            for mode in MODES:
                result, artifact = link_fixture(self.root, side, mode)
                join.require_link_commands(result, artifact, self.root, side, mode)

    def test_wrong_profile_script_rejects(self):
        for side in ("Native", "Reference"):
            result, artifact = link_fixture(self.root, side)
            argv = result["Commands"][-1]["Argv"]
            argv[argv.index("-T") + 1] = str(self.root / "source/tools/fixtures/cm0_final_image/reference/link.ld")
            with self.subTest(side=side), self.assertRaises(ValueError):
                join.require_link_commands(result, artifact, self.root, side, "O2")

    def test_wrong_object_order_rejects(self):
        for side in ("Native", "Reference"):
            result, artifact = link_fixture(self.root, side)
            result["Sources"].reverse()
            with self.subTest(side=side), self.assertRaises(ValueError):
                join.require_link_commands(result, artifact, self.root, side, "O2")

    def test_missing_or_reordered_emit_flag_rejects(self):
        for mutate in ("remove", "move"):
            result, artifact = link_fixture(self.root, "Reference")
            argv = result["Commands"][-1]["Argv"]
            argv.remove("-Wl,--emit-relocs")
            if mutate == "move":
                argv.append("-Wl,--emit-relocs")
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                join.require_link_commands(result, artifact, self.root, "Reference", "O2")

    def test_extra_link_override_rejects(self):
        result, artifact = link_fixture(self.root)
        result["Commands"][-1]["Argv"].insert(1, "-flto")
        with self.assertRaises(ValueError):
            join.require_link_commands(result, artifact, self.root, "Native", "O2")

    def test_map_or_output_mismatch_rejects(self):
        for field in ("Map", "Path"):
            result, artifact = link_fixture(self.root)
            result["Links"][1][field] = str(self.root / "not-the-actual-link")
            with self.subTest(field=field), self.assertRaises(ValueError):
                join.require_link_commands(result, artifact, self.root, "Native", "O2")

    def test_duplicate_link_command_rejects(self):
        result, artifact = link_fixture(self.root)
        result["Commands"].append(copy.deepcopy(result["Commands"][-1]))
        with self.assertRaises(ValueError):
            join.require_link_commands(result, artifact, self.root, "Native", "O2")


class BoundaryControls(unittest.TestCase):
    def ledger(self):
        identities = list(dict.fromkeys(value for row in mechanisms() for value in row["DifferenceIds"]))
        return identities, "\n".join("### " + value + "\n\nSource-derived rationale.\n" for value in identities)

    def test_six_nonempty_captured_rationales(self):
        identities, text = self.ledger()
        join.require_ledger(text, dict(DifferenceIds=identities))

    def test_each_empty_rationale_rejects(self):
        identities, text = self.ledger()
        for identity in identities:
            changed = text.replace("### " + identity + "\n\nSource-derived rationale.", "### " + identity + "\n\n")
            with self.subTest(identity=identity), self.assertRaises(ValueError):
                join.require_ledger(changed, dict(DifferenceIds=identities))

    def test_duplicate_rationale_heading_rejects(self):
        identities, text = self.ledger()
        with self.assertRaises(ValueError):
            join.require_ledger(text + "\n### " + identities[0] + "\nSecond rationale.\n", dict(DifferenceIds=identities))

    def test_missing_rationale_heading_rejects(self):
        identities, text = self.ledger()
        with self.assertRaises(ValueError):
            join.require_ledger(text.replace("### " + identities[0], "### FOREIGN"), dict(DifferenceIds=identities))

    def test_other_section_cannot_fill_empty_rationale(self):
        identities, text = self.ledger()
        text = text.replace("### " + identities[0] + "\n\nSource-derived rationale.",
                            "### " + identities[0] + "\n\n### FOREIGN\nDifferent section.")
        with self.assertRaises(ValueError):
            join.require_ledger(text, dict(DifferenceIds=identities))

    def input_pair(self):
        temporary = tempfile.TemporaryDirectory(prefix="cm3-physical-controls-")
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        left, right = root / "native.o", root / "reference.o"
        left.write_bytes(b"native synthetic object")
        right.write_bytes(b"reference synthetic object")
        return left, right

    def test_disjoint_native_reference_roles(self):
        left, right = self.input_pair()
        join.require_cross_side_inputs(dict(ImageInputs=[left]), dict(ImageInputs=[right]))

    def test_cross_side_same_path_rejects(self):
        left, _ = self.input_pair()
        with self.assertRaises(ValueError):
            join.require_cross_side_inputs(dict(ImageInputs=[left]), dict(ImageInputs=[left]))

    def test_cross_side_hard_link_rejects(self):
        left, right = self.input_pair()
        right.unlink()
        os.link(left, right)
        with self.assertRaises(ValueError):
            join.require_cross_side_inputs(dict(ImageInputs=[left]), dict(ImageInputs=[right]))


class OutputAdmissionControls(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="cm3-output-admission-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.native, self.reference = self.root / "native", self.root / "reference"
        self.inventory, self.checkout, self.headers = (self.root / name for name in ("inventory", "freertos", "headers"))
        for path in (self.native, self.reference, self.inventory, self.checkout / "include", self.headers):
            path.mkdir(parents=True)
        original = self.headers / "source.h"
        original.write_bytes(b"synthetic header")
        for producer in (self.native, self.reference):
            captured, generated = producer / "copy.h", producer / "generated.h"
            captured.write_bytes(b"synthetic header")
            generated.write_bytes(b"synthetic generated header")
            result = dict(SourceInventoryReceipt=str(self.inventory), Commands=[dict(Label="reference git status",
                          Argv=["git.exe", "-C", str(self.checkout), "status"])])
            inputs = dict(Files=[dict(Original=str(original), Captured=str(captured), Sha256="A" * 64)],
                          Generated={str(generated): "B" * 64})
            (producer / "results.json").write_text(json.dumps(result), encoding="ascii")
            (producer / "inputs.json").write_text(json.dumps(inputs), encoding="ascii")
            artifacts = {name: hashlib.sha256((producer / name).read_bytes()).hexdigest().upper()
                         for name in ("results.json", "inputs.json")}
            (producer / "artifacts.json").write_text(json.dumps(dict(Artifacts=artifacts)), encoding="ascii")

    def arguments(self, output=None):
        values = dict(output_dir=str(output or self.root / "fresh-output"),
                      native_build=str(self.native), reference_build=str(self.reference))
        for side, producer in (("native", self.native), ("reference", self.reference)):
            for kind, name in (("receipt", "results.json"), ("artifacts", "artifacts.json")):
                values[side + "_" + kind + "_sha256"] = hashlib.sha256((producer / name).read_bytes()).hexdigest().upper()
        return SimpleNamespace(**values)

    def test_unrelated_fresh_output_remains_uncreated(self):
        output = self.root / "fresh-output"
        self.assertEqual(join.output_directory(output, self.native, self.reference), output)
        self.assertFalse(output.exists())

    def test_original_reference_include_output_rejects_before_mkdir(self):
        output = self.checkout / "include" / "fresh-output"
        with self.assertRaises(ValueError):
            join.output_directory(output, self.native, self.reference)
        self.assertFalse(output.exists())

    def test_inventory_output_rejects_before_mkdir(self):
        output = self.inventory / "fresh-output"
        with self.assertRaises(ValueError):
            join.output_directory(output, self.native, self.reference)
        self.assertFalse(output.exists())

    def test_original_header_tree_output_rejects_before_mkdir(self):
        output = self.headers / "fresh-output"
        with self.assertRaises(ValueError):
            join.output_directory(output, self.native, self.reference)
        self.assertFalse(output.exists())


    def test_authenticated_preparation_does_not_create_output(self):
        args = self.arguments()
        self.assertEqual(join.prepare_output(args), Path(args.output_dir))
        self.assertFalse(Path(args.output_dir).exists())

    def test_each_wrong_caller_hash_rejects_before_mkdir(self):
        for side in ("native", "reference"):
            for kind in ("receipt", "artifacts"):
                args = self.arguments()
                setattr(args, side + "_" + kind + "_sha256", "0" * 64)
                with self.subTest(side=side, kind=kind), self.assertRaisesRegex(ValueError, "hash mismatch"):
                    join.prepare_output(args)
                self.assertFalse(Path(args.output_dir).exists())

    def test_unbound_inputs_reject_before_mkdir(self):
        args = self.arguments()
        (self.native / "inputs.json").write_bytes(b'{"Files":[],"Generated":{}}')
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            join.prepare_output(args)
        self.assertFalse(Path(args.output_dir).exists())

    def test_transient_weakened_declaration_rejects_before_mkdir(self):
        args = self.arguments(self.checkout / "include" / "fresh-output")
        original_read = Path.read_bytes
        target = self.reference / "inputs.json"
        changed = json.loads(target.read_bytes())
        changed["Files"] = []
        substitute = json.dumps(changed).encode("ascii")
        calls = []

        def intercept(path):
            if path == target and not calls:
                calls.append(True)
                return substitute
            return original_read(path)

        with patch.object(Path, "read_bytes", intercept), self.assertRaisesRegex(ValueError, "hash mismatch"):
            join.prepare_output(args)
        self.assertEqual(calls, [True])
        self.assertFalse(Path(args.output_dir).exists())

    def test_valid_hash_manifest_must_bind_same_receipt(self):
        artifact_path = self.native / "artifacts.json"
        manifest = json.loads(artifact_path.read_bytes())
        manifest["Artifacts"]["results.json"] = "0" * 64
        artifact_path.write_text(json.dumps(manifest), encoding="ascii")
        args = self.arguments()
        with self.assertRaisesRegex(ValueError, "receipt/manifest binding"):
            join.prepare_output(args)
        self.assertFalse(Path(args.output_dir).exists())

    def test_authenticated_input_roots_reject_before_mkdir(self):
        for root in (self.checkout / "include", self.inventory, self.headers):
            args = self.arguments(root / "fresh-output")
            with self.subTest(root=root), self.assertRaises(ValueError):
                join.prepare_output(args)
            self.assertFalse(Path(args.output_dir).exists())


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--report", required=True)
    args = parser.parse_args()
    output = Path(args.report).resolve()
    if sys.flags.optimize or output.exists() or not output.is_relative_to(Path(tempfile.gettempdir()).resolve()):
        raise SystemExit("unoptimized Python and fresh TEMP report required")
    sources = (Path(__file__), HERE / "join.py", join._SHARED_PATH, join._GENERIC_PATH)
    hashes = {str(path): hashlib.sha256(path.read_bytes()).hexdigest().upper() for path in sources}
    if hashes[str(HERE / "join.py")] != hashlib.sha256(SOURCE_BYTES).hexdigest().upper():
        raise SystemExit("executed join source drift")
    for path, data in ((join._SHARED_PATH, join._SHARED_BYTES), (join._GENERIC_PATH, join._GENERIC_BYTES)):
        if hashes[str(path)] != hashlib.sha256(data).hexdigest().upper():
            raise SystemExit("executed join helper drift")
    suite = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(case)
                              for case in (MechanismControls, CodegenControls, LinkControls, BoundaryControls,
                                           OutputAdmissionControls))
    with patch("subprocess.Popen", side_effect=AssertionError("pure controls cannot launch processes")):
        result = unittest.TextTestRunner(verbosity=2).run(suite)
    drift = [str(path) for path in sources if hashlib.sha256(path.read_bytes()).hexdigest().upper() != hashes[str(path)]]
    report = dict(Status="PASS" if result.wasSuccessful() and not drift else "FAIL", Tests=result.testsRun,
        Failures=len(result.failures), Errors=len(result.errors), Skipped=len(result.skipped), SourceHashes=hashes,
        SourceDrift=drift, Scope="PURE_CM3_FINAL_JOIN_CONTRACTS_ONLY", RequiredCellsSatisfied=0,
        NativeCommandsExecuted=0, CpuExecution=False, BoardExecution=False, GlobalFreezeQualified=False,
        FailureDetails=[dict(Test=str(case), Detail=detail) for case, detail in result.failures + result.errors])
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="ascii")
    print(report["Status"], str(output))
    return 0 if report["Status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
