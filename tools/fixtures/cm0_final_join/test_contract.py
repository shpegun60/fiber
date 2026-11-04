"""Pure CM0 join contracts; synthetic inputs, no ELF parser or target proof."""
import argparse
import builtins
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("cm0_join_contract", HERE / "join.py")
join = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(join)

PROFILES = ("CM0", "CM0PLUS", "CM0PLUSVTOR")
MODES = ("O0", "Og", "O2", "Os", "O3")
REFERENCE_ROOTS = ("vStartFirstTask", "SVC_Handler", "vPortSVCHandler_C",
                   "vRestoreContextOfFirstTask", "PendSV_Handler")
DIFFERENCES = ("FAP-COMMON-START", "FAP-COMMON-PROVENANCE",
               "FAP-CM0-STAGED-FRAME", "FAP-COMMON-SCHEDULER",
               "FAP-COMMON-MASK-RESTORE")
FALSE_FLAGS = ("FinalReferenceParity", "InstructionEquivalence", "PolicyEquivalence",
               "CompleteObjectProof", "ArchiveExtraction", "LTO", "CpuExecution",
               "BoardExecution", "GlobalFreezeQualified")


def mechanisms():
    # Independent specification: the first-restore reference chain is one row.
    return [
        dict(Name="first-start", NativeRoot="fiber_port_start_first_context",
             ReferenceRoots=["vStartFirstTask"],
             DifferenceIds=["FAP-COMMON-START", "FAP-COMMON-PROVENANCE"]),
        dict(Name="first-restore", NativeRoot="SVC_Handler",
             ReferenceRoots=["SVC_Handler", "vPortSVCHandler_C", "vRestoreContextOfFirstTask"],
             DifferenceIds=["FAP-COMMON-PROVENANCE", "FAP-CM0-STAGED-FRAME"]),
        dict(Name="PendSV", NativeRoot="PendSV_Handler", ReferenceRoots=["PendSV_Handler"],
             DifferenceIds=["FAP-COMMON-SCHEDULER", "FAP-COMMON-PROVENANCE",
                            "FAP-COMMON-MASK-RESTORE", "FAP-CM0-STAGED-FRAME"]),
    ]


class ContractTests(unittest.TestCase):
    def owners(self):
        self.calls = []
        self.answers = (object(), object())

        def image(index):
            def function(name, **options):
                self.calls.append((index, name, options))
                return self.answers[index]
            return SimpleNamespace(function=function)

        return join.ReferenceOwners(image(0), image(1))

    def test_fixed_profiles_modes_and_pin(self):
        self.assertEqual(join.PROFILES, PROFILES)
        self.assertEqual(join.MODES, MODES)
        self.assertEqual(join.PIN, "a50edad08b29052631aa469d4df6e6ec7ff68878")

    def test_five_reference_roots_route_to_exact_owning_object(self):
        owners = self.owners()
        for name in REFERENCE_ROOTS:
            index = 0 if name == "vPortSVCHandler_C" else 1
            with self.subTest(name=name):
                self.assertIs(owners.function(name), self.answers[index])
                self.assertEqual(self.calls[-1], (index, name, {}))
        self.assertEqual(len(self.calls), 5)

    def test_decoder_optins_are_forwarded_without_token_rewriting(self):
        owners = self.owners()
        options = dict(literal_islands=True, thumb1_tail_nop=True)
        for name in REFERENCE_ROOTS:
            index = 0 if name == "vPortSVCHandler_C" else 1
            with self.subTest(name=name):
                self.assertIs(owners.function(name, **options), self.answers[index])
                self.assertEqual(self.calls[-1], (index, name, options))
        self.assertEqual(options, dict(literal_islands=True, thumb1_tail_nop=True))

    def test_foreign_reference_names_reject_before_either_owner(self):
        owners = self.owners()
        for name in ("fiber_port_start_first_context", "vTaskSwitchContext", "pxCurrentTCB",
                     "vPortSVCHandler", "xPortPendSVHandler", "svc_handler", "", None, True, 5):
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "exact reference root"):
                owners.function(name, literal_islands=True)
        self.assertEqual(self.calls, [])

    def test_owner_rejection_propagates_without_fallback(self):
        for name in REFERENCE_ROOTS:
            port, assembly = Mock(), Mock()
            selected = port if name == "vPortSVCHandler_C" else assembly
            other = assembly if selected is port else port
            error = RuntimeError("synthetic owning decoder rejection")
            selected.function.side_effect = error
            with self.subTest(name=name), self.assertRaises(RuntimeError) as caught:
                join.ReferenceOwners(port, assembly).function(name, literal_islands=True)
            self.assertIs(caught.exception, error)
            selected.function.assert_called_once_with(name, literal_islands=True)
            other.function.assert_not_called()

    def test_exact_three_mechanisms_for_all_profiles(self):
        for profile in PROFILES:
            with self.subTest(profile=profile):
                join.require_pairings(dict(Mechanisms=mechanisms()), profile)

    def test_missing_duplicate_extra_and_reordered_mechanisms_reject(self):
        rows = mechanisms()
        variants = (rows[:-1], [rows[0], rows[0], rows[2]], rows + [rows[0]], rows[::-1])
        for profile in PROFILES:
            for index, changed in enumerate(variants):
                with self.subTest(profile=profile, variant=index), self.assertRaisesRegex(ValueError, "exact mechanism/difference"):
                    join.require_pairings(dict(Mechanisms=changed), profile)

    def test_native_and_reference_assignments_are_not_interchangeable(self):
        for index in range(3):
            for field, value in (("Name", "foreign"), ("NativeRoot", "foreign"),
                                 ("ReferenceRoots", ["foreign"])):
                rows = mechanisms()
                rows[index][field] = value
                with self.subTest(index=index, field=field), self.assertRaises(ValueError):
                    join.require_pairings(dict(Mechanisms=rows), "CM0")
        rows = mechanisms()
        rows[0]["NativeRoot"], rows[1]["NativeRoot"] = rows[1]["NativeRoot"], rows[0]["NativeRoot"]
        with self.assertRaises(ValueError):
            join.require_pairings(dict(Mechanisms=rows), "CM0")

    def test_first_restore_requires_complete_ordered_three_root_chain(self):
        expected = ["SVC_Handler", "vPortSVCHandler_C", "vRestoreContextOfFirstTask"]
        for roots in ([expected[0]], expected[1:], expected[:2], expected[::-1],
                      [expected[0], expected[1], expected[1]], expected + ["vTaskSwitchContext"]):
            rows = mechanisms()
            rows[1]["ReferenceRoots"] = roots
            with self.subTest(roots=roots), self.assertRaises(ValueError):
                join.require_pairings(dict(Mechanisms=rows), "CM0")
        rows = mechanisms()
        rows[1]["ReferenceRoot"] = rows[1].pop("ReferenceRoots")
        with self.assertRaises(ValueError):
            join.require_pairings(dict(Mechanisms=rows), "CM0")

    def test_difference_membership_order_duplicates_and_assignment_are_exact(self):
        for index in range(3):
            original = mechanisms()[index]["DifferenceIds"]
            for ids in (original[:-1], original + ["UNREVIEWED"], original + [original[0]], original[::-1]):
                rows = mechanisms()
                rows[index]["DifferenceIds"] = ids
                with self.subTest(index=index, ids=ids), self.assertRaises(ValueError):
                    join.require_pairings(dict(Mechanisms=rows), "CM0")
        rows = mechanisms()
        rows[0]["DifferenceIds"], rows[1]["DifferenceIds"] = rows[1]["DifferenceIds"], rows[0]["DifferenceIds"]
        with self.assertRaises(ValueError):
            join.require_pairings(dict(Mechanisms=rows), "CM0")

    def test_foreign_pairing_profiles_reject(self):
        for profile in ("CM4", "CM7", "CM0+", "cm0", "", None, True, 0):
            with self.subTest(profile=profile), self.assertRaisesRegex(ValueError, "exact mechanism profile"):
                join.require_pairings(dict(Mechanisms=mechanisms()), profile)

    def codegen(self, profile="CM0", mode="O2"):
        cpu = "cortex-m0" if profile == "CM0" else "cortex-m0plus"
        artifact = dict(compile_flags=["-mcpu=" + cpu, "-mthumb", "-mfloat-abi=soft"])
        sources, commands = [], []
        for index, name in enumerate(("port.c", "startup.S")):
            flags = [*artifact["compile_flags"], "-" + mode, "-g0"]
            flags += (["-DPILOT_HAS_VTOR=" + str(int(profile == "CM0PLUSVTOR"))]
                      if name.endswith(".S") else ["-std=gnu11", "-ffreestanding"])
            obj = name + ".o"
            sources.append(dict(Source=name, Object=obj, CompileFlags=flags,
                                CompileDependencyFile=name + ".d"))
            commands.append(dict(Argv=["synthetic-gcc", *flags, "-MD", "-MF", name + ".d",
                                       "-MT", "pilot-source-" + str(index), "-c", name, "-o", obj]))
        return dict(Sources=sources, Commands=commands), artifact

    def test_all_fifteen_three_flag_codegen_prefixes(self):
        for profile in PROFILES:
            for mode in MODES:
                result, artifact = self.codegen(profile, mode)
                with self.subTest(profile=profile, mode=mode):
                    self.assertEqual(len(artifact["compile_flags"]), 3)
                    join.require_codegen_records(result, artifact, mode)

    def test_wrong_mode_or_target_prefix_rejects(self):
        original, artifact = self.codegen()
        for mode in ("O0", "Og", "Os", "O3"):
            with self.subTest(mode=mode), self.assertRaisesRegex(ValueError, "target/mode flag prefix"):
                join.require_codegen_records(original, artifact, mode)
        for prefix in (["-mthumb", "-mcpu=cortex-m0", "-mfloat-abi=soft"],
                       ["-mcpu=cortex-m0plus", "-mthumb", "-mfloat-abi=soft"],
                       ["-mcpu=cortex-m0", "-mthumb", "-mfloat-abi=hard"]):
            result = copy.deepcopy(original)
            result["Sources"][0]["CompileFlags"][:3] = prefix
            with self.subTest(prefix=prefix), self.assertRaises(ValueError):
                join.require_codegen_records(result, artifact, "O2")

    def test_recorded_codegen_overrides_reject(self):
        original, artifact = self.codegen()
        for flag in ("-O0", "-O2", "-O3", "-flto", "-flto=auto", "-march=armv7-m",
                     "-mabi=aapcs-linux", "-mcpu=cortex-m0plus", "-mfpu=fpv4-sp-d16", "-mfloat-abi=hard"):
            result = copy.deepcopy(original)
            result["Sources"][0]["CompileFlags"].append(flag)
            with self.subTest(flag=flag), self.assertRaisesRegex(ValueError, "codegen override"):
                join.require_codegen_records(result, artifact, "O2")

    def test_malformed_recorded_flags_reject(self):
        original, artifact = self.codegen()
        for flags in (None, "-O2", (), [True], ["-mcpu=cortex-m0", "-mthumb", 0, "-O2"]):
            result = copy.deepcopy(original)
            result["Sources"][0]["CompileFlags"] = flags
            with self.subTest(flags=flags), self.assertRaisesRegex(ValueError, "target/mode flag prefix"):
                join.require_codegen_records(result, artifact, "O2")

    def test_missing_or_duplicate_actual_compile_rejects(self):
        original, artifact = self.codegen()
        for duplicate in (False, True):
            result = copy.deepcopy(original)
            if duplicate:
                result["Commands"].append(copy.deepcopy(result["Commands"][0]))
            else:
                result["Commands"].pop(0)
            with self.subTest(duplicate=duplicate), self.assertRaisesRegex(ValueError, "exactly one actual compile"):
                join.require_codegen_records(result, artifact, "O2")

    def test_actual_compile_flag_source_and_object_binding(self):
        original, artifact = self.codegen()
        for field in ("flags", "source", "object"):
            result = copy.deepcopy(original)
            argv = result["Commands"][0]["Argv"]
            if field == "flags":
                argv[1] = "-mcpu=cortex-m7"
            elif field == "source":
                # Keep the declared path elsewhere so command discovery alone passes.
                argv[argv.index("-c") + 1] = "foreign.c"
                argv.append("port.c")
            else:
                argv[argv.index("-o") + 1] = "foreign.o"
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "compiler flag/source/object binding"):
                join.require_codegen_records(result, artifact, "O2")

    def test_actual_codegen_overrides_after_recorded_prefix_reject(self):
        original, artifact = self.codegen()
        for flag in ("-O3", "-flto", "-march=armv7-m", "-mcpu=cortex-m0plus", "-mfloat-abi=hard"):
            result = copy.deepcopy(original)
            argv = result["Commands"][0]["Argv"]
            argv.insert(argv.index("-c"), flag)
            with self.subTest(flag=flag), self.assertRaises(ValueError):
                join.require_codegen_records(result, artifact, "O2")

    def test_pinned_exact_bytes_include_final_newline_identity(self):
        for blob in (b"", b"single line", b"first\nsecond\n", b"first\nsecond"):
            with self.subTest(blob=blob):
                self.assertEqual(join.pinned_comparison(blob, blob), "exact")

    def test_pinned_whole_lf_to_crlf_only(self):
        for blob in (b"first\nsecond\n", b"first\nsecond", b"\n\n"):
            with self.subTest(blob=blob):
                self.assertEqual(join.pinned_comparison(blob.replace(b"\n", b"\r\n"), blob),
                                 "git-lf-worktree-crlf")

    def test_pinned_mixed_or_repeated_crlf_rejects(self):
        blob = b"first\nsecond\nthird\n"
        for actual in (b"first\r\nsecond\nthird\n", b"first\nsecond\r\nthird\r\n",
                       b"first\r\r\nsecond\r\nthird\r\n", b"first\rsecond\rthird\r"):
            with self.subTest(actual=actual), self.assertRaisesRegex(ValueError, "exact LF or whole-file CRLF"):
                join.pinned_comparison(actual, blob)

    def test_pinned_no_semantic_or_other_whitespace_transforms(self):
        blob = b"int value = 1;\nsecond\n"
        for actual in (b"int value=1;\nsecond\n", blob + b"\n", blob[:-1], b"\xef\xbb\xbf" + blob,
                       b"int value = 2;\nsecond\n", b"int value = 1; \nsecond\n"):
            with self.subTest(actual=actual), self.assertRaises(ValueError):
                join.pinned_comparison(actual, blob)
        with self.assertRaises(ValueError):
            join.pinned_comparison(b"first\nsecond\n", b"first\r\nsecond\r\n")

    def assert_scope(self, report):
        self.assertEqual(report["Scope"], "CM0_FAMILY_FINAL_MECHANISM_COMPOSITION_ONLY")
        for name in FALSE_FLAGS:
            self.assertIs(report[name], False, name)
        for name in ("RequiredCellsSatisfied", "NativeCommandsExecuted"):
            self.assertIs(type(report[name]), int, name)
            self.assertEqual(report[name], 0, name)

    def test_all_fifteen_initial_reports_have_no_promotion(self):
        for profile in PROFILES:
            for mode in MODES:
                with self.subTest(profile=profile, mode=mode):
                    report = join.scope_report(profile, mode)
                    self.assertEqual((report["Profile"], report["Mode"]), (profile, mode))
                    self.assertEqual(report["Status"], "FAIL")
                    self.assertIs(type(report["ClosedBodies"]), int)
                    self.assertEqual(report["ClosedBodies"], 0)
                    self.assertEqual(report["Mechanisms"], [])
                    self.assert_scope(report)

    def test_scope_report_does_not_share_mechanisms(self):
        first = join.scope_report("CM0", "O2")
        first["Mechanisms"].append(dict(Name="synthetic"))
        self.assertEqual(join.scope_report("CM0", "O2")["Mechanisms"], [])

    def synthetic_run(self, profile="CM0", mode="O2", checker_error=None):
        args = SimpleNamespace(native_build="synthetic-native", reference_build="synthetic-reference",
            native_receipt_sha256="A" * 64, native_artifacts_sha256="B" * 64,
            reference_receipt_sha256="C" * 64, reference_artifacts_sha256="D" * 64,
            profile=profile, mode=mode)
        inventory = Path("synthetic-inventory")

        def group(side, roots, prelinks, count):
            return dict(Inventory=inventory, Result=dict(SourceInventorySha256="E" * 64),
                MechanismObject=object(), Roots=[dict(Name=name) for name in roots],
                Twins=dict(Identical=True), Root=Path("synthetic-" + side.lower()),
                ReceiptSha256=("A" if side == "Native" else "C") * 64,
                Prelinks=[dict(Path=name, Sha256="F" * 64) for name in prelinks], UniqueImageInputs=count)

        native = group("Native", ("fiber_port_start_first_context", "SVC_Handler", "PendSV_Handler"),
                       ("03-fiber_port.o",), 13)
        reference = group("Reference", REFERENCE_ROOTS, ("00-port.o", "01-portasm.o"), 9)
        proof = dict(Mechanisms=mechanisms(), DifferenceIds=list(DIFFERENCES))
        checker = Mock(return_value=proof, side_effect=checker_error)
        admission = Mock()
        api = dict(checker=SimpleNamespace(check_pair=checker),
                   attributes=SimpleNamespace(require_proof=admission))
        watch = SimpleNamespace(structured=Mock(return_value={}),
            read=Mock(return_value="".join("### " + name + "\n" for name in DIFFERENCES).encode("ascii")))
        with patch.object(join, "load_api", return_value=api), \
                patch.object(join, "prepare_group", side_effect=(native, reference)):
            report = join.run(args, Path("synthetic-output"), watch)
        checker.assert_called_once_with(native["MechanismObject"], reference["MechanismObject"], mode)
        admission.assert_called_once_with(proof, mode)
        return report, native, reference, proof

    def test_synthetic_success_keeps_eight_bodies_and_all_scope_limits(self):
        for profile in PROFILES:
            for mode in MODES:
                with self.subTest(profile=profile, mode=mode):
                    report, native, reference, proof = self.synthetic_run(profile, mode)
                    self.assertEqual(report["Status"], "PASS")
                    self.assertEqual(report["ClosedBodies"], 8)
                    self.assertEqual(report["Mechanisms"], mechanisms())
                    self.assertIs(report["ProtocolProof"], proof)
                    self.assertIs(report["NativeFinalRoots"], native["Roots"])
                    self.assertIs(report["ReferenceFinalRoots"], reference["Roots"])
                    self.assertEqual([row["UniqueImageInputs"] for row in report["ProducerBindings"]], [13, 9])
                    self.assertEqual([len(row["Prelinks"]) for row in report["ProducerBindings"]], [1, 2])
                    self.assert_scope(report)

    def test_checker_rejection_cannot_return_successful_report(self):
        with self.assertRaisesRegex(ValueError, "synthetic complete protocol mismatch"):
            self.synthetic_run(checker_error=ValueError("synthetic complete protocol mismatch"))

    def test_import_does_not_load_parser_or_execute_or_write(self):
        before = {name: module for name, module in sys.modules.items()
                  if name == "elftools" or name.startswith("elftools.")}
        actual_import = builtins.__import__

        def guarded_import(name, *args, **kwargs):
            if name == "elftools" or name.startswith("elftools."):
                raise AssertionError("parser import forbidden in pure contract controls")
            return actual_import(name, *args, **kwargs)

        spec = importlib.util.spec_from_file_location("cm0_join_contract_import_control", HERE / "join.py")
        module = importlib.util.module_from_spec(spec)
        with patch("builtins.__import__", side_effect=guarded_import), \
                patch("subprocess.Popen", side_effect=AssertionError("process execution forbidden")), \
                patch.object(Path, "mkdir", side_effect=AssertionError("import write forbidden")), \
                patch.object(Path, "write_bytes", side_effect=AssertionError("import write forbidden")), \
                patch.object(Path, "write_text", side_effect=AssertionError("import write forbidden")):
            spec.loader.exec_module(module)
        after = {name: value for name, value in sys.modules.items()
                 if name == "elftools" or name.startswith("elftools.")}
        self.assertEqual(after, before)


def main():
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--report", required=True)
    args = parser.parse_args()
    path = Path(args.report).resolve()
    if path.exists() or sys.flags.optimize or not path.is_relative_to(Path(tempfile.gettempdir()).resolve()):
        raise SystemExit("fresh report inside TEMP / unoptimized Python required")
    sources = (Path(__file__).resolve(), HERE / "join.py", HERE.with_name("classic_final_join") / "join.py")
    hashes = {str(source): hashlib.sha256(source.read_bytes()).hexdigest().upper() for source in sources}
    with patch("subprocess.Popen", side_effect=AssertionError("process execution forbidden")):
        result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(ContractTests))
    drift = [name for name, value in hashes.items() if hashlib.sha256(Path(name).read_bytes()).hexdigest().upper() != value]
    report = dict(Status="PASS" if result.wasSuccessful() and not drift else "FAIL", Tests=result.testsRun,
        Failures=len(result.failures), Errors=len(result.errors), Skipped=len(result.skipped),
        SourceHashes=hashes, SourceDrift=drift, SyntheticFixturesOnly=True, ParserExecution=False,
        ToolInvocations=0, NativeCommandsExecuted=0, RequiredCellsSatisfied=0,
        FinalReferenceParity=False, InstructionEquivalence=False, PolicyEquivalence=False,
        CpuExecution=False, BoardExecution=False, GlobalFreezeQualified=False,
        FailureDetails=[dict(Test=str(case), Detail=detail) for case, detail in result.failures + result.errors])
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="ascii")
    print(report["Status"], report["Tests"], str(path))
    return 0 if report["Status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
