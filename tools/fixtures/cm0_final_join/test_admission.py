"""Pure CM0 metadata controls and an optional independent receipt-replay API.

No scripts, compiler, subprocess or target is invoked. Optional --actual-cases
JSON has Cases=[{Receipt, ReceiptSha256, Expected}], where Expected contains
the seven validate_receipt keyword arguments independently supplied by the
caller. Its --actual-cases-sha256 authenticates that expectation buffer.
Actual replay remains metadata admission, never artifact/ELF/closure proof.
"""
import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path, PureWindowsPath
import sys
import traceback
import unittest
from unittest.mock import patch


sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("cm0_final_join_admission_controls", HERE / "admission.py")
admission = importlib.util.module_from_spec(SPEC)
ADMISSION_BYTES = (HERE / "admission.py").read_bytes()
exec(compile(ADMISSION_BYTES, str(HERE / "admission.py"), "exec"), admission.__dict__)
SHA = "A" * 64
ACTUAL_CASES = []
ACTUAL_HASHES = {}


def artifact(profile):
    cpu = "cortex-m0" if profile == "CM0" else "cortex-m0plus"
    return dict(role="runtime", source_group_id="CM0", abi_contract="forward8",
        target=dict(cpu=cpu, architecture="ARMV6M", float_abi="soft", fpu_present=False, fpu_used=False,
            fpu_unit="", fp_stacking="none", vtor=profile == "CM0PLUSVTOR", mpu_regions=0,
            security_role="classic", psplim_slot=False, psplim_register=False, mve="none", pac=False,
            bti=False, errata_policy="none", r9_abi="aapcs", nvic_priority_bits=2, scheduler_basepri=0),
        compile_flags=["-mcpu=" + cpu, "-mthumb", "-mfloat-abi=soft"],
        defines=dict(FIBER_PORT_ARMV6M="1", FIBER_PORT_BUILD_SELECTED="1"),
        upstream_defines=dict(FIBER_FREERTOS_PARITY_ENABLE_MPU="0", FIBER_FREERTOS_PARITY_ENABLE_FPU="0",
                             FIBER_FREERTOS_PARITY_ENABLE_TRUSTZONE="0"),
        upstream_sources=["portable/GCC/ARM_CM0/port.c", "portable/GCC/ARM_CM0/portasm.c"])


def command(argv, label, root):
    return dict(Status="PASS", Exit=0, TimedOut=False, Error=None, Label=label, Argv=argv, Cwd=str(root), Seconds=0.01)


def receipt(side="Native", profile="CM0", mode="O2"):
    root = PureWindowsPath("C:/pure-not-executed") / side / (profile + "-" + mode)
    selected = artifact(profile)
    if side == "Native":
        names = ["context/" + name for name in ("context_core.c", "context_runtime_state.c", "context_panic.c")]
        names += ["fiber/port/ARM_CM0/" + name for name in ("fiber_port.c", "fiber_port_boot.c", "fiber_port_exception.c")]
        names += ["fiber/port/fiber_port_context_cohort_expectation.c",
                  "tools/fixtures/classic_final_image/application.c", "tools/fixtures/classic_final_image/startup.S"]
        sources = [str(root / "source" / name) for name in names]
    else:
        sources = [str(root / "freertos" / name) for name in selected["upstream_sources"]]
        sources += [str(root / "source/tools/fixtures/cm0_final_image/reference" / name)
                    for name in ("providers.c", "consumer.c", "startup.S")]
    row = dict(Verdict=admission.VERDICTS[side], Error=None, Profile=profile, Mode=mode,
        Cohort=admission.PROFILES[profile][0], Linkage="direct", RequiredCellsSatisfied=0, InputDrift=[],
        SourceInventorySha256=SHA, CohortArtifact=copy.deepcopy(selected), TranslationUnits=len(sources),
        FinalExecutableLinks=2, TwinLoadImageIdentical=True, TwinAllocatedSectionsIdentical=True,
        ReferenceBuilt=side == "Reference", Sources=[], Links=[], ObjectChecks=[], Commands=[])
    row.update({key: False for key in admission.FALSE_FIELDS})
    if side == "Reference":
        row.update({key: False for key in admission.REFERENCE_FALSE})
        row.update(ReferenceCommit="a50edad08b29052631aa469d4df6e6ec7ff68878", SourceGroup="CM0",
            ReferenceClosingIdentityVerified=True, ArtifactSealVerified=True,
            ProofScope="PINNED_REFERENCE_CM0_FIVE_OWNING_PRELINK_ROOTS_AND_DIRECT_TWINS_ONLY",
            SchedulerThreshold="BASEPRI-NOT-APPLICABLE;PRIMASK-ENVELOPE", FPPolicy="NOT-APPLICABLE-NO-FPU",
            DeclaredVTOR=profile == "CM0PLUSVTOR", FixtureHandlerInstallationCheck=int(profile == "CM0PLUSVTOR"))
    tool = "C:/pure-not-executed/gcc.exe"
    for index, source in enumerate(sources):
        obj = root / "objects" / ("%02d-" % index + PureWindowsPath(source).stem + ".o")
        assembly = source.endswith(".S")
        flags = [*selected["compile_flags"], "-" + mode, "-g0"]
        defines = ({"PILOT_HAS_VTOR": str(int(selected["target"]["vtor"]))} if side == "Native" else {}) if assembly else (
            selected["defines"] if side == "Native" else selected["upstream_defines"])
        flags += sorted("-D" + key + "=" + value for key, value in defines.items())
        dependencies = [dict(Path=source, Sha256=SHA)]
        dependency_file = str(obj.with_suffix(".compile.d"))
        row["Sources"].append(dict(Source=source, SourceSha256=SHA, Object=str(obj), ObjectSha256=SHA,
            CompileFlags=flags, CompileDependencyFile=dependency_file, CompileDependenciesVerified=True,
            Dependencies=dependencies, ActualCompileDependencies=copy.deepcopy(dependencies)))
        row["Commands"].append(command([tool, *flags, "-MD", "-MF", dependency_file, "-MT", "pilot-source-" + str(index),
                                         "-c", source, "-o", str(obj)], "compile " + PureWindowsPath(source).name, root))
    for kind in ("ordinary", "emit-relocs"):
        row["Links"].append(dict(Kind=kind, Path=str(root / (kind + ".elf")), Sha256=SHA,
                                 Map=str(root / (kind + ".map")), MapSha256=SHA))
        row["Commands"].append(command([tool, "link-metadata-control", kind], "link " + kind, root))
    row["ObjectChecks"] = [dict(Stage=stage, Status="PASS", Error=None) for stage in admission.CHECKPOINTS]
    return row, dict(side=side, profile=profile, mode=mode, expected_cohort=row["Cohort"],
                     expected_artifact=selected, expected_sources=sources)


class AdmissionTests(unittest.TestCase):
    def setUp(self):
        self.row, self.expected = receipt()

    def reject(self, change, reason="cm0-final-admission"):
        row = copy.deepcopy(self.row)
        change(row)
        with self.assertRaisesRegex(ValueError, reason):
            admission.validate_receipt(row, **self.expected)

    def test_all_thirty_fixed_selections_without_mutation(self):
        for side in ("Native", "Reference"):
            for profile in ("CM0", "CM0PLUS", "CM0PLUSVTOR"):
                for mode in admission.MODES:
                    row, expected = receipt(side, profile, mode)
                    before = copy.deepcopy((row, expected))
                    with self.subTest(side=side, profile=profile, mode=mode):
                        self.assertIsNone(admission.validate_receipt(row, **expected))
                        self.assertEqual((row, expected), before)

    def test_validator_is_pure(self):
        with patch("builtins.open", side_effect=AssertionError("I/O")), \
             patch.object(Path, "read_bytes", side_effect=AssertionError("I/O")), \
             patch.object(Path, "resolve", side_effect=AssertionError("filesystem")), \
             patch("subprocess.Popen", side_effect=AssertionError("process")):
            self.assertIsNone(admission.validate_receipt(self.row, **self.expected))

    def test_invalid_arguments_and_container_types(self):
        for key, value in (("side", "native"), ("side", True), ("profile", "CM4"), ("profile", True),
                           ("mode", "O1"), ("mode", True), ("expected_cohort", "other"),
                           ("expected_artifact", {}), ("expected_sources", []), ("expected_sources", ["relative.c"] * 9)):
            expected = dict(self.expected, **{key: value})
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                admission.validate_receipt(self.row, **expected)
        for value in (None, [], True):
            with self.assertRaises(ValueError):
                admission.validate_receipt(value, **self.expected)

    def test_exact_profile_mode_cohort_verdict(self):
        for key, value in (("Verdict", "PASS"), ("Verdict", "REFERENCE-CLASSIC-FP-FINAL-TWIN-BUILD-PASS"),
                           ("Profile", "CM0PLUS"), ("Mode", "Og"), ("Cohort", "other"),
                           ("Linkage", "archive"), ("Error", "late failure")):
            with self.subTest(key=key):
                self.reject(lambda row, k=key, v=value: row.__setitem__(k, v))

    def test_false_flags_are_not_integer_aliases(self):
        for key in admission.FALSE_FIELDS:
            for value in (True, 0, 1, None, "false"):
                with self.subTest(key=key, value=value):
                    self.reject(lambda row, k=key, v=value: row.__setitem__(k, v))
            self.reject(lambda row, k=key: row.pop(k))

    def test_optional_native_promotions_reject(self):
        self.assertNotIn("NativeBuilt", self.row)
        self.row["NativeBuilt"] = False
        admission.validate_receipt(self.row, **self.expected)
        for key in admission.REFERENCE_FALSE:
            for value in (True, 0, None):
                self.reject(lambda row, k=key, v=value: row.__setitem__(k, v))

    def test_reference_scope_pin_vtor_and_flags(self):
        for profile in admission.PROFILES:
            row, expected = receipt("Reference", profile)
            changes = [(key, value) for key in admission.REFERENCE_FALSE for value in (True, 0, None)]
            changes += [("ReferenceBuilt", 1), ("ReferenceBuilt", False), ("ReferenceCommit", "0" * 40),
                        ("SourceGroup", "CM4"), ("ReferenceClosingIdentityVerified", 1), ("ArtifactSealVerified", False),
                        ("ProofScope", "FINAL-PARITY"), ("FPPolicy", "upstream-lazy"),
                        ("SchedulerThreshold", "16"), ("DeclaredVTOR", int(profile == "CM0PLUSVTOR")),
                        ("FixtureHandlerInstallationCheck", profile == "CM0PLUSVTOR")]
            for key, value in changes:
                changed = copy.deepcopy(row)
                changed[key] = value
                with self.subTest(profile=profile, key=key, value=value), self.assertRaises(ValueError):
                    admission.validate_receipt(changed, **expected)

    def test_integer_counts_and_input_drift(self):
        for key, good in (("RequiredCellsSatisfied", 0), ("TranslationUnits", 9), ("FinalExecutableLinks", 2)):
            for value in (True, False, float(good), str(good), -1, good + 1):
                self.reject(lambda row, k=key, v=value: row.__setitem__(k, v))
        for value in (None, (), ["drift"], False):
            self.reject(lambda row, v=value: row.update(InputDrift=v))
        for value in (None, 0, "A" * 63, "G" * 64):
            self.reject(lambda row, v=value: row.update(SourceInventorySha256=v))

    def test_artifact_binding_is_typed_and_exact(self):
        for change in (lambda a: a["target"].update(vtor=0), lambda a: a["defines"].update(FIBER_PORT_ARMV6M=1),
                       lambda a: a["compile_flags"].append("-flto"), lambda a: a.update(extra="unadmitted"),
                       lambda a: a.update(compile_flags=tuple(a["compile_flags"])),
                       lambda a: a.update(target=dict(vtor=float("nan")))):
            self.reject(lambda row, c=change: c(row["CohortArtifact"]))
        self.row["CohortArtifact"] = dict(reversed(list(self.row["CohortArtifact"].items())))
        admission.validate_receipt(self.row, **self.expected)

    def test_even_matching_foreign_expected_artifact_rejects(self):
        for key, value in (("fpu_present", True), ("fpu_used", True), ("float_abi", "hard"),
                           ("nvic_priority_bits", 4), ("scheduler_basepri", 16), ("mpu_regions", 8), ("vtor", 0)):
            row, expected = receipt()
            for a in (row["CohortArtifact"], expected["expected_artifact"]):
                a["target"][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                admission.validate_receipt(row, **expected)

    def test_sources_empty_reordered_extra_or_unbound(self):
        for change in (lambda r: r.update(Sources=[]), lambda r: r["Sources"].reverse(),
                       lambda r: r["Sources"].append(copy.deepcopy(r["Sources"][0])),
                       lambda r: r["Sources"][0].update(Source="C:/other.c")):
            self.reject(change)

    def test_source_object_paths_hashes_and_aliases(self):
        for value in ("relative.o", "C:/x/../alias.o", self.row["Sources"][1]["Object"],
                      self.row["Sources"][1]["Object"].upper(), self.expected["expected_sources"][0]):
            self.reject(lambda r, v=value: r["Sources"][0].update(Object=v))
        for key in ("SourceSha256", "ObjectSha256"):
            for value in (None, True, "invalid"):
                self.reject(lambda r, k=key, v=value: r["Sources"][0].__setitem__(k, v))

    def test_compile_flags_cannot_override_target_mode_or_defines(self):
        for value in (None, (), [], [True]):
            self.reject(lambda r, v=value: r["Sources"][0].update(CompileFlags=v))
        for flag in ("-O3", "-flto", "-fno-lto", "-mcpu=cortex-m4", "-mfpu=fpv4-sp-d16",
                     "-mfloat-abi=hard", "-march=armv7-m", "-marm", "@untracked.rsp", "-DEXTRA=1"):
            self.reject(lambda r, f=flag: r["Sources"][0]["CompileFlags"].append(f))
        self.reject(lambda r: r["Sources"][0]["CompileFlags"].reverse())
        self.reject(lambda r: r["Sources"][-1]["CompileFlags"].append("-DPILOT_HAS_VTOR=1"))

    def test_exact_compile_command_binding_and_count(self):
        for change in (lambda r: r["Commands"].pop(0), lambda r: r["Commands"].append(copy.deepcopy(r["Commands"][0])),
                       lambda r: r["Commands"][0]["Argv"].insert(-4, "-O3"),
                       lambda r: r["Commands"][0]["Argv"].__setitem__(-1, "C:/wrong.o"),
                       lambda r: r["Commands"][0]["Argv"].__setitem__(-3, "C:/wrong.c"),
                       lambda r: r["Sources"][0].update(CompileDependencyFile="relative.d")):
            self.reject(change)

    def test_successful_git_config_options_are_not_compiler_invocations(self):
        for side in ("Native", "Reference"):
            row, expected = receipt(side)
            root = row["Commands"][0]["Cwd"]
            row["Commands"].insert(0, command([
                "C:/pure-not-executed/git.exe", "-c", "core.autocrlf=false", "-c", "core.safecrlf=false",
                "-C", "C:/pure-not-executed/FreeRTOS", "status", "--porcelain"], "git identity", root))
            with self.subTest(side=side):
                self.assertIsNone(admission.validate_receipt(row, **expected))

    def test_single_compiler_identity_and_extra_compile_rejects(self):
        self.reject(lambda row: row["Commands"][0]["Argv"].__setitem__(0, "C:/pure-not-executed/other-gcc.exe"),
                    "single compiler executable required")
        def extra_compile(row):
            extra = copy.deepcopy(row["Commands"][0])
            extra["Argv"][-3] = "C:/pure-not-executed/unadmitted.c"
            extra["Argv"][-1] = "C:/pure-not-executed/unadmitted.o"
            row["Commands"].append(extra)
        self.reject(extra_compile, "actual compile count")

    def test_dependencies_are_nonempty_exact_and_unique(self):
        for key in ("Dependencies", "ActualCompileDependencies"):
            for value in ([], None, (), [dict(Path="relative.h", Sha256=SHA)],
                          [dict(Path="C:/one.h", Sha256="wrong")]):
                self.reject(lambda r, k=key, v=value: r["Sources"][0].__setitem__(k, v))
            self.reject(lambda r, k=key: r["Sources"][0][k].append(copy.deepcopy(r["Sources"][0][k][0])))
        self.reject(lambda r: r["Sources"][0]["ActualCompileDependencies"][0].update(Sha256="B" * 64))
        self.reject(lambda r: r["Sources"][0].update(CompileDependenciesVerified=1))
        for key in ("Dependencies", "ActualCompileDependencies"):
            self.row["Sources"][0][key] = [dict(Path="C:/unrelated.h", Sha256=SHA)]
        with self.assertRaisesRegex(ValueError, "source dependency missing"):
            admission.validate_receipt(self.row, **self.expected)

    def test_twins_count_order_aliases_and_hashes(self):
        for change in (lambda r: r.update(Links=[]), lambda r: r["Links"].reverse(),
                       lambda r: r["Links"][1].update(Path=r["Links"][0]["Path"]),
                       lambda r: r["Links"][1].update(Map=r["Links"][0]["Map"]),
                       lambda r: r["Links"][0].update(Path=r["Sources"][0]["Object"]),
                       lambda r: r["Links"][0].update(Map="relative.map"),
                       lambda r: r["Links"][0].update(Sha256="bad")):
            self.reject(change)
        for key in ("TwinLoadImageIdentical", "TwinAllocatedSectionsIdentical"):
            for value in (False, 0, 1, None):
                self.reject(lambda r, k=key, v=value: r.__setitem__(k, v))

    def test_exact_seven_ordered_successful_checkpoints(self):
        for change in (lambda r: r.update(ObjectChecks=[]), lambda r: r["ObjectChecks"].pop(),
                       lambda r: r["ObjectChecks"].reverse(), lambda r: r["ObjectChecks"][0].update(Stage="closing"),
                       lambda r: r["ObjectChecks"][0].update(Status="ATTEMPT"),
                       lambda r: r["ObjectChecks"][0].update(Error="failure"), lambda r: r["ObjectChecks"][0].pop("Error")):
            self.reject(change)

    def test_terminal_command_types(self):
        self.reject(lambda r: r.update(Commands=[]))
        for key, values in (("Status", ("ATTEMPT", "FAIL", True)), ("Exit", (False, True, 0.0, None, 1)),
                ("TimedOut", (True, 0, None)), ("Error", ("failure", False)), ("Label", ("", None)),
                ("Argv", ([], "tool", ["relative.exe"], ["C:/tool.exe", 1])),
                ("Cwd", ("relative", None)), ("Seconds", (-1, True, float("inf"), float("nan"), None))):
            for value in values:
                self.reject(lambda r, k=key, v=value: r["Commands"][0].__setitem__(k, v))


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def structured(data):
    def invalid_constant(value):
        raise ValueError("non-finite JSON constant: " + value)
    return json.loads(data, object_pairs_hook=unique_object, parse_constant=invalid_constant)


def replay_receipt(data, *, expected_sha256, expected):
    """Hash and parse the same caller-supplied buffer; no filesystem access."""
    if type(data) is not bytes:
        raise ValueError("receipt bytes required")
    admission._sha(expected_sha256, "replay receipt hash")
    if hashlib.sha256(data).hexdigest().upper() != expected_sha256.upper():
        raise ValueError("receipt hash mismatch")
    if type(expected) is not dict:
        raise ValueError("independent expected arguments required")
    admission.validate_receipt(structured(data), **expected)


class ReplayApiTests(unittest.TestCase):
    def test_buffer_replay_separate_from_pure_validator(self):
        for side in ("Native", "Reference"):
            row, expected = receipt(side)
            data = json.dumps(row).encode("ascii")
            with patch.object(Path, "read_bytes", side_effect=AssertionError("I/O")):
                self.assertIsNone(replay_receipt(data, expected_sha256=hashlib.sha256(data).hexdigest(), expected=expected))

    def test_wrong_buffer_hash_and_duplicate_json_keys_reject(self):
        row, expected = receipt()
        data = json.dumps(row).encode("ascii")
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            replay_receipt(data + b"\n", expected_sha256=hashlib.sha256(data).hexdigest(), expected=expected)
        for data in (b'{"Verdict":"PASS","Verdict":"FAIL"}', b'{"extra":NaN}'):
            with self.assertRaises(ValueError):
                replay_receipt(data, expected_sha256=hashlib.sha256(data).hexdigest(), expected=expected)


class ActualReceiptTests(unittest.TestCase):
    def test_actual_receipt_buffers_against_independent_expectations(self):
        self.assertTrue(ACTUAL_CASES)
        for case in ACTUAL_CASES:
            with self.subTest(receipt=case["Receipt"]):
                replay_receipt(Path(case["Receipt"]).read_bytes(), expected_sha256=case["ReceiptSha256"], expected=case["Expected"])

    def test_actual_metadata_mutations_do_not_redefine_expectations(self):
        for case in ACTUAL_CASES:
            data = Path(case["Receipt"]).read_bytes()
            replay_receipt(data, expected_sha256=case["ReceiptSha256"], expected=case["Expected"])
            for key, value in (("Mode", "Og" if case["Expected"]["mode"] != "Og" else "O2"),
                               ("RequiredCellsSatisfied", False), ("FinalElfProof", True)):
                row = structured(data)
                row[key] = value
                with self.subTest(receipt=case["Receipt"], mutation=key), self.assertRaises(ValueError):
                    admission.validate_receipt(row, **case["Expected"])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--actual-cases", type=Path)
    parser.add_argument("--actual-cases-sha256")
    args = parser.parse_args(argv)
    report_path = args.report.resolve()
    repo = HERE.parents[2]
    if report_path.exists() or report_path.is_relative_to(repo) or repo.is_relative_to(report_path):
        parser.error("fresh external report required")
    if bool(args.actual_cases) != bool(args.actual_cases_sha256):
        parser.error("actual-cases and its independently supplied SHA256 are required together")
    paths = [Path(__file__).resolve(), HERE / "admission.py"]
    report = dict(Status="FAIL", Tests=0, Failures=0, Errors=0, Skipped=0, SourceHashes={}, SourceDrift=[],
        ActualReceipts=0, ActualReceiptHashes={}, ReceiptDrift=[], ActualReplayRequested=args.actual_cases is not None,
        Scope="PURE_CM0_PRODUCER_METADATA_ADMISSION_ONLY", ToolInvocations=0, RequiredCellsSatisfied=0,
        FinalElfProof=False, FinalReferenceParity=False, PolicyEquivalence=False, CpuExecution=False,
        BoardExecution=False, GlobalFreezeQualified=False, Error=None)
    try:
        if sys.flags.optimize or not __debug__:
            raise ValueError("optimized Python unsupported")
        global ACTUAL_CASES, ACTUAL_HASHES
        ACTUAL_CASES, ACTUAL_HASHES = [], {}
        report["SourceHashes"] = {str(path): hashlib.sha256(path.read_bytes()).hexdigest().upper() for path in paths}
        if report["SourceHashes"][str(HERE / "admission.py")] != hashlib.sha256(ADMISSION_BYTES).hexdigest().upper():
            raise ValueError("loaded admission source drift")
        if args.actual_cases:
            path = args.actual_cases.resolve(strict=True)
            data = path.read_bytes()
            admission._sha(args.actual_cases_sha256, "actual cases hash")
            if hashlib.sha256(data).hexdigest().upper() != args.actual_cases_sha256.upper():
                raise ValueError("actual cases hash mismatch")
            cases = structured(data)
            if type(cases) is not dict or set(cases) != {"Cases"} or type(cases["Cases"]) is not list or not cases["Cases"]:
                raise ValueError("nonempty explicit actual cases required")
            paths.append(path)
            report["SourceHashes"][str(path)] = hashlib.sha256(data).hexdigest().upper()
            found = set()
            for case in cases["Cases"]:
                if type(case) is not dict or set(case) != {"Receipt", "ReceiptSha256", "Expected"}:
                    raise ValueError("actual case schema")
                admission._path(case["Receipt"], "actual receipt path")
                expected = case["Expected"]
                if type(expected) is not dict:
                    raise ValueError("actual expected arguments")
                identity = (expected["side"], expected["profile"], expected["mode"])
                if identity in found or case["Receipt"] in ACTUAL_HASHES:
                    raise ValueError("duplicate actual receipt role")
                found.add(identity)
                receipt_bytes = Path(case["Receipt"]).read_bytes()
                replay_receipt(receipt_bytes, expected_sha256=case["ReceiptSha256"], expected=expected)
                ACTUAL_HASHES[case["Receipt"]] = hashlib.sha256(receipt_bytes).hexdigest().upper()
                ACTUAL_CASES.append(case)
        suite = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(cls) for cls in
                                  (AdmissionTests, ReplayApiTests, *([ActualReceiptTests] if ACTUAL_CASES else [])))
        count = suite.countTestCases()
        with patch("subprocess.Popen", side_effect=AssertionError("process execution forbidden")):
            result = unittest.TextTestRunner(verbosity=2).run(suite)
        report.update(Tests=result.testsRun, Failures=len(result.failures), Errors=len(result.errors), Skipped=len(result.skipped),
            ActualReceipts=len(ACTUAL_CASES), ActualReceiptHashes=ACTUAL_HASHES,
            FailureDetails=[dict(Test=str(case), Detail=detail) for case, detail in result.failures + result.errors])
        report["SourceDrift"] = [str(path) for path in paths if not path.is_file() or
            hashlib.sha256(path.read_bytes()).hexdigest().upper() != report["SourceHashes"][str(path)]]
        report["ReceiptDrift"] = [path for path, digest in ACTUAL_HASHES.items() if not Path(path).is_file() or
            hashlib.sha256(Path(path).read_bytes()).hexdigest().upper() != digest]
        if result.wasSuccessful() and result.testsRun == count > 0 and not result.skipped and not report["SourceDrift"] and not report["ReceiptDrift"]:
            report["Status"] = "PASS"
    except Exception:
        report.update(Status="FAIL", Errors=report["Errors"] + 1, Error=traceback.format_exc())
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="ascii")
    print("Receipt:", report_path, hashlib.sha256(report_path.read_bytes()).hexdigest().upper())
    return 0 if report["Status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
