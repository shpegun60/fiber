"""Pure receipt-metadata controls. No subprocesses, compilers or target execution."""
import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch


sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("classic_final_join_admission", HERE / "admission.py")
admission = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(admission)
SHA = "A" * 64


def receipt(side="Native", profile="CM4", mode="O2"):
    count = 9 if side == "Native" else 4
    root = "C:/pure-not-executed/" + side
    artifact = dict(target=dict(cpu="cortex-m4" if profile == "CM4" else "cortex-m7", vtor=True),
                    compile_flags=["-mthumb", "-mfloat-abi=hard"], defines=dict(ENABLE="1"))
    sources = [root + "/source/%02d.c" % i for i in range(count)]
    row = dict(Verdict=admission.VERDICTS[side], Error=None, Profile=profile, Mode=mode,
        Cohort="exact-" + profile, Linkage="direct", RequiredCellsSatisfied=0,
        InputDrift=[], SourceInventorySha256=SHA, CohortArtifact=copy.deepcopy(artifact),
        TranslationUnits=count, FinalExecutableLinks=2, TwinLoadImageIdentical=True,
        TwinAllocatedSectionsIdentical=True, Sources=[], Links=[], ObjectChecks=[], Commands=[])
    row.update({key: False for key in admission.FALSE_FIELDS})
    row["ReferenceBuilt"] = side == "Reference"
    for index, source in enumerate(sources):
        dependencies = [dict(Path=source, Sha256=SHA)]
        row["Sources"].append(dict(Source=source, SourceSha256=SHA, Object=root + "/%02d.o" % index,
            ObjectSha256=SHA, CompileDependenciesVerified=True, Dependencies=dependencies,
            ActualCompileDependencies=copy.deepcopy(dependencies)))
    for kind in ("ordinary", "emit-relocs"):
        row["Links"].append(dict(Kind=kind, Path=root + "/" + kind + ".elf", Sha256=SHA,
                                 Map=root + "/" + kind + ".map", MapSha256=SHA))
    row["ObjectChecks"] = [dict(Stage=stage, Status="PASS", Error=None) for stage in admission.CHECKPOINTS]
    row["Commands"] = [dict(Status="PASS", Exit=0, TimedOut=False, Error=None, Label="not executed",
        Argv=["C:/pure-not-executed/tool.exe", "argument"], Cwd=root, Seconds=0.1)]
    expected = dict(side=side, profile=profile, mode=mode, expected_cohort=row["Cohort"],
                    expected_artifact=artifact, expected_sources=sources)
    return row, expected


class AdmissionTests(unittest.TestCase):
    def setUp(self):
        self.row, self.expected = receipt()

    def reject(self, change, pattern=None):
        row = copy.deepcopy(self.row)
        change(row)
        with self.assertRaisesRegex(ValueError, pattern or "classic-final-admission"):
            admission.validate_receipt(row, **self.expected)

    def test_twenty_metadata_selections_and_no_mutation(self):
        for side in ("Native", "Reference"):
            for profile in ("CM4", "CM7"):
                for mode in admission.MODES:
                    row, expected = receipt(side, profile, mode)
                    before = copy.deepcopy((row, expected))
                    self.assertIsNone(admission.validate_receipt(row, **expected))
                    self.assertEqual((row, expected), before)

    def test_validator_has_no_io_or_process(self):
        with patch("builtins.open", side_effect=AssertionError("I/O")), \
             patch.object(Path, "read_bytes", side_effect=AssertionError("I/O")), \
             patch.object(Path, "resolve", side_effect=AssertionError("filesystem")), \
             patch("subprocess.Popen", side_effect=AssertionError("process")):
            self.assertIsNone(admission.validate_receipt(self.row, **self.expected))

    def test_native_built_not_invented(self):
        self.assertNotIn("NativeBuilt", self.row)
        admission.validate_receipt(self.row, **self.expected)
        self.row["NativeBuilt"] = False
        admission.validate_receipt(self.row, **self.expected)
        self.reject(lambda row: row.update(NativeBuilt=True))

    def test_wrong_receipt_selection(self):
        for key, value in (("Verdict", "PASS"), ("Profile", "CM7"), ("Mode", "Og"),
                           ("Cohort", "other"), ("Linkage", "archive"), ("Error", "late failure")):
            with self.subTest(key=key):
                self.reject(lambda row, key=key, value=value: row.__setitem__(key, value))

    def test_false_flags_require_actual_bool(self):
        for key in admission.FALSE_FIELDS:
            for value in (True, 0, 1, None, "false"):
                with self.subTest(key=key, value=value):
                    self.reject(lambda row, key=key, value=value: row.__setitem__(key, value))
            with self.subTest(missing=key):
                self.reject(lambda row, key=key: row.pop(key))

    def test_optional_promotions_reject_bool_aliases(self):
        for key in ("NativeBuilt", "FinalReferenceParity", "SchedulerSemanticsProven", "ReferenceKernelAvailable"):
            for value in (True, 0, None):
                with self.subTest(key=key, value=value):
                    self.reject(lambda row, key=key, value=value: row.__setitem__(key, value))

    def test_reference_requires_reference_built_true(self):
        row, expected = receipt("Reference")
        for value in (False, 0, 1, None):
            row["ReferenceBuilt"] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                admission.validate_receipt(row, **expected)

    def test_exact_integer_counters(self):
        for key, good in (("RequiredCellsSatisfied", 0), ("TranslationUnits", 9), ("FinalExecutableLinks", 2)):
            for value in (True, False, float(good), str(good), -1, good + 1):
                with self.subTest(key=key, value=value):
                    self.reject(lambda row, key=key, value=value: row.__setitem__(key, value))

    def test_inventory_sha_and_drift(self):
        for value in (None, 0, "A" * 63, "G" * 64, "A" * 65, " A" * 32):
            with self.subTest(value=value):
                self.reject(lambda row, value=value: row.update(SourceInventorySha256=value))
        for value in (None, (), ["drift"], False):
            self.reject(lambda row, value=value: row.update(InputDrift=value))

    def test_typed_artifact_binding(self):
        for change in (lambda artifact: artifact["target"].update(vtor=1),
                       lambda artifact: artifact["defines"].update(ENABLE=1),
                       lambda artifact: artifact["compile_flags"].append("-flto"),
                       lambda artifact: artifact.update(extra="unadmitted"),
                       lambda artifact: artifact.update(compile_flags=tuple(artifact["compile_flags"])),
                       lambda artifact: artifact.update(target=dict(vtor=float("nan")))):
            self.reject(lambda row, change=change: change(row["CohortArtifact"]))

    def test_artifact_mapping_order_is_not_semantics(self):
        self.row["CohortArtifact"] = dict(reversed(list(self.row["CohortArtifact"].items())))
        admission.validate_receipt(self.row, **self.expected)

    def test_sources_empty_extra_reordered_wrong_path(self):
        for change in (lambda row: row.update(Sources=[]),
                       lambda row: row["Sources"].append(copy.deepcopy(row["Sources"][0])),
                       lambda row: row["Sources"].reverse(),
                       lambda row: row["Sources"][0].update(Source="C:/other/file.c")):
            self.reject(change)

    def test_objects_unique_and_absolute(self):
        for value in ("relative.o", "C:/pure-not-executed/../alias.o", self.row["Sources"][1]["Object"],
                      self.row["Sources"][1]["Object"].upper(), self.expected["expected_sources"][0]):
            with self.subTest(value=value):
                self.reject(lambda row, value=value: row["Sources"][0].update(Object=value))

    def test_source_object_hashes(self):
        for key in ("SourceSha256", "ObjectSha256"):
            for value in (None, True, "invalid"):
                self.reject(lambda row, key=key, value=value: row["Sources"][0].__setitem__(key, value))

    def test_compile_dependencies_verified_exact_true(self):
        for value in (False, 0, 1, None):
            self.reject(lambda row, value=value: row["Sources"][0].update(CompileDependenciesVerified=value))

    def test_dependency_closures_nonempty_and_exact(self):
        for key in ("Dependencies", "ActualCompileDependencies"):
            for value in ([], None, (), [dict(Path="relative.h", Sha256=SHA)],
                          [dict(Path="C:/one.h", Sha256="wrong")]):
                with self.subTest(key=key, value=value):
                    self.reject(lambda row, key=key, value=value: row["Sources"][0].__setitem__(key, value))
        self.reject(lambda row: row["Sources"][0]["ActualCompileDependencies"][0].update(Sha256="B" * 64))
        for key in ("Dependencies", "ActualCompileDependencies"):
            self.row["Sources"][0][key] = [dict(Path="C:/unrelated.h", Sha256=SHA)]
        with self.assertRaisesRegex(ValueError, "source dependency missing"):
            admission.validate_receipt(self.row, **self.expected)

    def test_duplicate_dependency_metadata_rejects(self):
        for key in ("Dependencies", "ActualCompileDependencies"):
            self.reject(lambda row, key=key: row["Sources"][0][key].append(copy.deepcopy(row["Sources"][0][key][0])))

    def test_links_order_count_and_path_aliases(self):
        for change in (lambda row: row.update(Links=[]), lambda row: row["Links"].pop(),
                       lambda row: row["Links"].reverse(),
                       lambda row: row["Links"][1].update(Path=row["Links"][0]["Path"]),
                       lambda row: row["Links"][1].update(Map=row["Links"][0]["Map"]),
                       lambda row: row["Links"][0].update(Path=row["Sources"][0]["Object"]),
                       lambda row: row["Links"][0].update(Map="relative.map"),
                       lambda row: row["Links"][0].update(Sha256="bad"),
                       lambda row: row["Links"][0].update(MapSha256=None)):
            self.reject(change)

    def test_twin_metadata_exact_true(self):
        for key in ("TwinLoadImageIdentical", "TwinAllocatedSectionsIdentical"):
            for value in (False, 0, 1, None):
                self.reject(lambda row, key=key, value=value: row.__setitem__(key, value))

    def test_checkpoints_exact_seven_order_and_success(self):
        for change in (lambda row: row.update(ObjectChecks=[]), lambda row: row["ObjectChecks"].pop(),
                       lambda row: row["ObjectChecks"].reverse(),
                       lambda row: row["ObjectChecks"][0].update(Stage="closing"),
                       lambda row: row["ObjectChecks"][0].update(Status="ATTEMPT"),
                       lambda row: row["ObjectChecks"][0].update(Error="failure"),
                       lambda row: row["ObjectChecks"][0].pop("Error")):
            self.reject(change)

    def test_commands_nonempty_and_terminal_types(self):
        self.reject(lambda row: row.update(Commands=[]))
        for key, values in (("Status", ("ATTEMPT", "FAIL", True)), ("Exit", (False, True, 0.0, None, 1)),
                            ("TimedOut", (True, 0, None)), ("Error", ("failure", False)),
                            ("Label", ("", None)), ("Argv", ([], "tool", ["relative.exe"], ["C:/tool.exe", 1])),
                            ("Cwd", ("relative", None)), ("Seconds", (-1, True, float("inf"), float("nan"), None))):
            for value in values:
                with self.subTest(key=key, value=value):
                    self.reject(lambda row, key=key, value=value: row["Commands"][0].__setitem__(key, value))

    def test_argument_and_container_types(self):
        for key, value in (("side", "native"), ("side", True), ("profile", "CM0"), ("mode", "O1"),
                           ("mode", True), ("expected_cohort", ""), ("expected_artifact", {}),
                           ("expected_sources", []), ("expected_sources", ["relative.c"] * 9)):
            expected = dict(self.expected, **{key: value})
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                admission.validate_receipt(self.row, **expected)
        for value in (None, [], True):
            with self.assertRaises(ValueError):
                admission.validate_receipt(value, **self.expected)


class ActualReceiptTests(unittest.TestCase):
    """Metadata only: exact completed producer rows are independent positive inputs."""
    @classmethod
    def setUpClass(cls):
        cls.cases, cls.receipt_hashes = [], {}
        for profile in ("CM4", "CM7"):
            for mode in admission.MODES:
                rows = {}
                for side, root in (("Native", NATIVE_ROOT), ("Reference", REFERENCE_ROOT)):
                    path = root / (profile + "-" + mode) / "results.json"
                    data = path.read_bytes()
                    rows[side] = json.loads(data)
                    cls.receipt_hashes[str(path)] = hashlib.sha256(data).hexdigest().upper()
                cohort = ("cm4-cortex-m4-hard-fpu-eager-v1-mpu0-p4-b16-aapcs-default" if profile == "CM4" else
                          "cm7-cortex-m7-hard-fpu-eager-v1-mpu0-p4-b16-aapcs-default")
                for side, row in rows.items():
                    root = (NATIVE_ROOT if side == "Native" else REFERENCE_ROOT) / (profile + "-" + mode)
                    fixture = root / "source/tools/fixtures/classic_final_image"
                    if side == "Native":
                        port = "ARM_CM4" if profile == "CM4" else "ARM_CM7/r0p1"
                        paths = [root / "source/context" / name for name in
                                 ("context_core.c", "context_runtime_state.c", "context_panic.c")]
                        paths += [root / "source/fiber/port" / port / name for name in
                                  ("fiber_port.c", "fiber_port_boot.c", "fiber_port_exception.c")]
                        paths += [root / "source/fiber/port/fiber_port_context_cohort_expectation.c",
                                  fixture / "application.c", fixture / "startup.S"]
                    else:
                        port = "ARM_CM4F" if profile == "CM4" else "ARM_CM7/r0p1"
                        paths = [root / "freertos/portable/GCC" / port / "port.c"]
                        paths += [fixture / "reference" / name for name in ("providers.c", "consumer.c", "startup.S")]
                    cls.cases.append((row, dict(side=side, profile=profile, mode=mode,
                        expected_cohort=cohort, expected_artifact=rows["Native"]["CohortArtifact"],
                        expected_sources=[str(path.resolve()) for path in paths])))

    def test_completed_native_and_reference_all_ten_selections(self):
        self.assertEqual(len(self.cases), 20)
        for row, expected in self.cases:
            with self.subTest(side=expected["side"], profile=expected["profile"], mode=expected["mode"]):
                self.assertIsNone(admission.validate_receipt(row, **expected))

    def test_completed_receipt_metadata_mutations_reject(self):
        changes = (
            ("mode", lambda row: row.update(Mode="Og" if row["Mode"] != "Og" else "O2")),
            ("profile", lambda row: row.update(Profile="CM7" if row["Profile"] == "CM4" else "CM4")),
            ("extra-define", lambda row: row["CohortArtifact"]["upstream_defines"].update(UNADMITTED="1")),
            ("source-order", lambda row: row["Sources"].reverse()),
            ("object-alias", lambda row: row["Sources"][0].update(Object=row["Sources"][1]["Object"])),
            ("empty-dependencies", lambda row: row["Sources"][0].update(ActualCompileDependencies=[])),
            ("empty-commands", lambda row: row.update(Commands=[])),
            ("exit-bool", lambda row: row["Commands"][0].update(Exit=False)),
            ("counter-bool", lambda row: row.update(RequiredCellsSatisfied=False)),
            ("promotion", lambda row: row.update(FinalElfProof=True)),
        )
        for row, expected in self.cases:
            for label, change in changes:
                changed = copy.deepcopy(row)
                change(changed)
                with self.subTest(side=expected["side"], profile=expected["profile"], mode=expected["mode"], mutation=label):
                    with self.assertRaises(ValueError):
                        admission.validate_receipt(changed, **expected)


NATIVE_ROOT = Path("C:/fzfinal-native-join-grid-20261104-e1")
REFERENCE_ROOT = Path("C:/fzfinal-reference-grid-20261104-e2")


def main():
    global NATIVE_ROOT, REFERENCE_ROOT
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--native-grid", type=Path, default=NATIVE_ROOT)
    parser.add_argument("--reference-grid", type=Path, default=REFERENCE_ROOT)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    NATIVE_ROOT, REFERENCE_ROOT = args.native_grid, args.reference_grid
    if args.report.exists():
        parser.error("fresh report required")
    sources = [HERE / "admission.py", Path(__file__).resolve()]
    source_hashes = {str(path): hashlib.sha256(path.read_bytes()).hexdigest().upper() for path in sources}
    with patch("subprocess.Popen", side_effect=AssertionError("process execution forbidden")):
        result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__]))
    source_drift = [str(path) for path in sources if hashlib.sha256(path.read_bytes()).hexdigest().upper() != source_hashes[str(path)]]
    receipt_hashes = getattr(ActualReceiptTests, "receipt_hashes", {})
    receipt_drift = [path for path, digest in receipt_hashes.items()
                     if hashlib.sha256(Path(path).read_bytes()).hexdigest().upper() != digest]
    report = dict(Status="PASS" if result.wasSuccessful() and not source_drift and not receipt_drift else "FAIL", Tests=result.testsRun,
                  Failures=len(result.failures), Errors=len(result.errors), ToolInvocations=0,
                  Scope="PURE_PRODUCER_RECEIPT_METADATA_ONLY", NativeGrid=str(NATIVE_ROOT), ReferenceGrid=str(REFERENCE_ROOT),
                  SourceHashes=source_hashes, SourceDrift=source_drift,
                  ReceiptHashes=receipt_hashes, ReceiptDrift=receipt_drift,
                  FailureDetails=[dict(Test=str(case), Detail=detail) for case, detail in result.failures + result.errors])
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="ascii")
    print(json.dumps(report, sort_keys=True))
    return 0 if report["Status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
