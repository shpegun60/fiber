"""Pure admission/scope controls, not a replay of the actual ELF mutations."""

import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import traceback
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
WITNESS = HERE / "witness.py"
COMMON = HERE.with_name("cm3_lto_transport") / "probe.py"
ARCHIVE = HERE.with_name("cm3_lto_archive") / "probe.py"
ARCHIVE_FIXTURE = ARCHIVE.with_name("test_probe.py")
PROTOCOL = HERE.with_name("cm3_lto_protocol") / "protocol.py"
PROTOCOL_FIXTURE = PROTOCOL.with_name("test_protocol.py")
CHECKER = HERE.with_name("cm3_freeze_parity") / "check.py"
EXPECTED_METHODS = 10
subject = common = archive = archive_fixture_module = protocol = protocol_fixture = checker = None
COHORT = "cm3-cortex-m3-soft-nofpu-none-v1-mpu0-p4-b16-aapcs-default"
COMPLETION_FLAGS = (
    "LTO", "InputClosureVerified", "OutputSealVerified", "ArchiveCaptureComplete", "NoForcedExtraction",
    "TwinLoadImageCompared", "TwinLoadImageIdentical", "TwinAllocatedSectionsIdentical")
NONCLAIMS = (
    "ArchiveExtraction", "ArchiveExtractionQualified", "WeakAliasPrecedenceProven", "Qualification",
    "CanonicalProtocolValidated", "FinalRootRelocationProof", "FinalReferenceParity", "ReferenceBuilt",
    "FullABIProof", "SourceIRProof", "SourceToMachineSemanticProof", "OriginalTranslationUnitOwnership",
    "CompleteObjectProof", "PolicyEquivalence", "CpuExecution", "BoardExecution", "GlobalFreezeQualified",
    "RequiredCellSatisfied")

# Bind these cases to the landed pure validators, not a parallel validator.
TEST_PLAN = (
    "accept exact successful archive capture without mutation",
    "reject wrong mode/linkage/cohort/status and bool/integer aliases",
    "reject direct capture relabeled as archive",
    "require six ordered unique engine/port member bindings",
    "require exact complete member/object/extracted-file hash bindings",
    "require startup/application/expectation then archive link providers",
    "reject forced extraction, duplicated direct members and foreign providers",
    "require exactly three native roots and complete canonical protocols",
    "require literal zero tails and retained raw false canonical flags",
    "retain typed false broad claims and zero required-cell credit",
)


def sha(data):
    return hashlib.sha256(data).hexdigest().upper()


def capture_record():
    row = dict(Status="PASS", Error=None, Scope="NATIVE_CM3_O2_LTO_INDEXED_ARCHIVE_CAPTURE_ONLY",
        Profile="CM3", Mode="O2-lto", SeedMode="O2", Cohort=COHORT, Linkage="archive",
        TranslationUnits=9, SlimIRObjects=8, FinalExecutableLinks=2, SavedMachineObjects=2,
        RequiredCellsSatisfied=0, ArchiveMemberIndices=[0, 1, 2, 3, 4, 5], ExplicitObjectIndices=[8, 7, 6],
        CaptureProducer=dict(Path=str(subject.ROOT / subject.PRODUCER), Sha256=subject.FIXED[subject.PRODUCER]),
        FrozenCaptureHelpers=[dict(Path=str(subject.ROOT / key), Sha256=subject.FIXED[key])
                              for key in (subject.UTILITY, subject.LOADER, subject.BINDING)])
    row.update({key: True for key in COMPLETION_FLAGS})
    row.update({key: False for key in NONCLAIMS})
    return row


def require_record(row):
    return subject.Witness._record(SimpleNamespace(api=common), row)


def members_fixture():
    fixture = archive_fixture_module.archive_fixture()
    parsed = archive.archive_records(fixture.raw)
    sources = [dict(Source=name, Object="/synthetic/objects/" + (
                    parsed["Members"][index]["Name"] if index < 6 else "source-%02d.o" % index),
                    ObjectSha256=sha(fixture.members[index][1]) if index < 6 else sha(b"synthetic explicit object"))
               for index, name in enumerate(common.SOURCES)]
    declared = copy.deepcopy(parsed)
    declared["MemberCount"] = 6
    for index, row in enumerate(declared["Members"]):
        row.update(SourceIndex=index, Object=sources[index]["Object"], Source=sources[index]["Source"],
                   Captured="/synthetic/archive/members/" + row["Name"])
    extracted = dict(fixture.members)
    return SimpleNamespace(parsed=parsed, declared=declared, sources=sources, extracted=extracted)


def require_members(fixture):
    return subject.require_archive_members(fixture.parsed, fixture.declared, fixture.sources, fixture.extracted)


class WitnessTests(unittest.TestCase):
    def test_exact_archive_capture_is_admitted_without_mutation(self):
        row = capture_record()
        before = copy.deepcopy(row)
        require_record(row)
        self.assertEqual(row, before)

    def test_wrong_capture_identity_modes_status_and_typed_counts_reject(self):
        changes = (("Status", "FAIL"), ("Scope", "NATIVE_CM3_O2_LTO_CAPTURE_FEASIBILITY_ONLY"),
            ("Profile", "CM4"), ("Mode", "Os-lto"), ("SeedMode", "Os"), ("Linkage", "direct"),
            ("Cohort", COHORT.replace("b16", "b32")), ("Error", "capture failed"),
            ("TranslationUnits", 8), ("TranslationUnits", 9.0), ("SlimIRObjects", 8.0),
            ("FinalExecutableLinks", 2.0), ("SavedMachineObjects", 2.0), ("SavedMachineObjects", True))
        for key, value in changes:
            with self.subTest(field=key, value=value):
                row = capture_record()
                row[key] = value
                with self.assertRaises(ValueError):
                    require_record(row)

    def test_complete_six_raw_member_object_and_extracted_bindings_are_pure(self):
        fixture = members_fixture()
        before = copy.deepcopy(vars(fixture))
        require_members(fixture)
        self.assertEqual(vars(fixture), before)
        self.assertEqual(len(fixture.parsed["Members"]), 6)
        for index, row in enumerate(fixture.parsed["Members"]):
            self.assertEqual(sha(fixture.extracted[row["Name"]]), fixture.sources[index]["ObjectSha256"])
            self.assertEqual(fixture.declared["Members"][index]["Source"], common.SOURCES[index])

    def test_missing_foreign_reordered_or_changed_member_bindings_reject(self):
        cases = ("member-count", "float-count", "duplicate-name", "reordered-raw", "wrong-source-index",
                 "bool-source-index", "foreign-object", "foreign-source", "wrong-object-hash",
                 "wrong-declared-hash", "changed-extracted-bytes", "missing-extracted", "extra-extracted",
                 "changed-index", "changed-header")
        for case in cases:
            with self.subTest(case=case):
                fixture = members_fixture()
                rows, declared = fixture.parsed["Members"], fixture.declared["Members"]
                if case == "member-count":
                    rows.pop()
                    declared.pop()
                elif case == "float-count":
                    fixture.declared["MemberCount"] = 6.0
                elif case == "duplicate-name":
                    rows[1]["Name"] = declared[1]["Name"] = rows[0]["Name"]
                elif case == "reordered-raw":
                    rows[0], rows[1] = rows[1], rows[0]
                elif case == "wrong-source-index":
                    declared[0]["SourceIndex"] = 6
                elif case == "bool-source-index":
                    declared[1]["SourceIndex"] = True
                elif case == "foreign-object":
                    declared[0]["Object"] = "/synthetic/foreign.o"
                elif case == "foreign-source":
                    declared[0]["Source"] = common.SOURCES[6]
                elif case == "wrong-object-hash":
                    fixture.sources[0]["ObjectSha256"] = "0" * 64
                elif case == "wrong-declared-hash":
                    declared[0]["Sha256"] = "0" * 64
                elif case == "changed-extracted-bytes":
                    name = rows[0]["Name"]
                    raw = fixture.extracted[name]
                    fixture.extracted[name] = bytes([raw[0] ^ 1]) + raw[1:]
                elif case == "missing-extracted":
                    fixture.extracted.pop(rows[0]["Name"])
                elif case == "extra-extracted":
                    fixture.extracted["foreign.o"] = b"foreign"
                elif case == "changed-index":
                    fixture.parsed["Index"][0]["HeaderOffset"] += 2
                else:
                    rows[0]["HeaderSha256"] = "0" * 64
                with self.assertRaises(ValueError):
                    require_members(fixture)

    def test_link_provider_builder_is_exact_and_cannot_duplicate_direct_members(self):
        objects = [Path("/synthetic/objects/%02d.o" % index) for index in range(9)]
        library = Path("/synthetic/archive/libcm3_context.a")
        before = list(objects)
        providers = subject.required_provider_order(objects, library)
        self.assertEqual(providers, [str(objects[8]), str(objects[7]), str(objects[6]), str(library)])
        self.assertEqual(objects, before)
        self.assertEqual(len(providers), len(set(providers)))
        for path in objects[:6]:
            self.assertNotIn(str(path), providers)
        for flag in ("--whole-archive", "--undefined", "-u"):
            self.assertFalse(any(value == flag or value.startswith(flag + "=") for value in providers))
        invalid = ((objects[:-1], library), (objects + [Path("extra.o")], library),
                   (objects[:-1] + [objects[0]], library), (objects, objects[0]),
                   (objects[:-1] + [True], library), (objects[:-1] + [""], library),
                   (objects, ""), (objects, None), ({"objects": objects}, library))
        for index, (candidate, target) in enumerate(invalid):
            with self.subTest(case=index):
                with self.assertRaises(ValueError):
                    subject.required_provider_order(candidate, target)

    def test_frozen_native_protocol_requires_three_complete_roots_zero_tails_and_nonclaims(self):
        fixture = protocol_fixture.Fixture()
        before = copy.deepcopy((fixture.decoded.tokens, fixture.transport.records))
        result = protocol.check_native(fixture.decoded, fixture.transport, checker)
        roots = ("fiber_port_start_first_context", "SVC_Handler", "PendSV_Handler")
        self.assertEqual(tuple(row["Name"] for row in result["Roots"]), roots)
        self.assertEqual(result["ClosedBodies"], 3)
        self.assertIs(result["CanonicalProtocolValidated"], True)
        self.assertEqual(result["Scope"], "NATIVE_CM3_O2_LTO_THREE_CANONICAL_PROTOCOLS_ONLY")
        self.assertEqual([len(row["ProjectionEvidence"]) for row in result["Roots"]], [0, 1, 1])
        for row in result["MatchEvidence"]:
            self.assertIs(type(row["TailNops"]), int)
            self.assertEqual(row["TailNops"], 0)
        for row in result["Roots"]:
            self.assertIs(row["TransportRecord"]["CanonicalProtocolValidated"], False)
        for key in ("SourceToMachineSemanticProof", "FinalReferenceParity", "FullABIProof", "PolicyEquivalence",
                    "CompleteObjectProof", "CpuExecution", "BoardExecution", "GlobalFreezeQualified"):
            self.assertIs(result[key], False)
        self.assertIs(type(result["RequiredCellsSatisfied"]), int)
        self.assertEqual(result["RequiredCellsSatisfied"], 0)
        self.assertEqual((fixture.decoded.tokens, fixture.transport.records), before)
        bad_roots = dict(checker._NATIVE)
        bad_roots["foreign-root"] = bad_roots.pop(roots[-1])
        fresh = protocol_fixture.Fixture()
        with self.assertRaises(protocol.Rejected):
            protocol.check_native(fresh.decoded, fresh.transport,
                                  SimpleNamespace(_NATIVE=bad_roots, _match=checker._match))
        for tail in (False, 1):
            with self.subTest(tail=tail):
                fresh = protocol_fixture.Fixture()

                def match(*args):
                    evidence = checker._match(*args)
                    evidence["TailNops"] = tail
                    return evidence

                with self.assertRaises(protocol.Rejected):
                    protocol.check_native(fresh.decoded, fresh.transport,
                                          SimpleNamespace(_NATIVE=checker._NATIVE, _match=match))

    def test_direct_capture_relabel_cannot_replace_fixed_archive_producer(self):
        row = capture_record()
        # Counts and labels alone can look identical after dishonest relabeling.
        row["CaptureProducer"] = dict(Path=str(subject.ROOT / subject.UTILITY),
                                      Sha256=subject.FIXED[subject.UTILITY])
        with self.assertRaisesRegex(ValueError, "fixed archive producer"):
            require_record(row)

    def test_archived_and_explicit_provider_indices_are_exact_and_typed(self):
        changes = (
            ("ArchiveMemberIndices", [0, 1, 2, 3, 4]),
            ("ArchiveMemberIndices", [0, 1, 2, 3, 4, 5, 6]),
            ("ArchiveMemberIndices", [0, 1, 2, 3, 4, 4]),
            ("ArchiveMemberIndices", [1, 0, 2, 3, 4, 5]),
            ("ArchiveMemberIndices", [0, True, 2, 3, 4, 5]),
            ("ArchiveMemberIndices", [0.0, 1, 2, 3, 4, 5]),
            ("ExplicitObjectIndices", [6, 7, 8]),
            ("ExplicitObjectIndices", [8, 7, 7]),
            ("ExplicitObjectIndices", [8, 7]),
            ("ExplicitObjectIndices", [8.0, 7, 6]))
        for key, value in changes:
            with self.subTest(field=key, value=value):
                row = capture_record()
                row[key] = value
                with self.assertRaises(ValueError):
                    require_record(row)

    def test_producer_and_helper_source_bindings_are_exact(self):
        for target in ("producer-path", "producer-hash", "helper-path", "helper-hash", "helper-order", "missing-helper"):
            with self.subTest(target=target):
                row = capture_record()
                if target == "producer-path":
                    row["CaptureProducer"]["Path"] += ".foreign"
                elif target == "producer-hash":
                    row["CaptureProducer"]["Sha256"] = "0" * 64
                elif target == "helper-path":
                    row["FrozenCaptureHelpers"][0]["Path"] += ".foreign"
                elif target == "helper-hash":
                    row["FrozenCaptureHelpers"][0]["Sha256"] = "0" * 64
                elif target == "helper-order":
                    row["FrozenCaptureHelpers"].reverse()
                else:
                    row["FrozenCaptureHelpers"].pop()
                with self.assertRaises(ValueError):
                    require_record(row)

    def test_capture_completion_nonclaims_and_zero_credits_are_literal(self):
        for key in COMPLETION_FLAGS:
            for value in (False, 1, 1.0, None):
                with self.subTest(completion=key, value=value):
                    row = capture_record()
                    row[key] = value
                    with self.assertRaises(ValueError):
                        require_record(row)
        for key in NONCLAIMS:
            for value in (True, 0, 0.0, None):
                with self.subTest(nonclaim=key, value=value):
                    row = capture_record()
                    row[key] = value
                    with self.assertRaises(ValueError):
                        require_record(row)
        for value in (False, 0.0, 1, -1):
            with self.subTest(required_credit=value):
                row = capture_record()
                row["RequiredCellsSatisfied"] = value
                with self.assertRaises(ValueError):
                    require_record(row)


def load_module(name, path, data):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    exec(compile(data, str(path), "exec"), module.__dict__)
    return module


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    output, temporary = args.output_dir.resolve(), Path(tempfile.gettempdir()).resolve()
    if (output.exists() or args.output_dir.is_symlink() or output.is_relative_to(REPO)
            or REPO.is_relative_to(output) or not output.is_relative_to(temporary)):
        parser.error("fresh external TEMP output directory required")
    report = dict(
        Status="FAIL", Scope="PURE_SYNTHETIC_CM3_ARCHIVE_ROOT_ADMISSION_AND_SCOPE_ONLY",
        Tests=0, ExpectedTestMethods=EXPECTED_METHODS, Failures=0, Errors=0, Skipped=0,
        SourceHashes={}, SourceDrift=[], SourceClosureVerified=False, ClosingFilesVerified=0,
        TestPlan=list(TEST_PLAN), SyntheticInputs=True, ActualArchiveTested=False,
        ActualELFTested=False, ActualMutantsExecuted=0, WitnessExecuted=False,
        ToolInvocations=0, NativeCommandsExecuted=0, Qualification=False,
        CanonicalProtocolValidated=False, FinalRootRelocationProof=False,
        FinalReferenceParity=False, FullABIProof=False, CompleteObjectProof=False,
        SourceToMachineSemanticProof=False, OriginalTranslationUnitOwnership=False,
        KernelRuntimeProof=False, CpuExecution=False, BoardExecution=False,
        GlobalFreezeQualified=False, RequiredCellSatisfied=False, RequiredCellsSatisfied=0)
    try:
        if sys.flags.optimize or not __debug__:
            raise ValueError("optimized interpreter unsupported")
        paths = (Path(__file__).resolve(), WITNESS, COMMON, ARCHIVE, ARCHIVE_FIXTURE,
                 PROTOCOL, PROTOCOL_FIXTURE, CHECKER)
        buffers = {path: path.read_bytes() for path in paths}
        report["SourceHashes"] = {str(path): sha(data) for path, data in buffers.items()}
        global subject, common, archive, archive_fixture_module, protocol, protocol_fixture, checker
        with patch("subprocess.Popen", side_effect=AssertionError("pure archive-root controls cannot spawn processes")), \
                patch("os.system", side_effect=AssertionError("pure archive-root controls cannot execute tools")):
            common = load_module("synthetic_archive_root_common", COMMON, buffers[COMMON])
            archive = load_module("synthetic_archive_root_producer", ARCHIVE, buffers[ARCHIVE])
            archive_fixture_module = load_module("synthetic_archive_root_ar_fixture", ARCHIVE_FIXTURE, buffers[ARCHIVE_FIXTURE])
            protocol = load_module("synthetic_archive_root_protocol", PROTOCOL, buffers[PROTOCOL])
            checker = load_module("synthetic_archive_root_checker", CHECKER, buffers[CHECKER])
            protocol_fixture = load_module("synthetic_archive_root_protocol_fixture", PROTOCOL_FIXTURE, buffers[PROTOCOL_FIXTURE])
            protocol_fixture.p, protocol_fixture.c = protocol, checker
            subject = load_module("synthetic_archive_root_witness", WITNESS, buffers[WITNESS])
            suite = unittest.defaultTestLoader.loadTestsFromTestCase(WitnessTests)
            if suite.countTestCases() != EXPECTED_METHODS:
                raise ValueError("exact ten implemented archive-root controls required; skeleton cannot pass")
            result = unittest.TextTestRunner(verbosity=2).run(suite)
        report.update(Tests=result.testsRun, Failures=len(result.failures), Errors=len(result.errors),
            Skipped=len(result.skipped), FailureDetails=[
                dict(Test=str(case), Detail=detail) for case, detail in result.failures + result.errors])
        if result.wasSuccessful() and result.testsRun == EXPECTED_METHODS and not result.skipped:
            report["Status"] = "PASS"
    except Exception:
        report.update(Status="FAIL", Error=traceback.format_exc(), Errors=report["Errors"] + 1)
    finally:
        for path, expected in report["SourceHashes"].items():
            try:
                if sha(Path(path).read_bytes()) == expected:
                    report["ClosingFilesVerified"] += 1
                else:
                    report["SourceDrift"].append(path)
            except OSError:
                report["SourceDrift"].append(path)
        report["SourceClosureVerified"] = len(report["SourceHashes"]) == 8 and not report["SourceDrift"]
        if not report["SourceClosureVerified"]:
            report["Status"] = "FAIL"
    output.mkdir(parents=True, exist_ok=False)
    target = output / "results.json"
    target.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="ascii")
    print("Receipt:", target, sha(target.read_bytes()))
    return 0 if report["Status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
