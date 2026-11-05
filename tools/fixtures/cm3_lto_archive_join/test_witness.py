"""Pure archive-pair admission/composition controls, not actual ELF qualification."""

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
BASE_JOIN = HERE.with_name("cm3_lto_join") / "join.py"
PAIR_FIXTURE = BASE_JOIN.with_name("test_join.py")
CHECKER = HERE.with_name("cm3_freeze_parity") / "check.py"
POLICY = HERE.with_name("cm3_final_join") / "POLICY_DIFFERENCES.md"
NATIVE_WITNESS = HERE.with_name("cm3_lto_archive_roots") / "witness.py"
REFERENCE_PRODUCER = HERE.with_name("cm3_reference_lto_archive") / "probe.py"
REFERENCE_FIXTURE = REFERENCE_PRODUCER.with_name("test_probe.py")
EXPECTED_METHODS = 10
subject = base_join = pair_fixture = checker = native = reference = reference_fixture = None
policy_text = None
COHORT = "cm3-cortex-m3-soft-nofpu-none-v1-mpu0-p4-b16-aapcs-default"
COMPLETION = ("LTO", "InputClosureVerified", "OutputSealVerified", "ArchiveCaptureComplete", "NoForcedExtraction",
              "TwinLoadImageCompared", "TwinLoadImageIdentical", "TwinAllocatedSectionsIdentical")
NONCLAIMS = ("ArchiveExtraction", "ArchiveExtractionQualified", "WeakAliasPrecedenceProven", "Qualification",
    "CanonicalProtocolValidated", "FinalRootRelocationProof", "FinalReferenceParity", "FullABIProof", "SourceIRProof",
    "SourceToMachineSemanticProof", "OriginalTranslationUnitOwnership", "CompleteObjectProof", "PolicyEquivalence",
    "CpuExecution", "BoardExecution", "GlobalFreezeQualified", "RequiredCellSatisfied")
TEST_PLAN = (
    "exact side-specific archive capture scopes, roles, counts and commands",
    "literal completion/nonclaim/count types and no caller side aliases",
    "direct capture relabel refusal on either side",
    "six native versus one reference member/source bindings",
    "reference optional GNU name table with exact short member and index target",
    "complete raw/object/extracted member bytes and hashes",
    "explicit native 8/7/6 and reference 3/2/1 providers then own archive",
    "paired six-body canonical composition with separate machine/hash domains",
    "projection/raw transport invariants, zero tails and broad nonpromotion",
    "six unique substantive captured difference rationales",
)


def sha(data):
    return hashlib.sha256(data).hexdigest().upper()


class FrozenJoinFacade:
    def __getattr__(self, name):
        if name == "check_join":
            raise AssertionError("archive composition must not relabel the old public direct-link result")
        return getattr(base_join, name)


def check_pair(fixture, chosen_checker=None, master=None, policy=None):
    return subject.check_archive_pair(fixture.native, fixture.reference,
        checker if chosen_checker is None else chosen_checker,
        fixture.ledger if master is None else master, policy_text if policy is None else policy, FrozenJoinFacade())


def capture_record(side):
    is_reference = side == "Reference"
    row = dict(Status="PASS", Error=None, Profile="CM3", Mode="O2-lto", SeedMode="O2", Cohort=COHORT,
        Linkage="archive", Scope=("PINNED_REFERENCE_CM3_O2_LTO_INDEXED_ARCHIVE_CAPTURE_ONLY" if is_reference
                                 else "NATIVE_CM3_O2_LTO_INDEXED_ARCHIVE_CAPTURE_ONLY"),
        TranslationUnits=4 if is_reference else 9, SlimIRObjects=3 if is_reference else 8,
        FinalExecutableLinks=2, SavedMachineObjects=2, RequiredCellsSatisfied=0,
        ArchiveMemberIndices=[0] if is_reference else [0, 1, 2, 3, 4, 5],
        ExplicitObjectIndices=[3, 2, 1] if is_reference else [8, 7, 6])
    row.update({key: True for key in COMPLETION})
    row.update({key: False for key in NONCLAIMS})
    row["ReferenceBuilt"] = is_reference
    if is_reference:
        row.update(SeedSide="Reference", ReferenceCommit="a50edad08b29052631aa469d4df6e6ec7ff68878",
            Providers="TYPED-FAILSTOP-FIXTURE; NOT A REAL FREERTOS KERNEL", NativeBuilt=False,
            ReferenceKernelAvailable=False, SchedulerSemanticsProven=False, CSourceSemanticProof=False,
            HandlerRoutingProven=False)
    return row


def require_scope(side, row):
    if side == "Native":
        return native.require_capture_scope(row)
    if side == "Reference":
        return subject.require_reference_scope(row)
    raise AssertionError("unknown synthetic side")


class AdmissionBoundary(RuntimeError):
    """The tested admission prefix passed; never enter real seed/tool replay."""


def reference_record():
    row = capture_record("Reference")
    row["CaptureProducer"] = dict(Path=str(subject.ROOT / subject.REFERENCE),
                                  Sha256=subject.FIXED[subject.REFERENCE])
    row["FrozenCaptureHelpers"] = [dict(Path=str(subject.ROOT / relative), Sha256=digest)
        for relative, digest in (
            (native.UTILITY, native.FIXED[native.UTILITY]),
            (subject.REF_TRANSPORT, subject.FIXED[subject.REF_TRANSPORT]),
            (subject.REF_ADMISSION, subject.FIXED[subject.REF_ADMISSION]),
            (native.PRODUCER, native.FIXED[native.PRODUCER]),
            (native.LOADER, native.FIXED[native.LOADER]),
            (native.BINDING, native.FIXED[native.BINDING]))]
    return row


def reference_admission_prefix(row):
    root = Path("/synthetic/reference-capture")
    receipt, manifest = "A" * 64, "B" * 64
    artifacts = {"results.json": receipt}

    def structured(path, digest):
        if path == root / "artifacts.json" and digest == manifest:
            return dict(Artifacts=artifacts)
        if path == root / "results.json" and digest == receipt:
            return copy.deepcopy(row)
        raise AssertionError("unexpected synthetic receipt read")

    value = SimpleNamespace(
        api=SimpleNamespace(checked_path=lambda path: Path(path), digest_text=lambda value: value,
                            portable_name=Mock()), base=native,
        watch=SimpleNamespace(structured=Mock(side_effect=structured), tree=Mock()),
        _json=Mock(side_effect=AdmissionBoundary("producer authority admitted before input replay")))
    args = SimpleNamespace(reference_build=str(root), reference_receipt_sha256=receipt,
                           reference_artifacts_sha256=manifest)
    return value, args


class WitnessTests(unittest.TestCase):
    def test_both_exact_archive_capture_scopes_are_admitted_without_mutation(self):
        for side in ("Native", "Reference"):
            with self.subTest(side=side):
                row = capture_record(side)
                before = copy.deepcopy(row)
                require_scope(side, row)
                self.assertEqual(row, before)

    def test_side_mode_linkage_pin_counts_and_literal_flags_reject_aliases(self):
        for side in ("Native", "Reference"):
            valid = capture_record(side)
            changes = [("Status", "FAIL"), ("Mode", "Os-lto"), ("SeedMode", "Os"), ("Linkage", "direct"),
                ("Cohort", COHORT.replace("b16", "b32")), ("Error", "capture failed"),
                ("TranslationUnits", float(valid["TranslationUnits"])),
                ("SlimIRObjects", float(valid["SlimIRObjects"])), ("FinalExecutableLinks", 2.0),
                ("SavedMachineObjects", True), ("RequiredCellsSatisfied", False), ("RequiredCellsSatisfied", 0.0)]
            if side == "Reference":
                changes.extend((("ReferenceCommit", "0" * 40), ("SeedSide", "reference"),
                    ("Providers", "REAL-KERNEL"), ("ReferenceBuilt", 1), ("ReferenceKernelAvailable", True)))
            for key, value in changes:
                with self.subTest(side=side, field=key, value=value):
                    row = copy.deepcopy(valid)
                    row[key] = value
                    with self.assertRaises(ValueError):
                        require_scope(side, row)
            for key in COMPLETION:
                with self.subTest(side=side, completion=key):
                    row = copy.deepcopy(valid)
                    row[key] = 1
                    with self.assertRaises(ValueError):
                        require_scope(side, row)
            for key in NONCLAIMS:
                for value in (True, 0):
                    with self.subTest(side=side, nonclaim=key, value=value):
                        row = copy.deepcopy(valid)
                        row[key] = value
                        with self.assertRaises(ValueError):
                            require_scope(side, row)

    def test_native_six_reference_one_indices_and_cross_side_scopes_are_not_interchangeable(self):
        for side, other in (("Native", "Reference"), ("Reference", "Native")):
            with self.subTest(side=side, case="opposite scope"):
                with self.assertRaises(ValueError):
                    require_scope(side, capture_record(other))
            valid = capture_record(side)
            for key in ("ArchiveMemberIndices", "ExplicitObjectIndices"):
                expected = valid[key]
                candidates = [[], expected + [expected[0]], expected[:-1],
                              [float(expected[0]), *expected[1:]]]
                if len(expected) > 1:
                    candidates.extend((list(reversed(expected)), [expected[0]] * len(expected)))
                if key == "ArchiveMemberIndices":
                    candidates.append([False, *expected[1:]])
                for value in candidates:
                    with self.subTest(side=side, field=key, value=value):
                        row = copy.deepcopy(valid)
                        row[key] = value
                        with self.assertRaises(ValueError):
                            require_scope(side, row)

    def test_archive_provider_builders_keep_side_specific_explicit_order(self):
        for side, count, order, builder in (
                ("Native", 9, (8, 7, 6), native.required_provider_order),
                ("Reference", 4, (3, 2, 1), subject.required_reference_provider_order)):
            objects = [Path("/synthetic/" + side + "/%02d.o" % index) for index in range(count)]
            library = Path("/synthetic/" + side + "/archive.a")
            with self.subTest(side=side, case="exact order"):
                providers = builder(objects, library)
                self.assertEqual(providers, [*(str(objects[index]) for index in order), str(library)])
                self.assertEqual(len(providers), len(set(providers)))
                for index in range(6 if side == "Native" else 1):
                    self.assertNotIn(str(objects[index]), providers)
            for candidate, target in ((objects[:-1], library), (objects + [Path("extra.o")], library),
                    (objects[:-1] + [objects[0]], library), (objects[:-1] + [True], library),
                    (objects, objects[0]), (objects, "")):
                with self.subTest(side=side, objects=str(candidate), archive=str(target)):
                    with self.assertRaises(ValueError):
                        builder(candidate, target)

    def test_reference_optional_name_table_preserves_single_member_index_and_bytes(self):
        without = reference_fixture.one_member_fixture()
        for optional in (False, True):
            with self.subTest(optional_name_table=optional):
                fixture = reference_fixture.one_member_fixture(optional_table=optional)
                result = reference.archive_records(fixture.raw)
                self.assertEqual(len(result["Members"]), 1)
                row = result["Members"][0]
                self.assertEqual(row["Name"], "00-port.o")
                self.assertEqual(row["Ordinal"], 0)
                self.assertEqual(row["HeaderOffset"], fixture.member_header)
                self.assertEqual(row["Sha256"], sha(fixture.payload))
                self.assertEqual(fixture.raw[row["DataOffset"]:row["DataOffset"] + row["Size"]], fixture.payload)
                self.assertEqual([item["RawName"] for item in result["Records"]],
                                 ["/", "//", "00-port.o/"] if optional else ["/", "00-port.o/"])
                self.assertTrue(all(item["HeaderOffset"] == fixture.member_header for item in result["Index"]))
                self.assertGreater(len(result["Index"]), 1)
                if optional:
                    self.assertGreater(fixture.member_header, without.member_header)
                    invalid = reference_fixture.changed(fixture.raw, fixture.index_data + 4,
                        reference_fixture.struct.pack(">I", fixture.table_header))
                    with self.assertRaises(ValueError):
                        reference.archive_records(invalid)
        optional = reference_fixture.one_member_fixture(optional_table=True)
        table = optional.raw[optional.table_header:optional.member_header]
        invalid = (
            optional.raw[:optional.member_header] + table + optional.raw[optional.member_header:],
            reference_fixture.changed(optional.raw, optional.member_header, b"foreign.o/".ljust(16)),
            reference_fixture.changed(optional.raw, optional.member_header, b"/0".ljust(16)))
        for index, raw in enumerate(invalid):
            with self.subTest(case=index):
                with self.assertRaises(ValueError):
                    reference.archive_records(raw)
        with tempfile.TemporaryDirectory(prefix="synthetic-archive-pair-member-") as temporary:
            root = Path(temporary).resolve()
            obj, extracted = root / "objects/00-port.o", root / "archive/members/00-port.o"
            for path in (obj, extracted):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(without.payload)
            digest = sha(without.payload)
            group = dict(Root=root, Artifacts={path.relative_to(root).as_posix(): digest for path in (obj, extracted)})

            def read(path, expected):
                raw = path.read_bytes()
                if sha(raw) != expected:
                    raise ValueError("synthetic watched member hash drift")
                return raw

            value = SimpleNamespace(api=SimpleNamespace(regular=lambda path: Path(path)),
                                    watch=SimpleNamespace(read=Mock(side_effect=read)))
            self.assertEqual(subject.Witness._artifact(value, group, extracted, digest),
                             subject.Witness._artifact(value, group, obj, digest))
            with self.assertRaisesRegex(ValueError, "artifact/record hash binding"):
                subject.Witness._artifact(value, group, extracted, "0" * 64)
            with self.assertRaisesRegex(ValueError, "escaped owning build"):
                subject.Witness._artifact(value, group, root.parent / "foreign.o", digest)
            extracted.write_bytes(b"different extracted member bytes")
            with self.assertRaisesRegex(ValueError, "watched member hash drift"):
                subject.Witness._artifact(value, group, extracted, digest)

    def test_direct_capture_relabel_fails_actual_producer_record_gates(self):
        native_row = capture_record("Native")
        native_row["CaptureProducer"] = dict(Path=str(native.ROOT / native.PRODUCER), Sha256=native.FIXED[native.PRODUCER])
        native_row["FrozenCaptureHelpers"] = [dict(Path=str(native.ROOT / relative), Sha256=native.FIXED[relative])
            for relative in (native.UTILITY, native.LOADER, native.BINDING)]
        value = SimpleNamespace(api=SimpleNamespace(same=subject.same))
        native.Witness._record(value, native_row)
        relabeled = copy.deepcopy(native_row)
        relabeled["CaptureProducer"] = dict(Path=str(native.ROOT / native.UTILITY), Sha256=native.FIXED[native.UTILITY])
        with self.assertRaisesRegex(ValueError, "fixed archive producer"):
            native.Witness._record(value, relabeled)

        row = reference_record()
        value, args = reference_admission_prefix(row)
        with self.assertRaisesRegex(AdmissionBoundary, "producer authority admitted"):
            subject.Witness._admit_reference(value, args)
        value._json.assert_called_once()
        value.watch.tree.assert_called_once()
        for case in ("direct-producer", "wrong-producer-hash", "wrong-helper", "reordered-helpers"):
            with self.subTest(case=case):
                changed = copy.deepcopy(row)
                if case == "direct-producer":
                    changed["CaptureProducer"] = dict(Path=str(subject.ROOT / subject.REF_TRANSPORT),
                        Sha256=subject.FIXED[subject.REF_TRANSPORT])
                elif case == "wrong-producer-hash":
                    changed["CaptureProducer"]["Sha256"] = "0" * 64
                elif case == "wrong-helper":
                    changed["FrozenCaptureHelpers"][0]["Sha256"] = "0" * 64
                else:
                    changed["FrozenCaptureHelpers"].reverse()
                value, args = reference_admission_prefix(changed)
                with self.assertRaisesRegex(ValueError, "archive producer|immutable helper sources"):
                    subject.Witness._admit_reference(value, args)
                value._json.assert_not_called()

    def test_exact_native_reference_command_count_and_sidecar_bind_before_tool_replay(self):
        class SeedBoundary:
            @property
            def originals(self):
                raise AdmissionBoundary("native catalog admitted before tool replay")

            @property
            def artifact(self):
                raise AdmissionBoundary("reference catalog admitted before tool replay")

        for side, count in (("Native", 66), ("Reference", 41)):
            records = [dict(Label="synthetic-command-%03d" % index, Argv=["not-executed", str(index)],
                Cwd="/synthetic/capture", Status="PASS", Exit=0, TimedOut=False, Error=None, Seconds=0.0)
                for index in range(count)]
            for case in ("valid-prefix", "missing", "extra", "wrong-container", "sidecar-argv", "sidecar-exit"):
                with self.subTest(side=side, case=case):
                    selected = copy.deepcopy(records)
                    if case == "missing":
                        selected.pop()
                    elif case == "extra":
                        selected.append(copy.deepcopy(selected[-1]))
                    elif case == "wrong-container":
                        selected = tuple(selected)
                    sidecar = copy.deepcopy(selected)
                    if case == "sidecar-argv":
                        sidecar[0]["Argv"].append("--foreign")
                    elif case == "sidecar-exit":
                        sidecar[0]["Exit"] = False
                    result = dict(Commands=selected, SeedCohortArtifact={})
                    root, seed = Path("/synthetic/capture"), SeedBoundary()
                    value = SimpleNamespace(root=root, seed=seed, result=result,
                        _json=Mock(return_value=sidecar))
                    group = dict(Root=root, Seed=seed, Result=result)

                    def invoke():
                        if side == "Native":
                            return native.Witness._commands(value, SimpleNamespace())
                        return subject.Witness._reference_commands(value, group, SimpleNamespace(), SimpleNamespace())

                    if case == "valid-prefix":
                        with self.assertRaisesRegex(AdmissionBoundary, "catalog admitted before tool replay"):
                            invoke()
                        value._json.assert_called_once()
                    else:
                        with self.assertRaises(ValueError):
                            invoke()
                        if case in ("missing", "extra", "wrong-container"):
                            value._json.assert_not_called()
                        else:
                            value._json.assert_called_once()

    def test_frozen_pair_keeps_six_complete_roots_domains_and_nonpromotion(self):
        fixture = pair_fixture.Fixture()
        before = copy.deepcopy((fixture.native.evidence, fixture.reference.evidence,
                                fixture.native.transport.records, fixture.reference.transport.records))
        proof = check_pair(fixture)
        self.assertEqual(proof["Status"], "CM3-LTO-ARCHIVE-JOIN-PASS-NOT-QUALIFIED")
        self.assertEqual(proof["Scope"], "CM3_O2_LTO_P4_B16_ARCHIVE_SIX_CLOSED_ROOT_JOIN_ONLY")
        self.assertEqual(proof["Linkage"], "archive")
        self.assertEqual(base_join.SCOPE, "CM3_O2_LTO_P4_B16_DIRECT_SIX_CLOSED_ROOT_JOIN_ONLY")
        self.assertEqual(proof["ClosedBodies"], 6)
        self.assertEqual(proof["Mechanisms"], pair_fixture.MECHANISMS)
        self.assertEqual(proof["DifferenceIds"], list(pair_fixture.DIFFERENCES))
        self.assertNotEqual(proof["MachineSha256"]["Native"], proof["MachineSha256"]["Reference"])
        for side, view in fixture.sides():
            self.assertEqual(proof["MachineSha256"][side], sha(view.decoded.data))
            for row in proof["Roots"][side]:
                self.assertEqual(row["HashDomains"], pair_fixture.DOMAINS)
                self.assertIs(row["TransportRecord"]["CanonicalProtocolValidated"], False)
            self.assertTrue(all(row["CanonicalProtocolValidated"] is False for row in proof["RawTransportRoots"][side]))
        self.assertEqual([len(row["ProjectionEvidence"]) for row in proof["Roots"]["Native"]], [0, 1, 1])
        self.assertEqual([len(row["ProjectionEvidence"]) for row in proof["Roots"]["Reference"]], [0, 0, 0])
        for key in ("Qualification", "FinalReferenceParity", "FullABIProof", "FinalElfProof",
                    "SourceToMachineSemanticProof", "OriginalTranslationUnitOwnership", "InstructionEquivalence",
                    "PolicyEquivalence", "CompleteObjectProof", "KernelRuntimeProof", "CpuExecution",
                    "BoardExecution", "GlobalFreezeQualified", "RequiredCellSatisfied"):
            self.assertIs(proof[key], False)
        self.assertIs(type(proof["RequiredCellsSatisfied"]), int)
        self.assertEqual(proof["RequiredCellsSatisfied"], 0)
        self.assertEqual((fixture.native.evidence, fixture.reference.evidence,
                          fixture.native.transport.records, fixture.reference.transport.records), before)

    def test_pair_rejects_hash_domain_projection_rawflag_and_tail_substitution(self):
        for case in ("same-machine", "machine-domain", "reference-projection", "raw-canonical", "tail", "bool-tail"):
            with self.subTest(case=case):
                fixture = pair_fixture.Fixture()
                chosen_checker = None
                if case == "same-machine":
                    fixture.reference.rebind_machine(fixture.native.decoded.data)
                elif case == "machine-domain":
                    fixture.native.evidence[pair_fixture.NATIVE[1]]["HashDomains"]["MachineRoot"] = "SHA256-JSON-TOKENS"
                elif case == "reference-projection":
                    fixture.reference.evidence[pair_fixture.REFERENCE[1]]["ProjectionEvidence"] = [dict(Kind="foreign projection")]
                elif case == "raw-canonical":
                    fixture.native.transport.records[pair_fixture.NATIVE[0]]["CanonicalProtocolValidated"] = True
                elif case == "tail":
                    fixture.reference.append_tail(pair_fixture.REFERENCE[0])
                else:
                    chosen_checker = pair_fixture.ProofChecker(
                        lambda proof: proof["RootEvidence"][0].update(TailNops=False))
                with self.assertRaises((ValueError, base_join.Rejected, checker.Rejected)):
                    check_pair(fixture, chosen_checker)

    def test_all_six_difference_rationales_must_be_unique_and_substantive(self):
        fixture = pair_fixture.Fixture()
        proof = check_pair(fixture)
        self.assertEqual(set(proof["DifferenceRationales"]), set(pair_fixture.DIFFERENCES))
        self.assertEqual(set(proof["PolicyDifferenceRationales"]), set(pair_fixture.DIFFERENCES))
        self.assertEqual(proof["PolicyLedgerSha256"], sha(policy_text.encode("ascii")))
        for identity in pair_fixture.DIFFERENCES:
            for case in ("missing", "duplicate", "comment-only", "empty"):
                with self.subTest(identity=identity, case=case):
                    bodies = pair_fixture.rationale_bodies()
                    if case == "missing":
                        ledger = fixture.ledger.replace("### " + identity, "### foreign-" + identity)
                    elif case == "duplicate":
                        ledger = fixture.ledger + "\n### " + identity + "\nDuplicate rationale.\n"
                    else:
                        bodies[identity] = "<!-- comment is not rationale -->" if case == "comment-only" else ""
                        ledger = pair_fixture.ledger(bodies)
                    with self.assertRaises(base_join.Rejected):
                        check_pair(pair_fixture.Fixture(), master=ledger)
        with self.assertRaisesRegex(ValueError, "exact fixed policy ledger"):
            check_pair(pair_fixture.Fixture(), policy=policy_text + "\n")


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
        Status="FAIL", Scope="PURE_SYNTHETIC_CM3_ARCHIVE_PAIR_ADMISSION_AND_COMPOSITION_ONLY",
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
        paths = (Path(__file__).resolve(), WITNESS, BASE_JOIN, PAIR_FIXTURE, CHECKER, POLICY,
                 NATIVE_WITNESS, REFERENCE_PRODUCER, REFERENCE_FIXTURE)
        buffers = {path: path.read_bytes() for path in paths}
        report["SourceHashes"] = {str(path): sha(data) for path, data in buffers.items()}
        global subject, base_join, pair_fixture, checker, native, reference, reference_fixture, policy_text
        with patch("subprocess.Popen", side_effect=AssertionError("pure archive-pair controls cannot spawn processes")), \
                patch("os.system", side_effect=AssertionError("pure archive-pair controls cannot execute tools")):
            base_join = load_module("synthetic_archive_pair_frozen_join", BASE_JOIN, buffers[BASE_JOIN])
            checker = load_module("synthetic_archive_pair_checker", CHECKER, buffers[CHECKER])
            pair_fixture = load_module("synthetic_archive_pair_fixture", PAIR_FIXTURE, buffers[PAIR_FIXTURE])
            pair_fixture.j, pair_fixture.c = base_join, checker
            native = load_module("synthetic_archive_pair_native_admission", NATIVE_WITNESS, buffers[NATIVE_WITNESS])
            reference = load_module("synthetic_archive_pair_reference_producer", REFERENCE_PRODUCER, buffers[REFERENCE_PRODUCER])
            reference_fixture = load_module("synthetic_archive_pair_reference_fixture", REFERENCE_FIXTURE, buffers[REFERENCE_FIXTURE])
            policy_text = buffers[POLICY].decode("ascii")
            subject = load_module("synthetic_archive_pair_witness", WITNESS, buffers[WITNESS])
            suite = unittest.defaultTestLoader.loadTestsFromTestCase(WitnessTests)
            if suite.countTestCases() != EXPECTED_METHODS:
                raise ValueError("exact ten implemented archive-pair controls required; skeleton cannot pass")
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
        report["SourceClosureVerified"] = len(report["SourceHashes"]) == 9 and not report["SourceDrift"]
        if not report["SourceClosureVerified"]:
            report["Status"] = "FAIL"
    output.mkdir(parents=True, exist_ok=False)
    target = output / "results.json"
    target.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="ascii")
    print("Receipt:", target, sha(target.read_bytes()))
    return 0 if report["Status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
