"""Pure synthetic Os six-body composition controls; no ELF/parser/tool runs."""
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
from unittest.mock import patch

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
COMPOSE = HERE / "compose.py"
JOIN = HERE.with_name("cm3_lto_join") / "join.py"
FIXTURE = HERE.with_name("cm3_lto_join") / "test_join.py"
CHECKER = HERE.with_name("cm3_freeze_parity") / "check.py"
EXPECTED_METHODS = 10
a = f = b = c = None


def sha(data):
    return hashlib.sha256(data).hexdigest().upper()


class FrozenFacade:
    """Forward unchanged private predicates; never consume an old join result."""
    def __init__(self, **overrides):
        self.overrides = overrides

    def __getattr__(self, name):
        if name == "check_join":
            raise AssertionError("Os composition must not call the O2 public join")
        return self.overrides[name] if name in self.overrides else getattr(f, name)


class Inputs:
    def __init__(self):
        self.fixture = b.Fixture()
        self.native, self.reference = self.fixture.native, self.fixture.reference
        self.ledger = self.fixture.ledger

    def check(self, checker=None, frozen=None):
        return a.check_join(self.native, self.reference, c if checker is None else checker,
                            self.ledger, f if frozen is None else frozen)


class ComposeTests(unittest.TestCase):
    def rejects(self, inputs, **kwargs):
        with self.assertRaises((f.Rejected, c.Rejected)):
            inputs.check(**kwargs)

    def test_fresh_os_response_six_bodies_without_old_public_join(self):
        inputs = Inputs()
        result = inputs.check(frozen=FrozenFacade())
        self.assertEqual(result["Status"], "CM3-OS-LTO-SIX-BODY-JOIN-PASS-NOT-QUALIFIED")
        self.assertEqual(result["Scope"], "CM3_OS_LTO_P4_B16_DIRECT_SIX_CLOSED_ROOT_JOIN_ONLY")
        self.assertEqual((result["Profile"], result["Mode"], result["Cohort"], result["Linkage"]),
                         ("CM3", "Os-lto", b.COHORT, "direct"))
        self.assertIs(result["LTO"], True)
        self.assertIs(result["CanonicalProtocolValidated"], True)
        self.assertIs(result["OriginalTransportRecordsUnmodified"], True)
        self.assertIs(type(result["ClosedBodies"]), int)
        self.assertEqual(result["ClosedBodies"], 6)
        self.assertEqual(result["Mechanisms"], b.MECHANISMS)
        self.assertEqual(set(inputs.native.calls), set(b.NATIVE))
        self.assertEqual(set(inputs.reference.calls), set(b.REFERENCE))
        self.assertEqual(result["FrameContract"], dict(NativeCoreSlots=9, NativeExcReturn="PER-CONTEXT-SAVED-LR",
            ReferenceCoreSlots=8, ReferenceFirstRestoreExcReturn="ORR-LR-13", EquivalenceProven=False))

    def test_typed_fixed_helper_cohort_root_contract_and_distinct_sides(self):
        for value in (None, True, 16.0, "cm3-foreign-cohort"):
            with self.subTest(cohort=value):
                self.rejects(Inputs(), frozen=FrozenFacade(COHORT=value))
        for name in ("NATIVE_ROOTS", "REFERENCE_ROOTS"):
            with self.subTest(roots=name):
                self.rejects(Inputs(), frozen=FrozenFacade(**{name: ("foreign-root",)}))
        inputs = Inputs()
        inputs.reference = inputs.native
        self.rejects(inputs)
        inputs = Inputs()
        inputs.native, inputs.reference = inputs.reference, inputs.native
        self.rejects(inputs)
        for side in (True, 0, "native", "Foreign"):
            checker = b.ProofChecker(lambda proof, side=side: proof["RootEvidence"][0].update(Side=side))
            with self.subTest(side=side):
                self.rejects(Inputs(), checker=checker)

    def test_complete_six_root_membership_and_protocol_required(self):
        mutations = (lambda proof: proof.update(ClosedBodies=5), lambda proof: proof.update(ClosedBodies=6.0),
                     lambda proof: proof["RootEvidence"].pop(), lambda proof: proof["Roots"].pop(),
                     lambda proof: proof["Mechanisms"].pop())
        for index, change in enumerate(mutations):
            with self.subTest(index=index):
                self.rejects(Inputs(), checker=b.ProofChecker(change))
        for side in ("native", "reference"):
            inputs = Inputs()
            view = getattr(inputs, side)
            del view.evidence[view.names[-1]]
            with self.subTest(missing=side):
                self.rejects(inputs)
            inputs = Inputs()
            view = getattr(inputs, side)
            view.canonical[view.names[-1]][0] = ("nop", "")
            view.refresh_tokens(view.names[-1])
            with self.subTest(protocol=side):
                self.rejects(inputs)

    def test_exact_literal_zero_tail_nops_on_every_complete_root(self):
        for value in (False, True, 0.0, 1):
            checker = b.ProofChecker(lambda proof, value=value: proof["RootEvidence"][4].update(TailNops=value))
            with self.subTest(tail=value):
                self.rejects(Inputs(), checker=checker)
        for side in ("native", "reference"):
            inputs = Inputs()
            view = getattr(inputs, side)
            view.append_tail(view.names[0])
            with self.subTest(actual_tail=side):
                self.rejects(inputs)

    def test_distinct_whole_machine_identity_and_during_match_data_binding(self):
        for change in ("decoded-only", "hash", "same-machines", "late-change"):
            inputs = Inputs()
            if change == "decoded-only":
                inputs.native.decoded.data += b"changed"
            elif change == "hash":
                inputs.native.machine_sha = "0" * 64
            elif change == "same-machines":
                inputs.reference.rebind_machine(inputs.native.decoded.data)
            else:
                inputs.native.on_first_call = lambda: inputs.native.rebind_machine(inputs.native.decoded.data + b"late-change")
            with self.subTest(change=change):
                self.rejects(inputs)

    def test_raw_transport_body_hashes_and_origin_must_bind_own_machine(self):
        changes = (("MachineProviderSha256", "0" * 64), ("MachineBodySha256", "0" * 64),
                   ("FinalBodySha256", "0" * 64))
        for side in ("native", "reference"):
            for key, value in changes:
                inputs = Inputs()
                view = getattr(inputs, side)
                view.evidence[view.names[1]][key] = value
                with self.subTest(side=side, key=key):
                    self.rejects(inputs)
            inputs = Inputs()
            view = getattr(inputs, side)
            view.transport.records[view.names[1]]["RootOrigin"]["ProviderSha256"] = "0" * 64
            with self.subTest(origin=side):
                self.rejects(inputs)

    def test_raw_canonical_and_projected_token_domains_cannot_substitute(self):
        for side in ("native", "reference"):
            for change in ("domain", "raw-hash", "malformed", "token-body-hash"):
                inputs = Inputs()
                view = getattr(inputs, side)
                row = view.evidence[view.names[1]]
                if change == "domain":
                    row["HashDomains"]["MachineRoot"] = "SHA256-JSON-TOKENS"
                elif change == "raw-hash":
                    row["RawTokenSha256"] = row["MachineBodySha256"]
                elif change == "malformed":
                    row["RawCanonicalTokens"][0] = ["nop", ""]
                    row["RawTokenSha256"] = b.token_sha(row["RawCanonicalTokens"])
                else:
                    row["TransportRecord"]["BodySha256"] = row["RawTokenSha256"]
                with self.subTest(side=side, change=change):
                    self.rejects(inputs)
        inputs = Inputs()
        row = inputs.native.evidence[b.NATIVE[1]]
        row["ProjectedTokenSha256"] = row["MachineBodySha256"]
        self.rejects(inputs)

    def test_each_difference_requires_unique_nonempty_captured_rationale(self):
        for identity in b.DIFFERENCES:
            inputs = Inputs()
            inputs.ledger = inputs.ledger.replace("### " + identity, "### Missing-" + identity)
            with self.subTest(missing=identity):
                self.rejects(inputs)
        for change in ("duplicate", "comment-only", "nonascii", "wrong-type"):
            inputs = Inputs()
            if change == "duplicate":
                inputs.ledger += "\n### " + b.DIFFERENCES[0] + "\nDuplicate rationale.\n"
            elif change == "comment-only":
                bodies = b.rationale_bodies()
                bodies[b.DIFFERENCES[0]] = "<!-- not a rationale -->"
                inputs.ledger = b.ledger(bodies)
            elif change == "nonascii":
                inputs.ledger += "\u00e9"
            else:
                inputs.ledger = b"not text"
            with self.subTest(change=change):
                self.rejects(inputs)

    def test_protocol_transport_and_response_nonpromotion_is_typed(self):
        for key in ("RequiredCellSatisfied", "CompleteObjectProof", "InstructionEquivalence", "CpuExecution",
                    "FinalElfProof", "GlobalFreezeQualified"):
            with self.subTest(proof=key):
                self.rejects(Inputs(), checker=b.ProofChecker(lambda proof, key=key: proof.update({key: True})))
        for side in ("native", "reference"):
            inputs = Inputs()
            view = getattr(inputs, side)
            view.transport.records[view.names[1]]["CanonicalProtocolValidated"] = True
            with self.subTest(raw_promotion=side):
                self.rejects(inputs)
        result = Inputs().check()
        for key in ("Qualification", "FinalReferenceParity", "FullABIProof", "FinalElfProof", "SourceIRProof",
                    "SourceToIRSemanticProof", "SourceToMachineSemanticProof", "OriginalTranslationUnitOwnership",
                    "InstructionEquivalence", "PolicyEquivalence", "CompleteObjectProof", "KernelRuntimeProof",
                    "HandlerRoutingProven", "ProducerCompilersReexecuted", "MutantsReexecuted", "CpuExecution",
                    "BoardExecution", "GlobalFreezeQualified", "RequiredCellSatisfied"):
            self.assertIs(result[key], False)
        for key in ("NativeCommandsExecuted", "RequiredCellsSatisfied"):
            self.assertIs(type(result[key]), int)
            self.assertEqual(result[key], 0)

    def test_purity_detached_evidence_and_unchanged_frozen_helpers(self):
        inputs = Inputs()
        state = lambda: (inputs.native.decoded.data, inputs.reference.decoded.data,
            inputs.native.canonical, inputs.reference.canonical, inputs.native.evidence, inputs.reference.evidence,
            inputs.native.transport.records, inputs.reference.transport.records, c._NATIVE, c._REFERENCE)
        before = copy.deepcopy(state())
        helpers = dict(vars(f))
        with patch("builtins.open", side_effect=AssertionError("pure compose opened file")), \
                patch.object(Path, "open", side_effect=AssertionError("pure compose opened path")), \
                patch.object(Path, "read_bytes", side_effect=AssertionError("pure compose read file")), \
                patch.object(Path, "read_text", side_effect=AssertionError("pure compose read text")), \
                patch("subprocess.Popen", side_effect=AssertionError("pure compose spawned process")):
            result = inputs.check(frozen=FrozenFacade())
        result["Roots"]["Native"][0]["TransportRecord"]["RootOrigin"]["Name"] = "changed-output"
        result["RawTransportRoots"]["Reference"][0]["CanonicalProtocolValidated"] = True
        result["Mechanisms"][0]["DifferenceIds"].clear()
        self.assertEqual(state(), before)
        self.assertEqual(vars(f), helpers)
        self.assertEqual(f.PASS, "CM3-LTO-SIX-BODY-JOIN-PASS-NOT-QUALIFIED")
        self.assertEqual(f.SCOPE, "CM3_O2_LTO_P4_B16_DIRECT_SIX_CLOSED_ROOT_JOIN_ONLY")
        self.assertEqual(inputs.check()["Mechanisms"], b.MECHANISMS)


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
    report = dict(Status="FAIL", Tests=0, ExpectedTestMethods=EXPECTED_METHODS, Failures=0, Errors=0, Skipped=0,
        SourceHashes={}, SourceDrift=[], SourceClosureVerified=False, ClosingFilesVerified=0,
        Scope="PURE_SYNTHETIC_CM3_OS_LTO_SIX_BODY_COMPOSITION_CONTROLS_ONLY", SyntheticInputs=True,
        ActualELFTested=False, ActualMachineDecoderTested=False, ActualTransportPreservationTested=False,
        ActualWitnessTested=False, Qualification=False, NativeCommandsExecuted=0, ToolInvocations=0,
        FullABIProof=False, SourceIRProof=False, SourceToIRSemanticProof=False, SourceToMachineSemanticProof=False,
        OriginalTranslationUnitOwnership=False, CanonicalProtocolValidated=False, InstructionEquivalence=False,
        PolicyEquivalence=False, FinalReferenceParity=False, CompleteObjectProof=False, KernelRuntimeProof=False,
        CpuExecution=False, BoardExecution=False, GlobalFreezeQualified=False,
        RequiredCellSatisfied=False, RequiredCellsSatisfied=0)
    paths = (Path(__file__).resolve(), COMPOSE, JOIN, FIXTURE, CHECKER)
    try:
        if sys.flags.optimize or not __debug__:
            raise ValueError("optimized interpreter unsupported")
        buffers = {item: item.read_bytes() for item in paths}
        report["SourceHashes"] = {str(item): sha(data) for item, data in buffers.items()}
        global a, f, b, c
        with patch("subprocess.Popen", side_effect=AssertionError("pure controls cannot execute processes")), \
                patch("os.system", side_effect=AssertionError("pure controls cannot execute processes")):
            f = load_module("synthetic_os_compose_frozen_join", JOIN, buffers[JOIN])
            c = load_module("synthetic_os_compose_checker", CHECKER, buffers[CHECKER])
            b = load_module("synthetic_os_compose_fixture", FIXTURE, buffers[FIXTURE])
            b.j, b.c = f, c
            a = load_module("synthetic_os_compose_subject", COMPOSE, buffers[COMPOSE])
            suite = unittest.defaultTestLoader.loadTestsFromTestCase(ComposeTests)
            count = suite.countTestCases()
            if count != EXPECTED_METHODS:
                raise ValueError("exact ten synthetic Os composition methods required")
            result = unittest.TextTestRunner(verbosity=2).run(suite)
        report.update(Tests=result.testsRun, Failures=len(result.failures), Errors=len(result.errors),
            Skipped=len(result.skipped), FailureDetails=[dict(Test=str(case), Detail=detail)
            for case, detail in result.failures + result.errors])
        if result.wasSuccessful() and result.testsRun == count and not result.skipped:
            report["Status"] = "PASS"
    except Exception:
        report.update(Status="FAIL", Error=traceback.format_exc(), Errors=report["Errors"] + 1)
    finally:
        for path, expected in report["SourceHashes"].items():
            try:
                if sha(Path(path).read_bytes()) != expected:
                    report["SourceDrift"].append(path)
                else:
                    report["ClosingFilesVerified"] += 1
            except OSError:
                report["SourceDrift"].append(path)
        report["SourceClosureVerified"] = len(report["SourceHashes"]) == 5 and not report["SourceDrift"]
        if not report["SourceClosureVerified"]:
            report["Status"] = "FAIL"
    output.mkdir(parents=True, exist_ok=False)
    target = output / "results.json"
    target.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="ascii")
    print("Receipt:", target, sha(target.read_bytes()))
    return 0 if report["Status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
