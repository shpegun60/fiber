"""Synthetic frontend controls; no captures, ELF parsers, or target tools run."""

import argparse
from contextlib import contextmanager, redirect_stderr, redirect_stdout
import copy
import hashlib
import importlib.util
import io
import json
import os
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
SUBJECT = HERE / "witness.py"
REPLAY = REPO / "tools/freeze_replay.py"
REPLAY_SHA256 = "142BDDE647122DB2D66EF66E4C44A33ECEAA9292FFE304EF3C7CBCC740283275"
EXPECTED_METHODS = 14
PASS = "CM3-OS-LTO-JOIN-PASS-NOT-QUALIFIED"
SOURCE = "69A66CB09D699EA45A30B21BF4DBCD569CBE637A7770125E76EE64323D862313"
COHORT = "cm3-cortex-m3-soft-nofpu-none-v1-mpu0-p4-b16-aapcs-default"
ARGUMENTS = (
    "native_build", "native_receipt_sha256", "native_artifacts_sha256",
    "reference_build", "reference_receipt_sha256", "reference_artifacts_sha256",
    "inventory", "inventory_receipt_sha256", "inventory_artifacts_sha256", "output_dir",
)
subject = None
replay = None


def sha(raw):
    return hashlib.sha256(raw).hexdigest().upper()


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("ascii")


def module(name, path, raw):
    result = importlib.util.module_from_spec(importlib.util.spec_from_file_location(name, path))
    sys.modules[name] = result
    exec(compile(raw, str(path), "exec"), result.__dict__)
    return result


@contextmanager
def no_processes():
    with patch("subprocess.Popen", side_effect=AssertionError("synthetic suite cannot spawn")), \
            patch("os.system", side_effect=AssertionError("synthetic suite cannot use a shell")):
        yield


def args_for(root):
    return SimpleNamespace(native_build=str(root / "native"), native_receipt_sha256="A" * 64,
        native_artifacts_sha256="B" * 64, reference_build=str(root / "reference"),
        reference_receipt_sha256="C" * 64, reference_artifacts_sha256="D" * 64,
        inventory=str(root / "inventory"), inventory_receipt_sha256="E" * 64,
        inventory_artifacts_sha256="F" * 64, output_dir=str(root / "output"))


def argv_for(args):
    return [part for name in ARGUMENTS for part in ("--" + name.replace("_", "-"), getattr(args, name))]


def flags(**changes):
    values = dict(optimize=0, isolated=1, no_site=1)
    values.update(changes)
    return SimpleNamespace(**values)


def report_fixture():
    """Only the frozen report interface is modeled, not ELF/control semantics."""
    proof = dict(Verdict="CM3-CLOSED-ROOTS-PASS", ClosedBodies=6,
        RootEvidence=[dict(SyntheticBody=index) for index in range(6)],
        Mechanisms=[dict(Name=name) for name in ("first", "svc", "pendsv")],
        DifferenceIds=["SYNTHETIC-DIFFERENCE"])
    roots = {side: [dict(Name=name) for name in names] for side, names in (
        ("Native", ("fiber_port_start_first_context", "SVC_Handler", "PendSV_Handler")),
        ("Reference", ("prvPortStartFirstTask", "vPortSVCHandler", "xPortPendSVHandler")))}
    controls = {side: dict(
        Transport=[dict(Status="PASS", Files=[dict(Synthetic=True)], ClosingFilesVerified=5)
                   for _ in range(16)],
        Canonical=[dict(Status="PASS", Files=[dict(Synthetic=True)], ClosingFilesVerified=6)])
        for side in ("Native", "Reference")}
    return dict(Status=PASS, Scope="CM3_OS_LTO_SIX_BODY_MECHANISM_JOIN_ONLY", Profile="CM3",
        Mode="Os-lto", Cohort=COHORT, Linkage="direct", Error=None, PrimaryError=None,
        ClosingErrors=[], SourceInventorySha256=SOURCE, InputClosureVerified=True,
        ImmutableInputsConsumed=True, OutputSealVerified=True, ClosingFilesVerified=1,
        JoinProof=dict(ProtocolProof=proof, Roots=roots, ClosedBodies=6, CanonicalProtocolValidated=True),
        RecomputedSides={side: dict(Twins=dict(Identical=True, Segments=[dict(Synthetic=True)]))
                         for side in ("Native", "Reference")},
        Controls=controls, TransportControlsExecuted=32, CanonicalControlsExecuted=2,
        MutantsReexecuted=True, CanonicalProtocolValidated=True, FinalRootRelocationProof=True,
        GlobalFreezeQualified=False, FinalReferenceParity=False, CompleteObjectProof=False,
        PolicyEquivalence=False, CpuExecution=False, BoardExecution=False, FullABIProof=False,
        APIProof=False, Qualification=False, RequiredCellSatisfied=False, RequiredCellsSatisfied=0,
        SourceIRProof=False, SourceToMachineSemanticProof=False, InputDrift=[],
        CapturedInputDrift=[], UnexpectedOutputMembers=[], MissingDeclaredOutputMembers=[])


class FakeWitness:
    """Generated in-memory evidence and private TEMP files, never a real seed."""

    def __init__(self, root):
        self.args = args_for(root)
        self.output = Path(self.args.output_dir)
        self.report = report_fixture()
        self.replay_api = replay
        self.run = Mock(return_value=True)
        self._fail = Mock(side_effect=self.fail)
        self._seal = Mock(side_effect=self.seal)

    def fail(self, error):
        self.report.update(Status="FAIL", Error=(self.report.get("Error") or "") + "; " + str(error),
            InputClosureVerified=False, CanonicalProtocolValidated=False,
            FinalRootRelocationProof=False, ImmutableInputsConsumed=False, OutputSealVerified=False)

    def seal(self):
        self.output.mkdir(parents=True, exist_ok=True)
        self.report["OutputSealVerified"] = True
        self.write_pair()

    def write_pair(self):
        receipt = encoded(self.report)
        (self.output / "results.json").write_bytes(receipt)
        (self.output / "artifacts.json").write_bytes(encoded(dict(Artifacts={"results.json": sha(receipt)})))

    def seed_old_pass(self):
        self.output.mkdir()
        self.write_pair()


class SyntheticPreparation:
    def __init__(self, root, witness):
        self.root = root
        self.pins = {name: ("synthetic/" + name + ".py", sha((name + " buffer\n").encode("ascii")))
                     for name in ("capture", "legacy", "admission")}
        self.raw = {root / row[0]: (name + " buffer\n").encode("ascii")
                    for name, row in self.pins.items()}
        # prepare uses the literal repository-relative contract pathname.
        self.contract = root / "tools/fixtures/cm3_current_lto_replay/CONTRACT.md"
        self.raw[self.contract] = b"synthetic compile-free contract\n"
        self.contract_pin = sha(self.raw[self.contract])
        self.raw[SUBJECT] = b"synthetic frontend source\n"
        self.reads, self.loads = [], []
        self.constructor = Mock(return_value=witness)
        self.factory = Mock(return_value=self.constructor)
        self.modules = dict(capture=SimpleNamespace(Synthetic="capture"),
            legacy=SimpleNamespace(PASS=PASS), admission=SimpleNamespace(witness_type=self.factory))

    def read(self, path):
        path = Path(path)
        if path not in self.raw:
            raise AssertionError("unadmitted synthetic source read: " + str(path))
        self.reads.append(path)
        return self.raw[path]

    def load(self, name, path, raw):
        path = Path(path)
        if raw != self.raw[path]:
            raise AssertionError("loader did not receive authenticated source buffer")
        self.loads.append((name, path, raw))
        return self.modules[next(key for key, row in self.pins.items() if self.root / row[0] == path)]

    @contextmanager
    def active(self):
        with patch.object(subject, "ROOT", self.root), patch.object(subject, "PINS", self.pins), \
                patch.object(subject, "CONTRACT_SHA", self.contract_pin), \
                patch.object(subject.sys, "flags", flags()), patch.object(subject.sys, "dont_write_bytecode", True), \
                patch.object(Path, "read_bytes", lambda path: self.read(path)), \
                patch.object(subject, "load", side_effect=self.load) as load:
            yield load


class WitnessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="cm3-current-replay-synthetic-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.witness = FakeWitness(self.root)
        self.modules = dict(legacy=SimpleNamespace(PASS=PASS))

    def invoke(self, witness=None, prepare=None, require=None):
        witness = self.witness if witness is None else witness
        out, err = io.StringIO(), io.StringIO()
        with patch.object(subject, "prepare", prepare or Mock(return_value=(witness, self.modules))), \
                patch.object(subject, "require_result", require or Mock(wraps=subject.require_result)), \
                redirect_stdout(out), redirect_stderr(err):
            result = subject.main(argv_for(witness.args))
        return result, out.getvalue(), err.getvalue()

    def test_cli_requires_all_ten_arguments_and_rejects_extras_and_abbreviations(self):
        full = argv_for(self.witness.args)
        invalid = [full[:index] + full[index + 2:] for index in range(0, len(full), 2)]
        invalid += [full + ["--command", "synthetic"], ["--native-b", full[1], *full[2:]]]
        for value in invalid:
            with self.subTest(argv=value), patch.object(subject, "prepare") as prepare, \
                    redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                subject.main(value)
            self.assertEqual(error.exception.code, 2)
            prepare.assert_not_called()
        self.assertFalse(self.witness.output.exists())

    def test_prepare_requires_isolated_unoptimized_no_site_no_bytecode_before_io(self):
        for changes in (dict(optimize=1), dict(isolated=0), dict(no_site=0), dict(bytecode=False)):
            value = dict(changes)
            bytecode = value.pop("bytecode", True)
            with self.subTest(changes=changes), patch.object(subject.sys, "flags", flags(**value)), \
                    patch.object(subject.sys, "dont_write_bytecode", bytecode), \
                    patch.object(Path, "read_bytes") as read, patch.object(subject, "load") as load, \
                    self.assertRaisesRegex(ValueError, "isolated -I -S -B"):
                subject.prepare(self.witness.args)
            read.assert_not_called()
            load.assert_not_called()

    def test_prepare_rejects_inherited_parser_root_or_submodule_before_io(self):
        for name in ("elftools", "elftools.elf.elffile"):
            with self.subTest(name=name), patch.dict(sys.modules, {name: SimpleNamespace()}), \
                    patch.object(subject.sys, "flags", flags()), \
                    patch.object(subject.sys, "dont_write_bytecode", True), \
                    patch.object(Path, "read_bytes") as read, self.assertRaisesRegex(ValueError, "inherited parser"):
                subject.prepare(self.witness.args)
            read.assert_not_called()

    def test_prepare_authenticates_all_pins_before_any_exec_or_constructor(self):
        for target in ("capture", "legacy", "admission", "contract", "unqualified"):
            f = SyntheticPreparation(self.root, self.witness)
            path = f.contract if target == "contract" else self.root / f.pins.get(target, f.pins["admission"])[0]
            if target == "unqualified":
                f.pins["admission"] = (f.pins["admission"][0], "UNQUALIFIED")
            else:
                f.raw[path] += b" altered"
            with self.subTest(target=target), f.active() as load, self.assertRaisesRegex(ValueError, "authenticated source buffer"):
                subject.prepare(self.witness.args)
            load.assert_not_called()
            f.factory.assert_not_called()
            f.constructor.assert_not_called()
        self.assertFalse(self.witness.output.exists())

    def test_prepare_passes_same_authenticated_buffers_exact_factory_and_args(self):
        f = SyntheticPreparation(self.root, self.witness)
        with f.active():
            result, modules = subject.prepare(self.witness.args)
        self.assertIs(result, self.witness)
        self.assertEqual(modules, f.modules)
        self.assertEqual(len(f.loads), 3)
        f.factory.assert_called_once()
        call = f.factory.call_args
        self.assertEqual(call.args, (f.modules["legacy"], f.modules["capture"]))
        self.assertEqual(call.kwargs, dict(extra_sources=f.raw))
        f.constructor.assert_called_once_with(self.witness.args)
        self.assertTrue(all(f.reads.count(path) == 1 for path in f.raw))
        self.assertFalse(self.witness.output.exists())

    def test_load_executes_given_buffer_without_reading_its_disk_path(self):
        path = self.root / "never-created.py"
        name = "_current_replay_buffer_control"
        try:
            with patch.object(Path, "read_bytes", side_effect=AssertionError("unexpected disk reread")):
                result = subject.load(name, path, b"VALUE = 'admitted bytes'\n")
            self.assertEqual(result.VALUE, "admitted bytes")
            self.assertIs(sys.modules[name], result)
            self.assertEqual(Path(result.__file__), path)
            self.assertFalse(path.exists())
        finally:
            sys.modules.pop(name, None)

    def test_require_result_checks_status_error_fingerprint_then_delegates_exact_route(self):
        original = copy.deepcopy(self.witness.report)
        check = Mock(wraps=replay.report_evidence)
        self.witness.replay_api = SimpleNamespace(report_evidence=check)
        self.assertIs(subject.require_result(self.witness, self.modules), self.witness.report)
        check.assert_called_once_with("CM3/Os-lto/direct", self.witness.report)
        self.assertEqual(self.witness.report, original)
        for key, value in (("Status", "PASS"), ("Error", "failure"), ("SourceInventorySha256", "0" * 64),
                           ("SourceInventorySha256", None)):
            self.witness.report = dict(original, **{key: value})
            check.reset_mock()
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                subject.require_result(self.witness, self.modules)
            check.assert_not_called()

    def test_require_result_uses_frozen_schema_for_typed_counters_scope_and_nonpromotion(self):
        changes = (("Profile", "CM4"), ("Mode", "O2-lto"), ("Cohort", "foreign"),
            ("Linkage", "archive"), ("Scope", "arbitrary"), ("InputClosureVerified", False),
            ("ImmutableInputsConsumed", False), ("OutputSealVerified", False),
            ("ClosingFilesVerified", True), ("TransportControlsExecuted", 31),
            ("CanonicalControlsExecuted", True), ("MutantsReexecuted", False),
            ("RequiredCellsSatisfied", False), ("RequiredCellsSatisfied", 0.0),
            ("RequiredCellsSatisfied", 1), ("GlobalFreezeQualified", True),
            ("FullABIProof", True), ("CpuExecution", True), ("InputDrift", ["synthetic"]))
        for key, value in changes:
            self.witness.report = dict(report_fixture(), **{key: value})
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                subject.require_result(self.witness, self.modules)
        for side in ("Native", "Reference"):
            self.witness.report = report_fixture()
            self.witness.report["JoinProof"]["Roots"][side].pop()
            with self.subTest(missing_side_root=side), self.assertRaises(ValueError):
                subject.require_result(self.witness, self.modules)

    def test_main_success_runs_once_prints_narrow_summary_and_preserves_inputs(self):
        before = copy.deepcopy(self.witness.report)
        status, out, err = self.invoke()
        self.assertEqual((status, err), (0, ""))
        summary = json.loads(out)
        self.assertEqual(set(summary), {"Status", "Profile", "Mode", "InputClosureVerified",
            "OutputSealVerified", "TransportControlsExecuted", "CanonicalControlsExecuted", "RequiredCellsSatisfied"})
        self.assertEqual(summary["Status"], PASS)
        self.assertIs(type(summary["RequiredCellsSatisfied"]), int)
        self.assertEqual(summary["RequiredCellsSatisfied"], 0)
        self.witness.run.assert_called_once_with()
        self.witness._fail.assert_not_called()
        self.witness._seal.assert_not_called()
        self.assertEqual(self.witness.report, before)

    def test_main_blocks_process_and_shell_calls_through_prepare_run_and_postcheck(self):
        import subprocess
        for stage in ("prepare", "run", "postcheck"):
            for kind in ("process", "shell"):
                f = FakeWitness(self.root)
                call = (lambda *args: subprocess.Popen(["synthetic-never-executed"])) if kind == "process" else \
                       (lambda *args: os.system("synthetic-never-executed"))
                prepare = Mock(side_effect=call) if stage == "prepare" else None
                require = Mock(side_effect=call) if stage == "postcheck" else None
                if stage == "run":
                    f.run.side_effect = call
                with self.subTest(stage=stage, kind=kind):
                    status, out, err = self.invoke(f, prepare, require)
                self.assertEqual((status, out), (1, ""))
                self.assertIn("replay cannot execute", err)

    def test_main_preserves_primary_when_failure_evidence_sealing_also_raises(self):
        self.witness.seed_old_pass()
        self.witness.report["Error"] = "first build failure"
        self.witness.run.side_effect = ValueError("primary replay failure")
        self.witness._seal.side_effect = OSError("secondary failure seal")
        status, out, err = self.invoke()
        self.assertEqual((status, out), (1, ""))
        self.assertIn("primary replay failure", err)
        self.assertIn("secondary failure seal", err)
        self.assertIn("first build failure", self.witness.report["Error"])
        self.assertIn("primary replay failure", self.witness.report["Error"])
        self.assertEqual(self.witness.report["PrimaryError"], "first build failure")
        self.assertTrue(any("secondary failure seal" in error for error in self.witness.report["ClosingErrors"]))
        self.witness.run.assert_called_once_with()

    def test_main_rejects_nonliteral_success_and_failed_postconditions_without_rerun(self):
        for result, source in ((False, SOURCE), (1, SOURCE), (None, SOURCE), (True, "0" * 64)):
            root = self.root / str(result) / source[:3]
            root.mkdir(parents=True, exist_ok=True)
            f = FakeWitness(root)
            f.seed_old_pass()
            f.run.return_value = result
            f.report["SourceInventorySha256"] = source
            with self.subTest(result=result, source=source):
                status, out, err = self.invoke(f)
            self.assertEqual((status, out), (1, ""))
            self.assertTrue(err)
            self.assertEqual(json.loads((f.output / "results.json").read_bytes())["Status"], "FAIL")
            f.run.assert_called_once_with()
            f._fail.assert_called_once()
            f._seal.assert_called_once_with()

    def test_failure_hook_error_does_not_escape_or_hide_primary_or_skip_evidence(self):
        self.witness.seed_old_pass()
        self.witness.run.side_effect = ValueError("primary replay failure")
        self.witness._fail.side_effect = OSError("secondary failure hook")
        status, out, err = self.invoke()
        self.assertEqual((status, out), (1, ""))
        self.assertIn("primary replay failure", err)
        self.assertIn("secondary failure hook", err)
        recorded = json.loads((self.witness.output / "results.json").read_bytes())
        self.assertEqual(recorded["Status"], "FAIL")
        self.assertIn("primary replay failure", recorded["PrimaryError"])
        self.assertTrue(any("secondary failure hook" in error for error in recorded["ClosingErrors"]))
        self.witness.run.assert_called_once_with()

    def test_failure_seal_error_cannot_leave_stale_pass_receipt_manifest_pair(self):
        for transient in (False, True):
            root = self.root / str(transient)
            root.mkdir()
            f = FakeWitness(root)
            f.seed_old_pass()
            original = (f.output / "results.json").read_bytes()
            payload = b"retained synthetic diagnostic bytes\n"
            (f.output / "diagnostic.txt").write_bytes(payload)
            f.run.side_effect = ValueError("primary replay failure")
            f._seal.side_effect = OSError("synthetic failure seal")
            real_write = Path.write_bytes
            receipt_attempts = []

            def write_receipt(path, raw):
                if path == f.output / "results.json":
                    receipt_attempts.append(raw)
                    if transient and len(receipt_attempts) == 1:
                        raise OSError("synthetic first fallback write")
                return real_write(path, raw)

            with self.subTest(transient_fallback=transient), \
                    patch.object(subject, "persist_failure_evidence", wraps=subject.persist_failure_evidence) as persist, \
                    patch.object(Path, "write_bytes", write_receipt):
                status, out, err = self.invoke(f)
                self.assertEqual((status, out), (1, ""))
                self.assertIn("primary replay failure", err)
                self.assertEqual(persist.call_count, 2 if transient else 1)
                self.assertTrue(all(call.args == (f,) and call.kwargs == {} for call in persist.call_args_list))
                self.assertEqual(len(receipt_attempts), 2 if transient else 1)
                raw = (f.output / "results.json").read_bytes()
                self.assertNotEqual(sha(raw), sha(original))
                self.assertEqual(raw, encoded(f.report))
                recorded = json.loads(raw)
                self.assertEqual(recorded["Status"], "FAIL")
                self.assertIn("primary replay failure", recorded["PrimaryError"])
                self.assertIs(recorded["InputClosureVerified"], False)
                self.assertIs(recorded["OutputSealVerified"], False)
                for key in ("CanonicalProtocolValidated", "FinalRootRelocationProof", "ImmutableInputsConsumed"):
                    self.assertIs(recorded[key], False)
                if transient:
                    self.assertIn("synthetic first fallback write", err)
                    self.assertTrue(any("synthetic first fallback write" in error for error in recorded["ClosingErrors"]))
                manifest = json.loads((f.output / "artifacts.json").read_bytes())
                self.assertEqual(manifest, dict(Artifacts={"results.json": sha(raw), "diagnostic.txt": sha(payload)}))
                f.run.assert_called_once_with()
                f._seal.assert_called_once_with()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    output, temporary = args.output_dir.resolve(), Path(tempfile.gettempdir()).resolve()
    if (output.exists() or args.output_dir.is_symlink() or not output.is_relative_to(temporary)
            or output.is_relative_to(REPO) or REPO.is_relative_to(output)):
        parser.error("fresh external TEMP output directory required")
    paths = (Path(__file__).resolve(), SUBJECT, REPLAY)
    report = dict(Status="FAIL", Tests=0, ExpectedTestMethods=EXPECTED_METHODS, Failures=0, Errors=0,
        Skipped=0, SourceHashes={}, SourceDrift=[], SourceClosureVerified=False, ClosingFilesVerified=0,
        Scope="PURE_SYNTHETIC_CURRENT_CM3_OS_LTO_REPLAY_FRONTEND_CONTROLS_ONLY", SyntheticInputs=True,
        ActualCaptureRead=False, ActualELFTested=False, ActualRootProtocolTested=False,
        ActualManagedProcessTested=False, NativeCommandsExecuted=0, ToolInvocations=0,
        Qualification=False, FullABIProof=False, FullSemanticABIProof=False, FinalReferenceParity=False,
        FinalRootRelocationProof=False, CanonicalProtocolValidated=False, CompleteObjectProof=False,
        CpuExecution=False, BoardExecution=False, GlobalFreezeQualified=False,
        RequiredCellSatisfied=False, RequiredCellsSatisfied=0)
    try:
        if sys.flags.optimize or not __debug__:
            raise ValueError("unoptimized host Python required")
        buffers = {path: path.read_bytes() for path in paths}
        report["SourceHashes"] = {str(path): sha(raw) for path, raw in buffers.items()}
        if sha(buffers[REPLAY]) != REPLAY_SHA256:
            raise ValueError("fixed unchanged report-schema helper required")
        global subject, replay
        with no_processes():
            subject = module("_pure_current_cm3_replay_frontend", SUBJECT, buffers[SUBJECT])
            replay = module("_pure_current_cm3_replay_report_schema", REPLAY, buffers[REPLAY])
            suite = unittest.defaultTestLoader.loadTestsFromTestCase(WitnessTests)
            if suite.countTestCases() != EXPECTED_METHODS:
                raise ValueError("exact fourteen implemented synthetic methods required")
            result = unittest.TextTestRunner(verbosity=2).run(suite)
        report.update(Tests=result.testsRun, Failures=len(result.failures), Errors=len(result.errors),
            Skipped=len(result.skipped), FailureDetails=[dict(Test=str(case), Detail=detail)
                for case, detail in result.failures + result.errors])
        if result.wasSuccessful() and result.testsRun == EXPECTED_METHODS and not result.skipped:
            report["Status"] = "PASS"
    except Exception:
        report.update(Status="FAIL", Error=traceback.format_exc(), Errors=report["Errors"] + 1)
    finally:
        for path, value in report["SourceHashes"].items():
            try:
                if sha(Path(path).read_bytes()) == value:
                    report["ClosingFilesVerified"] += 1
                else:
                    report["SourceDrift"].append(path)
            except OSError:
                report["SourceDrift"].append(path)
        report["SourceClosureVerified"] = len(report["SourceHashes"]) == len(paths) and not report["SourceDrift"]
        if not report["SourceClosureVerified"]:
            report["Status"] = "FAIL"
    output.mkdir(parents=True, exist_ok=False)
    receipt = output / "results.json"
    receipt.write_bytes(encoded(report))
    print("Receipt:", receipt, sha(receipt.read_bytes()))
    return 0 if report["Status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
