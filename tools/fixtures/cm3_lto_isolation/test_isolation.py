"""Host-only synthetic isolation controls; no compiler, parser, or target runs."""
import argparse
import contextlib
import copy
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import traceback
import types
import unittest
from unittest.mock import Mock, patch


sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SUBJECT = HERE / "isolation.py"
COMPONENTS = ROOT / "tools/fixtures/cm0_final_cell/components.py"
CONTROLS = ROOT / "tools/fixtures/cm3_lto_abi_controls/controls.py"
PINS = {
    COMPONENTS: "16490A20B1A75C5DBD2D21A5FED988C5BD82F4DE919350985B33491CE473A5F7",
    CONTROLS: "7984A228966FC17641BD83D23486DB7E50BC2B7E5BC12D70A712F6E83800F14F",
}
EXPECTED_METHODS = 13
PLAN = (
    "discover isolated context_core", "compile isolated context_core", "inspect slim context_core",
    "discover isolated context_runtime_state", "compile isolated context_runtime_state",
    "inspect slim context_runtime_state", "discover isolated context_panic", "compile isolated context_panic",
    "inspect slim context_panic", "link isolated-common", "link isolated-common-emit",
    "disassemble isolated-common-emit",
)
PHASES = (
    "CpuFreeCommonValidated", "SourceOwnershipValidated", "WholeSlotAccessIsolation",
    "PositiveLinkRevalidated", "InputClosureVerified", "OutputSealVerified",
)
NONCLAIMS = (
    "Qualification", "CellContractSatisfied", "RequiredCellSatisfied", "FullABIProof",
    "FullSemanticABIProof", "SourceIRProof", "SourceToMachineSemanticProof", "OriginalTranslationUnitOwnership",
    "FinalReferenceParity", "CanonicalProtocolValidated", "PolicyEquivalence", "ArchiveExtraction",
    "CpuExecution", "BoardExecution", "HostedCIQualified", "GlobalFreezeQualified",
    "TypedDeclarationProbesValidated", "FiveLinkControlsValidated",
)
S = PROBES = BASE = None
BUFFERS = {}


def sha(raw):
    return hashlib.sha256(raw).hexdigest().upper()


def module_from_bytes(name, path, raw):
    module = types.ModuleType(name)
    module.__file__ = str(path)
    exec(compile(raw, str(path), "exec"), module.__dict__)
    return module


def flags(root):
    return ["-mcpu=cortex-m3", "-mthumb", "-mfloat-abi=soft", "-O2", "-flto", "-fno-fat-lto-objects",
        "-ffunction-sections", "-DFIBER_PORT_SCHEDULER_BASEPRI=16", "-I" + str(root / "fiber/port/ARM_CM3"),
        "-I", str(root / "../cmsis"), "-include", str(root / "tools/fixtures/classic_final_image/main.h")]


def commands():
    return [dict(Label=label, State="TERMINAL", Status="PASS", Exit=0, ExpectedExit=0,
                 TimedOut=False, JournalErrors=[]) for label in PLAN]


def report():
    # Top-level scaffolding only: the empty leaves deliberately do not prove isolation.
    return dict(Status=S.PASS, Scope=S.SCOPE, Profile="CM3", Mode="O2-lto", Linkage="direct", LTO=True,
        Error=None, PrimaryError=None, ClosingErrors=[], RequiredCellsSatisfied=0, RequiredCellCount=2774,
        RawIRIdentityClaim=False, Commands=commands(), IsolatedCommon=[None, None, None],
        WholeSlotAccessIsolationScope="SECTION_MEDIATED_CURRENT_CM3_O2_LTO_ONLY",
        SlotProofs=[dict(Kind="Original", Proof=None), dict(Kind="Isolated", Proof={})],
        **{name: True for name in PHASES}, **{name: False for name in NONCLAIMS})


def files_under(root):
    return {path.relative_to(root).as_posix(): path for path in root.rglob("*") if path.is_file()}


class FakeBase:
    """Minimal base constructor and journal; every managed command is forbidden."""
    calls = []

    def __init__(self, args, admitted, modules, buffers):
        self.calls.append((self, args, admitted, modules, buffers))
        if getattr(args, "reject_handoff", False):
            raise ValueError("fake admission output/input overlap")
        self.args, self.admitted, self.modules, self.buffers = args, admitted, modules, buffers
        self.report = report()
        self._started = self._finished = False
        self.commands = commands()
        self.expected = {"commands.json": sha(b"synthetic journal")}
        self.watch = types.SimpleNamespace(hashes={}, close=Mock())
        self.verify_objects = Mock()
        self._verify_outputs = Mock()
        self._save = Mock()
        self.command = Mock(side_effect=AssertionError("failure handling must not retry a tool"))
        self.hook_failure = False

    def _failure(self, error):
        if self.hook_failure:
            self.report.update(Status=S.PASS, **{name: True for name in PHASES})
            raise OSError("synthetic failure hook raised")
        message = type(error).__name__ + ": " + str(error)
        self.report.update(Status="FAIL", Error=self.report.get("Error") or message,
                           PrimaryError=self.report.get("PrimaryError") or message)


class IsolationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="cm3-lto-isolation-synthetic-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        FakeBase.calls = []

    def suite(self):
        admitted = types.SimpleNamespace(identity=Mock(return_value={"Synthetic": True}))
        suite = S.suite_type(FakeBase)(types.SimpleNamespace(), admitted,
            {"controls": BASE}, {SUBJECT: BUFFERS[SUBJECT]})
        suite.output = self.root / "output"
        suite.output.mkdir()
        info = suite.output.stat()
        suite.output_identity = (info.st_dev, info.st_ino)
        suite.api = types.SimpleNamespace(checked_path=lambda path, **kwargs: Path(path), files_under=files_under)
        return suite

    def assert_revoked(self, value):
        self.assertEqual(value["Status"], "FAIL")
        for name in PHASES:
            self.assertIs(value[name], False, name)

    def test_common_flags_preserve_real_lto_and_only_replace_include_inputs(self):
        root = self.root / "capture/source"
        before = flags(root)
        old = before[:]
        with patch.object(Path, "read_bytes", side_effect=AssertionError("pure flags read file")):
            actual = S.common_flags(PROBES, before, root)
        self.assertEqual(actual, old[:8] + ["-I" + str(root / name) for name in ("context", "fiber", "")])
        self.assertEqual(before, old)
        for value in ("-O2", "-flto", "-fno-fat-lto-objects", "-mcpu=cortex-m3", "-mfloat-abi=soft"):
            self.assertEqual(actual.count(value), 1)
        self.assertNotIn("-include", actual)

    def test_common_flags_missing_duplicate_and_alternate_includes_reject(self):
        root = self.root / "source"
        valid = flags(root)
        bad = [tuple(valid), [True], valid[:-2], valid + ["-I"],
               valid + ["-imacros", "foreign.h"], valid + ["-includeoops.h"]]
        for required in ("-O2", "-flto", "-fno-fat-lto-objects"):
            bad += [[item for item in valid if item != required], valid + [required]]
        for value in bad:
            with self.subTest(value=value), self.assertRaises(ValueError):
                S.common_flags(PROBES, value, root)
        broken_helper = types.SimpleNamespace(isolated_flags=lambda original, base: ["-O2"])
        with self.assertRaisesRegex(ValueError, "preserves optimization"):
            S.common_flags(broken_helper, valid, root)

    def test_command_plan_is_independently_spelled_exact_twelve(self):
        self.assertIs(type(S.command_plan()), tuple)
        self.assertEqual(S.command_plan(), PLAN)
        self.assertEqual(len(PLAN), 12)
        self.assertTrue(S.commands_pass(commands()))

    def test_command_records_reject_bool_exit_nonterminal_extra_and_reorder(self):
        for field, value in (("Exit", False), ("ExpectedExit", False), ("Exit", 0.0),
                ("ExpectedExit", 0.0), ("State", "RUNNING"), ("Status", "EXPECTED-NONZERO"),
                ("TimedOut", 0), ("JournalErrors", ["late stream write failed"])):
            rows = commands()
            rows[0][field] = value
            with self.subTest(field=field, value=value):
                self.assertFalse(S.commands_pass(rows))
        for rows in (commands()[:-1], commands() + [commands()[0]], commands() + [None],
                     list(reversed(commands())), tuple(commands()), None):
            with self.subTest(rows=rows):
                self.assertFalse(S.commands_pass(rows))

    def test_common_compile_uses_actual_dependencies_and_exact_two_command_recipe(self):
        root = self.root / "capture/source"
        output = self.root / "compile-output"
        output.mkdir()
        source = root / "context/context_core.c"
        header = root / "context/context_port_abi.h"
        data = {source: b"/* synthetic common provider */\n", header: b"/* synthetic header */\n"}
        deps = [dict(Path=str(path), Sha256=sha(raw)) for path, raw in data.items()]
        row = dict(Source=str(source), SourceSha256=sha(data[source]), SlimIR=True,
            CompileFlags=flags(root), ActualCompileDependencies=deps, Object=str(self.root / "original.o"),
            ObjectSha256=sha(b"original synthetic IR, not compared"))
        invocations, outputs, rows = [], {}, []

        def read(path, expected=None):
            raw = data[Path(path)]
            if expected is not None:
                self.assertEqual(sha(raw), expected)
            return raw

        def command(argv, label):
            invocations.append(([str(value) for value in argv], label))
            rows.append(dict(Label=label))
            return types.SimpleNamespace(stdout=b"", stderr=b"")

        def record(path):
            outputs[str(path)] = dict(Path=str(path), Sha256=sha(b"new synthetic slim IR"))
            return outputs[str(path)]

        def equal_dependencies(before, after):
            self.assertEqual(before, after)

        def inspect_ir(obj):
            rows.append(dict(Label="inspect slim context_core"))
            return {"SlimIR": True}

        native = types.SimpleNamespace(read_dependencies=Mock(return_value=[source, header]),
            require_compile_dependencies=Mock(side_effect=equal_dependencies))
        suite = types.SimpleNamespace(source=Mock(return_value=row), base=root.parent, output=output,
            api=types.SimpleNamespace(checked_path=Path), watch=types.SimpleNamespace(read=Mock(side_effect=read)),
            modules={"probes": PROBES}, tools={"gcc": "FAKE-NOT-EXECUTABLE-gcc"}, commands=rows,
            command=command, record_output=record, native=native, inspect_ir=inspect_ir)
        proof = S.compile_common(suite, 0)
        selected = S.common_flags(PROBES, row["CompileFlags"], root)
        obj = output / "isolated-common/context_core.o"
        self.assertEqual(invocations, [
            (["FAKE-NOT-EXECUTABLE-gcc", *selected, "-M", "-MF", str(obj.with_suffix(".discovery.d")),
              "-MT", "pilot-source-0", str(source)], PLAN[0]),
            (["FAKE-NOT-EXECUTABLE-gcc", *selected, "-MD", "-MF", str(obj.with_suffix(".compile.d")),
              "-MT", "pilot-source-0", "-c", str(source), "-o", str(obj)], PLAN[1])])
        self.assertEqual(proof["OriginalCompileFlags"], flags(root))
        self.assertEqual(proof["CompileFlags"], selected)
        self.assertEqual(proof["Dependencies"], deps)
        self.assertEqual(proof["CommandIndices"], [0, 1, 2])
        self.assertIs(proof["IncludeDelta"]["OtherSemanticFlagsUnchanged"], True)
        self.assertIs(proof["RawIRIdentityClaim"], False)
        self.assertIs(proof["SourceToMachineSemanticProof"], False)
        self.assertNotIn("WholeObjectByteIdentical", proof)
        native.require_compile_dependencies.assert_called_once()
        for index in (False, True, -1, 3, 0.0):
            with self.subTest(index=index), self.assertRaises(ValueError):
                S.compile_common(suite, index)
        for foreign in (root.parent / "cmsis/core.h", root / "fiber/port/ARM_CM3/port.h"):
            with self.subTest(foreign=foreign), self.assertRaises(ValueError):
                PROBES.isolated_dependencies([foreign], {foreign: "A" * 64}, root=root, cmsis=root.parent / "cmsis")
        with self.assertRaises(ValueError):
            PROBES.isolated_dependencies([source, source], {source: sha(data[source])},
                                        root=root, cmsis=root.parent / "cmsis")

    def test_suite_specialization_has_explicit_private_state_and_no_reclassification(self):
        args, admitted, modules, buffers = (types.SimpleNamespace(), object(), {"controls": BASE}, {})
        original = FakeBase(args, admitted, modules, buffers)
        previous = copy.deepcopy(original.report)
        specialized = S.suite_type(type(original))(args, admitted, modules, buffers)
        self.assertIs(type(original), FakeBase)
        self.assertIs(type(specialized).__bases__[0], FakeBase)
        self.assertEqual(original.report, previous)
        self.assertIsNot(original.report, specialized.report)
        self.assertIs(specialized.admitted, admitted)
        self.assertIs(specialized.modules, modules)
        self.assertIs(specialized.buffers, buffers)
        self.assertIs(specialized._isolation_done, False)
        self.assertEqual(specialized.report["Scope"], S.SCOPE)
        self.assert_revoked(specialized.report)
        for name in NONCLAIMS:
            self.assertIs(specialized.report[name], False, name)
        self.assertEqual(len(FakeBase.calls), 2)

    def test_failure_revokes_persisted_pass_despite_hook_and_first_persistence_errors(self):
        suite = self.suite()
        suite._started, suite.hook_failure = True, True
        suite.report = report()
        suite.report["PrimaryError"] = "original managed command failed"
        (suite.output / "results.json").write_bytes(S.encoded(suite.report))
        (suite.output / "artifacts.json").write_bytes(S.encoded({"Artifacts": {
            "results.json": sha((suite.output / "results.json").read_bytes())}}))
        original_persist = BASE.persist_failure
        attempts = []

        def persist(current):
            attempts.append(copy.deepcopy(current.report))
            self.assert_revoked(current.report)
            if len(attempts) == 1:
                raise OSError("one-shot failure diagnostic write")
            return original_persist(current)

        with patch.object(BASE, "persist_failure", side_effect=persist):
            S.revoke_failure(suite, ValueError("later closing failure"))
        self.assertEqual(len(attempts), 2)
        self.assert_revoked(suite.report)
        self.assertEqual(suite.report["PrimaryError"], "original managed command failed")
        self.assertTrue(any("failure hook" in value for value in suite.report["ClosingErrors"]))
        self.assertTrue(any("failure persistence 1" in value for value in suite.report["ClosingErrors"]))
        retained = json.loads((suite.output / "results.json").read_bytes())
        self.assertEqual(retained, suite.report)
        manifest = json.loads((suite.output / "artifacts.json").read_bytes())
        self.assertEqual(manifest, {"Artifacts": {"results.json": sha((suite.output / "results.json").read_bytes())}})
        suite.command.assert_not_called()

    def test_finish_missing_phase_and_late_closure_revoke_without_tool_retry(self):
        for kind in ("done", "command", *PHASES[:-2]):
            suite = self.suite()
            suite.report.update(**{name: True for name in PHASES})
            suite._isolation_done = True
            if kind == "done":
                suite._isolation_done = False
            elif kind == "command":
                suite.commands.pop()
            else:
                suite.report[kind] = False
            with self.subTest(kind=kind):
                self.assert_revoked(suite.finish())
                suite.command.assert_not_called()
                suite._save.assert_not_called()
                with self.assertRaisesRegex(ValueError, "exactly once"):
                    suite.finish()
            suite.output.rmdir()
        suite = self.suite()
        suite._started = suite._isolation_done = suite.hook_failure = True
        suite.report = report()
        suite.watch.close.side_effect = [None, OSError("late input close")]
        with patch.object(S, "succeeded", return_value=True):
            value = suite.finish()
        self.assert_revoked(value)
        self.assertIn("late input close", value["PrimaryError"])
        self.assertTrue(any("failure hook" in item for item in value["ClosingErrors"]))
        self.assert_revoked(json.loads((suite.output / "results.json").read_bytes()))
        suite.command.assert_not_called()

    def test_prepare_authenticates_all_pin_bytes_before_any_execution_and_interpreter_guard(self):
        args = types.SimpleNamespace()
        cases = [dict(optimize=1, isolated=1, no_site=1), dict(optimize=0, isolated=0, no_site=1),
                 dict(optimize=0, isolated=1, no_site=0)]
        for state in cases:
            with self.subTest(state=state), patch.object(S.sys, "flags", types.SimpleNamespace(**state)), \
                    patch.object(Path, "read_bytes", side_effect=AssertionError("preflight read")) as read, \
                    patch.object(S, "load") as load, self.assertRaisesRegex(ValueError, "interpreter"):
                S.prepare(args)
            read.assert_not_called()
            load.assert_not_called()
        pin_names = ("controls", "ownership", "slot", "contract")
        pins = {name: ("synthetic/" + name, sha(name.encode("ascii"))) for name in pin_names}
        data = {S.ROOT / path: name.encode("ascii") for name, (path, digest) in pins.items()}
        for name in pin_names:
            altered = dict(data)
            altered[S.ROOT / pins[name][0]] += b"UNAUTHENTICATED"
            with self.subTest(name=name), patch.object(S, "PINS", pins), \
                    patch.object(Path, "read_bytes", autospec=True, side_effect=lambda path: altered[path]), \
                    patch.object(S, "load") as load, self.assertRaisesRegex(ValueError, "fixed helper"):
                S.prepare(args)
            load.assert_not_called()

    def test_prepare_explicit_base_constructor_handoff_and_disjoint_refusal_before_writes(self):
        args = types.SimpleNamespace()
        admitted = object()
        original = FakeBase(args, admitted, {}, {})
        inherited = {"probes": PROBES, "retained": object()}
        helper = types.SimpleNamespace(prepare=Mock(return_value=(original, inherited)))
        fake_modules = {"controls": helper, "ownership": object(), "slot": object()}
        pins = {name: ("synthetic/" + name, sha(name.encode("ascii")))
                for name in (*fake_modules, "contract")}
        data = {S.ROOT / path: name.encode("ascii") for name, (path, digest) in pins.items()}
        data[SUBJECT.resolve()] = BUFFERS[SUBJECT]

        def load(name, path, raw):
            self.assertEqual(raw, data[path])
            return fake_modules[name.removeprefix("cm3_lto_isolation_")]

        with patch.object(S, "PINS", pins), patch.object(Path, "read_bytes", autospec=True,
                side_effect=lambda path: data[path]), patch.object(S, "load", side_effect=load) as loader:
            specialized, modules = S.prepare(args)
            self.assertIs(specialized.admitted, admitted)
            self.assertIs(specialized.modules, modules)
            self.assertIs(type(original), FakeBase)
            self.assertEqual(specialized.buffers, data)
            self.assertIs(modules["probes"], PROBES)
            self.assertEqual(loader.call_count, 3)
            args.reject_handoff = True
            with patch.object(Path, "mkdir", side_effect=AssertionError("output created before handoff")) as mkdir, \
                    self.assertRaisesRegex(ValueError, "output/input overlap"):
                S.prepare(args)
            mkdir.assert_not_called()
        helper.prepare.assert_called_with(args)
        self.assertFalse(specialized._started)

    def test_main_stdout_flush_failure_revokes_sealed_pass_even_when_hook_raises(self):
        suite = self.suite()
        suite.report, suite._started, suite.hook_failure = report(), True, True
        argv = []
        for name in ("capture-build", "capture-receipt-sha256", "capture-artifacts-sha256", "inventory",
                     "inventory-receipt-sha256", "inventory-artifacts-sha256", "output-dir"):
            argv.extend(["--" + name, "synthetic-not-read"])

        class FlushFailure(io.StringIO):
            def flush(self):
                raise OSError("stdout flush failed after sealed PASS")

        stderr = io.StringIO()
        with patch.object(S, "prepare", return_value=(suite, {"controls": BASE})) as prepare, \
                patch.object(S, "run", return_value=suite.report) as run, \
                patch.object(S, "succeeded", return_value=True), \
                contextlib.redirect_stdout(FlushFailure()), contextlib.redirect_stderr(stderr):
            result = S.main(argv)
        self.assertEqual(result, 1)
        self.assertIn("stdout flush failed", stderr.getvalue())
        self.assert_revoked(suite.report)
        self.assert_revoked(json.loads((suite.output / "results.json").read_bytes()))
        prepare.assert_called_once()
        run.assert_called_once()
        suite.command.assert_not_called()

    def test_postconditions_reject_empty_proof_leaves_and_typed_scope_promotions(self):
        port, assembly = b"synthetic port source", b"synthetic merged assembly"
        image = types.SimpleNamespace(prelink=types.SimpleNamespace(data=b"synthetic machine"),
            final=types.SimpleNamespace(data=b"synthetic final"), link_map_hash=sha(b"synthetic map"))
        leaf = dict(Status="CM3-LTO-SLOT-ISOLATION-PASS-NOT-QUALIFIED",
            Scope="NATIVE_CM3_O2_LTO_MERGED_MACHINE_SECTION_MEDIATED_SLOT_ACCESSES_ONLY",
            Profile="CM3", Mode="O2-lto", Linkage="direct", EmitRelocs=True,
            SlotIsolationValidated=True, RawSectionSymbolsPreserved=True,
            AllSectionMediatedSlotReferencesValidated=True, HandlerLoadPairs=2, ClosedCommonBodies=6,
            CommonLoads=5, CommonStores=1, SlotReferences=8, AppliedSlotReferences=8, RequiredCellsSatisfied=0,
            Publisher="fiber_internal_runtime_publish_current_context", SourceSha256=sha(port),
            AssemblySha256=sha(assembly), MachineSha256=sha(image.prelink.data),
            FinalSha256=sha(image.final.data), LinkMapSha256=image.link_map_hash,
            CommonSourceOwnershipValidated=False, CompleteHandlerBodiesValidated=False,
            ArbitraryPointerAliasProof=False, WholeProgramMemorySafetyProof=False, FullSemanticABIProof=False,
            SourceToMachineSemanticProof=False, OriginalTranslationUnitOwnership=False, Qualification=False,
            CellContractSatisfied=False, CpuExecution=False, BoardExecution=False, GlobalFreezeQualified=False,
            RequiredCellSatisfied=False)
        original = copy.deepcopy(leaf)
        with patch.object(Path, "read_bytes", side_effect=AssertionError("leaf predicate performed file IO")):
            S.require_slot_result(leaf, port, assembly, image)
        self.assertEqual(leaf, original)
        bad = [("Scope", "WHOLE_PROGRAM_SLOT_PROOF"), ("Profile", "CM0"), ("Mode", "Os-lto"),
               ("Linkage", "archive"), ("Publisher", "another_publisher"), ("EmitRelocs", 1)]
        for key in ("SourceSha256", "AssemblySha256", "MachineSha256", "FinalSha256", "LinkMapSha256"):
            bad.extend(((key, "F" * 64), (key, False)))
        for key in ("HandlerLoadPairs", "ClosedCommonBodies", "CommonLoads", "CommonStores",
                    "SlotReferences", "AppliedSlotReferences", "RequiredCellsSatisfied"):
            bad.extend(((key, bool(leaf[key])), (key, float(leaf[key])), (key, leaf[key] + 1)))
        for key, value in leaf.items():
            if type(value) is bool and value is False:
                bad.extend(((key, True), (key, 0)))
        for key, replacement in bad:
            changed = dict(leaf, **{key: replacement})
            with self.subTest(leaf_key=key, replacement=replacement), self.assertRaises(ValueError):
                S.require_slot_result(changed, port, assembly, image)
        for key in leaf:
            changed = dict(leaf)
            del changed[key]
            with self.subTest(missing_leaf_key=key), self.assertRaises(ValueError):
                S.require_slot_result(changed, port, assembly, image)
        for changed in (None, [], True):
            with self.subTest(nonrecord=changed), self.assertRaises(ValueError):
                S.require_slot_result(changed, port, assembly, image)
        for key, replacement in (("RequiredCellsSatisfied", False), ("RequiredCellCount", 2774.0),
                ("LTO", 1), ("RawIRIdentityClaim", 0), ("Profile", "CM4"), ("Mode", "Os-lto"),
                ("Linkage", "archive"), ("Commands", commands() + [None])):
            value = report()
            value[key] = replacement
            with self.subTest(key=key, replacement=replacement):
                self.assertFalse(S.succeeded(value))
        for key in (*PHASES, *NONCLAIMS):
            value = report()
            value[key] = 1 if key in PHASES else 0
            with self.subTest(key=key):
                self.assertFalse(S.succeeded(value))
        self.assertFalse(S.succeeded(report()), "top-level flags and Kind labels cannot authenticate empty leaves")

    def test_complete_synthetic_report_accepts_and_deep_common_slot_twin_mutations_reject(self):
        # Invented metadata exercises receipt shape only; none of these paths or ELF bytes exist.
        value = report()
        root = self.root / "invented-capture/source"
        original_flags = flags(root)
        isolated_flags = original_flags[:8] + ["-I" + str(root / part) for part in ("context", "fiber", "")]
        value["IsolatedCommon"] = []
        names = ("context/context_core.c", "context/context_runtime_state.c", "context/context_panic.c")
        for index, (name, indices) in enumerate(zip(names, ([0, 1, 2], [3, 4, 5], [6, 7, 8]))):
            source = str(root / name)
            obj = str(self.root / "invented-output" / (Path(name).stem + ".o"))
            source_hash, object_hash = sha(("source-" + name).encode("ascii")), sha(("IR-" + name).encode("ascii"))
            deps = [dict(Path=source, Sha256=source_hash),
                    dict(Path=str(root / "context/context_port_abi.h"), Sha256=sha(b"synthetic header"))]
            value["IsolatedCommon"].append(dict(TemplateIndex=index, Source=source, SourceSha256=source_hash,
                Object=obj, ObjectSha256=object_hash, OriginalObject=str(root.parent / (str(index) + ".o")),
                OriginalObjectSha256=sha(("original IR-" + name).encode("ascii")),
                CompileDependenciesVerified=True, ForcedMainHeaderRemoved=True,
                CmsisAndSelectedPortIncludesRemoved=True, RawIRIdentityClaim=False, SourceToMachineSemanticProof=False,
                CommandIndices=indices, SlimIR=dict(Object=obj, Sha256=object_hash, SlimIR=True,
                    Sections=[dict(Index=1, Name=".gnu.lto_synthetic", Size=16, Flags="")]),
                CompileFlags=isolated_flags[:], OriginalCompileFlags=original_flags[:],
                Dependencies=deps, DiscoveryDependencies=copy.deepcopy(deps),
                IncludeDelta=dict(RemovedForcedHeader=str(root / "tools/fixtures/classic_final_image/main.h"),
                    ReplacementSearchPaths=[str(root / part) for part in ("context", "fiber", "")],
                    OtherSemanticFlagsUnchanged=True)))
        body_names = ("fiber_internal_runtime_context_configuration_is_open",
            "fiber_internal_runtime_select_scheduler_candidate", "fiber_internal_runtime_publish_current_context",
            "fiber_internal_runtime_require_current_context", "ctxrt_v1_set_dispatcher",
            "fiber_internal_runtime_load_current_context")
        value["SlotProofs"] = []
        for label in ("Original", "Isolated"):
            proof = dict(Status="CM3-LTO-SLOT-ISOLATION-PASS-NOT-QUALIFIED",
                Scope="NATIVE_CM3_O2_LTO_MERGED_MACHINE_SECTION_MEDIATED_SLOT_ACCESSES_ONLY",
                Profile="CM3", Mode="O2-lto", Linkage="direct", EmitRelocs=True,
                SlotIsolationValidated=True, RawSectionSymbolsPreserved=True,
                AllSectionMediatedSlotReferencesValidated=True, HandlerLoadPairs=2, ClosedCommonBodies=6,
                CommonLoads=5, CommonStores=1, SlotReferences=8, AppliedSlotReferences=8, RequiredCellsSatisfied=0,
                Publisher="fiber_internal_runtime_publish_current_context",
                CommonBodies=[dict(Name=name, CompleteBodyValidated=True,
                    MachineBodySha256=sha((label + " machine " + name).encode("ascii")),
                    FinalBodySha256=sha((label + " final " + name).encode("ascii"))) for name in body_names],
                HandlerLoads=[dict(Owner="SVC_Handler", Register="r0"), dict(Owner="PendSV_Handler", Register="r1")],
                CommonSourceOwnershipValidated=False, CompleteHandlerBodiesValidated=False,
                ArbitraryPointerAliasProof=False, WholeProgramMemorySafetyProof=False,
                FullSemanticABIProof=False, SourceToMachineSemanticProof=False, OriginalTranslationUnitOwnership=False,
                Qualification=False, CellContractSatisfied=False, CpuExecution=False, BoardExecution=False,
                GlobalFreezeQualified=False, RequiredCellSatisfied=False)
            proof.update({name: sha((label + " " + name).encode("ascii")) for name in
                ("SourceSha256", "AssemblySha256", "MachineSha256", "FinalSha256", "LinkMapSha256")})
            value["SlotProofs"].append(dict(Kind=label, Proof=proof))
        value["LoadImageComparisons"] = {name: dict(Identical=True, Segments=[dict(Vaddr=0x08000000,
            FileSize=16, MemorySize=16, BytesSha256=sha(b"invented loaded segment"))])
            for name in ("OriginalToIsolated", "IsolatedTwins", "OriginalTwins")}
        before = copy.deepcopy(value)
        with patch.object(Path, "read_bytes", side_effect=AssertionError("receipt predicate read invented file")):
            self.assertTrue(S.evidence_records_pass(value))
            self.assertTrue(S.succeeded(value))
        self.assertEqual(value, before)
        mutations = [
            (("IsolatedCommon",), []),
            (("IsolatedCommon", 0, "TemplateIndex"), False),
            (("IsolatedCommon", 1, "Source"), str(root / names[0])),
            (("IsolatedCommon", 2, "ObjectSha256"), "not a hash"),
            (("IsolatedCommon", 0, "CommandIndices"), [False, 1, 2]),
            (("IsolatedCommon", 0, "SlimIR", "Object"), "foreign-object.o"),
            (("IsolatedCommon", 0, "SlimIR", "Sha256"), "F" * 64),
            (("IsolatedCommon", 0, "SlimIR", "SlimIR"), 1),
            (("IsolatedCommon", 0, "SlimIR", "Sections"), []),
            (("IsolatedCommon", 0, "CompileFlags"), ["-O2", "-flto"]),
            (("IsolatedCommon", 0, "OriginalCompileFlags"), original_flags + ["-flto"]),
            (("IsolatedCommon", 0, "Dependencies"), []),
            (("IsolatedCommon", 0, "DiscoveryDependencies", 0, "Sha256"), "F" * 64),
            (("SlotProofs",), [value["SlotProofs"][0]]),
            (("SlotProofs", 1, "Kind"), "Original"),
            (("SlotProofs", 0, "Proof", "CommonBodies"), []),
            (("SlotProofs", 0, "Proof", "CommonBodies", 1), None),
            (("SlotProofs", 0, "Proof", "CommonBodies", 0, "CompleteBodyValidated"), 1),
            (("SlotProofs", 1, "Proof", "CommonBodies", 5, "MachineBodySha256"), False),
            (("SlotProofs", 1, "Proof", "CommonBodies", 5, "FinalBodySha256"), "short"),
            (("SlotProofs", 0, "Proof", "HandlerLoads"), []),
            (("SlotProofs", 0, "Proof", "CompleteHandlerBodiesValidated"), True),
            (("SlotProofs", 1, "Proof", "FinalSha256"), "not a hash"),
            (("LoadImageComparisons",), {}),
            (("LoadImageComparisons", "OriginalToIsolated", "Identical"), 1),
            (("LoadImageComparisons", "IsolatedTwins", "Segments"), []),
            (("LoadImageComparisons", "OriginalTwins", "Segments"), ("synthetic",)),
        ]
        for path, replacement in mutations:
            changed = copy.deepcopy(value)
            node = changed
            for key in path[:-1]:
                node = node[key]
            node[path[-1]] = copy.deepcopy(replacement)
            with self.subTest(path=path):
                self.assertFalse(S.evidence_records_pass(changed))
                self.assertFalse(S.succeeded(changed))
        changed = copy.deepcopy(value)
        changed["LoadImageComparisons"]["Unexpected"] = copy.deepcopy(changed["LoadImageComparisons"]["OriginalTwins"])
        self.assertFalse(S.succeeded(changed))
        self.assertEqual(value, before)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    output = args.output_dir.resolve()
    temporary = Path(tempfile.gettempdir()).resolve()
    if (output.exists() or args.output_dir.is_symlink() or output.is_relative_to(ROOT)
            or ROOT.is_relative_to(output) or not output.is_relative_to(temporary)):
        parser.error("fresh external TEMP output directory required")
    result_report = dict(Status="FAIL", Scope="PURE_SYNTHETIC_CM3_LTO_ISOLATION_CONTROLS_ONLY",
        ExpectedTestMethods=EXPECTED_METHODS, Tests=0, Errors=0, Failures=0, Skipped=0,
        SourceHashes={}, SourceDrift=[], ClosingFilesVerified=0, SourceClosureVerified=False,
        SyntheticToolResults=True, ActualCaptureRead=False, ActualCompilerExecuted=False,
        ActualELFTested=False, TargetExecuted=False, FullABIProof=False, FullSemanticABIProof=False,
        CellContractSatisfied=False, GlobalFreezeQualified=False, RequiredCellsSatisfied=0)
    paths = (Path(__file__).resolve(), SUBJECT, COMPONENTS, CONTROLS)
    try:
        if sys.flags.optimize or not __debug__:
            raise ValueError("unoptimized host Python required")
        BUFFERS.update({path: path.read_bytes() for path in paths})
        result_report["SourceHashes"] = {str(path): sha(raw) for path, raw in BUFFERS.items()}
        for path, expected in PINS.items():
            if sha(BUFFERS[path]) != expected:
                raise ValueError("frozen pure helper source identity: " + str(path))
        global S, PROBES, BASE
        with patch("subprocess.Popen", side_effect=AssertionError("pure controls cannot start a process")), \
                patch("os.system", side_effect=AssertionError("pure controls cannot execute commands")):
            S = module_from_bytes("_cm3_isolation_subject", SUBJECT, BUFFERS[SUBJECT])
            PROBES = module_from_bytes("_cm3_isolation_frozen_flags", COMPONENTS, BUFFERS[COMPONENTS])
            BASE = module_from_bytes("_cm3_isolation_frozen_failure", CONTROLS, BUFFERS[CONTROLS])
            suite = unittest.defaultTestLoader.loadTestsFromTestCase(IsolationTests)
            if suite.countTestCases() != EXPECTED_METHODS:
                raise ValueError("exact thirteen implemented test methods required")
            result = unittest.TextTestRunner(verbosity=2).run(suite)
        result_report.update(Tests=result.testsRun, Errors=len(result.errors), Failures=len(result.failures),
            Skipped=len(result.skipped), Details=[dict(Test=str(test), Error=error)
                for test, error in result.errors + result.failures])
        if result.wasSuccessful() and result.testsRun == EXPECTED_METHODS and not result.skipped:
            result_report["Status"] = "PASS"
    except Exception:
        result_report.update(Status="FAIL", Errors=result_report["Errors"] + 1, Error=traceback.format_exc())
    finally:
        for path, expected in result_report["SourceHashes"].items():
            try:
                if sha(Path(path).read_bytes()) != expected:
                    result_report["SourceDrift"].append(path)
                else:
                    result_report["ClosingFilesVerified"] += 1
            except OSError:
                result_report["SourceDrift"].append(path)
        result_report["SourceClosureVerified"] = len(result_report["SourceHashes"]) == 4 and not result_report["SourceDrift"]
        if not result_report["SourceClosureVerified"]:
            result_report["Status"] = "FAIL"
    output.mkdir(parents=True, exist_ok=False)
    target = output / "results.json"
    target.write_bytes((json.dumps(result_report, sort_keys=True, indent=2) + "\n").encode("ascii"))
    print("Receipt:", target, sha(target.read_bytes()))
    return 0 if result_report["Status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
