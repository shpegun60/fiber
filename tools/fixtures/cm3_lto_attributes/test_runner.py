"""Synthetic host controls for the hostile-LTO runner; no compiler or ELF execution."""
import argparse
import contextlib
import copy
import hashlib
import io
import json
import os
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
SUBJECT = HERE / "runner.py"
ATTRIBUTES = HERE / "attributes.py"
COMPONENTS = ROOT / "tools/fixtures/cm0_final_cell/components.py"
CONTROLS = ROOT / "tools/fixtures/cm3_lto_abi_controls/controls.py"
NATIVE = ROOT / "tools/fixtures/classic_final_image/run.py"
PINS = {
    COMPONENTS: "16490A20B1A75C5DBD2D21A5FED988C5BD82F4DE919350985B33491CE473A5F7",
    CONTROLS: "7984A228966FC17641BD83D23486DB7E50BC2B7E5BC12D70A712F6E83800F14F",
    NATIVE: "FBCBA0C4FF480E139ADE401ECFA90822E9EA01A6AB554CEF157036EC9DE7F014",
}
SOURCE_NAMES = (
    "context/context_core.c", "context/context_runtime_state.c", "context/context_panic.c",
    "context/context_api_decl.h", "context/context_runtime_state.h", "context/context_panic.h",
    "context/context_runtime_port_abi.h", "context/context_api_attributes.h",
    "context/context_port_abi.h", "fiber/fiber_api_attributes.h",
)
HOSTILE = ("-finstrument-functions", "-fstack-protector-all", "-fprofile-arcs", "-ftest-coverage",
           "-fsanitize=undefined", "-fsanitize-coverage=trace-pc")
ROOT_NAMES = (
    "fiber_internal_task_return", "ctxrt_v1_init", "ctxrt_v1_current", "ctxrt_v1_start",
    "ctxrt_v1_set_dispatcher", "ctxrt_v1_yield", "fiber_internal_runtime_load_current_context",
    "fiber_internal_runtime_select_scheduler_candidate", "fiber_internal_runtime_publish_current_context",
    "fiber_internal_runtime_require_current_context", "fiber_internal_scheduler_is_configured",
    "fiber_internal_runtime_close_context_configuration", "fiber_internal_runtime_context_configuration_is_open",
    "fiber_panic",
)
GROUPS = ("positive", "mutant-engine", "mutant-state", "mutant-panic", "stress-protected", "stress-unprotected")
MUTANTS = {"mutant-engine": "ctxrt_v1_current", "mutant-state": ROOT_NAMES[6], "mutant-panic": "fiber_panic"}
PHASES = ("SourceAnnotationsValidated", "CpuFreeHostileCommonValidated", "DriverAdapterValidated",
    "ActualLtransOptionsValidated", "ProtectedEffectsValidated", "AnnotationControlsValidated",
    "DispatcherStressValidated", "InputClosureVerified", "OutputSealVerified")
NONCLAIMS = ("Qualification", "CellContractSatisfied", "RequiredCellSatisfied", "FullABIProof",
    "FullSemanticABIProof", "SourceIRProof", "SourceToMachineSemanticProof", "OriginalTranslationUnitOwnership",
    "FinalReferenceParity", "CanonicalProtocolValidated", "PolicyEquivalence", "ArchiveExtraction",
    "CpuExecution", "BoardExecution", "HostedCIQualified", "GlobalFreezeQualified",
    "TypedDeclarationProbesValidated", "FiveLinkControlsValidated", "WholeSlotAccessIsolation",
    "PositiveLinkRevalidated", "GeneralRegistersOnlyEffectProved", "FullAttributeEquivalence",
    "TransitiveProtection", "RuntimeLibraryProvided")
EXPECTED_METHODS = 13
S = A = PROBES = BASE = N = None
BUFFERS = {}


def sha(raw):
    return hashlib.sha256(raw).hexdigest().upper()


def plan():
    labels = ["dump compiler specs"]
    for group, stems in (("positive", ("context_core", "context_runtime_state", "context_panic")),
        ("mutant-engine", ("context_core",)), ("mutant-state", ("context_runtime_state",)),
        ("mutant-panic", ("context_panic",)), ("stress-protected", ("stress",)),
        ("stress-unprotected", ("stress",))):
        for stem in stems:
            labels += ["discover " + group + " " + stem, "compile " + group + " " + stem,
                       "inspect slim " + stem, "imports " + group + " " + stem]
        labels += ["lower " + group, "disassemble " + group]
    return tuple(labels)


def commands():
    return [dict(Label=label, State="TERMINAL", Status="PASS", Exit=0, ExpectedExit=0,
                 TimedOut=False, JournalErrors=[]) for label in plan()]


def flags(root):
    return ["-mcpu=cortex-m3", "-mthumb", "-mfloat-abi=soft", "-O2", "-flto", "-fno-fat-lto-objects",
        "-ffreestanding", "-DFIBER_SCHEDULER_BASEPRI=16", "-I" + str(root / "fiber/port/ARM_CM3"),
        "-I", str(root.parent / "cmsis"), "-include", str(root / "tools/fixtures/classic_final_image/main.h")]


def effects(group, object_hash):
    """Invented complete metadata, not learned machine bodies or actual ELF evidence."""
    stress = group.startswith("stress-")
    names = ("ctxrt_attribute_stress",) if stress else ROOT_NAMES
    mutation = "ctxrt_attribute_stress" if group == "stress-unprotected" else MUTANTS.get(group)
    rows = []
    for name in names:
        refs = []
        if name == mutation:
            hooks = ("__cyg_profile_func_enter",) if name == "fiber_panic" else (
                "__cyg_profile_func_enter", "__cyg_profile_func_exit")
            refs = [dict(CompilerHook=True, CompilerCounter=False, OriginalHookTransferValidated=True,
                         Target=dict(name=hook)) for hook in hooks]
        rows.append(dict(Name=name, Symbol=dict(name=name), BodySha256=sha(name.encode("ascii")),
            InstructionCount=4, References=refs, MappedData=[], DirectCompilerEffects=len(refs),
            AnnotationMutant=name == mutation))
    return dict(Status="CONTEXT-LTO-ANNOTATION-MUTANT-DETECTED" if mutation else
            "CONTEXT-LTO-DIRECT-ATTRIBUTE-CHECKS-PASS",
        Scope="CM3_O2_LTO_CONTEXT_ATTRIBUTE_EFFECT_COMPONENT_ONLY", ObjectSha256=object_hash,
        ProtectedFunctions=len(names), RequiredCellCount=0, RootEvidence=rows, Undefined=[],
        UnresolvedAttribution=[], AllProtectedBodiesClean=mutation is None,
        CompiledAnnotationMutantDetected=mutation is not None, StressFamiliesActivated=group == "stress-unprotected",
        ThreadSectionValidated=not stress, OrdinaryColdActivityValidated=not stress, ColdInlineAttributionValidated=True,
        TransitiveProtection=False, FullABI=False, FullIRSemantics=False, FullInstructionSemantics=False,
        FullAttributeEquivalence=False, CPUExecution=False, BoardExecution=False, GlobalQualification=False)


def report():
    lowered = []
    for group in GROUPS:
        h = sha(("synthetic aggregate " + group).encode("ascii"))
        mh = sha(("synthetic machine " + group).encode("ascii"))
        execution = dict(CompilerReportedWorkerExecutionVerified=True, OsProcessTraceVerified=False,
            TranscriptSha256=sha(("synthetic diagnostics " + group).encode("ascii")),
            WorkerInvocations=[dict(Stage=marker, Executable="synthetic/lto1.exe",
                ExecutableSha256=sha(b"synthetic lto1"), ResponseSha256=sha(marker.encode("ascii")),
                Argv=["synthetic/lto1.exe", marker]) for marker in ("-fwpa", "-fltrans")],
            Assembler=dict(Executable="synthetic/as.exe", ExecutableSha256=sha(b"synthetic assembler"),
                Argv=["synthetic/as.exe", "-o", "synthetic/machine.o", "synthetic/machine.s"]))
        lowered.append(dict(Group=group, ObjectSha256=h,
            ActualWorker=dict(ActualHostileOptionsVerified=True, RuntimeLibraryProvided=False, MachineSha256=mh,
                DriverSpecsSha256=sha(b"synthetic specs"), Execution=execution),
            Effects=effects(group, h), WorkerEffects=effects(group, mh),
            OriginalProtectedPredicateRejected=group.startswith("mutant-") or group == "stress-unprotected"))
    return dict(Status=S.PASS, Scope=S.SCOPE, Profile="CM3", Mode="O2-lto", Linkage="direct", LTO=True,
        Error=None, PrimaryError=None, ClosingErrors=[], RequiredCellsSatisfied=0, RequiredCellCount=2774,
        RawIRIdentityClaim=False, Commands=commands(), Lowerings=lowered,
        Compilations=[dict(CompileDependenciesVerified=True, CpuFreeIncludes=True, SlimIR=dict(SlimIR=True))
                      for _ in range(8)],
        AnnotationControls=[dict(Role=role, Detected=True, OriginalProtectedPredicateRejected=True)
                            for role in ("engine", "state", "panic")],
        **{name: True for name in PHASES}, **{name: False for name in NONCLAIMS})


def load_buffer(name, path):
    module = types.ModuleType(name)
    module.__file__ = str(path)
    exec(compile(BUFFERS[path], str(path), "exec"), module.__dict__)
    return module


def files_under(root):
    return {p.relative_to(root).as_posix(): p for p in root.rglob("*") if p.is_file()}


class FakeBase:
    def __init__(self, args, admitted, modules, buffers):
        self.args, self.admitted, self.modules, self.buffers = args, admitted, modules, buffers
        self.report = report()
        self._started = self._finished = False
        self.commands, self.expected = commands(), {"commands.json": sha(b"synthetic journal")}
        self.watch = types.SimpleNamespace(hashes={}, close=Mock())
        self.verify_objects, self._verify_outputs = Mock(), Mock()
        self.command = Mock(side_effect=AssertionError("failure handling retried a tool"))
        self.hook_failure = False

    def _failure(self, error):
        if self.hook_failure:
            self.report.update(Status=S.PASS, **{name: True for name in PHASES})
            raise OSError("synthetic inherited failure hook")
        message = type(error).__name__ + ": " + str(error)
        self.report.update(Status="FAIL", Error=self.report.get("Error") or message,
            PrimaryError=self.report.get("PrimaryError") or message)

    def _save(self, name, value):
        raw = BASE.encoded(value)
        (self.output / name).write_bytes(raw)
        self.expected[name] = sha(raw)


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="cm3-attribute-runner-synthetic-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()

    def suite(self):
        admitted = types.SimpleNamespace(identity=Mock(return_value={"Synthetic": True}))
        suite = S.suite_type(FakeBase)(types.SimpleNamespace(), admitted, {"controls": BASE}, {})
        suite.output = self.root / "output"
        suite.output.mkdir()
        info = suite.output.stat()
        suite.output_identity = info.st_dev, info.st_ino
        suite.api = types.SimpleNamespace(checked_path=lambda path, **kwargs: Path(path), files_under=files_under)
        return suite

    def assert_revoked(self, value):
        self.assertEqual(value["Status"], "FAIL")
        for name in PHASES:
            self.assertIs(value[name], False, name)

    def worker_fixture(self):
        directory = self.root / "workers"
        directory.mkdir()
        lowered = directory / "aggregate.o"
        specs = directory / "owned.specs"
        objects = [directory / ("input%d.o" % i) for i in range(3)]
        intermediate, machine = Path(str(lowered) + ".ltrans0.o"), Path(str(lowered) + ".ltrans0.ltrans.o")
        lto, assembler = directory / "bin/lto1.exe", directory / "bin/as.exe"

        def arguments(values):
            return ("\n".join(value.replace("\\", "\\\\") for value in values) + "\n").encode("ascii")

        raw = {specs: b"synthetic specs\n", intermediate: b"synthetic WPA IR", machine: b"synthetic NOT AN ELF",
               lto: b"not executable lto1", assembler: b"not executable assembler"}
        raw.update({obj: ("synthetic IR %d" % i).encode("ascii") for i, obj in enumerate(objects)})
        options = [*HOSTILE, "-mcpu=cortex-m3", "-mthumb", "-mfloat-abi=soft", "-O2", "-flto-partition=one",
                   "-nostdlib", "-r", "-flinker-output=nolto-rel", "-specs=" + str(specs)]
        raw[Path(str(lowered) + ".ltrans_args")] = arguments(options + ["-fwpa", *(str(obj) for obj in objects)])
        raw[Path(str(lowered) + ".ltrans0.ltrans_args")] = arguments(options + ["-fltrans", "-o", str(machine), str(intermediate)])
        raw[Path(str(lowered) + ".wpa.args.0")] = arguments([str(obj) for obj in objects])
        raw[Path(str(lowered) + ".ltrans0.ltrans.args.0")] = arguments([str(intermediate)])
        raw[Path(str(lowered) + ".ltrans.out")] = ("0\n" + str(intermediate) + "\n").encode("ascii")
        for path, data in raw.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)

        def checked(path):
            value = Path(path)
            if ".." in value.parts or "." in value.parts:
                raise ValueError("checked_path refuses dot component")
            return value

        def read(path, expected=None):
            path = Path(path)
            self.assertIn(path, raw, "unknown synthetic worker input")
            data = path.read_bytes()
            if expected is not None:
                self.assertEqual(sha(data), expected)
            return data

        suite = types.SimpleNamespace(modules={"attributes": A}, api=types.SimpleNamespace(checked_path=checked),
            admitted=types.SimpleNamespace(base=types.SimpleNamespace(stable_path=lambda path: Path(os.path.abspath(path)))),
            watch=types.SimpleNamespace(read=Mock(side_effect=read)),
            transport=types.SimpleNamespace(require_elf32le=Mock(return_value={"SyntheticHeader": True})),
            result={"ResolvedWorkers": {"lto1": {"Path": str(lto), "Sha256": sha(raw[lto])},
                                       "as": {"Path": str(assembler), "Sha256": sha(raw[assembler])}}})
        diagnostics = (" " + str(lto) + " " + " ".join(HOSTILE) + " -fwpa @" + str(lowered) + ".wpa.args.0\n"
            + " " + str(lto) + " " + " ".join(HOSTILE) + " -fltrans -o " + str(lowered)
            + ".ltrans0.ltrans.s @" + str(lowered) + ".ltrans0.ltrans.args.0\n"
            + " " + str(assembler) + " -o " + str(machine) + " " + str(lowered) + ".ltrans0.ltrans.s\n").encode("ascii")
        return suite, lowered, objects, specs, raw, diagnostics, arguments

    def test_exact_forty_five_command_plan_and_literal_terminal_records(self):
        self.assertEqual(len(plan()), 45)
        self.assertEqual(S.command_plan(), plan())
        self.assertTrue(S.commands_pass(commands()))
        for field, value in (("Exit", False), ("Exit", 0.0), ("ExpectedExit", False),
            ("State", "RUNNING"), ("TimedOut", 0), ("JournalErrors", ["late stdout"]), ("Status", "FAIL")):
            rows = commands()
            rows[0][field] = value
            with self.subTest(field=field, value=value):
                self.assertFalse(S.commands_pass(rows))
        for rows in (commands()[:-1], commands() + [None], commands() + [commands()[0]],
                     list(reversed(commands())), tuple(commands())):
            with self.subTest(rows=rows):
                self.assertFalse(S.commands_pass(rows))

    def test_flags_preserve_slim_lto_and_rebase_only_three_includes_for_private_sources(self):
        seed = self.root / "seed/source"
        original = flags(seed)
        suite = types.SimpleNamespace(base=seed.parent, source=Mock(return_value={"CompileFlags": original}),
            modules={"probes": PROBES, "attributes": A})
        for root in (seed, self.root / "private/mutant-engine", self.root / "private/stress-protected"):
            with self.subTest(root=root):
                self.assertEqual(S.flags_for(suite, 0, root), original[:8] +
                    ["-I" + str(root / name) for name in ("context", "fiber", "")] + list(HOSTILE))
        self.assertEqual(original, flags(seed))
        for missing in ("-O2", "-flto", "-fno-fat-lto-objects"):
            suite.source.return_value = {"CompileFlags": [flag for flag in original if flag != missing]}
            with self.subTest(missing=missing), self.assertRaises(ValueError):
                S.flags_for(suite, 0, seed)
        suite.source.return_value = {"CompileFlags": original + [HOSTILE[0]]}
        with self.assertRaises(ValueError):
            S.flags_for(suite, 0, seed)

    def test_frozen_dependency_parser_preserves_pilot_source_target(self):
        source = self.root / "context/context_core.c"
        source.parent.mkdir()
        source.write_bytes(b"/* synthetic source only */\n")
        dep = self.root / "own.d"
        dep.write_bytes(("pilot-source-0: " + str(source) + "\n").encode("utf-8"))
        self.assertEqual(N.read_dependencies(dep), (source,))
        dep.write_bytes(("attribute-source-0: " + str(source) + "\n").encode("utf-8"))
        with self.assertRaisesRegex(RuntimeError, "dependency grammar"):
            N.read_dependencies(dep)
        seen = []
        attrs = types.SimpleNamespace(HOSTILE_FLAGS=HOSTILE,
            inspect_ir_undefined=Mock(return_value={"Synthetic": True}))
        suite = types.SimpleNamespace(base=self.root, output=self.root, sources=[{"ActualCompileDependencies": []}]*3,
            source=Mock(return_value={"CompileFlags": flags(self.root / "source")}),
            api=types.SimpleNamespace(checked_path=Path), modules={"attributes": attrs, "probes": PROBES},
            tools={"gcc": "FAKE-gcc"}, commands=[], report={"Compilations": []}, native=N,
            watch=types.SimpleNamespace(read=Mock(return_value=b"synthetic")),
            record_output=Mock(return_value={"Sha256": sha(b"synthetic IR")}),
            inspect_ir=Mock(return_value={"SlimIR": True}), _undefined=Mock(return_value=([], {})))
        private_source = self.root / "source/context/context_core.c"
        private_source.parent.mkdir(parents=True)
        private_source.write_bytes(b"synthetic")

        def command(argv, label):
            seen.append(list(argv))
            target = argv[argv.index("-MT") + 1]
            Path(argv[argv.index("-MF") + 1]).write_bytes((target + ": " + str(private_source) + "\n").encode("ascii"))
            suite.commands.append({"Label": label})
            return types.SimpleNamespace(stdout=b"", stderr=b"")

        suite.command = command
        S.compile_ir(suite, "positive", 0, self.root / "source", {"context/context_core.c": b"synthetic"})
        self.assertEqual([argv[argv.index("-MT") + 1] for argv in seen], ["pilot-source-0"]*2)
        self.assertEqual(seen[0][-1], str(private_source))
        self.assertEqual(seen[1][-4:], ["-c", str(private_source), "-o", str(self.root / "ir/positive/context_core.o")])

    def test_saved_worker_chain_exact_ir_order_options_response_and_no_input_mutation(self):
        suite, lowered, objects, specs, raw, diagnostics, arguments = self.worker_fixture()
        original_objects, original_result = objects[:], copy.deepcopy(suite.result)
        machine, proof = S.worker_chain(suite, lowered, objects, specs, diagnostics)
        self.assertEqual(machine, Path(str(lowered) + ".ltrans0.ltrans.o"))
        self.assertIs(proof["ActualHostileOptionsVerified"], True)
        self.assertIs(proof["RuntimeLibraryProvided"], False)
        self.assertIs(proof["Execution"]["OsProcessTraceVerified"], False)
        self.assertEqual(proof["WpaInputs"], [dict(Path=str(path), Sha256=sha(raw[path])) for path in objects])
        self.assertEqual(proof["DriverSpecsSha256"], sha(raw[specs]))
        self.assertTrue(S.worker_evidence_pass(proof))
        self.assertEqual(suite.result, original_result)
        self.assertEqual(objects, original_objects)
        changes = [
            (Path(str(lowered) + ".wpa.args.0"), arguments([str(obj) for obj in reversed(objects)])),
            (Path(str(lowered) + ".wpa.args.0"), arguments([str(obj) for obj in objects] + ["foreign.o"])),
            (Path(str(lowered) + ".ltrans0.ltrans.args.0"), arguments(["foreign.o"])),
            (Path(str(lowered) + ".ltrans.out"), b"0\nforeign.o\n"),
            (Path(str(lowered) + ".ltrans_args"), raw[Path(str(lowered) + ".ltrans_args")] + b"-fno-sanitize=undefined\n"),
            (Path(str(lowered) + ".ltrans0.ltrans_args"), raw[Path(str(lowered) + ".ltrans0.ltrans_args")]
                .replace(b"-O2\n", b"-O3\n")),
            (Path(str(lowered) + ".ltrans_args"), raw[Path(str(lowered) + ".ltrans_args")]
                .replace(arguments(["-specs=" + str(specs)]), b"-specs=foreign.specs\n")),
        ]
        for path, data in changes:
            with self.subTest(path=path):
                path.write_bytes(data)
                try:
                    with self.assertRaises(ValueError):
                        S.worker_chain(suite, lowered, objects, specs, diagnostics)
                finally:
                    path.write_bytes(raw[path])
        self.assertEqual({path: path.read_bytes() for path in raw}, raw)
        for bad in (None, "arg", b"", b"arg\0\n", b" arg\n", b"arg\n\n"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                S.argument_lines(bad)

    def test_worker_diagnostics_dotted_same_identity_accepts_foreign_and_wrong_chain_reject(self):
        suite, lowered, objects, specs, raw, diagnostics, arguments = self.worker_fixture()
        lto, assembler = (Path(suite.result["ResolvedWorkers"][name]["Path"]) for name in ("lto1", "as"))
        dotted_lto = str(lto.parent / "subdir/../lto1.exe")
        dotted_as = str(assembler.parent / "subdir/../as.exe")
        dotted = diagnostics.replace(str(lto).encode("ascii"), dotted_lto.encode("ascii"))
        dotted = dotted.replace(str(assembler).encode("ascii"), dotted_as.encode("ascii"))
        proof = S.worker_diagnostics(suite, dotted, lowered)
        self.assertIs(proof["CompilerReportedWorkerExecutionVerified"], True)
        self.assertIs(proof["OsProcessTraceVerified"], False)
        self.assertEqual(proof["WorkerInvocations"][0]["Executable"], str(lto))
        self.assertEqual(proof["WorkerInvocations"][0]["Argv"][0], dotted_lto)
        self.assertEqual(proof["Assembler"]["Executable"], str(assembler))
        self.assertEqual(proof["Assembler"]["Argv"][0], dotted_as)
        foreign = str(assembler.parent / "foreign/as.exe").encode("ascii")
        cases = [diagnostics.replace(str(assembler).encode("ascii"), foreign),
            diagnostics.replace(str(lto).encode("ascii"), str(lto.parent / "foreign/lto1.exe").encode("ascii")),
            diagnostics.replace(b"-fwpa ", b"-fltrans "),
            diagnostics.replace(HOSTILE[0].encode("ascii") + b" ", b""),
            diagnostics + b"warning: ignored attribute\n",
            diagnostics.replace(b".ltrans0.ltrans.s\n", b".foreign.s\n"),
            diagnostics.replace(b".wpa.args.0\n", b".wpa.args.0 @foreign\n")]
        for text in cases:
            with self.subTest(text=text), self.assertRaises(ValueError):
                S.worker_diagnostics(suite, text, lowered)
        self.assertEqual({path: path.read_bytes() for path in raw}, raw)

    def test_effect_leaf_positive_all_six_groups_and_exact_mutation_hooks(self):
        for group in GROUPS:
            h = sha(group.encode("ascii"))
            value = effects(group, h)
            before = copy.deepcopy(value)
            with self.subTest(group=group), patch.object(Path, "read_bytes", side_effect=AssertionError("leaf IO")):
                self.assertTrue(S.effects_pass(value, group, h))
            self.assertEqual(value, before)
            self.assertEqual(value["ProtectedFunctions"], 1 if group.startswith("stress-") else 14)

    def test_effect_leaf_rejects_wrong_count_scope_hash_root_hooks_and_stronger_claims(self):
        h = sha(b"synthetic lowered ELF")
        for field, changed in (("Scope", "WHOLE_PROGRAM"), ("ObjectSha256", "F"*64),
            ("ProtectedFunctions", True), ("ProtectedFunctions", 13), ("RequiredCellCount", False),
            ("RootEvidence", []), ("TransitiveProtection", True), ("FullAttributeEquivalence", 0),
            ("UnresolvedAttribution", ["unknown counter"]), ("ColdInlineAttributionValidated", 1)):
            value = effects("positive", h)
            value[field] = changed
            with self.subTest(field=field):
                self.assertFalse(S.effects_pass(value, "positive", h))
        for field, changed in (("Name", "foreign"), ("BodySha256", "bad"), ("InstructionCount", True),
            ("DirectCompilerEffects", False), ("AnnotationMutant", 0), ("Symbol", {"name": "foreign"})):
            value = effects("positive", h)
            value["RootEvidence"][0][field] = changed
            with self.subTest(root_field=field):
                self.assertFalse(S.effects_pass(value, "positive", h))
        for group in ("mutant-engine", "mutant-state", "mutant-panic", "stress-unprotected"):
            value = effects(group, h)
            mutation = "ctxrt_attribute_stress" if group == "stress-unprotected" else MUTANTS[group]
            row = next(row for row in value["RootEvidence"] if row["Name"] == mutation)
            row["References"][0]["OriginalHookTransferValidated"] = False
            with self.subTest(group=group):
                self.assertFalse(S.effects_pass(value, group, h))

    def test_succeeded_accepts_nested_synthetic_report_and_rejects_forged_narrow_leaves(self):
        value = report()
        before = copy.deepcopy(value)
        self.assertTrue(S.succeeded(value))
        self.assertEqual(value, before)
        mutations = [(("RequiredCellsSatisfied",), False), (("RequiredCellCount",), 2774.0),
            (("LTO",), 1), (("FullABIProof",), 0), (("Mode",), "Os-lto"),
            (("Compilations",), []), (("Compilations", 0, "SlimIR", "SlimIR"), 1),
            (("Lowerings", 0, "Effects", "RootEvidence"), []),
            (("Lowerings", 0, "Effects", "ProtectedFunctions"), True),
            (("Lowerings", 0, "WorkerEffects", "ObjectSha256"), "F"*64),
            (("Lowerings", 2, "ActualWorker", "RuntimeLibraryProvided"), 0),
            (("Lowerings", 0, "ActualWorker", "Execution"), {}),
            (("Lowerings", 0, "ActualWorker", "Execution"), None),
            (("Lowerings", 0, "ActualWorker", "DriverSpecsSha256"), False),
            (("Lowerings", 0, "ActualWorker", "Execution", "CompilerReportedWorkerExecutionVerified"), 1),
            (("Lowerings", 0, "ActualWorker", "Execution", "OsProcessTraceVerified"), True),
            (("Lowerings", 0, "ActualWorker", "Execution", "TranscriptSha256"), "bad"),
            (("Lowerings", 0, "ActualWorker", "Execution", "WorkerInvocations"), []),
            (("Lowerings", 0, "ActualWorker", "Execution", "WorkerInvocations", 0, "Stage"), "-fltrans"),
            (("Lowerings", 0, "ActualWorker", "Execution", "WorkerInvocations", 1, "ResponseSha256"), "bad"),
            (("Lowerings", 0, "ActualWorker", "Execution", "Assembler"), {}),
            (("Lowerings", 0, "ActualWorker", "Execution", "Assembler", "Argv"), []),
            (("AnnotationControls", 0, "Detected"), 1),
            (("Lowerings", 5, "WorkerEffects", "StressFamiliesActivated"), False)]
        for path, replacement in mutations:
            changed = copy.deepcopy(value)
            node = changed
            for key in path[:-1]:
                node = node[key]
            node[path[-1]] = replacement
            with self.subTest(path=path):
                self.assertFalse(S.succeeded(changed))
        missing = copy.deepcopy(value)
        del missing["Lowerings"][0]["ActualWorker"]["Execution"]
        self.assertFalse(S.succeeded(missing))
        for name in PHASES:
            changed = copy.deepcopy(value)
            changed[name] = 1
            with self.subTest(phase=name):
                self.assertFalse(S.succeeded(changed))

    def test_suite_private_state_missing_finish_phases_and_single_finish(self):
        suite = self.suite()
        self.assertIs(type(suite).__bases__[0], FakeBase)
        self.assertIs(suite._attributes_done, False)
        self.assert_revoked(suite.report)
        value = suite.finish()
        self.assert_revoked(value)
        self.assertIsNot(value, suite.report)
        self.assertIs(suite._finished, True)
        self.assertFalse((suite.output / "results.json").exists())
        with self.assertRaisesRegex(ValueError, "exactly once"):
            suite.finish()
        suite.command.assert_not_called()

    def test_revoke_persisted_pass_throwing_hook_first_write_failure_keeps_primary(self):
        suite = self.suite()
        suite._started = suite.hook_failure = True
        suite.report = report()
        suite.report["PrimaryError"] = "earlier managed command failed"
        suite._save("results.json", suite.report)
        suite._save("artifacts.json", {"Artifacts": {"results.json": suite.expected["results.json"]}})
        original = BASE.persist_failure
        attempts = []

        def persist(current):
            self.assert_revoked(current.report)
            attempts.append(1)
            if len(attempts) == 1:
                raise OSError("one-shot fail receipt write")
            return original(current)

        with patch.object(BASE, "persist_failure", side_effect=persist):
            S.revoke_failure(suite, OSError("later closing failure"))
        self.assertEqual(len(attempts), 2)
        self.assert_revoked(suite.report)
        self.assertEqual(suite.report["PrimaryError"], "earlier managed command failed")
        self.assertTrue(any("failure hook" in item for item in suite.report["ClosingErrors"]))
        self.assertTrue(any("failure persistence 1" in item for item in suite.report["ClosingErrors"]))
        self.assertEqual(json.loads((suite.output / "results.json").read_bytes()), suite.report)
        self.assertEqual(json.loads((suite.output / "artifacts.json").read_bytes()),
                         {"Artifacts": {"results.json": sha((suite.output / "results.json").read_bytes())}})
        suite.command.assert_not_called()

    def test_late_close_and_stdout_flush_revoke_returned_and_written_pass(self):
        suite = self.suite()
        suite._started = suite._attributes_done = suite.hook_failure = True
        suite.report = report()
        suite.watch.close.side_effect = [None, OSError("late physical input close")]
        value = suite.finish()
        self.assert_revoked(value)
        self.assert_revoked(json.loads((suite.output / "results.json").read_bytes()))
        self.assertIn("late physical input close", value["PrimaryError"])
        suite.watch.close.side_effect = None
        suite.report = report()

        class BadFlush(io.StringIO):
            def flush(self):
                raise OSError("stdout flush after sealed PASS")

        argv = []
        for name in ("capture-build", "capture-receipt-sha256", "capture-artifacts-sha256", "inventory",
                     "inventory-receipt-sha256", "inventory-artifacts-sha256", "output-dir"):
            argv += ["--" + name, "synthetic-unread"]
        with patch.object(S, "prepare", return_value=(suite, {"controls": BASE})), \
                patch.object(S, "run", return_value=suite.report) as run, \
                contextlib.redirect_stdout(BadFlush()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(S.main(argv), 1)
        run.assert_called_once()
        self.assert_revoked(suite.report)
        self.assert_revoked(json.loads((suite.output / "results.json").read_bytes()))
        suite.command.assert_not_called()

    def test_source_mutants_remove_only_two_actual_annotation_sites_and_stress_one_token(self):
        sources = {name: BUFFERS[ROOT / name] for name in SOURCE_NAMES}
        before = copy.deepcopy(sources)
        A.inspect_sources(sources)
        expected = {
            "engine": ("context/context_api_decl.h", "context/context_core.c", "ctxrt_v1_current"),
            "state": ("context/context_runtime_state.h", "context/context_runtime_state.c", ROOT_NAMES[6]),
            "panic": ("context/context_panic.h", "context/context_panic.c", "fiber_panic"),
        }
        for role, (header, implementation, name) in expected.items():
            value = A.annotation_mutant(role, sources)
            changed = {path for path in sources if sources[path] != value["Sources"][path]}
            self.assertEqual(changed, {header, implementation})
            self.assertEqual(value["Function"], name)
            self.assertEqual(len(value["Edits"]), 2)
            for edit in value["Edits"]:
                old, new = sources[edit["Path"]], value["Sources"][edit["Path"]]
                self.assertEqual(edit["BeforeSha256"], sha(old))
                self.assertEqual(edit["AfterSha256"], sha(new))
                self.assertIs(type(edit["RemovedTokens"]), int)
                self.assertEqual(edit["RemovedTokens"], 1)
                self.assertEqual(len(old) - len(new), len(b"CTXRT_API_ATTR_SENSITIVE"))
                self.assertEqual(old.count(b"CTXRT_API_ATTR_SENSITIVE") - new.count(b"CTXRT_API_ATTR_SENSITIVE"), 1)
            with self.assertRaises(A.Rejected):
                A.inspect_sources(value["Sources"])
        self.assertEqual(sources, before)
        stress = A.stress_sources()
        self.assertEqual(stress["Protected"].replace(b"CTXRT_DISPATCH_ATTR\n", b"", 1), stress["Unprotected"])
        self.assertEqual(stress["Protected"].count(b"CTXRT_DISPATCH_ATTR"), 1)
        self.assertEqual(set(stress["RequiredFamilies"]), {"FunctionInstrumentation", "StackProtector", "Profiling",
                                                          "UndefinedBehavior", "SanitizerCoverage"})

    def test_inspect_lowerings_uses_one_reader_for_twelve_roles_and_failure_grants_no_batch_credit(self):
        class Rejected(ValueError):
            pass

        def fixture(*, fail_last_worker=False):
            rows, owners = [], {}
            for group in GROUPS:
                aggregate = self.root / group / "aggregate.o"
                worker = Path(str(aggregate) + ".ltrans0.ltrans.o")
                mutation = "ctxrt_attribute_stress" if group == "stress-unprotected" else MUTANTS.get(group)
                rows.append(dict(Group=group, Object=str(aggregate), ActualWorker=dict(Machine=str(worker)),
                    Mutation=mutation, Stress=group.startswith("stress-")))
                owners[aggregate], owners[worker] = group, group
            state = dict(active=False, entered=0, exited=0)
            parsed, inspected = [], []
            graph = types.SimpleNamespace(executed=[dict(Name="synthetic_reader", Sha256=sha(b"synthetic reader"))])
            admitted = object()

            def elf(path, expected_type):
                self.assertTrue(state["active"], "every image must be parsed inside the single reader scope")
                self.assertEqual(expected_type, "ET_REL")
                self.assertIn(path, owners)
                parsed.append(path)
                return types.SimpleNamespace(path=path)

            core = types.SimpleNamespace(_ELF=Mock(side_effect=elf))

            @contextlib.contextmanager
            def reader(actual_admitted, paths):
                self.assertIs(actual_admitted, admitted)
                self.assertFalse(state["active"])
                self.assertEqual(len(paths), 12)
                self.assertEqual(len(set(paths)), 12)
                state.update(active=True, entered=state["entered"] + 1)
                try:
                    yield core, graph
                finally:
                    state.update(active=False, exited=state["exited"] + 1)

            def inspect(image, actual_core, *, mutation=None, stress=False):
                self.assertTrue(state["active"])
                self.assertIs(actual_core, core)
                group = owners[image.path]
                expected = "ctxrt_attribute_stress" if group == "stress-unprotected" else MUTANTS.get(group)
                self.assertIs(stress, group.startswith("stress-"))
                inspected.append((image.path, mutation, stress))
                if fail_last_worker and group == "stress-unprotected" and str(image.path).endswith(".ltrans.o"):
                    raise Rejected("synthetic last worker failed effects")
                if expected is not None and mutation is None:
                    raise Rejected("unchanged protected predicate rejects synthetic mutant")
                self.assertEqual(mutation, expected)
                return effects(group, sha(str(image.path).encode("ascii")))

            suite = types.SimpleNamespace(admitted=admitted,
                report=dict(Status="FAIL", Lowerings=rows, **{name: False for name in PHASES}),
                modules={"controls": types.SimpleNamespace(reader=Mock(side_effect=reader)),
                         "attributes": types.SimpleNamespace(inspect_lowered=Mock(side_effect=inspect), Rejected=Rejected)},
                watch=types.SimpleNamespace(close=Mock()))
            return suite, state, parsed, inspected, graph

        suite, state, parsed, inspected, graph = fixture()
        expected_paths = tuple(Path(path) for row in suite.report["Lowerings"]
                               for path in (row["Object"], row["ActualWorker"]["Machine"]))
        with patch.object(Path, "read_bytes", side_effect=AssertionError("synthetic batch must not read ELF bytes")):
            S.inspect_lowerings(suite)
        suite.modules["controls"].reader.assert_called_once_with(suite.admitted, expected_paths)
        self.assertEqual(parsed, list(expected_paths))
        self.assertEqual(len(inspected), 16)  # Twelve body proofs and four unchanged-predicate refusals.
        self.assertEqual(state, dict(active=False, entered=1, exited=1))
        suite.watch.close.assert_called_once()
        self.assertEqual(suite.report["ExecutedReaderBuffers"], graph.executed)
        self.assertIsNot(suite.report["ExecutedReaderBuffers"], graph.executed)
        for row in suite.report["Lowerings"]:
            group = row["Group"]
            self.assertEqual(row["Effects"], effects(group, sha(row["Object"].encode("ascii"))))
            self.assertEqual(row["WorkerEffects"], effects(group, sha(row["ActualWorker"]["Machine"].encode("ascii"))))
            self.assertIs(row["OriginalProtectedPredicateRejected"], row["Mutation"] is not None)
        self.assert_revoked(suite.report)  # The caller, not this metadata pass, owns final phase credit.

        for invalid in ("order", "duplicate-role-path", "stress-selector", "last-worker"):
            suite, state, parsed, inspected, graph = fixture(fail_last_worker=invalid == "last-worker")
            if invalid == "order":
                suite.report["Lowerings"].reverse()
            elif invalid == "duplicate-role-path":
                suite.report["Lowerings"][1]["Object"] = suite.report["Lowerings"][0]["Object"]
            elif invalid == "stress-selector":
                suite.report["Lowerings"][0]["Stress"] = 0
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                S.inspect_lowerings(suite)
            if invalid in ("order", "duplicate-role-path"):
                suite.modules["controls"].reader.assert_not_called()
            else:
                self.assertEqual(state, dict(active=False, entered=1, exited=1))
            self.assert_revoked(suite.report)
            self.assertNotIn("ExecutedReaderBuffers", suite.report)
            suite.watch.close.assert_not_called()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    output = args.output_dir.resolve()
    if (output.exists() or args.output_dir.is_symlink() or output.is_relative_to(ROOT)
            or ROOT.is_relative_to(output) or not output.is_relative_to(Path(tempfile.gettempdir()).resolve())):
        parser.error("fresh external TEMP output directory required")
    result_report = dict(Status="FAIL", Scope="PURE_SYNTHETIC_CM3_HOSTILE_LTO_RUNNER_CONTROLS_ONLY",
        ExpectedTestMethods=EXPECTED_METHODS, Tests=0, Errors=0, Failures=0, Skipped=0, SourceHashes={},
        SourceDrift=[], ClosingFilesVerified=0, SourceClosureVerified=False, RepositorySourceFixturesRead=True,
        ActualCaptureRead=False, ActualCompilerExecuted=False, ActualELFTested=False, TargetExecuted=False,
        FullABIProof=False, FullAttributeEquivalence=False, CellContractSatisfied=False,
        GlobalFreezeQualified=False, RequiredCellsSatisfied=0)
    paths = (Path(__file__).resolve(), SUBJECT, ATTRIBUTES, COMPONENTS, CONTROLS, NATIVE) + tuple(ROOT / n for n in SOURCE_NAMES)
    try:
        if sys.flags.optimize or not __debug__:
            raise ValueError("unoptimized host Python required")
        BUFFERS.update({path: path.read_bytes() for path in paths})
        result_report["SourceHashes"] = {str(path): sha(raw) for path, raw in BUFFERS.items()}
        for path, digest in PINS.items():
            if sha(BUFFERS[path]) != digest:
                raise ValueError("frozen helper pin: " + str(path))
        global S, A, PROBES, BASE, N
        with patch("subprocess.Popen", side_effect=AssertionError("pure tests cannot start a process")), \
                patch("os.system", side_effect=AssertionError("pure tests cannot execute commands")):
            S = load_buffer("_attribute_runner_under_test", SUBJECT)
            A = load_buffer("_attribute_runner_leaf_plans", ATTRIBUTES)
            PROBES = load_buffer("_attribute_runner_frozen_probes", COMPONENTS)
            BASE = load_buffer("_attribute_runner_frozen_failure", CONTROLS)
            N = load_buffer("_attribute_runner_frozen_dependencies", NATIVE)
            suite = unittest.defaultTestLoader.loadTestsFromTestCase(RunnerTests)
            if suite.countTestCases() != EXPECTED_METHODS:
                raise ValueError("exact implemented method count required")
            result = unittest.TextTestRunner(verbosity=2).run(suite)
        result_report.update(Tests=result.testsRun, Errors=len(result.errors), Failures=len(result.failures),
            Skipped=len(result.skipped), Details=[dict(Test=str(test), Error=error) for test, error in result.errors + result.failures])
        if result.wasSuccessful() and result.testsRun == EXPECTED_METHODS and not result.skipped:
            result_report["Status"] = "PASS"
    except Exception:
        result_report.update(Status="FAIL", Errors=result_report["Errors"] + 1, Error=traceback.format_exc())
    finally:
        for path, digest in result_report["SourceHashes"].items():
            try:
                if sha(Path(path).read_bytes()) != digest:
                    result_report["SourceDrift"].append(path)
                else:
                    result_report["ClosingFilesVerified"] += 1
            except OSError:
                result_report["SourceDrift"].append(path)
        result_report["SourceClosureVerified"] = len(result_report["SourceHashes"]) == 16 and not result_report["SourceDrift"]
        if not result_report["SourceClosureVerified"]:
            result_report["Status"] = "FAIL"
    output.mkdir(parents=True, exist_ok=False)
    target = output / "results.json"
    target.write_bytes((json.dumps(result_report, indent=2, sort_keys=True) + "\n").encode("ascii"))
    print("Receipt:", target, sha(target.read_bytes()))
    return 0 if result_report["Status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
