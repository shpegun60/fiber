"""Pure synthetic reference witness admission and sealing, not ELF controls.

The filesystem, interpreter identity and qualified parser/root stage are mocked.
Fixed self-trusted utilities execute only their pure receipt/closure helpers.
Lookup callbacks are AST-isolated from their enclosing parser/mutation stages.
"""
import argparse
import ast
from contextlib import contextmanager
import copy
import hashlib
import importlib.util
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
WITNESS, ADAPTER, MUTATIONS = HERE / "witness.py", HERE / "reference.py", HERE / "mutations.py"
UTILITY = HERE.parent / "cm3_lto_transport/probe.py"
PRODUCER = HERE.parent / "cm3_reference_lto_transport/probe.py"
ADMISSION = HERE.parent / "cm3_reference_lto_transport/admission.py"
LOADER = HERE.parent / "cm3_final_roots/reference_witness.py"
CORE = HERE.parent / "classic_final_image/elf.py"
PIN = "a50edad08b29052631aa469d4df6e6ec7ff68878"
COHORT = "cm3-cortex-m3-soft-nofpu-none-v1-mpu0-p4-b16-aapcs-default"
MODEL = (("prvPortStartFirstTask", 32, 10), ("vPortSVCHandler", 36, 10), ("xPortPendSVHandler", 68, 19))
w = p = None
SOURCE_BYTES = {}


def sha(data):
    return hashlib.sha256(data).hexdigest().upper()


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n").encode("ascii")


def module(name, path, data):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    sys.modules[name] = result
    exec(compile(data, str(path), "exec"), result.__dict__)
    return result


def nested_reader(path, owner, name, namespace):
    tree = ast.parse(SOURCE_BYTES[path], filename=str(path))
    owners = [node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == owner]
    if len(owners) != 1:
        raise AssertionError("one exact captured reader owner required")
    readers = [node for node in ast.walk(owners[0]) if isinstance(node, ast.FunctionDef) and node.name == name]
    if len(readers) != 1:
        raise AssertionError("one exact captured nested reader required")
    selected = ast.Module(body=[copy.deepcopy(readers[0])], type_ignores=[])
    exec(compile(ast.fix_missing_locations(selected), str(path), "exec"), namespace)
    return namespace[name]


class Fixture:
    def __init__(self):
        self.base = Path(tempfile.gettempdir()).resolve() / "reference-cm3-lto-witness-memory-only"
        self.root, self.seed, self.output = self.base / "capture", self.base / "seed", self.base / "output"
        self.buffers, self.inputs = {}, {"Files": [], "Watched": []}
        self.mkdir_calls, self.load_calls, self.save_statuses = [], [], []
        self.save_attempts, self.on_save = {}, None
        self.core_path = self.seed / "source/tools/fixtures/classic_final_image/elf.py"
        originals = [(path, SOURCE_BYTES[path]) for path in (UTILITY, PRODUCER, ADMISSION, LOADER)]
        originals.append((self.core_path, SOURCE_BYTES[CORE]))
        for index, (original, data) in enumerate(originals):
            captured = self.root / "input-bytes" / ("%02d-" % index + original.name)
            self.buffers[original] = self.buffers[captured] = data
            self.inputs["Files"].append(dict(Original=str(original), Captured=str(captured), Sha256=sha(data)))
            self.inputs["Watched"].append(dict(Path=str(original), Sha256=sha(data)))
        for path in (WITNESS, ADAPTER, MUTATIONS):
            self.buffers[path] = SOURCE_BYTES[path]
        self.interpreter = self.base / "python/python.exe"
        self.buffers[self.interpreter] = b"synthetic interpreter module; never executed"
        self.inputs["Watched"].append(dict(Path=str(self.interpreter), Sha256=sha(self.buffers[self.interpreter])))
        vector = bytes.fromhex("0010002001010008")
        twins = dict(Identical=True, Entry=0x08000101, VectorAddress=0x08000000, VectorBytes=vector.hex(),
            Segments=[dict(Vaddr=0x08000000, Paddr=0x08000000, FileSize=len(vector), MemorySize=len(vector),
                           Flags=5, Align=4, BytesSha256=sha(vector))])
        twin_path = self.root / "load-image.json"
        self.buffers[twin_path] = encoded(twins)
        self.result = dict(Status="PASS", Scope="PINNED_REFERENCE_CM3_O2_LTO_CAPTURE_FEASIBILITY_ONLY",
            Profile="CM3", Mode="O2-lto", Cohort=COHORT, Linkage="direct", ReferenceCommit=PIN,
            TranslationUnits=4, SlimIRObjects=3, FinalExecutableLinks=2, SavedMachineObjects=2,
            RequiredCellsSatisfied=0, SeedBuild=str(self.seed),
            TwinLoadImagesPath=str(twin_path), TwinLoadImagesSha256=sha(self.buffers[twin_path]), TwinLoadImages=twins,
            Sources=[], Links=[], Commands=[dict(Status="PASS", Exit=0, TimedOut=False, Error=None,
                Label="synthetic successful producer record", Argv=["never-executed.exe"], Cwd=str(self.root))])
        for key in ("ReferenceBuilt", "InputClosureVerified", "OutputSealVerified", "TwinLoadImageCompared",
                    "TwinLoadImageIdentical", "TwinAllocatedSectionsIdentical"):
            self.result[key] = True
        for key in ("NativeBuilt", "FinalRootRelocationProof", "FinalReferenceParity", "SourceToMachineSemanticProof",
                    "OrdinaryOwnerContractSatisfied", "PolicyEquivalence", "ReferenceKernelAvailable",
                    "SchedulerSemanticsProven", "CSourceSemanticProof", "CanonicalProtocolValidated",
                    "CpuExecution", "BoardExecution", "GlobalFreezeQualified", "RequiredCellSatisfied"):
            self.result[key] = False
        paths = ["freertos/portable/GCC/ARM_CM3/port.c", *(
            "source/tools/fixtures/cm3_final_image/reference/" + name for name in ("providers.c", "consumer.c", "startup.S"))]
        for index, relative in enumerate(paths):
            source = self.seed / relative
            obj = self.root / "objects" / ("%02d-" % index + source.stem + ".o")
            self.buffers[source] = ("synthetic source role " + relative).encode("ascii")
            self.buffers[obj] = b"synthetic slim IR" if index < 3 else b"synthetic native startup"
            self.inputs["Watched"].append(dict(Path=str(source), Sha256=sha(self.buffers[source])))
            self.result["Sources"].append(dict(Source=str(source), SourceSha256=sha(self.buffers[source]),
                Object=str(obj), ObjectSha256=sha(self.buffers[obj]), SlimIR=index < 3, CompileDependenciesVerified=True))
        for kind in ("ordinary", "emit-relocs"):
            directory = self.root / kind
            image, machine, link_map = directory / "image.elf", directory / "image.elf.ltrans0.ltrans.o", directory / "image.map"
            self.buffers[image], self.buffers[machine], self.buffers[link_map] = b"synthetic final", b"synthetic machine", b"synthetic map"
            self.buffers[Path(str(image) + ".dis")] = b"synthetic disassembly"
            self.result["Links"].append(dict(Kind=kind, Path=str(image), Sha256=sha(self.buffers[image]),
                Machine=str(machine), MachineSha256=sha(self.buffers[machine]), Map=str(link_map), MapSha256=sha(self.buffers[link_map])))
        self.args = SimpleNamespace(capture_build=str(self.root), output_dir=str(self.output),
                                   capture_receipt_sha256="", capture_artifacts_sha256="")
        self.reseal()

    def reseal(self):
        self.buffers[self.root / "results.json"] = encoded(self.result)
        self.buffers[self.root / "inputs.json"] = encoded(self.inputs)
        members = {path.relative_to(self.root).as_posix(): sha(data) for path, data in self.buffers.items()
                   if path.is_relative_to(self.root) and path != self.root / "artifacts.json"}
        self.buffers[self.root / "artifacts.json"] = encoded(dict(Artifacts=members))
        self.args.capture_receipt_sha256 = sha(self.buffers[self.root / "results.json"])
        self.args.capture_artifacts_sha256 = sha(self.buffers[self.root / "artifacts.json"])

    def regular(self, path):
        path = Path(path)
        if path not in self.buffers:
            raise FileNotFoundError(str(path))
        return path

    def files(self, root):
        root = Path(root)
        return {path.relative_to(root).as_posix(): path for path in self.buffers if path.is_relative_to(root)}

    def save(self, path, value):
        path = Path(path)
        self.save_attempts[path] = self.save_attempts.get(path, 0) + 1
        attempt = self.save_attempts[path]
        if path == self.output / "results.json":
            self.save_statuses.append(value["Status"])
        if self.on_save:
            self.on_save("before", path, attempt, self.buffers)
        self.buffers[path] = encoded(value)
        if self.on_save:
            self.on_save("after", path, attempt, self.buffers)

    def load(self, name, path, data):
        self.load_calls.append((name, Path(path), data))
        if name != "cm3_reference_lto_root_utilities" or Path(path) != UTILITY or data != SOURCE_BYTES[UTILITY]:
            raise AssertionError("qualified parser/root stage must stay mocked in pure envelope controls")
        return p

    @contextmanager
    def active(self):
        def exists(path):
            return Path(path) in self.buffers or any(item.is_relative_to(path) for item in self.buffers)

        def mkdir(path, *args, **kwargs):
            self.mkdir_calls.append(Path(path))

        with patch.object(w, "load", side_effect=self.load), \
                patch.object(w, "interpreter_path", return_value=self.interpreter), \
                patch.object(p, "regular", side_effect=self.regular), \
                patch.object(p, "checked_path", side_effect=lambda path, must_exist=True: Path(os.path.abspath(path))), \
                patch.object(p, "files_under", side_effect=self.files), patch.object(p, "save", side_effect=self.save), \
                patch.object(Path, "read_bytes", lambda path: self.buffers[self.regular(path)]), \
                patch.object(Path, "exists", exists), patch.object(Path, "mkdir", mkdir), \
                patch("subprocess.Popen", side_effect=AssertionError("pure controls forbid process execution")):
            yield

    def construct(self):
        with self.active():
            return w.Witness(self.args)


class ReaderLookupTests(unittest.TestCase):
    def outer(self, snapshots, mutable_paths, raw_read):
        return nested_reader(WITNESS, "_read", "fixed_read",
                             dict(w.__dict__, snapshots=snapshots, mutable_paths=mutable_paths, raw_read=raw_read))

    def inner(self, snapshots, raw_read):
        namespace = dict(Path=Path, os=os, snapshots=snapshots, raw_read=raw_read, consumed=set())
        tree = ast.parse(SOURCE_BYTES[MUTATIONS], filename=str(MUTATIONS))
        helpers = [copy.deepcopy(node) for node in tree.body if isinstance(node, ast.FunctionDef)
                   and node.name in ("need", "stable", "stable_path")]
        exec(compile(ast.fix_missing_locations(ast.Module(body=helpers, type_ignores=[])), str(MUTATIONS), "exec"), namespace)
        return nested_reader(MUTATIONS, "run_cases", "fixed_read", namespace)

    def test_outer_immutable_source_and_binary_are_lexical_no_resolution_reads(self):
        base = Path(tempfile.gettempdir()).absolute() / "reference-lto-lookup-memory-only"
        snapshots = {base / "source/core.py": b"immutable source", base / "positive/Final.elf": b"immutable binary"}
        raw_read = Mock(return_value=b"untrusted disk replacement")
        read = self.outer(snapshots, set(), raw_read)
        with patch.object(Path, "resolve", side_effect=AssertionError("lookup must not resolve paths")):
            for path, expected in snapshots.items():
                with self.subTest(path=path):
                    self.assertEqual(read(path), expected)
                    self.assertEqual(read(path.parent / "not-a-directory" / ".." / path.name), expected)
        raw_read.assert_not_called()

    def test_outer_unknown_inputs_never_fall_back_even_under_known_roots(self):
        base = Path(tempfile.gettempdir()).absolute() / "reference-lto-lookup-memory-only"
        source, private = base / "source/core.py", base / "mutants/case/Final.elf"
        raw_read = Mock(return_value=b"unknown disk bytes")
        read = self.outer({source: b"immutable"}, {private}, raw_read)
        with patch.object(Path, "resolve", side_effect=AssertionError("lookup must not resolve paths")):
            for path in (source.parent / "extra.py", private.parent / "extra.elf", base / "mutants/other/Final.elf"):
                with self.subTest(path=path), self.assertRaisesRegex(ValueError, "unknown reader input"):
                    read(path)
        raw_read.assert_not_called()

    def test_outer_live_reads_are_exact_declared_private_paths_and_snapshot_wins(self):
        base = Path(tempfile.gettempdir()).absolute() / "reference-lto-lookup-memory-only"
        positive, private = base / "positive/Final.elf", base / "mutants/case/Final.elf"
        raw_read = Mock(return_value=b"declared mutable private bytes")
        read = self.outer({positive: b"immutable"}, {positive, private}, raw_read)
        with patch.object(Path, "resolve", side_effect=AssertionError("lookup must not resolve paths")):
            self.assertEqual(read(private), b"declared mutable private bytes")
            self.assertEqual(read(positive), b"immutable")
        raw_read.assert_called_once_with(private)

    def test_inner_requires_exact_canonical_snapshot_keys_without_resolution_or_disk(self):
        base = Path(tempfile.gettempdir()).absolute() / "reference-lto-lookup-memory-only"
        snapshots = {base / "mutants/case/Final.elf": b"snapshot final", base / "mutants/case/LinkMap.map": b"snapshot map"}
        raw_read = Mock(return_value=b"changed private bytes")
        read = self.inner(snapshots, raw_read)
        with patch.object(Path, "resolve", side_effect=AssertionError("lookup must not resolve paths")):
            for path, expected in snapshots.items():
                with self.subTest(path=path):
                    self.assertEqual(read(path), expected)
                    with self.assertRaisesRegex(ValueError, "unknown or noncanonical input"):
                        read(path.parent / "not-a-directory" / ".." / path.name)
        self.assertEqual(read.__globals__["consumed"], set(snapshots))
        raw_read.assert_not_called()

    def test_inner_unknown_files_or_other_cases_cannot_escape_to_disk(self):
        base = Path(tempfile.gettempdir()).absolute() / "reference-lto-lookup-memory-only"
        private = base / "mutants/case/Final.elf"
        raw_read = Mock(return_value=b"unknown private bytes")
        read = self.inner({private: b"snapshot"}, raw_read)
        with patch.object(Path, "resolve", side_effect=AssertionError("lookup must not resolve paths")):
            for path in (private.parent / "extra.elf", base / "mutants/other/Final.elf", base / "positive/Final.elf"):
                with self.subTest(path=path), self.assertRaisesRegex(ValueError, "unknown.*input"):
                    read(path)
        raw_read.assert_not_called()


class AdmissionTests(unittest.TestCase):
    def denied(self, fixture):
        with self.assertRaises((ValueError, FileNotFoundError)):
            fixture.construct()
        self.assertEqual(fixture.mkdir_calls, [])
        self.assertEqual([row[0] for row in fixture.load_calls], ["cm3_reference_lto_root_utilities"])

    def test_valid_reference_four_tu_three_ir_fixture_loads_only_fixed_utility(self):
        fixture = Fixture()
        witness = fixture.construct()
        self.assertEqual(witness.output, fixture.output)
        self.assertEqual(fixture.mkdir_calls, [])
        self.assertEqual(len(fixture.load_calls), 1)
        self.assertEqual(set(witness.buffers) - {WITNESS, ADAPTER, MUTATIONS},
                         {UTILITY, PRODUCER, ADMISSION, LOADER, fixture.core_path})
        self.assertEqual([row["SlimIR"] for row in fixture.result["Sources"]], [True, True, True, False])
        self.assertEqual(fixture.result["ReferenceCommit"], PIN)
        self.assertTrue(fixture.result["Sources"][0]["Source"].endswith("freertos/portable/GCC/ARM_CM3/port.c".replace("/", os.sep)))
        self.assertEqual(witness.report["Interpreter"]["ModulePath"], str(fixture.interpreter))
        self.assertEqual(witness.watch.hashes[fixture.interpreter], sha(fixture.buffers[fixture.interpreter]))

    def test_caller_hashes_and_fixed_self_trusted_utility_pin_fail_before_import_or_mkdir(self):
        for key in ("capture_receipt_sha256", "capture_artifacts_sha256"):
            fixture = Fixture()
            setattr(fixture.args, key, "0" * 64)
            with self.subTest(key=key):
                self.denied(fixture)
        fixture = Fixture()
        fixture.buffers[UTILITY] += b"# changed utility\n"
        with self.assertRaisesRegex(ValueError, "fixed self-trusted capture utilities"):
            fixture.construct()
        self.assertEqual(fixture.load_calls, [])
        self.assertEqual(fixture.mkdir_calls, [])

    def test_manifest_receipt_binding_and_complete_artifact_membership_are_required(self):
        for change in ("receipt-binding", "extra", "missing"):
            fixture = Fixture()
            if change == "receipt-binding":
                path = fixture.root / "artifacts.json"
                value = json.loads(fixture.buffers[path])
                value["Artifacts"]["results.json"] = "0" * 64
                fixture.buffers[path] = encoded(value)
                fixture.args.capture_artifacts_sha256 = sha(fixture.buffers[path])
            elif change == "extra":
                fixture.buffers[fixture.root / "not-in-manifest"] = b"extra"
            else:
                fixture.buffers.pop(Path(fixture.result["Sources"][0]["Object"]))
            with self.subTest(change=change):
                self.denied(fixture)

    def test_fixed_reference_pin_scope_profile_mode_and_typed_counts_cannot_alias(self):
        for key, value in (("Status", "FAIL"), ("ReferenceCommit", "0" * 40), ("Profile", "CM4"), ("Mode", "O2"),
                           ("Scope", "NATIVE_CM3_O2_LTO_CAPTURE_FEASIBILITY_ONLY"), ("Cohort", COHORT + "-foreign"),
                           ("Linkage", "archive"), ("TranslationUnits", 9), ("TranslationUnits", 4.0),
                           ("SlimIRObjects", 8), ("FinalExecutableLinks", True), ("SavedMachineObjects", 1)):
            fixture = Fixture()
            fixture.result[key] = value
            fixture.reseal()
            with self.subTest(key=key, value=value):
                self.denied(fixture)
        fixture = Fixture()
        fixture.result["Links"].reverse()
        fixture.reseal()
        self.denied(fixture)

    def test_literal_phase_markers_nonclaims_and_zero_required_counter_are_strict(self):
        true_keys = ("ReferenceBuilt", "InputClosureVerified", "OutputSealVerified", "TwinLoadImageCompared",
                     "TwinLoadImageIdentical", "TwinAllocatedSectionsIdentical")
        false_keys = ("NativeBuilt", "FinalRootRelocationProof", "FinalReferenceParity", "SourceToMachineSemanticProof",
                      "OrdinaryOwnerContractSatisfied", "PolicyEquivalence", "ReferenceKernelAvailable", "SchedulerSemanticsProven",
                      "CSourceSemanticProof", "CanonicalProtocolValidated", "CpuExecution", "BoardExecution",
                      "GlobalFreezeQualified", "RequiredCellSatisfied")
        for keys, values in ((true_keys, (False, 1, None)), (false_keys, (True, 0, None)),
                             (("RequiredCellsSatisfied",), (False, 0.0, 1))):
            for key in keys:
                for value in values:
                    fixture = Fixture()
                    fixture.result[key] = value
                    fixture.reseal()
                    with self.subTest(key=key, value=value):
                        self.denied(fixture)

    def test_missing_sources_empty_commands_and_nonterminal_or_bool_exit_records_reject(self):
        for change in ("sources", "commands", "pending", "exit", "nonzero", "timeout"):
            fixture = Fixture()
            if change == "sources":
                fixture.result["Sources"].pop()
            elif change == "commands":
                fixture.result["Commands"].clear()
            elif change == "pending":
                fixture.result["Commands"][0]["Status"] = "ATTEMPT"
            elif change == "exit":
                fixture.result["Commands"][0]["Exit"] = False
            elif change == "nonzero":
                fixture.result["Commands"][0]["Exit"] = 1
            else:
                fixture.result["Commands"][0]["TimedOut"] = True
            fixture.reseal()
            with self.subTest(change=change):
                self.denied(fixture)

    def test_duplicate_or_escaped_captures_and_original_captured_watched_drift_reject(self):
        for change in ("duplicate", "outside", "original", "captured", "watched"):
            fixture = Fixture()
            row = fixture.inputs["Files"][1]
            if change == "duplicate":
                fixture.inputs["Files"].append(copy.deepcopy(row))
            elif change == "outside":
                outside = fixture.base / "not-capture/probe.py"
                fixture.buffers[outside] = fixture.buffers[Path(row["Captured"])]
                row["Captured"] = str(outside)
            elif change == "original":
                fixture.buffers[Path(row["Original"])] += b"tampered"
            elif change == "captured":
                fixture.buffers[Path(row["Captured"])] += b"tampered"
            else:
                fixture.buffers[fixture.interpreter] += b"tampered"
            fixture.reseal()
            with self.subTest(change=change):
                self.denied(fixture)

    def test_authenticated_foreign_executed_helpers_or_core_cannot_rebind_fixed_hashes(self):
        for source in (PRODUCER, ADMISSION, LOADER, None):
            fixture = Fixture()
            original = fixture.core_path if source is None else source
            row = next(item for item in fixture.inputs["Files"] if item["Original"] == str(original))
            changed = fixture.buffers[original] + b"\n# foreign captured helper\n"
            fixture.buffers[original] = fixture.buffers[Path(row["Captured"])] = changed
            row["Sha256"] = sha(changed)
            next(item for item in fixture.inputs["Watched"] if item["Path"] == str(original))["Sha256"] = sha(changed)
            fixture.reseal()
            with self.subTest(source=source):
                self.denied(fixture)

    def test_output_overlaps_input_repo_and_actual_interpreter_are_denied_before_mkdir(self):
        base = Fixture()
        for output in (REPO / "new-output", base.root, base.root / "nested", base.base,
                       base.core_path.parent / "new-output", base.interpreter.parent / "new-output"):
            fixture = Fixture()
            fixture.args.output_dir = str(output)
            with self.subTest(output=output):
                self.denied(fixture)
        fixture = Fixture()
        fixture.interpreter = fixture.base / "current-runtime/python.exe"
        fixture.buffers[fixture.interpreter] = b"current unlisted interpreter module"
        witness = fixture.construct()
        self.assertEqual(witness.watch.hashes[fixture.interpreter], sha(fixture.buffers[fixture.interpreter]))
        fixture.args.output_dir = str(fixture.interpreter.parent / "new-output")
        fixture.load_calls.clear()
        self.denied(fixture)

    def test_twin_path_hash_value_and_late_admission_input_drift_reject_before_mkdir(self):
        for change in ("path", "hash", "value"):
            fixture = Fixture()
            if change == "path":
                fixture.result["TwinLoadImagesPath"] = str(fixture.root / "other-twins.json")
            elif change == "hash":
                fixture.result["TwinLoadImagesSha256"] = "0" * 64
            else:
                fixture.result["TwinLoadImages"]["Entry"] += 2
            fixture.reseal()
            with self.subTest(change=change):
                self.denied(fixture)
        fixture = Fixture()
        closing = p.Closure.close

        def drift(closure):
            fixture.buffers[fixture.interpreter] += b"late admission drift"
            closing(closure)

        with patch.object(p.Closure, "close", drift):
            self.denied(fixture)

    def test_ast_isolated_positive_role_guards_reject_machine_rebinding_and_aliases(self):
        tree = ast.parse(SOURCE_BYTES[WITNESS], filename=str(WITNESS))
        owner = next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == "_read")
        start = next(index for index, node in enumerate(owner.body) if isinstance(node, ast.Assign)
                     and any(isinstance(target, ast.Name) and target.id == "link" for target in node.targets))
        stop = next(index for index, node in enumerate(owner.body) if isinstance(node, ast.Assign)
                    and any(isinstance(target, ast.Name) and target.id == "snapshots" for target in node.targets))
        selected = ast.Module(body=copy.deepcopy(owner.body[start:stop]), type_ignores=[])
        self.assertEqual(len(selected.body), 4)
        code = compile(ast.fix_missing_locations(selected), str(WITNESS), "exec")
        for change in ("machine", "same-path", "physical-alias"):
            fixture = Fixture()
            witness = fixture.construct()
            if change == "machine":
                witness.result["Links"][1]["Machine"] = witness.result["Links"][0]["Machine"]
            elif change == "same-path":
                witness.result["Sources"][3]["Object"] = witness.result["Links"][1]["Path"]
            with fixture.active(), patch.object(Path, "samefile", return_value=change == "physical-alias"):
                with self.subTest(change=change), self.assertRaisesRegex(ValueError, "machine role|physical positive roles"):
                    exec(code, dict(self=witness, need=w.need, Path=Path))


class ClosingTests(unittest.TestCase):
    def run_witness(self, fixture, *, stage_error=None, after_stage=None, on_close=None):
        with fixture.active():
            witness = w.Witness(fixture.args)

            def stage():
                if stage_error is not None:
                    raise stage_error
                witness.report["Roots"] = [dict(Name=name, Size=size, InstructionCount=count, SyntheticStageStub=True)
                                           for name, size, count in MODEL]
                witness.report["Twins"] = copy.deepcopy(fixture.result["TwinLoadImages"])
                witness.report["PureRootStageStub"] = True
                watched = fixture.output / "synthetic-root-stage.json"
                witness.declare(watched)
                p.save(watched, dict(SyntheticStageStub=True, Roots=witness.report["Roots"]))
                witness.watch.read(watched, sha(fixture.buffers[watched]))
                diagnostic = fixture.output / "side-report.json"
                witness.declare(diagnostic)
                p.save(diagnostic, dict(SyntheticDiagnostic=True))
                if after_stage:
                    after_stage(witness, fixture)

            close, calls = witness.watch.close, 0

            def closing():
                nonlocal calls
                calls += 1
                if on_close:
                    on_close(calls, fixture)
                close()

            with patch.object(witness, "_read", side_effect=stage) as reader, \
                    patch.object(witness.watch, "close", side_effect=closing):
                passed = witness.run()
            reader.assert_called_once()
            self.assertEqual([row[0] for row in fixture.load_calls], ["cm3_reference_lto_root_utilities"])
            return passed, witness

    def receipt(self, fixture, status, *, sealed=True):
        row = json.loads(fixture.buffers[fixture.output / "results.json"])
        self.assertEqual(row["Status"], status)
        self.assertIs(row["OutputSealVerified"], sealed)
        for key in ("Qualification", "ActualELFMutationControlsExecuted", "CanonicalProtocolValidated", "FinalReferenceParity",
                    "FullABIProof", "SourceToMachineSemanticProof", "OriginalTranslationUnitOwnership", "CompleteObjectProof",
                    "PolicyEquivalence", "CpuExecution", "BoardExecution", "GlobalFreezeQualified"):
            self.assertIs(row[key], False)
        self.assertEqual(row["Mutants"], [])
        self.assertIs(type(row["RequiredCellsSatisfied"]), int)
        self.assertEqual(row["RequiredCellsSatisfied"], 0)
        self.assertEqual(row["NativeCommandsExecuted"], 0)
        if sealed:
            expected = {path.relative_to(fixture.output).as_posix(): sha(data) for path, data in fixture.buffers.items()
                        if path.is_relative_to(fixture.output) and path != fixture.output / "artifacts.json"}
            self.assertEqual(json.loads(fixture.buffers[fixture.output / "artifacts.json"]), dict(Artifacts=expected))
        return row

    def test_mocked_stage_success_is_sealed_but_never_elf_or_mutant_qualification(self):
        fixture = Fixture()
        passed, witness = self.run_witness(fixture)
        self.assertIs(passed, True)
        row = self.receipt(fixture, w.PASS)
        self.assertEqual(row["ReferenceCommit"], PIN)
        self.assertIs(row["InputClosureVerified"], True)
        self.assertEqual(row["UnexpectedOutputMembers"], [])
        self.assertEqual(row["MissingDeclaredOutputMembers"], [])
        self.assertEqual([root["Name"] for root in row["Roots"]], [name for name, *_ in MODEL])
        self.assertEqual(fixture.mkdir_calls, [fixture.output])
        self.assertEqual(row["ClosingFilesVerified"], len(witness.watch.hashes))

    def test_reader_failure_or_baseexception_leaves_only_failure_receipts(self):
        for error in (ValueError("synthetic root rejection"), KeyboardInterrupt("synthetic interruption")):
            fixture = Fixture()
            with self.subTest(error=error):
                passed, _ = self.run_witness(fixture, stage_error=error)
                self.assertIs(passed, False)
                row = self.receipt(fixture, "FAIL")
                self.assertIs(row["InputClosureVerified"], False)
                self.assertIn(str(error), row["Error"])
                self.assertEqual(set(fixture.save_statuses), {"FAIL"})

    def test_original_or_generated_watched_input_drift_fails_before_first_success_seal(self):
        for original in (False, True):
            fixture = Fixture()

            def change(witness, data):
                path = ADAPTER if original else data.output / "synthetic-root-stage.json"
                data.buffers[path] += b"changed after admission"

            with self.subTest(original=original):
                passed, _ = self.run_witness(fixture, after_stage=change)
                self.assertIs(passed, False)
                row = self.receipt(fixture, "FAIL")
                self.assertIs(row["InputClosureVerified"], False)
                self.assertIn("input hash mismatch", row["Error"])
                self.assertEqual(set(fixture.save_statuses), {"FAIL"})

    def test_preseal_foreign_or_missing_declared_member_cannot_become_success(self):
        for extra in (False, True):
            fixture = Fixture()

            def change(witness, data):
                path = data.output / "unexpected.json" if extra else data.output / "declared-missing.json"
                if extra:
                    data.buffers[path] = b"unplanned forensic output"
                else:
                    witness.declare(path)

            with self.subTest(extra=extra):
                passed, _ = self.run_witness(fixture, after_stage=change)
                self.assertIs(passed, False)
                row = self.receipt(fixture, "FAIL")
                self.assertEqual(row["UnexpectedOutputMembers"], ["unexpected.json"] if extra else [])
                self.assertEqual(row["MissingDeclaredOutputMembers"], [] if extra else ["declared-missing.json"])
                self.assertIn("predetermined output membership", row["Error"])

    def test_duplicate_or_escaped_output_declarations_are_denied_without_creation(self):
        fixture = Fixture()
        witness = fixture.construct()
        witness.declare(fixture.output / "new.json")
        for path in (fixture.output / "new.json", fixture.output / "results.json", fixture.base / "escaped.json"):
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, "declared output|duplicate declared"):
                witness.declare(path)
        self.assertEqual(fixture.mkdir_calls, [])

    def test_add_change_or_delete_during_manifest_write_downgrades_and_reseals_failure(self):
        for change in ("add", "change", "delete"):
            fixture = Fixture()

            def fault(phase, path, attempt, buffers):
                if phase == "after" and path == fixture.output / "artifacts.json" and attempt == 1:
                    if change == "add":
                        buffers[fixture.output / "late-extra"] = b"late output"
                    elif change == "change":
                        buffers[fixture.output / "side-report.json"] += b"changed"
                    else:
                        del buffers[fixture.output / "side-report.json"]

            fixture.on_save = fault
            with self.subTest(change=change):
                passed, _ = self.run_witness(fixture)
                self.assertIs(passed, False)
                row = self.receipt(fixture, "FAIL")
                self.assertIn("post-manifest output closure", row["Error"])
                self.assertIn(w.PASS, fixture.save_statuses)

    def test_written_manifest_must_equal_expected_dictionary_and_have_unique_keys(self):
        for contents in (encoded(dict(Artifacts={})), b'{"Artifacts":{},"Artifacts":{}}'):
            fixture = Fixture()

            def fault(phase, path, attempt, buffers):
                if phase == "after" and path == fixture.output / "artifacts.json" and attempt == 1:
                    buffers[path] = contents

            fixture.on_save = fault
            with self.subTest(contents=contents):
                passed, _ = self.run_witness(fixture)
                self.assertIs(passed, False)
                row = self.receipt(fixture, "FAIL")
                self.assertIn("written manifest value" if contents.startswith(b"{\n") else "duplicate JSON key", row["Error"])

    def test_one_time_or_permanent_manifest_storage_failure_never_preserves_success(self):
        for permanent in (False, True):
            fixture = Fixture()

            def fault(phase, path, attempt, buffers):
                if phase == "before" and path == fixture.output / "artifacts.json" and (permanent or attempt == 1):
                    raise OSError("synthetic manifest storage failure")

            fixture.on_save = fault
            with self.subTest(permanent=permanent):
                passed, _ = self.run_witness(fixture)
                self.assertIs(passed, False)
                row = self.receipt(fixture, "FAIL", sealed=not permanent)
                self.assertIn("synthetic manifest storage failure", row["Error"])
                if permanent:
                    self.assertIn("synthetic manifest storage failure", row["SealError"])

    def test_late_unwatched_output_add_change_delete_is_not_hidden_by_prior_seal(self):
        for change in ("add", "change", "delete"):
            fixture = Fixture()

            def fault(count, data):
                if count == 2:
                    if change == "add":
                        data.buffers[data.output / "late-extra"] = b"late output"
                    elif change == "change":
                        data.buffers[data.output / "side-report.json"] += b"changed"
                    else:
                        del data.buffers[data.output / "side-report.json"]

            with self.subTest(change=change):
                passed, _ = self.run_witness(fixture, on_close=fault)
                self.assertIs(passed, False)
                row = self.receipt(fixture, "FAIL")
                self.assertIn("late output closure", row["Error"])

    def test_late_manifest_raw_bytes_and_late_input_hash_are_closed(self):
        for manifest in (False, True):
            fixture = Fixture()

            def fault(count, data):
                if count == 2:
                    path = data.output / "artifacts.json" if manifest else data.interpreter
                    data.buffers[path] += b" \n"

            with self.subTest(manifest=manifest):
                passed, _ = self.run_witness(fixture, on_close=fault)
                self.assertIs(passed, False)
                row = self.receipt(fixture, "FAIL")
                self.assertIs(row["InputClosureVerified"], False)
                self.assertIn("late manifest drift" if manifest else "input hash mismatch", row["Error"])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    output = args.output_dir.resolve()
    if output.exists() or output.is_relative_to(REPO) or not output.is_relative_to(Path(tempfile.gettempdir()).resolve()):
        parser.error("fresh external TEMP output directory required")
    report = dict(Status="FAIL", Tests=0, Failures=0, Errors=0, Skipped=0, SourceHashes={}, SourceDrift=[],
        Scope="PURE_SYNTHETIC_REFERENCE_CM3_LTO_WITNESS_ENVELOPE_ONLY", SyntheticInputs=True,
        ActualELFTested=False, ActualParserExecuted=False, ActualMutationCasesTested=False,
        QualifiedCapturedParserExecuted=False, ToolInvocations=0, NativeCommandsExecuted=0,
        GeneratedMachineBoundRootPreservation=False, CanonicalProtocolValidated=False,
        OriginalTranslationUnitOwnership=False, SourceToMachineSemanticProof=False, FinalReferenceParity=False,
        FullABIProof=False, PolicyEquivalence=False, CpuExecution=False, BoardExecution=False,
        RequiredCellsSatisfied=0, GlobalFreezeQualified=False)
    paths = [Path(__file__).resolve(), WITNESS, ADAPTER, MUTATIONS, UTILITY, PRODUCER, ADMISSION, LOADER, CORE]
    try:
        if sys.flags.optimize or not __debug__:
            raise ValueError("optimized Python unsupported")
        global SOURCE_BYTES, w, p
        SOURCE_BYTES = {path: path.read_bytes() for path in paths}
        report["SourceHashes"] = {str(path): sha(data) for path, data in SOURCE_BYTES.items()}
        with patch("subprocess.Popen", side_effect=AssertionError("pure controls forbid process execution")):
            w = module("pure_reference_cm3_lto_witness", WITNESS, SOURCE_BYTES[WITNESS])
            p = module("pure_reference_cm3_lto_fixed_utilities", UTILITY, SOURCE_BYTES[UTILITY])
            suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
            count = suite.countTestCases()
            if not count:
                raise ValueError("nonempty pure witness controls required")
            result = unittest.TextTestRunner(verbosity=2).run(suite)
        report.update(Tests=result.testsRun, Failures=len(result.failures), Errors=len(result.errors), Skipped=len(result.skipped),
            FailureDetails=[dict(Test=str(case), Detail=detail) for case, detail in result.failures + result.errors])
        report["SourceDrift"] = [str(path) for path in paths if not path.is_file() or sha(path.read_bytes()) != report["SourceHashes"][str(path)]]
        if result.wasSuccessful() and result.testsRun == count > 0 and not result.skipped and not report["SourceDrift"]:
            report["Status"] = "PASS"
    except Exception:
        report.update(Status="FAIL", Error=traceback.format_exc(), Errors=report["Errors"] + 1)
    output.mkdir(parents=True, exist_ok=False)
    target = output / "results.json"
    target.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="ascii")
    print("Receipt:", target, sha(target.read_bytes()))
    return 0 if report["Status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
