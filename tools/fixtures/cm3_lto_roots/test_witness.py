"""Pure source/admission/closure controls, not ELF mutation qualification.

Producer receipts and object data below are synthetic in-memory fixtures.
Fixed utility source buffers are read and hashed. Qualified parser/root work
is an explicit mocked boundary; fixed self-trusted utilities may load before
caller receipt authentication.
"""
import argparse
import ast
from contextlib import contextmanager
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
NATIVE = HERE / "native.py"
MUTATIONS = HERE / "mutations.py"
PROBE = HERE.parent / "cm3_lto_transport/probe.py"
LOADER = HERE.parent / "cm3_final_roots/reference_witness.py"
CORE = HERE.parent / "classic_final_image/elf.py"
COHORT = "cm3-cortex-m3-soft-nofpu-none-v1-mpu0-p4-b16-aapcs-default"
MODEL = (("SVC_Handler", 184, 64, 5), ("PendSV_Handler", 204, 72, 6),
         ("fiber_port_start_first_context", 104, 34, 2))
w = p = m = None
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
    # Execute only the captured lookup callback, never its enclosing ELF stage.
    selected = ast.Module(body=[copy.deepcopy(readers[0])], type_ignores=[])
    exec(compile(ast.fix_missing_locations(selected), str(path), "exec"), namespace)
    return namespace[name]


class ReaderLookupTests(unittest.TestCase):
    def outer(self, immutable, mutable_paths, raw_read):
        namespace = dict(w.__dict__, immutable=immutable, mutable_paths=mutable_paths, raw_read=raw_read)
        return nested_reader(WITNESS, "_read_roots", "source_read", namespace)

    def inner(self, snapshots, raw_read):
        return nested_reader(MUTATIONS, "run_cases", "fixed_read", dict(m.__dict__, snapshots=snapshots, raw_read=raw_read))

    def test_outer_immutable_source_and_binary_lookup_never_resolves_or_reads_disk(self):
        base = Path(tempfile.gettempdir()).absolute() / "cm3-lto-lookup-memory-only"
        immutable = {base / "source/core.py": b"captured source", base / "positive/Final.elf": b"captured binary"}
        raw_read = Mock(return_value=b"untrusted replacement disk bytes")
        read = self.outer(immutable, set(), raw_read)
        with patch.object(Path, "resolve", side_effect=AssertionError("reader lookup must not resolve paths")):
            for path, expected in immutable.items():
                alias = path.parent / "not-a-real-directory" / ".." / path.name
                with self.subTest(path=path):
                    self.assertEqual(read(path), expected)
                    self.assertEqual(read(alias), expected)
        raw_read.assert_not_called()

    def test_outer_unknown_inputs_cannot_fall_back_to_disk_even_under_known_roots(self):
        base = Path(tempfile.gettempdir()).absolute() / "cm3-lto-lookup-memory-only"
        source, private = base / "source/core.py", base / "mutants/case/Final.elf"
        raw_read = Mock(return_value=b"unknown disk input must never be consumed")
        read = self.outer({source: b"immutable"}, {private}, raw_read)
        unknown = (source.parent / "other.py", base / "other/core.py", private.parent / "extra.elf",
                   base / "mutants/other-case/Final.elf")
        with patch.object(Path, "resolve", side_effect=AssertionError("reader lookup must not resolve paths")):
            for path in unknown:
                with self.subTest(path=path), self.assertRaisesRegex(ValueError, "unknown reader input"):
                    read(path)
        raw_read.assert_not_called()

    def test_outer_only_exact_declared_private_file_is_live_and_immutable_has_precedence(self):
        base = Path(tempfile.gettempdir()).absolute() / "cm3-lto-lookup-memory-only"
        private = base / "mutants/case/Final.elf"
        immutable = base / "positive/Final.elf"
        raw_read = Mock(return_value=b"declared private bytes before snapshot")
        read = self.outer({immutable: b"immutable bytes"}, {private, immutable}, raw_read)
        with patch.object(Path, "resolve", side_effect=AssertionError("reader lookup must not resolve paths")):
            self.assertEqual(read(private), b"declared private bytes before snapshot")
            self.assertEqual(read(immutable), b"immutable bytes")
        raw_read.assert_called_once_with(private)

    def test_inner_private_snapshot_lookup_never_resolves_or_reads_disk(self):
        base = Path(tempfile.gettempdir()).absolute() / "cm3-lto-lookup-memory-only"
        snapshots = {base / "mutants/case/Final.elf": b"snapshotted final", base / "mutants/case/LinkMap.map": b"snapshotted map"}
        raw_read = Mock(return_value=b"changed private disk bytes")
        read = self.inner(snapshots, raw_read)
        with patch.object(Path, "resolve", side_effect=AssertionError("snapshot lookup must not resolve paths")):
            for path, expected in snapshots.items():
                alias = path.parent / "not-a-real-directory" / ".." / path.name
                with self.subTest(path=path):
                    self.assertEqual(read(path), expected)
                    self.assertEqual(read(alias), expected)
        raw_read.assert_not_called()

    def test_inner_unknown_input_cannot_escape_snapshot_to_disk_or_other_case(self):
        base = Path(tempfile.gettempdir()).absolute() / "cm3-lto-lookup-memory-only"
        private = base / "mutants/case/Final.elf"
        raw_read = Mock(return_value=b"unapproved disk bytes")
        read = self.inner({private: b"snapshot"}, raw_read)
        unknown = (private.parent / "extra.elf", base / "mutants/other-case/Final.elf", base / "positive/Final.elf")
        with patch.object(Path, "resolve", side_effect=AssertionError("snapshot lookup must not resolve paths")):
            for path in unknown:
                with self.subTest(path=path), self.assertRaisesRegex(ValueError, "unknown private reader input"):
                    read(path)
        raw_read.assert_not_called()


class Fixture:
    def __init__(self):
        self.base = Path(tempfile.gettempdir()).resolve() / "cm3-lto-witness-memory-only"
        self.root, self.seed = self.base / "capture", self.base / "seed"
        self.output = self.base / "output"
        self.buffers, self.inputs = {}, {"Files": [], "Watched": []}
        self.mkdir_calls, self.load_calls, self.save_statuses = [], [], []
        self.save_attempts = {}
        self.on_save = None
        self.core_path = self.seed / "source/tools/fixtures/classic_final_image/elf.py"
        originals = ((PROBE, SOURCE_BYTES[PROBE]), (LOADER, SOURCE_BYTES[LOADER]), (self.core_path, SOURCE_BYTES[CORE]))
        for index, (original, data) in enumerate(originals):
            captured = self.root / "input-bytes" / ("%02d-" % index + original.name)
            self.buffers[original] = self.buffers[captured] = data
            row = dict(Original=str(original), Captured=str(captured), Sha256=sha(data))
            self.inputs["Files"].append(row)
            self.inputs["Watched"].append(dict(Path=str(original), Sha256=sha(data)))
        for path in (WITNESS, NATIVE, MUTATIONS):
            self.buffers[path] = SOURCE_BYTES[path]
        self.interpreter = self.base / "python/python.exe"
        self.buffers[self.interpreter] = b"synthetic interpreter module, never executed"
        self.inputs["Watched"].append(dict(Path=str(self.interpreter), Sha256=sha(self.buffers[self.interpreter])))
        vector = bytes.fromhex("0010002001010008")
        twins = dict(Identical=True, Entry=0x08000101, VectorAddress=0x08000000, VectorBytes=vector.hex(),
            Segments=[dict(Vaddr=0x08000000, Paddr=0x08000000, FileSize=len(vector), MemorySize=len(vector),
                           Flags=5, Align=4, BytesSha256=sha(vector))])
        twin_path = self.root / "load-image.json"
        self.buffers[twin_path] = encoded(twins)
        self.result = dict(Status="PASS", Scope="NATIVE_CM3_O2_LTO_CAPTURE_FEASIBILITY_ONLY", Profile="CM3",
            Mode="O2-lto", Cohort=COHORT, Linkage="direct", TranslationUnits=9, SlimIRObjects=8,
            FinalExecutableLinks=2, SavedMachineObjects=2, RequiredCellsSatisfied=0, SeedBuild=str(self.seed),
            Interpreter=dict(ModulePath=str(self.interpreter), Sha256=sha(self.buffers[self.interpreter])),
            TwinLoadImagesPath=str(twin_path), TwinLoadImagesSha256=sha(self.buffers[twin_path]), TwinLoadImages=twins,
            Sources=[], Links=[], Commands=[dict(Status="PASS", Exit=0, TimedOut=False, Error=None,
                Label="synthetic producer record", Argv=["never-executed.exe"], Cwd=str(self.root))])
        for key in ("InputClosureVerified", "OutputSealVerified", "TwinLoadImageCompared", "TwinLoadImageIdentical",
                    "TwinAllocatedSectionsIdentical"):
            self.result[key] = True
        for key in ("FinalRootRelocationProof", "FinalReferenceParity", "SourceToMachineSemanticProof",
                    "OrdinaryOwnerContractSatisfied", "PolicyEquivalence", "CpuExecution", "BoardExecution",
                    "GlobalFreezeQualified", "ReferenceBuilt", "ArchiveExtraction", "RequiredCellSatisfied"):
            self.result[key] = False
        for index in range(9):
            source, obj = self.root / ("source-%d.c" % index), self.root / ("object-%d.o" % index)
            self.buffers[source], self.buffers[obj] = ("synthetic source %d" % index).encode("ascii"), b"synthetic object; not ELF"
            self.result["Sources"].append(dict(Source=str(source), SourceSha256=sha(self.buffers[source]),
                Object=str(obj), ObjectSha256=sha(self.buffers[obj])))
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
        if name != "cm3_lto_root_capture_utilities" or Path(path) != PROBE or data != SOURCE_BYTES[PROBE]:
            raise AssertionError("qualified captured parser/root import is outside pure envelope controls")
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
                patch.object(p, "checked_path", side_effect=lambda path, must_exist=True: Path(path).absolute()), \
                patch.object(p, "files_under", side_effect=self.files), patch.object(p, "save", side_effect=self.save), \
                patch.object(Path, "read_bytes", lambda path: self.buffers[self.regular(path)]), \
                patch.object(Path, "write_bytes", lambda path, data: self.buffers.__setitem__(Path(path), bytes(data))), \
                patch.object(Path, "exists", exists), patch.object(Path, "mkdir", mkdir), \
                patch("subprocess.Popen", side_effect=AssertionError("pure witness controls forbid process execution")):
            yield

    def construct(self):
        with self.active():
            return w.Witness(self.args)


class AdmissionTests(unittest.TestCase):
    def denied(self, fixture):
        with self.assertRaises((ValueError, FileNotFoundError)):
            fixture.construct()
        self.assertEqual(fixture.mkdir_calls, [])
        self.assertEqual([row[0] for row in fixture.load_calls], ["cm3_lto_root_capture_utilities"])

    def test_valid_synthetic_admission_loads_only_fixed_self_trusted_utilities(self):
        fixture = Fixture()
        witness = fixture.construct()
        self.assertEqual(witness.output, fixture.output)
        self.assertEqual(fixture.mkdir_calls, [])
        self.assertEqual(len(fixture.load_calls), 1)
        self.assertEqual(set(witness.buffers) - {WITNESS, NATIVE, MUTATIONS}, {PROBE, LOADER, fixture.core_path})
        self.assertEqual(witness.report["Interpreter"]["ModulePath"], str(fixture.interpreter))
        self.assertEqual(witness.report["Interpreter"]["Sha256"], sha(fixture.buffers[fixture.interpreter]))

    def test_wrong_caller_receipt_or_manifest_hash_rejects_before_qualified_import(self):
        for key in ("capture_receipt_sha256", "capture_artifacts_sha256"):
            fixture = Fixture()
            setattr(fixture.args, key, "0" * 64)
            with self.subTest(key=key):
                self.denied(fixture)

    def test_extra_or_missing_authenticated_artifact_membership_rejects(self):
        for extra in (False, True):
            fixture = Fixture()
            if extra:
                fixture.buffers[fixture.root / "not-in-manifest"] = b"extra"
            else:
                fixture.buffers.pop(fixture.root / "object-0.o")
            with self.subTest(extra=extra):
                self.denied(fixture)

    def test_self_trusted_utility_pin_is_checked_before_any_utility_import(self):
        fixture = Fixture()
        fixture.buffers[PROBE] += b"# changed utility\n"
        with self.assertRaisesRegex(ValueError, "fixed capture-admission utilities"):
            fixture.construct()
        self.assertEqual(fixture.load_calls, [])
        self.assertEqual(fixture.mkdir_calls, [])

    def test_manifest_cannot_rebind_the_caller_receipt_hash(self):
        fixture = Fixture()
        path = fixture.root / "artifacts.json"
        manifest = json.loads(fixture.buffers[path])
        manifest["Artifacts"]["results.json"] = "0" * 64
        fixture.buffers[path] = encoded(manifest)
        fixture.args.capture_artifacts_sha256 = sha(fixture.buffers[path])
        self.denied(fixture)

    def test_exact_profile_mode_scope_counts_and_ordered_links_are_required(self):
        for key, value in (("Status", "FAIL"), ("Profile", "CM4"), ("Mode", "O2"), ("Cohort", COHORT + "-foreign"),
                           ("Scope", "unrelated"), ("Linkage", "archive"), ("TranslationUnits", 8),
                           ("SlimIRObjects", 8.0), ("FinalExecutableLinks", True), ("SavedMachineObjects", 1)):
            fixture = Fixture()
            fixture.result[key] = value
            fixture.reseal()
            with self.subTest(key=key, value=value):
                self.denied(fixture)
        fixture = Fixture()
        fixture.result["Links"].reverse()
        fixture.reseal()
        self.denied(fixture)

    def test_true_closure_markers_cannot_be_truthy_aliases(self):
        for key in ("InputClosureVerified", "OutputSealVerified", "TwinLoadImageCompared", "TwinLoadImageIdentical",
                    "TwinAllocatedSectionsIdentical"):
            for value in (False, 1, None):
                fixture = Fixture()
                fixture.result[key] = value
                fixture.reseal()
                with self.subTest(key=key, value=value):
                    self.denied(fixture)

    def test_producer_promotions_and_boolean_required_count_reject(self):
        for key in ("FinalRootRelocationProof", "FinalReferenceParity", "SourceToMachineSemanticProof",
                    "OrdinaryOwnerContractSatisfied", "PolicyEquivalence", "CpuExecution", "BoardExecution",
                    "GlobalFreezeQualified", "ReferenceBuilt", "ArchiveExtraction", "RequiredCellSatisfied"):
            for value in (True, 0):
                fixture = Fixture()
                fixture.result[key] = value
                fixture.reseal()
                with self.subTest(key=key, value=value):
                    self.denied(fixture)
        fixture = Fixture()
        fixture.result["RequiredCellsSatisfied"] = False
        fixture.reseal()
        self.denied(fixture)

    def test_nonempty_source_and_successful_terminal_command_records_required(self):
        for change in ("sources", "commands", "pending", "exit", "timeout"):
            fixture = Fixture()
            if change == "sources":
                fixture.result["Sources"].pop()
            elif change == "commands":
                fixture.result["Commands"].clear()
            elif change == "pending":
                fixture.result["Commands"][0]["Status"] = "ATTEMPT"
            elif change == "exit":
                fixture.result["Commands"][0]["Exit"] = False
            else:
                fixture.result["Commands"][0]["TimedOut"] = True
            fixture.reseal()
            with self.subTest(change=change):
                self.denied(fixture)

    def test_duplicate_original_or_outside_capture_provider_rejects(self):
        fixture = Fixture()
        fixture.inputs["Files"].append(copy.deepcopy(fixture.inputs["Files"][0]))
        fixture.reseal()
        self.denied(fixture)
        fixture = Fixture()
        row = fixture.inputs["Files"][0]
        outside = fixture.base / "not-the-capture/probe.py"
        fixture.buffers[outside] = fixture.buffers[Path(row["Captured"])]
        row["Captured"] = str(outside)
        fixture.reseal()
        self.denied(fixture)

    def test_original_captured_and_watched_bytes_are_independently_closed(self):
        for target in ("original", "captured", "watched"):
            fixture = Fixture()
            row = fixture.inputs["Files"][1]
            path = Path(row["Original"] if target == "original" else row["Captured"])
            if target == "watched":
                path = fixture.interpreter
            fixture.buffers[path] += b"tampered"
            if target == "captured":
                fixture.reseal()
            with self.subTest(target=target):
                self.denied(fixture)

    def test_authenticated_but_foreign_loader_or_core_source_cannot_import(self):
        for original in (LOADER, None):
            fixture = Fixture()
            selected = fixture.core_path if original is None else original
            row = next(item for item in fixture.inputs["Files"] if item["Original"] == str(selected))
            changed = fixture.buffers[selected] + b"\n# foreign source\n"
            fixture.buffers[selected] = fixture.buffers[Path(row["Captured"])] = changed
            row["Sha256"] = sha(changed)
            next(item for item in fixture.inputs["Watched"] if item["Path"] == str(selected))["Sha256"] = sha(changed)
            fixture.reseal()
            with self.subTest(original=original):
                self.denied(fixture)

    def test_output_denials_use_authenticated_input_and_actual_interpreter_roots(self):
        fixture = Fixture()
        for output in (REPO / "new-output", fixture.root, fixture.root / "nested", fixture.base,
                       fixture.core_path.parent / "new-output", fixture.interpreter.parent / "new-output"):
            fixture = Fixture()
            fixture.args.output_dir = str(output)
            with self.subTest(output=output):
                self.denied(fixture)

    def test_current_interpreter_module_is_watched_even_if_not_a_producer_input(self):
        fixture = Fixture()
        fixture.interpreter = fixture.base / "current-runtime/python.exe"
        fixture.buffers[fixture.interpreter] = b"current interpreter module bytes"
        witness = fixture.construct()
        self.assertEqual(witness.report["Interpreter"]["ModulePath"], str(fixture.interpreter))
        self.assertEqual(witness.watch.hashes[fixture.interpreter], sha(fixture.buffers[fixture.interpreter]))
        fixture.args.output_dir = str(fixture.interpreter.parent / "new-output")
        fixture.load_calls.clear()
        self.denied(fixture)

    def test_twin_file_path_hash_and_value_all_bind_producer_record(self):
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


class ClosingTests(unittest.TestCase):
    def run_witness(self, fixture, *, root_error=None, on_close=None, after_roots=None):
        with fixture.active():
            witness = w.Witness(fixture.args)

            def roots():
                if root_error is not None:
                    raise root_error
                # This is a trusted-stage stub, not a fabricated reader/mutant receipt.
                witness.report["Roots"] = [dict(Name=name, Size=size, InstructionCount=count, SyntheticStageStub=True)
                                           for name, size, count, _ in MODEL]
                witness.report["Twins"] = copy.deepcopy(fixture.result["TwinLoadImages"])
                witness.report["PureRootStageStub"] = True
                watched = fixture.output / "synthetic-root-stage.json"
                witness.declare_output(watched)
                p.save(watched, dict(SyntheticStageStub=True, Roots=witness.report["Roots"]))
                witness.watch.read(watched, sha(fixture.buffers[watched]))
                diagnostic = fixture.output / "side-report.json"
                witness.declare_output(diagnostic)
                p.save(diagnostic, dict(SyntheticDiagnostic=True))
                if after_roots:
                    after_roots(witness, fixture)

            close, calls = witness.watch.close, 0

            def closing():
                nonlocal calls
                calls += 1
                if on_close:
                    on_close(calls, fixture)
                close()

            with patch.object(witness, "_read_roots", side_effect=roots) as reader, \
                    patch.object(witness.watch, "close", side_effect=closing):
                passed = witness.run()
            reader.assert_called_once()
            self.assertEqual([row[0] for row in fixture.load_calls], ["cm3_lto_root_capture_utilities"])
            return passed, witness

    def receipt(self, fixture, status, *, sealed=True):
        row = json.loads(fixture.buffers[fixture.output / "results.json"])
        self.assertEqual(row["Status"], status)
        self.assertIs(row["OutputSealVerified"], sealed)
        for key in ("SourceToMachineSemanticProof", "CanonicalProtocolValidated", "FinalReferenceParity",
                    "PolicyEquivalence", "CompleteObjectProof", "CpuExecution", "BoardExecution", "GlobalFreezeQualified"):
            self.assertIs(row[key], False)
        self.assertIs(type(row["RequiredCellsSatisfied"]), int)
        self.assertEqual(row["RequiredCellsSatisfied"], 0)
        if sealed:
            expected = {path.relative_to(fixture.output).as_posix(): sha(data) for path, data in fixture.buffers.items()
                        if path.is_relative_to(fixture.output) and path != fixture.output / "artifacts.json"}
            self.assertEqual(json.loads(fixture.buffers[fixture.output / "artifacts.json"]), {"Artifacts": expected})
        return row

    def test_successful_synthetic_envelope_seals_without_root_or_mutation_execution(self):
        fixture = Fixture()
        passed, witness = self.run_witness(fixture)
        self.assertIs(passed, True)
        row = self.receipt(fixture, "MACHINE-ROOT-WITNESS-PASS-NOT-QUALIFIED")
        self.assertIs(row["Qualification"], False)
        self.assertIs(row["InputClosureVerified"], True)
        self.assertEqual(row["UnexpectedOutputMembers"], [])
        self.assertEqual(row["MissingDeclaredOutputMembers"], [])
        self.assertEqual([root["Name"] for root in row["Roots"]], [name for name, *_ in MODEL])
        self.assertEqual(fixture.mkdir_calls, [fixture.output])
        self.assertEqual(row["ClosingFilesVerified"], len(witness.watch.hashes))

    def test_root_or_mutation_stage_failure_and_baseexception_cannot_promote(self):
        for error in (ValueError("synthetic reader rejection"), KeyboardInterrupt("synthetic stage interruption")):
            fixture = Fixture()
            with self.subTest(error=error):
                passed, _ = self.run_witness(fixture, root_error=error)
                self.assertIs(passed, False)
                row = self.receipt(fixture, "FAIL")
                self.assertIs(row["InputClosureVerified"], False)
                self.assertIn(str(error), row["Error"])
                self.assertEqual(set(fixture.save_statuses), {"FAIL"})

    def test_source_change_after_admission_cannot_finalize_success(self):
        fixture = Fixture()

        def change(witness, data):
            data.buffers[NATIVE] += b"# changed after admission\n"

        passed, _ = self.run_witness(fixture, after_roots=change)
        self.assertIs(passed, False)
        row = self.receipt(fixture, "FAIL")
        self.assertIs(row["InputClosureVerified"], False)
        self.assertIn("input hash mismatch", row["Error"])

    def test_generated_watched_file_changes_are_closed_before_initial_seal(self):
        fixture = Fixture()

        def change(witness, data):
            data.buffers[data.output / "synthetic-root-stage.json"] += b"changed"

        passed, _ = self.run_witness(fixture, after_roots=change)
        self.assertIs(passed, False)
        row = self.receipt(fixture, "FAIL")
        self.assertIn("input hash mismatch", row["Error"])
        self.assertEqual(set(fixture.save_statuses), {"FAIL"})

    def test_preseal_undeclared_output_cannot_become_successful_inventory(self):
        fixture = Fixture()

        def add(witness, data):
            data.buffers[data.output / "foreign-before-seal.json"] = b"foreign artifact"

        passed, _ = self.run_witness(fixture, after_roots=add)
        self.assertIs(passed, False)
        row = self.receipt(fixture, "FAIL")
        self.assertIs(row["InputClosureVerified"], False)
        self.assertEqual(row["UnexpectedOutputMembers"], ["foreign-before-seal.json"])
        self.assertEqual(row["MissingDeclaredOutputMembers"], [])
        self.assertIn("predetermined witness artifact membership", row["Error"])

    def test_preseal_missing_declared_output_cannot_finalize_success(self):
        fixture = Fixture()

        def omit(witness, data):
            witness.declare_output(data.output / "declared-but-missing.json")

        passed, _ = self.run_witness(fixture, after_roots=omit)
        self.assertIs(passed, False)
        row = self.receipt(fixture, "FAIL")
        self.assertIs(row["InputClosureVerified"], False)
        self.assertEqual(row["UnexpectedOutputMembers"], [])
        self.assertEqual(row["MissingDeclaredOutputMembers"], ["declared-but-missing.json"])
        self.assertIn("predetermined witness artifact membership", row["Error"])

    def test_add_change_or_delete_during_manifest_write_persists_consistent_failure(self):
        for change in ("add", "change", "delete"):
            fixture = Fixture()

            def fault(phase, path, attempt, buffers):
                if phase == "after" and path == fixture.output / "artifacts.json" and attempt == 1:
                    if change == "add":
                        buffers[fixture.output / "late.extra"] = b"late artifact"
                    elif change == "change":
                        buffers[fixture.output / "side-report.json"] += b"changed"
                    else:
                        del buffers[fixture.output / "side-report.json"]

            fixture.on_save = fault
            with self.subTest(change=change):
                passed, _ = self.run_witness(fixture)
                self.assertIs(passed, False)
                row = self.receipt(fixture, "FAIL")
                self.assertIn("closing:", row["Error"])
                self.assertIn("MACHINE-ROOT-WITNESS-PASS-NOT-QUALIFIED", fixture.save_statuses)

    def test_manifest_value_must_match_written_artifact_dictionary_not_only_its_hash(self):
        fixture = Fixture()

        def fault(phase, path, attempt, buffers):
            if phase == "after" and path == fixture.output / "artifacts.json" and attempt == 1:
                buffers[path] = encoded({"Artifacts": {}})

        fixture.on_save = fault
        passed, _ = self.run_witness(fixture)
        self.assertIs(passed, False)
        self.receipt(fixture, "FAIL")

    def test_one_time_manifest_write_failure_after_success_becomes_failure(self):
        fixture = Fixture()

        def fault(phase, path, attempt, buffers):
            if phase == "before" and path == fixture.output / "artifacts.json" and attempt == 1:
                raise OSError("synthetic manifest write failed")

        fixture.on_save = fault
        passed, _ = self.run_witness(fixture)
        self.assertIs(passed, False)
        row = self.receipt(fixture, "FAIL")
        self.assertIn("synthetic manifest write failed", row["Error"])

    def test_late_output_add_change_or_delete_downgrades_persisted_success(self):
        for change in ("add", "change", "delete"):
            fixture = Fixture()

            def fault(count, data):
                if count == 2:
                    target = data.output / "side-report.json"
                    if change == "add":
                        data.buffers[data.output / "late.extra"] = b"late artifact"
                    elif change == "change":
                        data.buffers[target] += b"late mutation"
                    else:
                        del data.buffers[target]

            with self.subTest(change=change):
                passed, _ = self.run_witness(fixture, on_close=fault)
                self.assertIs(passed, False)
                row = self.receipt(fixture, "FAIL")
                self.assertIn("late witness artifact membership/hash closure", row["Error"])

    def test_late_manifest_raw_byte_drift_is_not_hidden_by_equal_json(self):
        fixture = Fixture()

        def fault(count, data):
            if count == 2:
                data.buffers[data.output / "artifacts.json"] += b" \n"

        passed, _ = self.run_witness(fixture, on_close=fault)
        self.assertIs(passed, False)
        row = self.receipt(fixture, "FAIL")
        self.assertIn("late witness manifest drift", row["Error"])

    def test_late_input_rehash_failure_downgrades_persisted_success(self):
        fixture = Fixture()

        def fault(count, data):
            if count == 2:
                data.buffers[data.interpreter] += b"late module change"

        passed, _ = self.run_witness(fixture, on_close=fault)
        self.assertIs(passed, False)
        row = self.receipt(fixture, "FAIL")
        self.assertIs(row["InputClosureVerified"], False)
        self.assertIn("input hash mismatch", row["Error"])

    def test_permanent_manifest_write_failure_leaves_no_qualified_success(self):
        fixture = Fixture()

        def fault(phase, path, attempt, buffers):
            if phase == "before" and path == fixture.output / "artifacts.json":
                raise OSError("persistent manifest storage failure")

        fixture.on_save = fault
        passed, _ = self.run_witness(fixture)
        self.assertIs(passed, False)
        row = self.receipt(fixture, "FAIL", sealed=False)
        self.assertIn("persistent manifest storage failure", row["SealError"])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    output = args.output_dir.resolve()
    if output.exists() or output.is_relative_to(REPO) or not output.is_relative_to(Path(tempfile.gettempdir()).resolve()):
        parser.error("fresh external TEMP output directory required")
    report = dict(Status="FAIL", Tests=0, Failures=0, Errors=0, Skipped=0, SourceHashes={}, SourceDrift=[],
        Scope="PURE_SYNTHETIC_CM3_LTO_WITNESS_ENVELOPE_ONLY", SyntheticInputs=True, ActualELFTested=False,
        ActualMutationCasesTested=False, QualifiedCapturedParserExecuted=False, ToolInvocations=0, NativeCommandsExecuted=0,
        CanonicalProtocolValidated=False, SourceToMachineSemanticProof=False, PolicyEquivalence=False,
        CpuExecution=False, BoardExecution=False, RequiredCellsSatisfied=0, GlobalFreezeQualified=False)
    paths = [Path(__file__).resolve(), WITNESS, PROBE, LOADER, CORE, NATIVE, MUTATIONS]
    try:
        if sys.flags.optimize or not __debug__:
            raise ValueError("optimized Python unsupported")
        global SOURCE_BYTES, w, p, m
        SOURCE_BYTES = {path: path.read_bytes() for path in paths}
        report["SourceHashes"] = {str(path): sha(data) for path, data in SOURCE_BYTES.items()}
        with patch("subprocess.Popen", side_effect=AssertionError("pure controls cannot execute processes")):
            w = module("pure_cm3_lto_witness", WITNESS, SOURCE_BYTES[WITNESS])
            p = module("pure_cm3_lto_fixed_utilities", PROBE, SOURCE_BYTES[PROBE])
            m = module("pure_cm3_lto_private_lookup_utilities", MUTATIONS, SOURCE_BYTES[MUTATIONS])
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
