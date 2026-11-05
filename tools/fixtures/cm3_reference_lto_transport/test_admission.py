"""Bounded pure unit controls using fixed reference-seed metadata copies.

Filesystem, capture authority and qualified helper boundaries are mocked.
These controls do not execute Seed admission end to end, helpers or tools.
"""
import argparse
import ast
from contextlib import nullcontext
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
import tempfile
import traceback
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
ADMISSION = HERE / "admission.py"
SEED = Path("C:/fzfinal-cm3-reference-grid-20261104-e1/CM3-O2")
RECEIPT_SHA = "9B605CEC54DE39C55662B6AAA2FAC260647C54F63AC903890FB9717EE3C3C2EC"
MANIFEST_SHA = "A762CF954D7D9956A2F8D83DC3EC3B3A2620A3BF7759C27BDAACF399F5EDD6FC"
a = None
BUFFERS, METADATA = {}, {}


def sha(data):
    return hashlib.sha256(data).hexdigest().upper()


def need(condition, message):
    if not condition:
        raise ValueError(message)


def same(actual, expected, message):
    encode = lambda value: json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    need(encode(actual) == encode(expected), message)


def digest(value):
    need(type(value) is str and re.fullmatch(r"[A-F0-9]{64}", value) is not None, "literal SHA256")
    return value


def portable(value):
    need(type(value) is str and "\\" not in value and not Path(value).is_absolute()
         and value and all(part not in ("", ".", "..") for part in value.split("/")), "portable member")
    return Path(value)


def api():
    return SimpleNamespace(need=need, same=same, digest_text=digest, portable_name=portable, sha=sha,
        regular=a.stable_path, checked_path=lambda path, must_exist=True: a.stable_path(path), REPO=REPO,
        LINK_OPTIONS="-Wl,--gc-sections,--no-undefined,--fatal-warnings,--build-id=none,-z,noexecstack")


class Fixture:
    def __init__(self):
        self.seed = a.Seed.__new__(a.Seed)
        s = self.seed
        s.api, s.root = api(), SEED
        s.result = copy.deepcopy(METADATA["Result"])
        s.inputs = copy.deepcopy(METADATA["Inputs"])
        s.artifacts = copy.deepcopy(METADATA["Manifest"]["Artifacts"])
        s.originals = {Path(row["Original"]): row for row in s.inputs["Files"]}
        s.captures = {Path(row["Captured"]): row for row in s.inputs["Files"]}
        s.generated = s.inputs["Generated"]
        s.sources, s.commands = s.result["Sources"], s.result["Commands"]
        s.artifact, s.flags = s.result["CohortArtifact"], copy.deepcopy(METADATA["Result"]["CompileFlags"])
        s.fixture, s.script = SEED / "source" / a.FIXTURE, SEED / "source" / a.FIXTURE / "link.ld"
        s.validated_commands = set()
        gcc = next(row["Argv"][0] for row in s.commands if row["Label"] == "compiler version")
        s.gcc, s.tool_root = Path(gcc), Path(gcc).parent.parent
        self.payload = dict(BUFFERS)
        self.stdout_data = {}
        for index, command in enumerate(s.commands):
            label = command["Label"]
            if label.startswith("reference git show"):
                relative = command["Argv"][-1].split(":", 1)[1]
                data = BUFFERS[SEED / "reference-blobs" / relative]
            elif label == "reference git rev-parse":
                data = a.PIN.encode("ascii") + b"\n"
            elif label == "reference git status":
                data = b""
            elif label.startswith("resolve ") or label in ("compiler version", "compiler target"):
                data = BUFFERS[SEED / ("command-%04d.stdout" % index)]
            elif label.startswith("inspect "):
                data = b"synthetic inspector text"
            else:
                data = b"synthetic nonempty command output"
            self.stdout_data[index] = data
            self.payload[SEED / ("command-%04d.stdout" % index)] = data
            self.payload[SEED / ("command-%04d.stderr" % index)] = b""
        for row in s.result["ReferenceFileBindings"]:
            self.payload[Path(row["Original"])] = BUFFERS[Path(row["Captured"])]
        self.member_calls = []

        def member(path, expected=None):
            path = Path(path)
            self.member_calls.append((path, expected))
            return self.payload.get(path, b"synthetic inspector text")

        self.member = member
        s.member = Mock(side_effect=member)
        s.stdout = Mock(side_effect=lambda index: self.stdout_data[index])
        original_commands = copy.deepcopy(METADATA["Result"]["Commands"])
        s.closure = SimpleNamespace(
            structured=Mock(side_effect=lambda path, *args: copy.deepcopy(original_commands[int(Path(path).stem.split("-")[1])])),
            read=Mock(side_effect=lambda path, expected=None: self.payload.get(Path(path), b"mocked input authority")))
        s.inspect, s.distinct = Mock(), Mock()
        s.model = SimpleNamespace(require_attributes=Mock())
        self.config = METADATA["Result"]["ConfigText"]
        self.binding = dict(Flags=copy.deepcopy(s.flags), ConfigText="synthetic recipe config boundary", PortmacroProvider=a.PORTMACRO,
            ExtraIncludes=[], WitnessKind="none", ExactTargetRecipe=True,
            Differences=copy.deepcopy(METADATA["Result"]["RecipeDifferences"]))
        s.recipe = SimpleNamespace(reference_recipe=Mock(side_effect=lambda *args: copy.deepcopy(self.binding)))
        s.reference_recipe = SimpleNamespace(configuration_text=Mock(return_value=self.config), require_dependency_roles=Mock())
        s.inventory_gate = SimpleNamespace(inventory=SimpleNamespace(reference_bytes_match=self.reference_comparison))

    @staticmethod
    def reference_comparison(actual, blob):
        if actual == blob:
            return "exact"
        need(b"\r" not in blob and actual == blob.replace(b"\n", b"\r\n"), "noncanonical reference bytes")
        return "git-lf-worktree-crlf"

    def files(self, root):
        root = Path(root)
        if root == SEED / "freertos":
            return {row["Path"]: Path(row["Captured"]) for row in self.seed.result["ReferenceFileBindings"]}
        if root == self.seed.fixture:
            names = ("reference.h", "providers.c", "consumer.c", "startup.S", "link.ld", "FreeRTOSConfig.h", "freeze_base_FreeRTOSConfig.h")
            return {name: root / name for name in names}
        raise AssertionError("unexpected synthetic membership root")


class AdmissionTests(unittest.TestCase):
    def test_fixed_seed_and_caller_hashes_reject_before_authentication_or_mkdir(self):
        for field, value in (("reference_build", str(SEED.parent / "foreign")), ("reference_receipt_sha256", "0" * 64),
                              ("reference_artifacts_sha256", "0" * 64)):
            args = SimpleNamespace(reference_build=str(SEED), reference_receipt_sha256=RECEIPT_SHA,
                                   reference_artifacts_sha256=MANIFEST_SHA, output_dir=str(SEED.parent / "new-output"))
            setattr(args, field, value)
            host = api()
            closure = SimpleNamespace(structured=Mock(side_effect=AssertionError("caller must reject before authenticated reads")))
            host.Closure, host.load_buffer = Mock(return_value=closure), Mock()
            with self.subTest(field=field), patch.object(Path, "mkdir") as mkdir, self.assertRaises(ValueError):
                a.Seed(host, args)
            closure.structured.assert_not_called()
            host.load_buffer.assert_not_called()
            mkdir.assert_not_called()

    def test_correct_caller_reaches_authentication_not_qualified_helper_loading(self):
        host = api()
        closure = SimpleNamespace(structured=Mock(side_effect=ValueError("synthetic authentication rejection")))
        host.Closure, host.load_buffer = Mock(return_value=closure), Mock()
        args = SimpleNamespace(reference_build=str(SEED), reference_receipt_sha256=RECEIPT_SHA,
                               reference_artifacts_sha256=MANIFEST_SHA, output_dir=str(SEED.parent / "new-output"))
        with patch.object(Path, "mkdir") as mkdir, self.assertRaisesRegex(ValueError, "synthetic authentication rejection"):
            a.Seed(host, args)
        closure.structured.assert_called_once_with(SEED / "results.json", RECEIPT_SHA)
        host.load_buffer.assert_not_called()
        mkdir.assert_not_called()

    def test_output_denials_cover_both_overlap_directions_and_precede_helper_loading(self):
        fixture = Fixture()
        s = fixture.seed
        base = Path(tempfile.gettempdir()).absolute() / "reference-admission-memory-only"
        roots = {REPO, SEED, base / "inventory", base / "originals", base / "captures", base / "generated",
                 base / "tools", base / "interpreter", base / "reference"}
        with patch.object(Path, "exists", return_value=False), patch.object(Path, "mkdir") as mkdir:
            for root in roots:
                for output in (root, root / "nested", root.parent):
                    s.output = output
                    with self.subTest(root=root, output=output), self.assertRaises(ValueError):
                        s.deny_output(roots)
            s.output = base / "fresh-separate-output"
            s.deny_output(roots)
        mkdir.assert_not_called()
        tree = ast.parse(BUFFERS[ADMISSION], filename=str(ADMISSION))
        cls = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "Seed")
        init = next(node for node in cls.body if isinstance(node, ast.FunctionDef) and node.name == "__init__")
        calls = [node for node in ast.walk(init) if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)]
        denials = sorted((node for node in calls if node.func.attr == "deny_output"), key=lambda node: node.lineno)
        denied = [node.lineno for node in denials]
        loader = next(node.lineno for node in calls if node.func.attr == "load_buffer")
        self.assertEqual(len(denied), 2)
        self.assertLess(denied[0], loader)
        expressions = [{ast.unparse(node) for node in ast.walk(call.args[0])} for call in denials]
        self.assertTrue({"api.REPO", "self.root", "self.inventory", "self.originals", "self.captures", "self.generated"} <= expressions[0])
        self.assertTrue({"self.tool_root", "self.interpreter.parent", "self.reference_root", "loader_path.parent",
                         "api.__file__", "__file__"} <= expressions[1])
        self.assertFalse(any(node.func.attr in ("mkdir", "write_bytes", "write_text", "run", "Popen") for node in calls))

    def test_seed_scope_and_nonpromotion_flags_are_literal(self):
        fixture = Fixture()
        before = copy.deepcopy(fixture.seed.result)
        fixture.seed.validate_scope()
        self.assertEqual(fixture.seed.result, before)
        for key, value in (("GlobalFreezeQualified", True), ("FinalReferenceParity", True), ("CpuExecution", 0),
                           ("LTO", 0), ("RequiredCellsSatisfied", False), ("ReferenceBuilt", 1),
                           ("ArtifactSealVerified", 1), ("InputDrift", ["changed"]), ("Error", "failure")):
            fixture = Fixture()
            fixture.seed.result[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                fixture.seed.validate_scope()

    def test_wrong_profile_mode_cohort_pin_and_checkpoint_records_reject(self):
        for key, value in (("Profile", "CM4"), ("Mode", "Og"), ("Cohort", "foreign"), ("ReferenceCommit", "0" * 40),
                           ("SourceGroup", "CM0"), ("TranslationUnits", 5), ("FinalExecutableLinks", True)):
            fixture = Fixture()
            fixture.seed.result[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                fixture.seed.validate_scope()
        fixture = Fixture()
        fixture.seed.result["ObjectChecks"].reverse()
        with self.assertRaises(ValueError):
            fixture.seed.validate_scope()

    def test_command_metadata_accepts_git_config_c_but_requires_four_compiles(self):
        fixture = Fixture()
        with patch.object(Path, "glob", return_value=[]):
            fixture.seed.validate_commands()
        self.assertEqual(len(fixture.seed.workers), 6)
        self.assertGreater(sum("-c" in row["Argv"] for row in fixture.seed.commands), 4)
        for change in ("order", "missing-source"):
            fixture = Fixture()
            fixture.seed.result["Sources"] = list(reversed(fixture.seed.sources)) if change == "order" else fixture.seed.sources[:-1]
            with self.subTest(change=change), self.assertRaises(ValueError):
                fixture.seed.validate_commands()

    def test_terminal_and_saved_command_records_cannot_be_pending_or_bool_exit(self):
        for key, value in (("Status", "ATTEMPT"), ("Exit", False), ("TimedOut", True), ("Error", "failure"), ("Cwd", str(SEED.parent))):
            fixture = Fixture()
            fixture.seed.commands[0][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                fixture.seed.validate_commands()
        fixture = Fixture()
        fixture.seed.commands[0]["Argv"].append("foreign")
        with self.assertRaisesRegex(ValueError, "saved reference command"):
            fixture.seed.validate_commands()

    def test_full_source_flags_compile_argv_and_dependency_metadata_bindings(self):
        fixture = Fixture()
        fixture.seed.validate_sources()
        for change in ("flags", "object", "verified", "dependencies", "actual", "compile-argv"):
            fixture = Fixture()
            row = fixture.seed.sources[0]
            if change == "flags":
                row["CompileFlags"].append("-flto")
            elif change == "object":
                row["Object"] = fixture.seed.sources[1]["Object"]
            elif change == "verified":
                row["CompileDependenciesVerified"] = 1
            elif change == "dependencies":
                row["Dependencies"] = []
            elif change == "actual":
                row["ActualCompileDependencies"] = row["ActualCompileDependencies"][:-1]
            else:
                next(command for command in fixture.seed.commands if command["Label"] == "compile port.c")["Argv"].append("-O3")
            with self.subTest(change=change), self.assertRaises(ValueError):
                fixture.seed.validate_sources()

    def test_raw_dependency_targets_membership_and_empty_inputs_are_strict(self):
        fixture = Fixture()
        row = fixture.seed.sources[0]
        path = Path(row["CompileDependencyFile"])
        expected = {Path(item["Path"]) for item in row["Dependencies"]}
        self.assertEqual(fixture.seed.dependencies(path, 0), expected)
        for data in (b"reference-lto-source-0: C:/fake.h\n", b"pilot-source-0: \n", b"missing-separator"):
            fixture.payload[path] = data
            with self.subTest(data=data), self.assertRaises(ValueError):
                fixture.seed.dependencies(path, 0)
        original = BUFFERS[path]
        fixture.payload[path] = original + b" C:/not-declared-extra.h\n"
        with self.assertRaisesRegex(ValueError, "physical dependency membership"):
            fixture.seed.validate_sources()

    def test_reference_blob_roles_hashes_and_byte_comparison_records_bind(self):
        fixture = Fixture()
        with patch.object(fixture.seed.api, "files_under", side_effect=fixture.files, create=True):
            fixture.seed.validate_reference()
        for key, value in (("Captured", str(SEED / "foreign-port.c")), ("GitBlobSha256", "0" * 64),
                           ("ByteComparison", "semantic-equivalence"), ("WorktreeSha256", "0" * 64)):
            fixture = Fixture()
            fixture.seed.result["ReferenceFileBindings"][0][key] = value
            with self.subTest(key=key), patch.object(fixture.seed.api, "files_under", side_effect=fixture.files, create=True), self.assertRaises(ValueError):
                fixture.seed.validate_reference()

    def test_configuration_threshold_assertion_and_flags_are_not_overridden(self):
        fixture = Fixture()
        with patch.object(fixture.seed.api, "files_under", side_effect=fixture.files, create=True):
            fixture.seed.validate_recipe()
        for change in ("threshold", "flags", "assertion", "handler-check"):
            fixture = Fixture()
            if change == "threshold":
                fixture.seed.result["ConfigText"] = fixture.config.replace("16U", "128U")
            elif change == "flags":
                fixture.seed.result["CompileFlags"].append("-mfpu=fpv4-sp-d16")
            elif change == "assertion":
                path = fixture.seed.fixture / "freeze_base_FreeRTOSConfig.h"
                fixture.payload[path] = fixture.payload[path].replace(b"#define configASSERT(x)", b"#define disabledASSERT(x)")
            else:
                fixture.seed.result["ConfigText"] = fixture.config.replace("configCHECK_HANDLER_INSTALLATION 1", "configCHECK_HANDLER_INSTALLATION 0")
            with self.subTest(change=change), patch.object(fixture.seed.api, "files_under", side_effect=fixture.files, create=True), self.assertRaises(ValueError):
                fixture.seed.validate_recipe()

    def test_member_rejects_outside_path_and_row_hash_or_actual_byte_mismatch(self):
        seed = Fixture().seed
        path, data = SEED / "synthetic.bin", b"synthetic authenticated artifact"
        seed.artifacts = {"synthetic.bin": sha(data)}

        def read(selected, expected):
            need(sha(data) == expected, "actual bytes mismatch")
            return data

        seed.closure = SimpleNamespace(read=Mock(side_effect=read))
        self.assertEqual(a.Seed.member(seed, path, sha(data)), data)
        with self.assertRaises(ValueError):
            a.Seed.member(seed, SEED.parent / "outside.bin")
        with self.assertRaises(ValueError):
            a.Seed.member(seed, path, "0" * 64)
        seed.artifacts["synthetic.bin"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "actual bytes mismatch"):
            a.Seed.member(seed, path)

    def test_immutable_helper_lookup_is_lexical_and_unknown_read_has_no_disk_fallback(self):
        relative = a.CLASSIC + "run.py"
        source, foreign = SEED / "source" / relative, SEED / "source/unknown.py"
        for unknown in (False, True):
            seed = Fixture().seed
            seed.buffers = {source: b"synthetic captured helper bytes, never executed"}
            marker = object()

            def load(name, path):
                self.assertEqual(Path(path), source)
                selected = foreign if unknown else source.parent / "nonexistent" / ".." / source.name
                data = selected.read_bytes()
                self.assertEqual(data, seed.buffers[source])
                return marker

            seed.frozen = SimpleNamespace(active=lambda: nullcontext(), load=Mock(side_effect=load))
            with self.subTest(unknown=unknown), patch.object(Path, "resolve", side_effect=AssertionError("helper lookup must not resolve")), \
                    patch.object(Path, "read_bytes", side_effect=AssertionError("no disk fallback")):
                if unknown:
                    with self.assertRaisesRegex(ValueError, "outside authenticated immutable buffers"):
                        seed.module(relative)
                else:
                    self.assertIs(seed.module(relative), marker)

    def test_ordinary_inspector_sidecars_replace_suffix_not_append_new_capture_suffix(self):
        for path in (SEED / "objects/00-port.o", SEED / "ordinary.elf"):
            fixture = Fixture()
            a.Seed.inspect(fixture.seed, path)
            requested = [selected for selected, _ in fixture.member_calls]
            self.assertEqual(requested, [path.with_suffix(suffix) for suffix in (".dis", ".readelf", ".attributes", ".nm")])
            self.assertNotIn(Path(str(path) + ".dis"), requested)
            fixture.seed.model.require_attributes.assert_called_once_with("synthetic inspector text")

    def test_exact_link_argv_order_and_complete_command_consumption(self):
        fixture = Fixture()
        fixture.seed.validated_commands = {index for index, row in enumerate(fixture.seed.commands) if not row["Label"].startswith("link ")}
        fixture.seed.validate_links()
        for change in ("twins", "argv", "map", "unconsumed"):
            fixture = Fixture()
            fixture.seed.validated_commands = set(range(len(fixture.seed.commands)))
            if change == "twins":
                fixture.seed.result["Links"].reverse()
            elif change == "argv":
                next(row for row in fixture.seed.commands if row["Label"] == "link ordinary")["Argv"].append("-flto")
            elif change == "map":
                fixture.seed.result["Links"][1]["Map"] = fixture.seed.result["Links"][0]["Map"]
            else:
                fixture.seed.validated_commands.remove(0)
            with self.subTest(change=change), self.assertRaises(ValueError):
                fixture.seed.validate_links()


def unique(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def load_inputs():
    global BUFFERS, METADATA
    BUFFERS = {Path(__file__).resolve(): Path(__file__).read_bytes(), ADMISSION: ADMISSION.read_bytes()}
    for name, expected in (("results.json", RECEIPT_SHA), ("artifacts.json", MANIFEST_SHA)):
        path = SEED / name
        data = path.read_bytes()
        need(sha(data) == expected, "fixed seed metadata hash: " + name)
        BUFFERS[path] = data
    result = json.loads(BUFFERS[SEED / "results.json"], object_pairs_hook=unique)
    manifest = json.loads(BUFFERS[SEED / "artifacts.json"], object_pairs_hook=unique)
    same(manifest["Artifacts"]["results.json"], RECEIPT_SHA, "seed metadata receipt/manifest binding")

    def capture(path):
        path = Path(path)
        need(path.is_absolute() and path.is_relative_to(SEED) and ".." not in path.parts, "bounded selected metadata input")
        relative = path.relative_to(SEED).as_posix()
        data = path.read_bytes()
        need(sha(data) == digest(manifest["Artifacts"][relative]), "selected seed artifact hash: " + relative)
        BUFFERS[path] = data

    capture(SEED / "inputs.json")
    inputs = json.loads(BUFFERS[SEED / "inputs.json"], object_pairs_hook=unique)
    for row in result["ReferenceFileBindings"]:
        capture(row["Captured"])
        capture(row["GitBlob"])
    for row in result["Sources"]:
        capture(row["DiscoveryDependencyFile"])
        capture(row["CompileDependencyFile"])
    fixture = SEED / "source/tools/fixtures/cm3_final_image/reference"
    capture(fixture / "FreeRTOSConfig.h")
    capture(fixture / "freeze_base_FreeRTOSConfig.h")
    for index, command in enumerate(result["Commands"]):
        if command["Label"].startswith("resolve ") or command["Label"] in ("compiler version", "compiler target"):
            capture(SEED / ("command-%04d.stdout" % index))
    METADATA = dict(Result=result, Manifest=manifest, Inputs=inputs)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    output = args.output_dir.resolve()
    if output.exists() or output.is_relative_to(REPO) or not output.is_relative_to(Path(tempfile.gettempdir()).resolve()):
        parser.error("fresh external TEMP output directory required")
    report = dict(Status="FAIL", Tests=0, Failures=0, Errors=0, Skipped=0, SourceHashes={}, SourceDrift=[],
        Scope="PURE_CM3_REFERENCE_LTO_SEED_UNIT_CONTROLS_ONLY", CapturedMetadataUsed=True,
        PhysicalFilesystemMocked=True, ArtifactAuthorityMocked=True, PinnedUtilitiesMocked=True,
        FullSeedAdmissionExecuted=False, QualifiedHelpersExecuted=False, ActualELFTested=False,
        ToolInvocations=0, NativeCommandsExecuted=0, FinalReferenceParity=False, PolicyEquivalence=False,
        CpuExecution=False, BoardExecution=False, GlobalFreezeQualified=False, RequiredCellsSatisfied=0)
    try:
        if sys.flags.optimize or not __debug__:
            raise ValueError("optimized interpreter unsupported")
        load_inputs()
        report["SourceHashes"] = {str(path): sha(data) for path, data in BUFFERS.items()}
        global a
        spec = importlib.util.spec_from_file_location("pure_cm3_reference_lto_admission", ADMISSION)
        a = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = a
        with patch("subprocess.Popen", side_effect=AssertionError("pure admission controls cannot execute processes")):
            exec(compile(BUFFERS[ADMISSION], str(ADMISSION), "exec"), a.__dict__)
            suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
            count = suite.countTestCases()
            need(count > 0, "nonempty pure admission controls required")
            result = unittest.TextTestRunner(verbosity=2).run(suite)
        report.update(Tests=result.testsRun, Failures=len(result.failures), Errors=len(result.errors), Skipped=len(result.skipped),
            FailureDetails=[dict(Test=str(case), Detail=detail) for case, detail in result.failures + result.errors])
        report["SourceDrift"] = [str(path) for path, data in BUFFERS.items() if not path.is_file() or path.read_bytes() != data]
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
