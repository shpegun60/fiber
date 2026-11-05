"""Pure ordinary-capture controls; generated inputs and fake managed children only."""

import argparse
from contextlib import contextmanager, redirect_stderr, redirect_stdout
import copy
import hashlib
import importlib.util
import io
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
SUBJECT = REPO / "tools/freeze_capture.py"
REPLAY = REPO / "tools/freeze_replay.py"
CONTRACT = HERE / "CAPTURE_CONTRACT.md"
MANIFEST = REPO / "tools/freeze_cohorts.json"
INVENTORY = REPO / "tools/freeze_cohorts.py"
LOADER = HERE.with_name("cm3_final_roots") / "reference_witness.py"
RUNNER = HERE / "process_runner.py"
EXPECTED_METHODS = 12
subject = replay = manifest = None
MODES = ("O0", "Og", "O2", "Os", "O3")
PROFILES = {
    "CM0": ("cm0-cortex-m0-soft-nofpu-none-v0-mpu0-p2-b0-aapcs-default", "CM0", "cm0_final_image", "cm0_final_join"),
    "CM0PLUS": ("cm0-cortex-m0plus-soft-nofpu-none-v0-mpu0-p2-b0-aapcs-default", "CM0", "cm0_final_image", "cm0_final_join"),
    "CM0PLUSVTOR": ("cm0-cortex-m0plus-soft-nofpu-none-v1-mpu0-p2-b0-aapcs-default", "CM0", "cm0_final_image", "cm0_final_join"),
    "CM3": ("cm3-cortex-m3-soft-nofpu-none-v1-mpu0-p4-b16-aapcs-default", "CM3", "cm3_final_image", "cm3_final_join"),
    "CM4": ("cm4-cortex-m4-hard-fpu-eager-v1-mpu0-p4-b16-aapcs-default", "CM4", "classic_final_image", "classic_final_join"),
    "CM7": ("cm7-cortex-m7-hard-fpu-eager-v1-mpu0-p4-b16-aapcs-default", "CM7", "classic_final_image", "classic_final_join"),
}
STAGE_SOURCES = tuple(sorted({REPO / "tools/fixtures/classic_final_image/run.py",
    *(REPO / "tools/fixtures" / row[2] / "reference_run.py" for row in PROFILES.values()),
    *(REPO / "tools/fixtures" / row[3] / "join.py" for row in PROFILES.values())}))


def sha(data):
    return hashlib.sha256(data).hexdigest().upper()


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes((json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode("ascii"))
    return sha(path.read_bytes())


def request(*routes):
    return dict(SchemaVersion=1, Routes=list(routes or ("CM3/O2/direct",)))


def paths(root=None):
    root = Path(tempfile.gettempdir()).absolute() / "synthetic-capture-paths" if root is None else root
    return dict(gcc=root / "tools with spaces/gcc.exe", cmsis=root / "cmsis", git=root / "git/git.exe",
                freertos=root / "reference", python_modules=root / "modules", inventory=root / "inventory",
                case_dir=root / "cases/CM3-O2")


def producer(case_dir, stage):
    return dict(Build=str(case_dir / stage), ReceiptSha256=sha((stage + " receipt").encode("ascii")),
                ArtifactsSha256=sha((stage + " artifacts").encode("ascii")))


@contextmanager
def pure_calls():
    with patch("builtins.open", side_effect=AssertionError("pure API opened a file")), \
            patch.object(Path, "open", side_effect=AssertionError("pure API opened a path")), \
            patch.object(Path, "read_bytes", side_effect=AssertionError("pure API read a file")), \
            patch.object(Path, "write_bytes", side_effect=AssertionError("pure API wrote a file")), \
            patch.object(Path, "stat", side_effect=AssertionError("pure API inspected a path")), \
            patch.object(importlib.util, "spec_from_file_location", side_effect=AssertionError("pure API imported a helper")):
        yield


def arguments(argv):
    if type(argv) is not list or not argv or not all(type(item) is str for item in argv) or len(argv) % 2 != 1:
        raise AssertionError("fixed script followed by paired string flags required")
    values = dict(zip(argv[1::2], argv[2::2]))
    if len(values) * 2 + 1 != len(argv):
        raise AssertionError("duplicate generated stage flag")
    script = Path(argv[0])
    return script if script.is_absolute() else REPO / script, values


class PrepareFixture:
    """Synthetic upstream inventory admission, real local opening-file checks.

    No canonical 27-group qualification, FreeRTOS tree or real tool is supplied.
    Fixed producer/recipe imports are stubs; their algorithms are not tested here.
    """

    def __init__(self, root, selected=("CM3/O2/direct", "CM0/O0/direct")):
        self.root, self.selected = root, list(selected)
        self.values = paths(root / "inputs")
        self.values["gcc"] = root / "inputs/toolchain/arm-none-eabi-gcc.exe"
        for key in ("cmsis", "freertos", "python_modules", "inventory"):
            self.values[key].mkdir(parents=True)
        for path in (self.values["gcc"], self.values["git"], *(self.values["gcc"].with_name("arm-none-eabi-" + name + ".exe")
                for name in ("objdump", "readelf", "nm"))):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(("synthetic never-executed tool " + str(path)).encode("ascii"))
        (self.values["cmsis"] / "core_synthetic.h").write_bytes(b"/* synthetic CMSIS membership only */\n")
        package = self.values["python_modules"] / "elftools"
        package.mkdir()
        (package / "__init__.py").write_bytes(b"SYNTHETIC_ONLY = True\n")
        self.interpreter = root / "host/python.exe"
        self.interpreter.parent.mkdir()
        self.interpreter.write_bytes(b"synthetic interpreter; never executed")
        self.request = root / "request/request.json"
        request_sha = write_json(self.request, request(*selected))
        self.descriptor = dict(Build=str(self.values["inventory"]), ReceiptSha256="A" * 64, ArtifactsSha256="B" * 64)
        self.snapshot = dict(Bundle=dict(Root=self.values["inventory"], Descriptor=self.descriptor),
            SourceInventorySha256=sha(b"synthetic current inventory"), Manifest=copy.deepcopy(manifest),
            Required=dict(RequiredCells=[dict(Cohort=row["Cohort"], ArtifactRole="runtime", Representation="final",
                Mode=row["Mode"], Linkage="direct", SourceGroup=row["SourceGroup"])
                for row in (replay.route_for(route) for route in selected)]))
        self.args = SimpleNamespace(**{key: str(value) for key, value in self.values.items() if key != "case_dir"},
            inventory_receipt_sha256="A" * 64, inventory_artifacts_sha256="B" * 64,
            request=str(self.request), request_sha256=request_sha, output_dir=str(root / "output"))
        self.watch = replay.Closure()
        self.admission = SimpleNamespace(bundles={}, snapshots={})

        def snapshot(item, *, current=False):
            replay.same(item, self.descriptor, "synthetic inventory receipt binding")
            if current is not True:
                raise AssertionError("capture must admit current inventory, not historic evidence")
            self.watch.denied.add(self.values["inventory"])
            return self.snapshot

        self.admission.snapshot = Mock(side_effect=snapshot)
        self.api = SimpleNamespace(**{name: getattr(replay, name) for name in (
            "Rejected", "routes", "checked_path", "digest", "structured", "files_under", "relative_name",
            "_cell_key", "_selection_key", "LOADER", "BOOTSTRAP", "Dispatcher", "gate_arguments")})
        self.api.SOURCE_PINS = {name: value for name, value in replay.SOURCE_PINS.items()
            if name == subject.RUNNER or REPO / name in STAGE_SOURCES}
        self.api.Closure = Mock(return_value=self.watch)
        self.api.Admission = Mock(return_value=self.admission)
        self.api.interpreter_path = Mock(return_value=self.interpreter)
        self.api.process_environment = Mock(return_value={})
        self.api.fixed_module = Mock(side_effect=lambda *args: SimpleNamespace())

    def rewrite_request(self, value=None):
        self.args.request_sha256 = write_json(self.request, request(*self.selected) if value is None else value)

    @contextmanager
    def active(self):
        with patch.object(subject, "pinned_replay", return_value=(self.api, REPLAY.read_bytes())):
            yield


def batch_fixture(root, failure="valid"):
    """Exercise real orchestration/seals, stubbing producer semantic admission.

    These invented child reports are deliberately not valid ELF proof receipts.
    A real capture must use its unchanged _audit; no helper globals are patched.
    """
    fixture = PrepareFixture(root, ("CM3/O2/direct", "CM0/O0/direct", "CM7/Os/direct"))
    with fixture.active():
        capture = subject.prepare(fixture.args)
    calls = []

    def fake_run(argv, *, cwd, env, timeout):
        ordinal = len(calls)
        calls.append(list(argv))
        route = fixture.selected[ordinal // 3]
        side = ("Native", "Reference", "Join")[ordinal % 3]
        label = route + ":" + side
        attempt = json.loads((capture.output / ("commands/%03d.json" % ordinal)).read_bytes())
        if attempt["State"] != "ATTEMPT" or attempt["Label"] != label:
            raise AssertionError("stage attempt must be durable and in Native/Reference/Join order")
        if cwd != str(capture.output) or env != capture.environment or timeout != 900:
            raise AssertionError("fixed managed runner fields")
        if ordinal // 3 == 1 and failure in ("fail-" + side, "primary-plus-closing"):
            if failure == "primary-plus-closing":
                capture._close_inputs = Mock(side_effect=subject.Rejected("synthetic secondary closing cause"))
            return SimpleNamespace(stdout=b"PASS cannot promote exit 1\n", stderr=b"synthetic original stage cause",
                                   returncode=1, timed_out=False, elapsed=0.0)
        output = Path(argv[argv.index("--output-dir") + 1])
        output.mkdir(parents=True)
        for row in capture.aliases:
            path = Path(row["Copy"])
            if path.is_relative_to(output):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(capture.opening_buffers[Path(row["Original"])])
        if failure == "alias-bytes" and ordinal == 3:
            alias = next(Path(row["Copy"]) for row in capture.aliases if Path(row["Copy"]).is_relative_to(output))
            alias.write_bytes(b"foreign bytes despite a consistent child artifact seal\n")
        trace = dict(SourceSnapshotSha256=capture.source_snapshot_sha, Entry=argv[8], ExitCode=0,
                     Executed=[dict(Path=argv[8], Sha256=capture.sources[argv[8]]["Sha256"])])
        write_json(Path(argv[9]), trace)
        if failure == "missing-report" and ordinal == 3:
            return SimpleNamespace(stdout=b"PASS\n", stderr=b"", returncode=0, timed_out=False, elapsed=0.0)
        write_json(output / "results.json", dict(SyntheticOnly=True, Route=route, Stage=side))
        members = {path.relative_to(output).as_posix(): sha(path.read_bytes()) for path in output.rglob("*") if path.is_file()}
        write_json(output / "artifacts.json", dict(Artifacts=members))
        if failure == "bad-manifest" and ordinal == 3:
            (output / "artifacts.json").write_bytes(b"{}\n")
        elif failure == "late-tool" and ordinal == 3:
            Path(fixture.args.gcc).write_bytes(b"changed opening compiler bytes")
        elif failure == "late-parser-member" and ordinal == 3:
            (Path(fixture.args.python_modules) / "elftools/late.py").write_bytes(b"EXTRA = True\n")
        return SimpleNamespace(stdout=b"synthetic child only\n", stderr=b"", returncode=0, timed_out=False, elapsed=0.0)

    def synthetic_audit(case, side, case_dir):
        # Only semantic proof admission is stubbed. Real Closure.tree binds all
        # generated bytes and memberships, and _actual_aliases stays unchanged.
        root = case_dir / side
        raw = capture.watch.read(root / "results.json")
        result = replay.structured(raw)
        if result != dict(SyntheticOnly=True, Route=case["Route"], Stage=side):
            raise AssertionError("synthetic child identity")
        raw_manifest = capture.watch.read(root / "artifacts.json")
        manifest = replay.structured(raw_manifest)
        if type(manifest) is not dict or set(manifest) != {"Artifacts"}:
            raise subject.Rejected("synthetic malformed child manifest")
        members = manifest["Artifacts"]
        if members.get("results.json") != sha(raw):
            raise subject.Rejected("synthetic child receipt/manifest binding")
        capture.watch.tree(root, dict(members, **{"artifacts.json": sha(raw_manifest)}))
        descriptor = dict(Build=str(root), ReceiptSha256=sha(raw), ArtifactsSha256=sha(raw_manifest))
        for relative, value in dict(members, **{"artifacts.json": sha(raw_manifest)}).items():
            path = root / relative
            name = path.relative_to(capture.output).as_posix()
            capture.expected[name] = value
            capture.output_identities[name] = capture.watch.identities[path]
        case["Descriptors"][side] = descriptor
        cm0 = case["Profile"].startswith("CM0")
        case["Audits"][side] = (dict(ClosedBodies=8 if cm0 else 6, Mechanisms=3, ToolCommands=0) if side == "Join" else
            dict(TranslationUnits=9 if side == "Native" else 5 if cm0 else 4, Links=2, Checkpoints=7,
                 ToolCommands=73 if side == "Native" else 79 if cm0 else 71))
        return set()

    capture.runner = SimpleNamespace(run=Mock(side_effect=fake_run))
    capture._audit = synthetic_audit
    execute_case = capture._execute_case

    def execute_and_tamper(case):
        execute_case(case)
        if failure == "late-output" and len(capture.completed) == 3:
            (capture.output / "unexpected.bin").write_bytes(b"unplanned output")

    capture._execute_case = execute_and_tamper
    if failure == "receipt-substitution":
        original_json = capture._json

        def substituted_json(name, value):
            path = original_json(name, value)
            if name == "results.json" and value.get("Status") == "PASS":
                path.write_bytes(b'{"Status":"PASS","foreign":true}\n')
            return path

        capture._json = substituted_json
    return capture, fixture, calls


class CaptureTests(unittest.TestCase):
    def test_exact_thirty_routes_are_fresh_closed_ordinary_records(self):
        with pure_calls():
            actual = subject.routes()
            self.assertEqual(set(actual), {profile + "/" + mode + "/direct" for profile in PROFILES for mode in MODES})
            for profile, (cohort, group, _, join) in PROFILES.items():
                for mode in MODES:
                    identity = profile + "/" + mode + "/direct"
                    self.assertEqual(actual[identity], dict(Profile=profile, Mode=mode, Linkage="direct", Cohort=cohort,
                        SourceGroup=group, ArtifactRole="runtime", Gate="tools/fixtures/" + join + "/join.py"))
            actual["CM3/O2/direct"]["Mode"] = "foreign"
            self.assertEqual(subject.routes()["CM3/O2/direct"]["Mode"], "O2")

    def test_request_detached_ordered_routes_without_discovery(self):
        value = request("CM7/O3/direct", "CM0PLUSVTOR/O0/direct", "CM3/Os/direct")
        original = copy.deepcopy(value)
        with pure_calls():
            result = subject.validate_request(value)
        self.assertIs(type(result), list)
        self.assertEqual(result, value["Routes"])
        result.append("CM4/Og/direct")
        self.assertEqual(value, original)

    def test_request_rejects_alias_types_duplicates_and_arbitrary_execution(self):
        invalid = [None, True, 1, [], {}, dict(SchemaVersion=True, Routes=["CM3/O2/direct"]),
                   dict(SchemaVersion=1.0, Routes=["CM3/O2/direct"]), dict(SchemaVersion="1", Routes=["CM3/O2/direct"]),
                   dict(SchemaVersion=1, Routes=[]), dict(SchemaVersion=1, Routes="CM3/O2/direct"),
                   dict(SchemaVersion=1, Routes=("CM3/O2/direct",)), dict(SchemaVersion=1, Routes=[True])]
        for extra in ("Command", "Argv", "Script", "Native", "PriorJoin", "Tools", "routes", "schemaversion"):
            value = request()
            value[extra] = ["arbitrary.exe"]
            invalid.append(value)
        invalid.append(request("CM3/O2/direct", "CM3/O2/direct"))
        for route in ("cm3/O2/direct", "CM3/o2/direct", "CM3/O2/archive", "CM3/O2-lto/direct", "CM3/Os-lto/direct",
                      "CM3/O2-lto/archive", "CM0PLUS/Os/Direct", "../../foreign.py", "CM3/O2/direct\0", "CM3/O2/direct --gcc evil"):
            invalid.append(request(route))
        with pure_calls():
            for index, value in enumerate(invalid):
                with self.subTest(case=index), self.assertRaises(subject.Rejected):
                    subject.validate_request(value)

    def test_native_stage_has_only_caller_tools_and_exact_profile_mode(self):
        selected = paths()
        for profile in PROFILES:
            for mode in MODES:
                identity = profile + "/" + mode + "/direct"
                with self.subTest(route=identity), pure_calls():
                    script, flags = arguments(subject.stage_arguments(identity, "Native", **selected))
                self.assertEqual(script, REPO / "tools/fixtures/classic_final_image/run.py")
                self.assertEqual(flags, {"--gcc": str(selected["gcc"]), "--cmsis": str(selected["cmsis"]),
                    "--python-modules": str(selected["python_modules"]), "--inventory": str(selected["inventory"]),
                    "--profile": profile, "--mode": mode, "--output-dir": str(selected["case_dir"] / "Native")})

    def test_reference_stage_selects_only_fixed_three_family_producers(self):
        selected = paths()
        for profile, (_, _, reference, _) in PROFILES.items():
            for mode in MODES:
                with self.subTest(profile=profile, mode=mode), pure_calls():
                    script, flags = arguments(subject.stage_arguments(profile + "/" + mode + "/direct", "Reference", **selected))
                self.assertEqual(script, REPO / "tools/fixtures" / reference / "reference_run.py")
                self.assertEqual(flags, {"--gcc": str(selected["gcc"]), "--git": str(selected["git"]),
                    "--freertos": str(selected["freertos"]), "--python-modules": str(selected["python_modules"]),
                    "--inventory": str(selected["inventory"]), "--profile": profile, "--mode": mode,
                    "--output-dir": str(selected["case_dir"] / "Reference")})

    def test_join_argv_binds_both_completed_producer_descriptors(self):
        selected = paths()
        native, reference = (producer(selected["case_dir"], stage) for stage in ("Native", "Reference"))
        before = copy.deepcopy((native, reference))
        for profile, (_, _, _, family) in PROFILES.items():
            for mode in MODES:
                with self.subTest(profile=profile, mode=mode), pure_calls():
                    script, flags = arguments(subject.stage_arguments(profile + "/" + mode + "/direct", "Join",
                        **selected, native=native, reference=reference))
                expected = {"--profile": profile, "--mode": mode, "--output-dir": str(selected["case_dir"] / "Join")}
                for role, value in (("native", native), ("reference", reference)):
                    expected.update({"--" + role + "-" + suffix: value[field] for suffix, field in
                        (("build", "Build"), ("receipt-sha256", "ReceiptSha256"), ("artifacts-sha256", "ArtifactsSha256"))})
                self.assertEqual(script, REPO / "tools/fixtures" / family / "join.py")
                self.assertEqual(flags, expected)
        self.assertEqual((native, reference), before)

    def test_stage_rejects_unknown_routes_stages_and_misplaced_descriptors(self):
        selected = paths()
        native, reference = (producer(selected["case_dir"], stage) for stage in ("Native", "Reference"))
        cases = [("CM3/O2-lto/direct", "Native", {}), ("CM3/O2/archive", "Join", dict(native=native, reference=reference))]
        for stage in (True, 1, None, "native", "Compile", "Join --command evil", "../../evil.py"):
            cases.append(("CM3/O2/direct", stage, {}))
        for stage in ("Native", "Reference"):
            cases.extend(("CM3/O2/direct", stage, values) for values in (dict(native=native), dict(reference=reference),
                                                                                     dict(native=native, reference=reference)))
        cases.extend(("CM3/O2/direct", "Join", values) for values in ({}, dict(native=native), dict(reference=reference)))
        with pure_calls():
            for index, (route, stage, values) in enumerate(cases):
                with self.subTest(case=index), self.assertRaises(subject.Rejected):
                    subject.stage_arguments(route, stage, **selected, **values)

    def test_scope_is_fresh_fail_default_and_literal_zero_not_boolean(self):
        with pure_calls():
            report, other = subject.scope_report(), subject.scope_report()
        self.assertEqual(report["Status"], "FAIL")
        self.assertIs(report["CatalogReady"], False)
        self.assertEqual(report["Cases"], [])
        self.assertEqual(report["Pending"], [])
        for key in ("RequiredCellSatisfied", "CompleteObjectProof", "FullABIProof", "APIProof", "FinalReferenceParity",
                    "InstructionEquivalence", "PolicyEquivalence", "CpuExecution", "BoardExecution", "GlobalFreezeQualified"):
            self.assertIs(report[key], False)
        self.assertIs(type(report["RequiredCellsSatisfied"]), int)
        self.assertEqual(report["RequiredCellsSatisfied"], 0)
        report["Cases"].append("mutation")
        report["Pending"].append("mutation")
        self.assertEqual(other["Cases"], [])
        self.assertEqual(other["Pending"], [])

    def test_cli_requires_all_eleven_inputs_and_rejects_discovery_override(self):
        root = Path(tempfile.gettempdir()).absolute() / "synthetic-capture-cli"
        values = dict(gcc=str(root / "tools/gcc.exe"), cmsis=str(root / "cmsis"), git=str(root / "git/git.exe"),
            freertos=str(root / "freertos"), python_modules=str(root / "modules"), inventory=str(root / "inventory"),
            inventory_receipt_sha256="A" * 64, inventory_artifacts_sha256="B" * 64,
            request=str(root / "request.json"), request_sha256="C" * 64, output_dir=str(root / "fresh"))
        full = [arg for key, value in values.items() for arg in ("--" + key.replace("_", "-"), value)]
        for key in values:
            flag = "--" + key.replace("_", "-")
            index = full.index(flag)
            argv = full[:index] + full[index + 2:]
            with self.subTest(missing=key), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()), \
                    patch.object(subject, "prepare") as prepare:
                with self.assertRaises(SystemExit) as error:
                    subject.main(argv)
                self.assertEqual(error.exception.code, 2)
                prepare.assert_not_called()
        for extra in ("--old-inputs", "--prior-join", "--command", "--python", "--native-build", "--recipe"):
            with self.subTest(extra=extra), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()), \
                    patch.object(subject, "prepare") as prepare:
                with self.assertRaises(SystemExit) as error:
                    subject.main(full + [extra, "foreign"])
                self.assertEqual(error.exception.code, 2)
                prepare.assert_not_called()

    def test_prepare_authenticates_explicit_inputs_without_output_or_old_receipts(self):
        with tempfile.TemporaryDirectory(prefix="pure-capture-admission-") as temporary:
            root = Path(temporary).resolve()
            for case in ("valid", "request-hash", "inventory-hash", "duplicate-json", "non-ascii", "extra-command",
                         "wrong-cohort", "role-hardlink", "source-hardlink", "output-existing", "output-repo",
                         "output-tool", "output-inventory", "output-request", "output-reference", "output-cmsis", "output-parser"):
                with self.subTest(case=case):
                    directory = root / case
                    directory.mkdir()
                    fixture = PrepareFixture(directory)
                    if case == "request-hash":
                        fixture.args.request_sha256 = "0" * 64
                    elif case == "inventory-hash":
                        fixture.args.inventory_receipt_sha256 = "0" * 64
                    elif case in ("duplicate-json", "non-ascii"):
                        raw = (b'{"SchemaVersion":1,"SchemaVersion":1,"Routes":["CM3/O2/direct"]}' if case == "duplicate-json"
                               else '{"SchemaVersion":1,"Routes":["CM3/O2/direct"],"note":"\\u00e9"}'.replace("\\u00e9", "\u00e9").encode("utf-8"))
                        fixture.request.write_bytes(raw)
                        fixture.args.request_sha256 = sha(raw)
                    elif case == "extra-command":
                        fixture.rewrite_request(dict(request(), Command=["foreign.exe"]))
                    elif case == "wrong-cohort":
                        fixture.snapshot["Required"]["RequiredCells"][0]["Cohort"] = "foreign"
                    elif case in ("role-hardlink", "source-hardlink"):
                        git = Path(fixture.args.git)
                        git.unlink()
                        original = Path(fixture.args.gcc)
                        if case == "source-hardlink":
                            original = directory / "synthetic_source.py"
                            original.write_bytes(b"VALUE = 1\n")
                            fixture.api.SOURCE_PINS[str(original)] = sha(original.read_bytes())
                        git.hardlink_to(original)
                    elif case == "output-existing":
                        Path(fixture.args.output_dir).mkdir()
                    elif case.startswith("output-"):
                        name = case.removeprefix("output-")
                        parent = dict(repo=REPO, tool=Path(fixture.args.gcc).parent, inventory=Path(fixture.args.inventory),
                            request=fixture.request.parent, reference=Path(fixture.args.freertos), cmsis=Path(fixture.args.cmsis),
                            parser=Path(fixture.args.python_modules))[name]
                        fixture.args.output_dir = str(parent / "must-not-create")
                    before = Path(fixture.args.output_dir).exists()
                    with fixture.active(), patch.object(Path, "mkdir", side_effect=AssertionError("prepare cannot create output")):
                        if case == "valid":
                            capture = subject.prepare(fixture.args)
                            self.assertEqual(capture.request, fixture.selected)
                            self.assertEqual(capture.report["Counts"]["Cases"], 0)
                            self.assertIs(capture.report["CatalogReady"], False)
                            self.assertEqual(capture.commands, [])
                            self.assertEqual(capture.expected, {})
                            self.assertEqual(set(capture.tools), {"gcc", "git", "objdump", "readelf", "nm"})
                            for name, path in capture.tools.items():
                                self.assertEqual(capture.report["ToolInputs"][name]["Path"], str(path))
                                self.assertEqual(capture.report["ToolInputs"][name]["Sha256"], sha(path.read_bytes()))
                            fixture.admission.snapshot.assert_called_once_with(fixture.descriptor, current=True)
                        else:
                            with self.assertRaises((subject.Rejected, replay.Rejected, OSError)):
                                subject.prepare(fixture.args)
                    self.assertEqual(Path(fixture.args.output_dir).exists(), before)

    def test_command_attempt_terminal_bytes_typed_results_and_no_arbitrary_child(self):
        with tempfile.TemporaryDirectory(prefix="pure-capture-command-") as temporary:
            root = Path(temporary).resolve()
            cases = ("valid", "runner-error", "exit-one", "bool-exit", "int-timeout", "timed-out", "cleanup",
                     "bool-seconds", "nan-seconds", "negative-seconds", "exit-one-terminal-write",
                     "runner-error-terminal-write", "success-terminal-write")
            for case in cases:
                with self.subTest(case=case):
                    directory = root / case
                    directory.mkdir()
                    fixture = PrepareFixture(directory)
                    with fixture.active():
                        capture = subject.prepare(fixture.args)
                    argv = [str(fixture.interpreter), "-I", "-S", "-B", "-c", replay.BOOTSTRAP,
                            "synthetic-snapshot", "A" * 64, "synthetic-entry", "synthetic-trace"]

                    def fake_run(actual, *, cwd, env, timeout):
                        attempt = json.loads((capture.output / "commands/000.json").read_bytes())
                        self.assertEqual(attempt["State"], "ATTEMPT")
                        self.assertEqual(attempt["Argv"], argv)
                        self.assertEqual(cwd, str(capture.output))
                        self.assertEqual(env, capture.environment)
                        self.assertEqual(timeout, 900)
                        if case in ("runner-error", "runner-error-terminal-write"):
                            raise RuntimeError("synthetic managed failure")
                        result = SimpleNamespace(stdout=b"PASS text is not authority\n", stderr=b"", returncode=0,
                                                 timed_out=False, elapsed=0.0)
                        if case in ("exit-one", "exit-one-terminal-write", "bool-exit"):
                            result.returncode = False if case == "bool-exit" else 1
                        elif case in ("timed-out", "int-timeout"):
                            result.timed_out = True if case == "timed-out" else 0
                        elif case == "cleanup":
                            result.returncode, result.stderr = 125, b"[process-runner] synthetic cleanup failure"
                        elif case in ("bool-seconds", "nan-seconds", "negative-seconds"):
                            result.elapsed = {"bool-seconds": False, "nan-seconds": float("nan"), "negative-seconds": -1.0}[case]
                        return result

                    capture.runner = SimpleNamespace(run=Mock(side_effect=fake_run))
                    journal_failure = case.endswith("terminal-write")
                    failed_writes = []
                    original_write = capture._write

                    def write_with_one_failure(name, raw):
                        if journal_failure and name == "commands/000.stdout" and not failed_writes:
                            failed_writes.append(name)
                            raise OSError("synthetic terminal stdout journal failure")
                        return original_write(name, raw)

                    capture._write = write_with_one_failure
                    if case == "valid":
                        capture.command(argv, "CM3/O2/direct:Native")
                    else:
                        expected = RuntimeError if case in ("runner-error", "runner-error-terminal-write") else subject.Rejected
                        with self.assertRaises(expected) as caught:
                            capture.command(argv, "CM3/O2/direct:Native")
                        if journal_failure:
                            if case == "success-terminal-write":
                                self.assertEqual(str(caught.exception), "freeze-capture: terminal journal persistence failed: "
                                    "terminal journal commands/000.stdout: OSError: synthetic terminal stdout journal failure")
                            # This is the real run -> finish(error) handoff, not
                            # the existing later _close_inputs failure control.
                            self.assertIs(capture.finish(caught.exception), False)
                            self.assertEqual(failed_writes, ["commands/000.stdout"])
                            self.assertEqual(capture.report["Status"], "FAIL")
                            self.assertIs(capture.report["CatalogReady"], False)
                            self.assertEqual(capture.report["Error"], capture.report["PrimaryError"])
                            if case == "success-terminal-write":
                                self.assertIn("synthetic terminal stdout journal failure", capture.report["PrimaryError"])
                            else:
                                primary = ("RuntimeError: synthetic managed failure" if case == "runner-error-terminal-write"
                                           else "Rejected: freeze-capture: failed stage: CM3/O2/direct:Native")
                                self.assertEqual(capture.report["PrimaryError"], primary)
                                self.assertTrue(any("synthetic terminal stdout journal failure" in message
                                    for message in capture.report["ClosingErrors"]))
                    capture.runner.run.assert_called_once()
                    record = json.loads((capture.output / "commands/000.json").read_bytes())
                    self.assertEqual(record["State"], "TERMINAL")
                    self.assertEqual(record["Status"], "PASS" if case == "valid" else "FAIL")
                    for field in ("Stdout", "Stderr"):
                        path = capture.output / record[field]
                        if journal_failure and field == "Stdout" and not path.exists():
                            self.assertEqual(failed_writes, [record[field]])
                        else:
                            self.assertEqual(sha(path.read_bytes()), record[field + "Sha256"])
                    self.assertEqual(json.loads((capture.output / "commands.json").read_bytes()), [record])
                    if case in ("runner-error", "runner-error-terminal-write"):
                        self.assertIn("synthetic managed failure", record["Error"])
                    elif case == "exit-one-terminal-write":
                        self.assertIn("failed stage: CM3/O2/direct:Native", record["Error"])
            directory = root / "refused"
            directory.mkdir()
            fixture = PrepareFixture(directory)
            with fixture.active():
                capture = subject.prepare(fixture.args)
            capture.runner = SimpleNamespace(run=Mock(side_effect=AssertionError("refused command must not reach runner")))
            valid = [str(fixture.interpreter), "-I", "-S", "-B", "-c", replay.BOOTSTRAP]
            invalid = [(["arbitrary.exe"], "CM3/O2/direct:Native", 900),
                (valid, "CM3/O2/direct:Native --command evil", 900), (valid, "CM7/O2/direct:Native", 900)]
            invalid.extend((valid, "CM3/O2/direct:Native", timeout) for timeout in (True, 0, 901, 1.0))
            for argv, label, timeout in invalid:
                with self.subTest(refused_label=label, timeout=timeout), self.assertRaises(subject.Rejected):
                    capture.command(argv, label, timeout=timeout)
            capture.runner.run.assert_not_called()
            self.assertFalse(capture.output.exists())

    def test_batch_fresh_bindings_fail_stop_pending_catalog_and_late_nonpromotion(self):
        with tempfile.TemporaryDirectory(prefix="pure-capture-batch-") as temporary:
            root = Path(temporary).resolve()
            for failure in ("valid", "fail-Native", "fail-Reference", "fail-Join", "primary-plus-closing", "missing-report",
                            "bad-manifest", "alias-bytes", "late-tool", "late-parser-member", "late-output", "receipt-substitution"):
                with self.subTest(case=failure):
                    directory = root / failure
                    directory.mkdir()
                    capture, fixture, calls = batch_fixture(directory, failure)
                    success = capture.run()
                    self.assertIs(success, failure == "valid", capture.report.get("Error"))
                    report = json.loads((capture.output / "results.json").read_bytes())
                    pending = json.loads((capture.output / "pending.json").read_bytes())
                    catalog = json.loads((capture.output / "catalog.json").read_bytes())
                    members = json.loads((capture.output / "artifacts.json").read_bytes())["Artifacts"]
                    self.assertEqual(set(members), {path.relative_to(capture.output).as_posix() for path in capture.output.rglob("*")
                        if path.is_file() and path != capture.output / "artifacts.json"})
                    for name, digest in members.items():
                        self.assertEqual(sha((capture.output / name).read_bytes()), digest)
                    self.assertEqual(members["catalog.json"], sha((capture.output / "catalog.json").read_bytes()))
                    self.assertEqual(report["Status"], "PASS" if success else "FAIL")
                    self.assertIs(report["CatalogReady"], success)
                    for key in ("RequiredCellSatisfied", "CompleteObjectProof", "FullABIProof", "APIProof", "FinalReferenceParity",
                                "InstructionEquivalence", "PolicyEquivalence", "CpuExecution", "BoardExecution", "GlobalFreezeQualified"):
                        self.assertIs(report[key], False)
                    self.assertIs(type(report["RequiredCellsSatisfied"]), int)
                    self.assertEqual(report["RequiredCellsSatisfied"], 0)
                    self.assertTrue(all(type(value) is int for value in report["Counts"].values()))
                    closed = [row for row in report["Cases"] if row["CaseClosed"]]
                    self.assertEqual(len(catalog["Selections"]), len(closed))
                    for row, case in zip(catalog["Selections"], closed):
                        self.assertEqual(row["Route"], case["Route"])
                        self.assertEqual(row["Inventory"], fixture.descriptor)
                        for role, stage in (("Native", "Native"), ("Reference", "Reference"), ("PriorJoin", "Join")):
                            descriptor = row[role]
                            expected = capture.output / "cases" / (case["Profile"] + "-" + case["Mode"]) / stage
                            self.assertEqual(Path(descriptor["Build"]), expected)
                            self.assertEqual(descriptor["ReceiptSha256"], sha((expected / "results.json").read_bytes()))
                            self.assertEqual(descriptor["ArtifactsSha256"], sha((expected / "artifacts.json").read_bytes()))
                    for ordinal, argv in enumerate(calls):
                        command = json.loads((capture.output / ("commands/%03d.json" % ordinal)).read_bytes())
                        self.assertEqual(command["State"], "TERMINAL")
                        self.assertEqual(command["Argv"], argv)
                        if ordinal % 3 == 2:
                            flags = dict(zip(argv[10::2], argv[11::2]))
                            case_dir = Path(flags["--output-dir"]).parent
                            for role in ("native", "reference"):
                                self.assertEqual(Path(flags["--" + role + "-build"]), case_dir / role.title())
                                self.assertEqual(flags["--" + role + "-receipt-sha256"],
                                    sha((case_dir / role.title() / "results.json").read_bytes()))
                    if success:
                        self.assertEqual(report["Counts"], dict(Cases=3, TranslationUnits=40, Links=12, Checkpoints=42,
                            ToolCommands=440, ClosedBodies=20, Mechanisms=9, OuterPythonInvocations=9))
                        self.assertEqual(len(calls), 9)
                        self.assertEqual(pending["Routes"], [])
                        self.assertEqual(replay.validate_catalog(catalog), catalog["Selections"])
                        self.assertIs(report["InputClosureVerified"], True)
                        self.assertIs(report["OutputSealVerified"], True)
                    else:
                        self.assertEqual(report["Error"], report["PrimaryError"])
                        self.assertTrue(report["PrimaryError"])
                        self.assertIs(report["InputClosureVerified"], False)
                        if failure not in ("late-output", "receipt-substitution"):
                            self.assertEqual(len(closed), 1)
                            self.assertEqual(report["Counts"], dict(Cases=1, TranslationUnits=13, Links=4, Checkpoints=14,
                                ToolCommands=144, ClosedBodies=6, Mechanisms=3, OuterPythonInvocations=3))
                            self.assertEqual([row["Route"] for row in pending["Routes"]], fixture.selected[1:])
                            self.assertEqual(report["Cases"][2]["Status"], "PENDING")
                            self.assertLessEqual(len(calls), 6)
                        if failure == "primary-plus-closing":
                            self.assertIn("failed stage", report["PrimaryError"])
                            self.assertTrue(any("synthetic secondary closing cause" in item for item in report["ClosingErrors"]))
                    with self.assertRaises(subject.Rejected):
                        capture.run()
            directory = root / "empty"
            directory.mkdir()
            fixture = PrepareFixture(directory)
            with fixture.active():
                capture = subject.prepare(fixture.args)
            self.assertIs(capture.finish(), False)
            self.assertIs(capture.report["CatalogReady"], False)
            self.assertFalse(capture.output.exists())


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
    report = dict(Status="FAIL", Scope="PURE_SYNTHETIC_ORDINARY_CAPTURE_CONTROLS_ONLY", Tests=0,
        ExpectedTestMethods=EXPECTED_METHODS, Failures=0, Errors=0, Skipped=0, SourceHashes={}, SourceDrift=[],
        SourceClosureVerified=False, ClosingFilesVerified=0, SyntheticInputs=True, ActualChildExecuted=False,
        ActualCompilerExecuted=False, ActualELFTested=False, ToolInvocations=0, NativeCommandsExecuted=0,
        Qualification=False, FullABIProof=False, APIProof=False, CompleteObjectProof=False,
        FinalReferenceParity=False, CpuExecution=False, BoardExecution=False, GlobalFreezeQualified=False,
        RequiredCellSatisfied=False, RequiredCellsSatisfied=0)
    try:
        if sys.flags.optimize or not __debug__:
            raise ValueError("optimized interpreter unsupported")
        inputs = (Path(__file__).resolve(), SUBJECT, REPLAY, CONTRACT, MANIFEST, INVENTORY, LOADER, RUNNER, *STAGE_SOURCES)
        buffers = {path: path.read_bytes() for path in inputs}
        report["SourceHashes"] = {str(path): sha(data) for path, data in buffers.items()}
        global subject, replay, manifest
        with patch("subprocess.Popen", side_effect=AssertionError("pure capture controls cannot spawn children")), \
                patch("os.system", side_effect=AssertionError("pure capture controls cannot execute tools")):
            replay = load_module("synthetic_capture_dispatcher", REPLAY, buffers[REPLAY])
            manifest = json.loads(buffers[MANIFEST])
            subject = load_module("synthetic_ordinary_capture", SUBJECT, buffers[SUBJECT])
            suite = unittest.defaultTestLoader.loadTestsFromTestCase(CaptureTests)
            if suite.countTestCases() != EXPECTED_METHODS:
                raise ValueError("exact twelve implemented controls required; incomplete suite cannot PASS")
            result = unittest.TextTestRunner(verbosity=2).run(suite)
        report.update(Tests=result.testsRun, Failures=len(result.failures), Errors=len(result.errors), Skipped=len(result.skipped),
            FailureDetails=[dict(Test=str(case), Detail=detail) for case, detail in result.failures + result.errors])
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
        report["SourceClosureVerified"] = len(report["SourceHashes"]) == 8 + len(STAGE_SOURCES) and not report["SourceDrift"]
        if not report["SourceClosureVerified"]:
            report["Status"] = "FAIL"
    output.mkdir(parents=True, exist_ok=False)
    target = output / "results.json"
    target.write_bytes((json.dumps(report, sort_keys=True, indent=2) + "\n").encode("ascii"))
    print("Receipt:", target, sha(target.read_bytes()))
    return 0 if report["Status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
