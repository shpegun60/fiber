"""Pure closed-dispatcher controls with synthetic receipts and fake child execution."""

import argparse
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
DISPATCHER = REPO / "tools/freeze_replay.py"
INVENTORY = REPO / "tools/freeze_cohorts.py"
MANIFEST = REPO / "tools/freeze_cohorts.json"
CONTRACT = HERE / "REPLAY_CONTRACT.md"
LOADER = HERE.with_name("cm3_final_roots") / "reference_witness.py"
EXPECTED_METHODS = 12
EXPECTED_PLAN_KEYS = 2774
subject = inventory = manifest = None
loader_buffer = bootstrap_directory = None
bootstrap_result = {}
ORDINARY = ("O0", "Og", "O2", "Os", "O3")
PROFILES = {
    "CM0": ("cm0-cortex-m0-soft-nofpu-none-v0-mpu0-p2-b0-aapcs-default", "CM0", "cm0_final_join/join.py"),
    "CM0PLUS": ("cm0-cortex-m0plus-soft-nofpu-none-v0-mpu0-p2-b0-aapcs-default", "CM0", "cm0_final_join/join.py"),
    "CM0PLUSVTOR": ("cm0-cortex-m0plus-soft-nofpu-none-v1-mpu0-p2-b0-aapcs-default", "CM0", "cm0_final_join/join.py"),
    "CM4": ("cm4-cortex-m4-hard-fpu-eager-v1-mpu0-p4-b16-aapcs-default", "CM4", "classic_final_join/join.py"),
    "CM7": ("cm7-cortex-m7-hard-fpu-eager-v1-mpu0-p4-b16-aapcs-default", "CM7", "classic_final_join/join.py"),
    "CM3": ("cm3-cortex-m3-soft-nofpu-none-v1-mpu0-p4-b16-aapcs-default", "CM3", "cm3_final_join/join.py"),
}
TEST_PLAN = (
    "closed exact route table, unsupported route never executes",
    "only generated fixed argv, no caller-selected command or script",
    "wrong admitted hashes refuse before output and child execution",
    "semantic role aliases and links refuse before output",
    "output overlaps, existing output and escaped paths refuse before writes",
    "valid synthetic fresh child report/manifest remains bounded",
    "exit zero with missing, stale or invalid report cannot pass",
    "exit zero with bad manifest, extra/missing artifacts or changed bytes fails",
    "wrong mode/cohort/linkage/source fingerprint cannot promote",
    "complete 2774-key inventory retains missing/unsupported/backlog rows",
    "historical evidence cannot become current snapshot evidence",
    "closing failures and nonzero child exit never promote or shrink the plan",
)


def sha(data):
    return hashlib.sha256(data).hexdigest().upper()


def declared_plan():
    """Real declared plan only; no registry/compiler/source qualification runs."""
    return inventory.plan(copy.deepcopy(manifest))


def selection(route="CM3/O2-lto/archive"):
    root = Path(tempfile.gettempdir()).absolute() / "synthetic-freeze-replay-descriptors"
    return dict(Route=route, **{role: dict(Build=str(root / role),
        ReceiptSha256=sha((role + " receipt").encode("ascii")),
        ArtifactsSha256=sha((role + " artifacts").encode("ascii")))
        for role in ("Inventory", "Native", "Reference", "PriorJoin")})


def catalog(*route_ids):
    return dict(SchemaVersion=1, Selections=[selection(route) for route in route_ids or ("CM3/O2-lto/archive",)])


@contextmanager
def pure_calls():
    with patch("builtins.open", side_effect=AssertionError("pure API cannot open files")), \
            patch.object(Path, "open", side_effect=AssertionError("pure API cannot open paths")), \
            patch.object(Path, "read_bytes", side_effect=AssertionError("pure API cannot read files")), \
            patch.object(Path, "write_bytes", side_effect=AssertionError("pure API cannot write files")), \
            patch.object(Path, "stat", side_effect=AssertionError("pure API cannot stat paths")):
        yield


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="ascii")
    return sha(path.read_bytes())


def sealed_fixture(root, report, files=None):
    """Small generated child tree, never an actual producer/witness receipt."""
    root.mkdir(parents=True, exist_ok=False)
    for name, data in ({} if files is None else files).items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    receipt = write_json(root / "results.json", report)
    members = {path.relative_to(root).as_posix(): sha(path.read_bytes())
               for path in root.rglob("*") if path.is_file()}
    artifacts = write_json(root / "artifacts.json", dict(Artifacts=members))
    return SimpleNamespace(root=root, report=report, receipt=receipt, artifacts=artifacts, members=members)


class FakeChild:
    """Same contained-runner result fields; no subprocess or selected helper."""

    def __init__(self, writer=None, returncode=0):
        self.writer, self.returncode, self.calls = writer, returncode, []

    def __call__(self, argv, *, cwd, env, timeout):
        argv = [str(value) for value in argv]
        self.calls.append(dict(Argv=argv, Cwd=str(cwd), Environment=dict(env), Timeout=timeout))
        if self.writer is not None:
            if argv.count("--output-dir") != 1:
                raise AssertionError("generated fixed child argv requires one output role")
            output = Path(argv[argv.index("--output-dir") + 1])
            self.writer(output)
        return SimpleNamespace(returncode=self.returncode, stdout=b"synthetic child only\n", stderr=b"",
                               timed_out=False, elapsed=0.0)


def gate_report(route_id="CM3/O2/direct"):
    """Invented report metadata only: no root bytes, parser or proof is claimed."""
    route = subject.route_for(route_id)
    cm0 = route["Profile"].startswith("CM0")
    names = dict(Native=["synthetic-native-%d" % index for index in range(3)],
                 Reference=["synthetic-reference-%d" % index for index in range(5 if cm0 else 3)])
    roots = {side: [dict(Name=name, Synthetic=True) for name in values] for side, values in names.items()}
    count = 8 if cm0 else 6
    proof = dict(ClosedBodies=count, Verdict="CM0-CLOSED-ROOTS-PASS" if cm0 else
        "CM3-CLOSED-ROOTS-PASS" if route["Profile"] == "CM3" else "CLASSIC-FP-CLOSED-ROOTS-PASS",
        RootEvidence=[dict(Name=name, Side=side, TailNops=0, Synthetic=True)
                      for side, values in names.items() for name in values],
        Mechanisms=[dict(Name=name) for name in ("first-start", "first-restore", "PendSV")],
        DifferenceIds=["synthetic-explicit-difference"])
    twins = {side: dict(Identical=True, Segments=[dict(Synthetic=True)]) for side in names}
    result = dict(Status="PASS", Error=None, Scope="CM0_FAMILY_FINAL_MECHANISM_COMPOSITION_ONLY" if cm0 else
        "CM3_FINAL_MECHANISM_COMPOSITION_ONLY" if route["Profile"] == "CM3" else "CLASSIC_FP_FINAL_MECHANISM_COMPOSITION_ONLY",
        Profile=route["Profile"], Mode=route["Mode"],
        OutputSealVerified=True, InputClosureVerified=True, ImmutableInputsConsumed=True, ClosingFilesVerified=1,
        GlobalFreezeQualified=False, FinalReferenceParity=False, CompleteObjectProof=False, PolicyEquivalence=False,
        CpuExecution=False, BoardExecution=False, FullABIProof=False, APIProof=False, Qualification=False,
        RequiredCellSatisfied=False, RequiredCellsSatisfied=0, SourceIRProof=False, SourceToMachineSemanticProof=False)
    if route["Mode"] in ORDINARY:
        result.update(ProtocolProof=proof, NativeFinalRoots=roots["Native"], ReferenceFinalRoots=roots["Reference"],
                      NativeTwins=twins["Native"], ReferenceTwins=twins["Reference"])
    else:
        result.update(Cohort=route["Cohort"], JoinProof=dict(ProtocolProof=proof, Roots=roots, ClosedBodies=6,
            CanonicalProtocolValidated=True, Cohort=route["Cohort"], Linkage=route["Linkage"]),
            RecomputedSides={side: dict(Twins=twins[side]) for side in names})
        if route_id == "CM3/O2-lto/direct":
            result.update(Status="CM3-LTO-JOIN-PASS-NOT-QUALIFIED", Scope="CM3_O2_LTO_SIX_BODY_MECHANISM_JOIN_ONLY",
                PriorTransportControlsAuthenticated=32, PriorCanonicalControlsAuthenticated=2, MutantsReexecuted=False)
        else:
            result.update(Status="CM3-OS-LTO-JOIN-PASS-NOT-QUALIFIED" if route["Mode"] == "Os-lto" else
                "CM3-LTO-ARCHIVE-JOIN-PASS-NOT-QUALIFIED", Scope="CM3_OS_LTO_SIX_BODY_MECHANISM_JOIN_ONLY" if
                route["Mode"] == "Os-lto" else "CM3_O2_LTO_P4_B16_ARCHIVE_SIX_CLOSED_ROOT_JOIN_ONLY",
                TransportControlsExecuted=32, CanonicalControlsExecuted=2, MutantsReexecuted=True,
                Controls={side: dict(Transport=[dict(Status="PASS", Files=[dict(Synthetic=True)], ClosingFilesVerified=5)
                    for _ in range(16)], Canonical=[dict(Status="PASS", Files=[dict(Synthetic=True)], ClosingFilesVerified=6)])
                    for side in names})
    return result


class PrepareFixture:
    """Mock already-admitted evidence; exercise the actual prepare wiring only."""

    def __init__(self, root, route="CM3/O2/direct"):
        self.root, self.route = root, route
        self.row = selection(self.route)
        for role in ("Inventory", "Native", "Reference", "PriorJoin"):
            path = root / role
            path.mkdir()
            self.row[role]["Build"] = str(path)
        self.current_root = root / "Current"
        self.current_root.mkdir()
        self.interpreter = root / "host/python.exe"
        self.interpreter.parent.mkdir()
        self.interpreter.write_bytes(b"synthetic interpreter bytes, never executed")
        required = declared_plan()
        self.current_descriptor = dict(Build=str(self.current_root), ReceiptSha256="A" * 64, ArtifactsSha256="B" * 64)
        self.current = dict(Bundle=dict(Root=self.current_root, Descriptor=self.current_descriptor), Required=required,
                            SourceInventorySha256=sha(b"current snapshot"), Manifest=copy.deepcopy(manifest))
        self.historical = dict(Bundle=dict(Root=Path(self.row["Inventory"]["Build"]), Descriptor=self.row["Inventory"]), Required=copy.deepcopy(required),
                               SourceInventorySha256=sha(b"historical snapshot"), Manifest=copy.deepcopy(manifest))
        self.groups = {side: dict(Root=Path(self.row[side]["Build"]), Result=dict(
            SourceInventorySha256=self.historical["SourceInventorySha256"],
            SourceInventoryReceipt=self.row["Inventory"]["Build"]), Nested=[])
            for side in ("Native", "Reference", "PriorJoin")}
        prior = gate_report(self.route)
        prior.update(self.groups["PriorJoin"]["Result"])
        prior["ProducerBindings"] = [dict(Side=side, **copy.deepcopy(self.row[side])) for side in ("Native", "Reference")]
        self.groups["PriorJoin"]["Result"] = prior
        self.catalog = root / "catalog.json"
        digest = write_json(self.catalog, dict(SchemaVersion=1, Selections=[self.row]))
        self.args = SimpleNamespace(inventory=str(self.current_root), inventory_receipt_sha256="A" * 64,
            inventory_artifacts_sha256="B" * 64, catalog=str(self.catalog), catalog_sha256=digest,
            output_dir=str(root / "fresh-output"))
        self.watch = SimpleNamespace(hashes={}, denied={subject.ROOT}, close=Mock())
        self.watch.read = Mock(side_effect=self.read)
        self.runner, self.dispatcher = SimpleNamespace(run=Mock()), Mock(return_value=SimpleNamespace(SyntheticPrepared=True))

    def rewrite_catalog(self):
        self.args.catalog_sha256 = write_json(self.catalog, dict(SchemaVersion=1, Selections=[self.row]))

    def read(self, path, expected=None):
        path = Path(path)
        raw = path.read_bytes() if path in (self.catalog, self.interpreter) else b"synthetic preadmitted source"
        if path == self.catalog and expected is not None and sha(raw) != expected:
            raise subject.Rejected("synthetic catalog SHA256 mismatch")
        self.watch.hashes[path] = sha(raw) if expected is None else expected
        return raw

    @contextmanager
    def active(self):
        fixture = self

        class Admitted:
            require_inventory_binding = subject.Admission.require_inventory_binding

            def __init__(self, watch):
                self.inventory = inventory
                self.bundles = {value["Root"]: value for value in fixture.groups.values()}

            def snapshot(self, item, *, current=False):
                value = fixture.current if Path(item["Build"]) == fixture.current_root else fixture.historical
                fixture.watch.denied.add(value["Bundle"]["Root"])
                return value

            def bundle(self, item):
                path = Path(item["Build"])
                fixture.watch.denied.add(path)
                return next(value for value in fixture.groups.values() if value["Root"] == path)

        with patch.object(subject, "Closure", return_value=self.watch), \
                patch.object(subject, "Admission", Admitted), \
                patch.object(subject, "interpreter_path", return_value=self.interpreter), \
                patch.object(subject, "fixed_module", return_value=self.runner), \
                patch.object(subject, "process_environment", return_value={}), \
                patch.object(subject, "Dispatcher", self.dispatcher, create=True):
            yield


def run_fixture(root, case="valid"):
    """Real dispatcher lifecycle with generated receipts and a nonexecuting runner.

    Upstream admission is supplied explicitly, not claimed as a qualified seed.
    Fresh child manifests and complete output/closing checks use the real code.
    """
    fixture = PrepareFixture(root)
    watch = subject.Closure()
    watch.read(fixture.catalog, fixture.args.catalog_sha256)
    watch.read(fixture.interpreter)
    authority = root / "authority.bin"
    authority.write_bytes(b"synthetic child input authority")
    watch.read(authority)
    route = subject.route_for(fixture.route)
    gate = subject.ROOT / route["Gate"]
    watch.read(gate)  # Capture bytes only; no gate import, parser or execution.
    admission = subject.Admission.__new__(subject.Admission)
    admission.closure, admission.bundles = watch, {}
    entry = dict(Selection=fixture.row, Route=route, Snapshot=fixture.historical, Groups=fixture.groups,
                 Evidence=subject.report_evidence(fixture.route, gate_report(fixture.route)),
                 InventoryFacts={side: [] for side in ("Native", "Reference", "PriorJoin")})
    child = FakeChild(returncode=1 if case == "child-failed" else 0)
    dispatcher = subject.Dispatcher(Path(fixture.args.output_dir), watch, admission, fixture.current, [entry], {},
                                    fixture.interpreter, SimpleNamespace(run=child), fixture.catalog)

    def write_child(output):
        attempt = json.loads((dispatcher.output / "commands/00.json").read_bytes())
        if attempt["State"] != "ATTEMPT":
            raise AssertionError("attempt must be durable before invoking fake child")
        trace = dict(SourceSnapshotSha256=dispatcher.source_snapshot_sha, Entry=str(gate), ExitCode=0,
                     Executed=[dict(Path=str(gate), Sha256=dispatcher.sources[str(gate)]["Sha256"])])
        write_json(dispatcher.output / "execution/CM3-O2-direct.json", trace)
        if case == "runner-plus-closing":
            dispatcher.watch.close = Mock(side_effect=subject.Rejected("synthetic secondary closing failure"))
        if case in ("runner-exception", "runner-plus-closing"):
            raise RuntimeError("synthetic contained-runner failure")
        if case == "missing-report":
            output.mkdir(parents=True)
            return
        report = gate_report(fixture.route)
        report.update(ProducerBindings=[dict(Side=side, **copy.deepcopy(fixture.row[side])) for side in ("Native", "Reference")],
                      InputHashes={str(authority): sha(authority.read_bytes())},
                      SourceInventorySha256=fixture.historical["SourceInventorySha256"],
                      SourceInventoryReceipt=str(fixture.historical["Bundle"]["Root"]))
        if case == "child-failed":
            report.update(Status="FAIL", Error="synthetic child primary cause")
        elif case == "wrong-mode":
            report["Mode"] = "O3"
        elif case == "wrong-fingerprint":
            report["SourceInventorySha256"] = fixture.current["SourceInventorySha256"]
        sealed_fixture(output, report, {"evidence.bin": b"synthetic complete child artifact"})
        if case == "invalid-manifest":
            (output / "artifacts.json").write_bytes(b"{}\n")
        elif case == "unplanned-child":
            (output / "extra.bin").write_bytes(b"unplanned child artifact")
        elif case == "missing-child":
            (output / "evidence.bin").unlink()
        elif case == "late-input":
            authority.write_bytes(b"changed after original admission")
    child.writer = write_child
    return dispatcher, child, fixture


def nested_bootstrap_controls(directory):
    """Synthetic entry/payload only, using the real pinned FrozenSources class."""
    if sha(loader_buffer) != subject.SOURCE_PINS[subject.LOADER] or REPO / subject.LOADER != LOADER:
        raise AssertionError("bootstrap controls require the exact dispatcher-pinned loader")
    directory.mkdir(parents=True, exist_ok=False)
    entry, payload = directory / "entry.py", directory / "payload.py"
    entry_data = b'''import importlib.util
import json
from pathlib import Path
import sys

output, loader_path = Path(sys.argv[1]), Path(sys.argv[2])
payload = Path(__file__).with_name('payload.py')
spec = importlib.util.spec_from_file_location('_replay_pure_nested_loader', loader_path)
api = importlib.util.module_from_spec(spec)
spec.loader.exec_module(api)
inner = api.FrozenSources({payload: payload.read_bytes()})
with inner.active():
    module = inner.load('_replay_pure_payload', payload)
assert module.VALUE == 7

class ForeignLoader:
    def create_module(self, spec):
        return None
    def exec_module(self, module):
        raise AssertionError('foreign loader must never execute')

foreign_rejected = False
try:
    importlib.util.spec_from_file_location('foreign', payload, loader=ForeignLoader())
except RuntimeError as error:
    foreign_rejected = str(error) == 'replay unapproved custom loader'
assert foreign_rejected

bytes_rejected = False
altered = api.FrozenSources({payload: b'VALUE = 99\\n'})
try:
    with altered.active():
        altered.load('_replay_pure_altered_payload', payload)
except RuntimeError as error:
    bytes_rejected = str(error) == 'replay nested source bytes outside authenticated snapshot'
assert bytes_rejected
(output / 'inner.json').write_bytes((json.dumps(dict(Executed=inner.executed,
    CustomLoaderRejected=foreign_rejected, AlteredNestedBytesRejected=bytes_rejected),
    indent=2, sort_keys=True) + '\\n').encode('ascii'))
'''
    payload_data = b"VALUE = 7\n"
    entry.write_bytes(entry_data)
    payload.write_bytes(payload_data)
    sources = {}
    captured = directory / "captured"
    captured.mkdir()
    for original, data in ((LOADER, loader_buffer), (entry, entry_data), (payload, payload_data)):
        path = captured / (sha(data) + ".py")
        path.write_bytes(data)
        sources[str(original)] = dict(Captured=str(path), Sha256=sha(data))
    snapshot = directory / "snapshot.json"
    snapshot_sha = write_json(snapshot, dict(Loader=str(LOADER), Sources=sources,
                                           ClosedRoots=[str(REPO), str(directory)]))
    outer_path = directory / "outer.json"
    # No actual gate or child process: only the fixed bootstrap and synthetic
    # entry run. Restore its __main__, nested modules and argv in this process.
    with patch.dict(sys.modules), patch.object(sys, "argv", ["synthetic-bootstrap", str(snapshot), snapshot_sha,
            str(entry), str(outer_path), str(directory), str(LOADER)]):
        exec(compile(subject.BOOTSTRAP, str(DISPATCHER) + ":BOOTSTRAP", "exec"),
             dict(__name__="_replay_pure_bootstrap", __file__=str(DISPATCHER)))
    inner = json.loads((directory / "inner.json").read_bytes())
    outer = json.loads(outer_path.read_bytes())
    expected = dict(Name="_replay_pure_payload", Path=str(payload), Sha256=sha(payload_data))
    if (inner["Executed"] != [expected] or inner["CustomLoaderRejected"] is not True
            or inner["AlteredNestedBytesRejected"] is not True):
        raise AssertionError("three nested bootstrap controls must complete with exact inner evidence")
    if (type(outer["ExitCode"]) is not int or outer["ExitCode"] != 0
            or outer["SourceSnapshotSha256"] != snapshot_sha or outer["Entry"] != str(entry)
            or expected not in outer["Executed"]
            or not any(row["Path"] == str(entry) and row["Sha256"] == sha(entry_data) for row in outer["Executed"])):
        raise AssertionError("nested payload and entry must remain in the authenticated outer trace")
    for row in outer["Executed"]:
        if row["Path"] not in sources or row["Sha256"] != sources[row["Path"]]["Sha256"]:
            raise AssertionError("outer executed source outside the exact synthetic snapshot")
    for row in sources.values():
        if sha(Path(row["Captured"]).read_bytes()) != row["Sha256"]:
            raise AssertionError("captured bootstrap source changed during execution")
    return dict(Controls=3, NestedFrozenSources=True, InnerAndOuterTraceBound=True,
                UnapprovedCustomLoaderRejected=True, AlteredNestedBytesRejected=True,
                EvidenceFiles={path.relative_to(directory.parent).as_posix(): sha(path.read_bytes())
                    for path in directory.rglob("*") if path.is_file()})


class ReplayTests(unittest.TestCase):
    def test_all_33_routes_have_exact_cohorts_roles_and_fixed_gate_paths(self):
        expected = {profile + "/" + mode + "/direct": (profile, mode, "direct", values[2])
                    for profile, values in PROFILES.items() for mode in ORDINARY}
        expected.update({
            "CM3/O2-lto/direct": ("CM3", "O2-lto", "direct", "cm3_lto_join/witness.py"),
            "CM3/Os-lto/direct": ("CM3", "Os-lto", "direct", "cm3_os_lto_join/witness.py"),
            "CM3/O2-lto/archive": ("CM3", "O2-lto", "archive", "cm3_lto_archive_join/witness.py"),
        })
        with pure_calls():
            actual = subject.routes()
            self.assertEqual(len(actual), 33)
            self.assertEqual(set(actual), set(expected))
            for identity, (profile, mode, linkage, gate) in expected.items():
                with self.subTest(route=identity):
                    row = actual[identity]
                    self.assertEqual(row["Profile"], profile)
                    self.assertEqual(row["Mode"], mode)
                    self.assertEqual(row["Linkage"], linkage)
                    self.assertEqual(row["Cohort"], PROFILES[profile][0])
                    self.assertEqual(row["SourceGroup"], PROFILES[profile][1])
                    self.assertEqual(row["ArtifactRole"], "runtime")
                    path = Path(row["Gate"])
                    self.assertEqual(path if path.is_absolute() else REPO / path,
                                     REPO / "tools/fixtures" / gate)
            again = subject.routes()
            actual["CM3/O2-lto/archive"]["Cohort"] = "mutated"
            self.assertEqual(again["CM3/O2-lto/archive"]["Cohort"], PROFILES["CM3"][0])
            self.assertEqual(subject.SOURCE_PINS[again["CM3/O2-lto/archive"]["Gate"]],
                             "FFD12847C2362F4145F5F1693A7AAFD9FEAC0D30FAA2CC1AF8FF35F179753C4E")

    def test_route_lookup_is_fresh_and_rejects_arbitrary_or_aliased_selectors(self):
        with pure_calls():
            first = subject.route_for("CM3/O2-lto/archive")
            first["Mode"] = "foreign"
            self.assertEqual(subject.route_for("CM3/O2-lto/archive")["Mode"], "O2-lto")
            for value in (None, True, 1, [], "", "cm3/O2-lto/archive", "CM3/o2-lto/archive",
                          "CM3/Os-lto/archive", "CM4/O2/archive", "CM3/O2-lto/archive --command evil",
                          "../../arbitrary.py", "CM3/O2-lto/archive\0"):
                with self.subTest(route=value):
                    with self.assertRaises(subject.Rejected):
                        subject.route_for(value)

    def test_catalog_returns_detached_ordered_closed_selections_without_io(self):
        value = catalog("CM3/O2-lto/archive", "CM4/O2/direct")
        before = copy.deepcopy(value)
        with pure_calls():
            selected = subject.validate_catalog(value)
        self.assertIs(type(selected), list)
        self.assertEqual(selected, value["Selections"])
        self.assertEqual(value, before)
        selected[0]["Native"]["Build"] = "mutated"
        self.assertEqual(value, before)

    def test_catalog_rejects_unknown_fields_routes_schema_aliases_and_bad_descriptors(self):
        invalid = [None, True, [], {}, dict(SchemaVersion=True, Selections=[selection()]),
                   dict(SchemaVersion=1.0, Selections=[selection()]), dict(SchemaVersion=1, Selections=[])]
        for mutation in ("top-extra", "case-alias", "selection-extra", "role-alias", "duplicate-route", "unknown-route",
                         "descriptor-extra", "descriptor-relative", "descriptor-bool", "lowercase-hash", "short-hash", "foreign-hash"):
            value = catalog()
            row = value["Selections"][0]
            if mutation == "top-extra":
                value["Command"] = ["arbitrary.exe"]
            elif mutation == "case-alias":
                value["schemaversion"] = 1
            elif mutation == "selection-extra":
                row["Argv"] = ["--arbitrary"]
            elif mutation == "role-alias":
                row["native"] = copy.deepcopy(row["Native"])
            elif mutation == "duplicate-route":
                value["Selections"].append(copy.deepcopy(row))
            elif mutation == "unknown-route":
                row["Route"] = "CM3/Os-lto/archive"
            elif mutation == "descriptor-extra":
                row["Native"]["Gate"] = "arbitrary.py"
            elif mutation == "descriptor-relative":
                row["Native"]["Build"] = "relative/capture"
            elif mutation == "descriptor-bool":
                row["Reference"] = True
            else:
                row["PriorJoin"]["ReceiptSha256"] = {
                    "lowercase-hash": "a" * 64, "short-hash": "A" * 63, "foreign-hash": "G" * 64}[mutation]
            invalid.append(value)
        with pure_calls():
            for index, value in enumerate(invalid):
                with self.subTest(case=index):
                    with self.assertRaises(subject.Rejected):
                        subject.validate_catalog(value)
            for raw in (b'{"SchemaVersion":1,"SchemaVersion":1,"Selections":[]}',
                        b'{"SchemaVersion":1,"schemaversion":1,"Selections":[]}'):
                with self.subTest(raw_duplicate=raw):
                    with self.assertRaises(subject.Rejected):
                        subject.structured(raw)

    def test_gate_arguments_are_only_fixed_legacy_flags_for_each_closed_route(self):
        output = Path(tempfile.gettempdir()).absolute() / "synthetic-replay-child-output"
        with pure_calls():
            route_ids = tuple(subject.routes())
        for identity in route_ids:
            row = selection(identity)
            row["Native"]["Build"] += " path-with-spaces --not-a-real-flag"
            before = copy.deepcopy(row)
            with self.subTest(route=identity), pure_calls():
                args = subject.gate_arguments(identity, row, output)
                self.assertIs(type(args), list)
                self.assertTrue(all(type(value) is str for value in args))
                self.assertEqual(len(args) % 2, 0)
                values = dict(zip(args[::2], args[1::2]))
                self.assertEqual(len(values) * 2, len(args))
                expected = {"--output-dir": str(output)}
                for side in ("Native", "Reference"):
                    expected.update({"--" + side.lower() + "-" + suffix: row[side][field]
                        for suffix, field in (("build", "Build"), ("receipt-sha256", "ReceiptSha256"),
                                              ("artifacts-sha256", "ArtifactsSha256"))})
                profile, mode, _ = identity.split("/")
                if mode in ORDINARY:
                    expected.update({"--profile": profile, "--mode": mode})
                self.assertEqual(values, expected)
                self.assertEqual(row, before)

    def test_environment_is_sanitized_and_rejects_injection_aliases_and_nonstring_values(self):
        base = dict(SYSTEMROOT="C:/Windows", WINDIR="C:/Windows", PATH="C:/Windows/System32",
                    TEMP=str(Path(tempfile.gettempdir())), TMP=str(Path(tempfile.gettempdir())),
                    UNRELATED_SECRET="must-not-propagate")
        before = dict(base)
        with pure_calls():
            result = subject.process_environment(base)
        self.assertIs(type(result), dict)
        self.assertTrue(all(type(key) is str and type(value) is str for key, value in result.items()))
        self.assertNotIn("UNRELATED_SECRET", result)
        self.assertEqual(base, before)
        bad = [dict(base, PYTHONPATH="foreign"), dict(base, PYTHONHOME="foreign"),
               dict(base, pythonpath="foreign"), dict(base, GCC_EXEC_PREFIX="foreign"),
               dict(base, COMPILER_PATH="foreign"), dict(base, LD_PRELOAD="foreign"),
               dict(base, Path="case alias"), dict(base, SystemRoot="case alias"), dict(base, TEMP=True)]
        with pure_calls():
            for index, value in enumerate(bad):
                with self.subTest(case=index):
                    with self.assertRaises(subject.Rejected):
                        subject.process_environment(value)

    def test_scope_report_is_fresh_fail_default_with_literal_zero_credit(self):
        with pure_calls():
            report, again = subject.scope_report(), subject.scope_report()
        self.assertEqual(report["Status"], "FAIL")
        for key in ("RequiredCellSatisfied", "FullABIProof", "APIProof", "GlobalFreezeQualified"):
            self.assertIs(report[key], False)
        self.assertIs(type(report["RequiredCellsSatisfied"]), int)
        self.assertEqual(report["RequiredCellsSatisfied"], 0)
        self.assertEqual(report["Components"], [])
        for key in ("CpuExecution", "BoardExecution", "HostedCIQualified", "FinalReferenceParity",
                    "SourceToMachineSemanticProof", "OriginalTranslationUnitOwnership", "CompleteObjectProof"):
            if key in report:
                self.assertIs(report[key], False)
        report["Components"].append("must not share defaults")
        self.assertEqual(again["Components"], [])

    def test_closure_refuses_wrong_hash_hardlink_alias_and_changed_membership(self):
        with tempfile.TemporaryDirectory(prefix="synthetic-replay-admission-") as temporary:
            root = Path(temporary).resolve()
            original, alias = root / "original.bin", root / "alias.bin"
            original.write_bytes(b"synthetic input authority\n")
            alias.hardlink_to(original)
            output = root / "must-not-be-created"
            with patch.object(Path, "mkdir", side_effect=AssertionError("admission cannot create output")):
                with self.assertRaisesRegex(subject.Rejected, "SHA256 mismatch"):
                    subject.Closure().read(original, "0" * 64)
                closure = subject.Closure()
                self.assertEqual(closure.read(original, sha(original.read_bytes())), original.read_bytes())
                with self.assertRaisesRegex(subject.Rejected, "physical input/source alias"):
                    closure.read(alias, sha(alias.read_bytes()))
            self.assertFalse(output.exists())
            proof = sealed_fixture(root / "child", dict(Status="SYNTHETIC-NOT-QUALIFIED"),
                                   {"evidence.bin": b"synthetic evidence"})
            expected = dict(proof.members, **{"artifacts.json": proof.artifacts})
            closure = subject.Closure()
            closure.tree(proof.root, expected)
            closure.close()
            (proof.root / "extra.bin").write_bytes(b"late unplanned member")
            with self.assertRaisesRegex(subject.Rejected, "closing artifact membership"):
                closure.close()
            (proof.root / "extra.bin").unlink()
            (proof.root / "evidence.bin").write_bytes(b"changed after admission")
            with self.assertRaises(subject.Rejected):
                closure.close()

    def test_prepare_keeps_historical_snapshot_separate_and_refuses_before_output(self):
        with tempfile.TemporaryDirectory(prefix="synthetic-replay-prepare-") as temporary:
            root = Path(temporary).resolve()
            valid_root = root / "valid"
            valid_root.mkdir()
            fixture = PrepareFixture(valid_root)
            with fixture.active(), patch.object(Path, "mkdir", side_effect=AssertionError("prepare cannot mkdir")):
                prepared = subject.prepare(fixture.args)
            self.assertIs(prepared, fixture.dispatcher.return_value)
            self.assertFalse(Path(fixture.args.output_dir).exists())
            self.assertEqual(fixture.dispatcher.call_args.args[3]["SourceInventorySha256"], fixture.current["SourceInventorySha256"])
            self.assertEqual(fixture.dispatcher.call_args.args[4][0]["Snapshot"]["SourceInventorySha256"],
                             fixture.historical["SourceInventorySha256"])
            self.assertNotEqual(fixture.current["SourceInventorySha256"], fixture.historical["SourceInventorySha256"])
            for case in ("wrong-catalog-hash", "role-alias", "existing-output", "repo-overlap", "input-overlap",
                         "source-fingerprint", "wrong-cohort"):
                with self.subTest(case=case):
                    directory = root / case
                    directory.mkdir()
                    fixture = PrepareFixture(directory)
                    if case == "wrong-catalog-hash":
                        fixture.args.catalog_sha256 = "0" * 64
                    elif case == "role-alias":
                        fixture.row["Reference"] = copy.deepcopy(fixture.row["Native"])
                        fixture.rewrite_catalog()
                    elif case == "existing-output":
                        Path(fixture.args.output_dir).mkdir()
                    elif case == "repo-overlap":
                        fixture.args.output_dir = str(subject.ROOT / "must-not-create-replay-output")
                    elif case == "input-overlap":
                        fixture.args.output_dir = str(fixture.groups["Native"]["Root"] / "must-not-create")
                    elif case == "source-fingerprint":
                        fixture.groups["Native"]["Result"]["SourceInventorySha256"] = fixture.current["SourceInventorySha256"]
                    else:
                        fixture.historical["Required"]["RequiredCells"] = [row for row in fixture.historical["Required"]["RequiredCells"]
                            if row["Cohort"] != PROFILES["CM3"][0]]
                    before = Path(fixture.args.output_dir).exists()
                    with fixture.active(), patch.object(Path, "mkdir", side_effect=AssertionError("admission cannot mkdir")):
                        with self.assertRaises(subject.Rejected):
                            subject.prepare(fixture.args)
                    fixture.dispatcher.assert_not_called()
                    self.assertEqual(Path(fixture.args.output_dir).exists(), before)
            # O2-lto protocol receipts have no top-level inventory scalars. The
            # actual authority lives below Capture -> Seed, not in the catalog.
            for case in ("nested-E8-valid", "forged-E9-native", "forged-E9-reference", "nested-wrong-sha", "no-authority"):
                with self.subTest(case=case):
                    directory = root / case
                    directory.mkdir()
                    fixture = PrepareFixture(directory, "CM3/O2-lto/direct")
                    for side in ("Native", "Reference", "PriorJoin"):
                        fixture.groups[side]["Result"].pop("SourceInventorySha256")
                        fixture.groups[side]["Result"].pop("SourceInventoryReceipt")
                    for side in ("Native", "Reference"):
                        seed = dict(Root=directory / (side + "-seed"), Nested=[], Result=dict(
                            SourceInventoryReceipt=str(fixture.historical["Bundle"]["Root"]),
                            SourceInventorySha256=fixture.historical["SourceInventorySha256"]))
                        capture = dict(Root=directory / (side + "-capture"), Nested=[seed], Result={})
                        fixture.groups[side]["Nested"] = [capture]
                    if case.startswith("forged-E9"):
                        fixture.row["Inventory"] = copy.deepcopy(fixture.current_descriptor)
                        # Give the opposite side E9 authority so only the named
                        # side's buried E8 binding must cause this refusal.
                        opposite = "Reference" if case.endswith("native") else "Native"
                        seed = fixture.groups[opposite]["Nested"][0]["Nested"][0]
                        seed["Result"].update(SourceInventoryReceipt=str(fixture.current_root),
                            SourceInventorySha256=fixture.current["SourceInventorySha256"])
                        fixture.rewrite_catalog()
                    elif case == "nested-wrong-sha":
                        seed = fixture.groups["Native"]["Nested"][0]["Nested"][0]
                        seed["Result"]["SourceInventorySha256"] = fixture.current["SourceInventorySha256"]
                    elif case == "no-authority":
                        fixture.groups["Native"]["Nested"][0]["Nested"][0]["Result"] = {}
                    with fixture.active(), patch.object(Path, "mkdir", side_effect=AssertionError("admission cannot mkdir")):
                        if case == "nested-E8-valid":
                            subject.prepare(fixture.args)
                        else:
                            with self.assertRaisesRegex(subject.Rejected, "reachable source|source inventory authority"):
                                subject.prepare(fixture.args)
                    if case == "nested-E8-valid":
                        entry = fixture.dispatcher.call_args.args[4][0]
                        self.assertEqual(entry["Snapshot"]["Bundle"]["Root"], fixture.historical["Bundle"]["Root"])
                        self.assertEqual(len(entry["InventoryFacts"]["Native"]), 2)
                        self.assertEqual(len(entry["InventoryFacts"]["Reference"]), 2)
                        self.assertEqual(entry["InventoryFacts"]["PriorJoin"], [])
                    else:
                        fixture.dispatcher.assert_not_called()
                    self.assertFalse(Path(fixture.args.output_dir).exists())

    def test_structured_child_report_and_artifact_tree_not_exit_zero_are_authority(self):
        for route in ("CM0/O0/direct", "CM3/O2/direct", "CM3/O2-lto/direct", "CM3/Os-lto/direct", "CM3/O2-lto/archive"):
            with self.subTest(route=route, case="valid synthetic interface"):
                report = gate_report(route)
                # Do not invent mandatory headers absent from frozen gates.
                # Cohort/linkage semantics belong to their bound producer
                # admission and fixed route/argv, not this receipt projection.
                report.pop("Cohort", None)
                report.pop("Linkage", None)
                evidence = subject.report_evidence(route, report)
                self.assertEqual(evidence["ClosedBodies"], 8 if route.startswith("CM0/") else 6)
            for field, value in (("Mode", "foreign"), ("Profile", "foreign"),
                                 ("Status", "PASS-but-not-the-fixed-verdict"), ("RequiredCellsSatisfied", False),
                                 ("OutputSealVerified", 1), ("GlobalFreezeQualified", True)):
                with self.subTest(route=route, field=field):
                    report = gate_report(route)
                    report[field] = value
                    with self.assertRaises(subject.Rejected):
                        subject.report_evidence(route, report)
        with tempfile.TemporaryDirectory(prefix="synthetic-replay-producer-binding-") as temporary:
            fixture = PrepareFixture(Path(temporary).resolve())
            original = fixture.groups["PriorJoin"]["Result"]
            subject.require_bindings(original, fixture.row)
            for case in ("receipt", "manifest", "role-order", "foreign-producer"):
                with self.subTest(producer_binding=case):
                    report = copy.deepcopy(original)
                    rows = report["ProducerBindings"]
                    if case == "receipt":
                        rows[0]["ReceiptSha256"] = "0" * 64
                    elif case == "manifest":
                        rows[1]["ArtifactsSha256"] = "0" * 64
                    elif case == "role-order":
                        rows.reverse()
                    else:
                        rows[0]["Build"] = fixture.row["Reference"]["Build"]
                    with self.assertRaises(subject.Rejected):
                        subject.require_bindings(report, fixture.row)
        with tempfile.TemporaryDirectory(prefix="synthetic-replay-child-tree-") as temporary:
            root = Path(temporary).resolve()
            authority = root / "authority.bin"
            authority.write_bytes(b"synthetic input, not a compiled image")
            for case in ("valid", "wrong-manifest", "extra-file", "missing-file", "wrong-report-hash"):
                with self.subTest(case=case):
                    report = gate_report()
                    report["InputHashes"] = {str(authority): sha(authority.read_bytes())}
                    proof = sealed_fixture(root / case, report, {"body.bin": b"synthetic body evidence"})
                    descriptor = dict(Build=str(proof.root), ReceiptSha256=proof.receipt, ArtifactsSha256=proof.artifacts)
                    if case == "wrong-manifest":
                        descriptor["ArtifactsSha256"] = "0" * 64
                    elif case == "extra-file":
                        (proof.root / "extra.bin").write_bytes(b"unplanned")
                    elif case == "missing-file":
                        (proof.root / "body.bin").unlink()
                    elif case == "wrong-report-hash":
                        (proof.root / "results.json").write_bytes(b"{}\n")
                    admission = subject.Admission.__new__(subject.Admission)
                    admission.closure, admission.bundles = subject.Closure(), {}
                    if case == "valid":
                        self.assertEqual(admission.bundle(descriptor)["Result"], report)
                    else:
                        with self.assertRaises(subject.Rejected):
                            admission.bundle(descriptor)

    def test_complete_declared_plan_keeps_2774_unique_keys_and_all_backlog(self):
        before = copy.deepcopy(manifest)
        required = declared_plan()
        identity = ("Cohort", "ArtifactRole", "Representation", "Mode", "Linkage")
        keys = {tuple(row[field] for field in identity) for row in required["RequiredCells"]}
        self.assertEqual(required["RequiredCellCount"], EXPECTED_PLAN_KEYS)
        self.assertEqual(len(required["RequiredCells"]), EXPECTED_PLAN_KEYS)
        self.assertEqual(len(keys), EXPECTED_PLAN_KEYS)
        self.assertEqual(sum(row["Representation"] == "object" for row in required["RequiredCells"]), 730)
        self.assertEqual(sum(row["Representation"] == "final" for row in required["RequiredCells"]), 2044)
        self.assertEqual(len(manifest["cohorts"]), 142)
        self.assertEqual(sum(len(row["artifacts"]) for row in manifest["cohorts"]), 146)
        self.assertEqual(len(manifest["scope_backlog"]), 26)
        self.assertEqual(sum(row["status"] == "Pending" for row in manifest["scope_backlog"]), 23)
        self.assertEqual(sum(row["status"] == "ReferenceOnly" for row in manifest["scope_backlog"]), 3)
        self.assertIs(required["ExpectedOnly"], True)
        self.assertIs(required["GlobalFreezeQualified"], False)
        self.assertTrue(all(row["Execution"] == "NOT_RUN" for row in required["RequiredCells"]))
        self.assertEqual(manifest, before)

    def test_same_buffer_trace_fake_command_and_late_seal_never_promote(self):
        global bootstrap_result
        bootstrap_result = nested_bootstrap_controls(bootstrap_directory)
        self.assertEqual(bootstrap_result["Controls"], 3)
        with tempfile.TemporaryDirectory(prefix="synthetic-replay-lifecycle-") as temporary:
            root = Path(temporary).resolve()
            trace_root = root / "trace"
            trace_root.mkdir()
            gate = subject.ROOT / subject.route_for("CM3/O2/direct")["Gate"]
            trace = subject.Dispatcher.__new__(subject.Dispatcher)
            trace.output, trace.source_snapshot_sha = trace_root, "A" * 64
            trace.sources = {str(gate): dict(Sha256="B" * 64)}
            trace.expected, trace.output_identities = {}, {}
            record = dict(SourceSnapshotSha256=trace.source_snapshot_sha, Entry=str(gate), ExitCode=0,
                          Executed=[dict(Path=str(gate), Sha256="B" * 64)])
            target = trace_root / "trace.json"
            write_json(target, record)
            valid = target.read_bytes()
            trace._trace("trace.json", gate)
            self.assertEqual(trace.expected["trace.json"], sha(valid))
            trace.expected.clear()
            malformed = copy.deepcopy(record)
            malformed["ExitCode"] = 1
            invalid = json.dumps(malformed, sort_keys=True).encode("ascii")
            original_read = Path.read_bytes
            reads = []

            def alternating(path):
                if path == target:
                    values = (invalid, valid, invalid)
                    value = values[min(len(reads), 2)]
                    reads.append(value)
                    return value
                return original_read(path)

            # The old read(A), parse(read(B)), close(A) pattern accepted this.
            # Invalid captured A must reject even when a later read would be valid.
            with patch.object(Path, "read_bytes", autospec=True, side_effect=alternating):
                with self.assertRaisesRegex(subject.Rejected, "normal completion"):
                    trace._trace("trace.json", gate)
            self.assertEqual(reads, [invalid])
            self.assertEqual(trace.expected, {})

            for case in ("valid", "child-failed", "runner-exception", "runner-plus-closing", "missing-report", "invalid-manifest",
                         "unplanned-child", "missing-child", "wrong-mode", "wrong-fingerprint", "late-input",
                         "late-output", "late-closing", "receipt-substitution"):
                with self.subTest(case=case):
                    directory = root / case
                    directory.mkdir()
                    dispatcher, child, fixture = run_fixture(directory, case)
                    original_coverage = dispatcher._coverage

                    def coverage_then_tamper():
                        original_coverage()
                        if case == "late-output":
                            (dispatcher.output / "unplanned.bin").write_bytes(b"late output")
                        elif case == "late-closing":
                            dispatcher.watch.close = Mock(side_effect=subject.Rejected("synthetic final closing failure"))

                    dispatcher._coverage = coverage_then_tamper
                    if case == "receipt-substitution":
                        original_json = dispatcher._json

                        def substituted_json(name, value):
                            result = original_json(name, value)
                            if name == "results.json" and value.get("Status") == "PASS":
                                result.write_bytes(b'{"Status":"PASS","foreign":true}\n')
                            return result

                        dispatcher._json = substituted_json
                    success = dispatcher.run()
                    self.assertIs(success, case == "valid")
                    self.assertEqual(len(child.calls), 1)
                    self.assertEqual(child.calls[0]["Argv"][:6], [str(fixture.interpreter), "-I", "-S", "-B", "-c", subject.BOOTSTRAP])
                    self.assertEqual(len(dispatcher.commands), 1)
                    command = json.loads((dispatcher.output / "commands/00.json").read_bytes())
                    self.assertEqual(command["State"], "TERMINAL")
                    for field in ("Stdout", "Stderr"):
                        self.assertEqual(sha((dispatcher.output / command[field]).read_bytes()), command[field + "Sha256"])
                    retained = json.loads((dispatcher.output / "results.json").read_bytes())
                    self.assertEqual(retained["Status"], "PASS" if success else "FAIL")
                    self.assertIs(retained["GlobalFreezeQualified"], False)
                    self.assertIs(type(retained["RequiredCellsSatisfied"]), int)
                    self.assertEqual(retained["RequiredCellsSatisfied"], 0)
                    artifacts = json.loads((dispatcher.output / "artifacts.json").read_bytes())["Artifacts"]
                    self.assertEqual(set(artifacts), {path.relative_to(dispatcher.output).as_posix()
                        for path in dispatcher.output.rglob("*") if path.is_file() and path != dispatcher.output / "artifacts.json"})
                    for name, value in artifacts.items():
                        self.assertEqual(sha((dispatcher.output / name).read_bytes()), value)
                    if not success:
                        self.assertIs(retained["ComponentsUsable"], False)
                        self.assertIs(retained["InputClosureVerified"], False)
                        self.assertIs(type(retained["PrimaryError"]), str)
                        self.assertTrue(retained["PrimaryError"])
                        self.assertEqual(retained["Error"], retained["PrimaryError"])
                        self.assertIs(type(retained["ClosingErrors"]), list)
                        if case in ("runner-exception", "runner-plus-closing"):
                            self.assertEqual(retained["PrimaryError"], "RuntimeError: synthetic contained-runner failure")
                            self.assertTrue(retained["ClosingErrors"])
                            if case == "runner-plus-closing":
                                self.assertTrue(any("synthetic secondary closing failure" in message
                                    for message in retained["ClosingErrors"]))
                        elif case == "child-failed":
                            self.assertIn("proof gate command failed", retained["PrimaryError"])
                            self.assertIn("synthetic child primary cause", retained["PrimaryError"])
                            self.assertEqual(retained["FailedGate"]["ChildError"], "synthetic child primary cause")
                            self.assertIs(retained["FailedGate"]["ChildReportAuthenticated"], False)
                            self.assertEqual(retained["FailedGate"]["ReportSha256"],
                                sha(Path(retained["FailedGate"]["Report"]).read_bytes()))
                            self.assertTrue(retained["ClosingErrors"])
                        elif case == "wrong-fingerprint":
                            self.assertIn("reachable source fingerprint", retained["PrimaryError"])
                            self.assertTrue(retained["ClosingErrors"])
                        continue
                    self.assertIs(retained["OutputSealVerified"], True)
                    component, = retained["Components"]
                    self.assertIs(component["CurrentSnapshotEligible"], False)
                    self.assertNotEqual(component["SourceInventorySha256"], component["CurrentSourceInventorySha256"])
                    coverage = json.loads((dispatcher.output / "coverage.json").read_bytes())
                    missing = json.loads((dispatcher.output / "missing-work.json").read_bytes())
                    expected = declared_plan()["RequiredCells"]
                    self.assertEqual(len(coverage["Cells"]), EXPECTED_PLAN_KEYS)
                    self.assertEqual(len(missing["Cells"]), EXPECTED_PLAN_KEYS)
                    self.assertEqual([subject._cell_key(row) for row in coverage["Cells"]],
                                     [subject._cell_key(row) for row in expected])
                    self.assertTrue(all(row["Status"] == "PENDING" and row["RequiredCellSatisfied"] is False
                        and type(row["RequiredCellsSatisfied"]) is int and row["RequiredCellsSatisfied"] == 0
                        and row["VerifiedComponentReferences"] == [] for row in coverage["Cells"]))
                    self.assertEqual(sum(bool(row["HistoricalComponentReferences"]) for row in coverage["Cells"]), 1)
                    self.assertTrue(any(row["RouteAvailable"] is False for row in missing["Cells"]))
                    self.assertEqual(missing["Backlog"], manifest["scope_backlog"])
                    with self.assertRaisesRegex(subject.Rejected, "one-shot"):
                        dispatcher.run()

            # Empty/uncompleted state is not a successful dispatcher run.
            empty = subject.Dispatcher.__new__(subject.Dispatcher)
            empty.report, empty.commands, empty.entries = subject.scope_report(), [], []
            empty._completed, empty._started = False, False
            self.assertIs(empty.finish(), False)
            self.assertEqual(empty.report["Status"], "FAIL")


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
        Status="FAIL", Scope="PURE_SYNTHETIC_FREEZE_REPLAY_DISPATCHER_CONTROLS_ONLY",
        Tests=0, ExpectedTestMethods=EXPECTED_METHODS, Failures=0, Errors=0, Skipped=0,
        SourceHashes={}, SourceDrift=[], SourceClosureVerified=False, ClosingFilesVerified=0,
        TestPlan=list(TEST_PLAN), SyntheticInputs=True, ActualReplayExecuted=False,
        ActualCompilerExecuted=False, ActualELFTested=False, ActualMutantsExecuted=0,
        ToolInvocations=0, NativeCommandsExecuted=0, Qualification=False,
        CanonicalProtocolValidated=False, FinalRootRelocationProof=False,
        FinalReferenceParity=False, FullABIProof=False, CompleteObjectProof=False,
        SourceToMachineSemanticProof=False, OriginalTranslationUnitOwnership=False,
        KernelRuntimeProof=False, CpuExecution=False, BoardExecution=False,
        GlobalFreezeQualified=False, RequiredCellSatisfied=False, RequiredCellsSatisfied=0)
    output.mkdir(parents=True, exist_ok=False)
    try:
        if sys.flags.optimize or not __debug__:
            raise ValueError("optimized interpreter unsupported")
        paths = (Path(__file__).resolve(), DISPATCHER, INVENTORY, MANIFEST, CONTRACT, LOADER)
        buffers = {path: path.read_bytes() for path in paths}
        report["SourceHashes"] = {str(path): sha(data) for path, data in buffers.items()}
        global subject, inventory, manifest, loader_buffer, bootstrap_directory, bootstrap_result
        loader_buffer, bootstrap_directory, bootstrap_result = buffers[LOADER], output / "bootstrap", {}
        with patch("subprocess.Popen", side_effect=AssertionError("pure dispatcher controls cannot spawn processes")), \
                patch("os.system", side_effect=AssertionError("pure dispatcher controls cannot execute tools")):
            inventory = load_module("synthetic_freeze_replay_inventory", INVENTORY, buffers[INVENTORY])
            manifest = json.loads(buffers[MANIFEST])
            subject = load_module("synthetic_freeze_replay_dispatcher", DISPATCHER, buffers[DISPATCHER])
            suite = unittest.defaultTestLoader.loadTestsFromTestCase(ReplayTests)
            if suite.countTestCases() != EXPECTED_METHODS:
                raise ValueError("exact twelve implemented replay controls required; skeleton cannot pass")
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
        report["BootstrapControls"] = bootstrap_result
        report["SourceClosureVerified"] = len(report["SourceHashes"]) == 6 and not report["SourceDrift"]
        if not report["SourceClosureVerified"]:
            report["Status"] = "FAIL"
    target = output / "results.json"
    target.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="ascii")
    print("Receipt:", target, sha(target.read_bytes()))
    return 0 if report["Status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
