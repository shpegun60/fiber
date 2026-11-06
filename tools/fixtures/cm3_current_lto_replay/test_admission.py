"""Synthetic current Os-LTO admission controls; no producers or parsers run."""

import argparse
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
ROOT = HERE.parents[2]
SUBJECT = HERE / "os_admission.py"
CONTRACT = HERE / "CONTRACT.md"
RUNNER = HERE / "witness.py"
CAPTURE = HERE.with_name("cm3_current_lto_capture") / "capture.py"
LEGACY = HERE.with_name("cm3_os_lto_join") / "witness.py"
SUBJECT_SHA = "DA5EB7F209A1787A8C909267B258D7E5B835E64B77785ACCF052306D9D91E857"
CONTRACT_SHA = "CDB260181CF3A1E4999E392A7478921198A1B868DC108261390ADBC3E490A0EF"
SOURCE_SHA = "69A66CB09D699EA45A30B21BF4DBCD569CBE637A7770125E76EE64323D862313"
EXPECTED_METHODS = 14
subject = capture = legacy = None
source_buffers = {}


def sha(raw):
    return hashlib.sha256(raw).hexdigest().upper()


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("ascii")


def same(actual, expected, message):
    if encoded(actual) != encoded(expected):
        raise ValueError("synthetic binding: " + message)


def digest(value):
    if type(value) is not str or len(value) != 64 or any(c not in "0123456789ABCDEF" for c in value):
        raise ValueError("synthetic literal SHA256")
    return value


def stable(value):
    if type(value) is not str and not isinstance(value, Path):
        raise ValueError("synthetic literal path")
    return Path(os.path.abspath(value))


def checked_path(value, **unused):
    return stable(value)


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("synthetic duplicate JSON key")
        value[key] = item
    return value


def module(name, path, raw):
    result = importlib.util.module_from_spec(importlib.util.spec_from_file_location(name, path))
    sys.modules[name] = result
    exec(compile(raw, str(path), "exec"), result.__dict__)
    return result


@contextmanager
def no_processes():
    with patch("subprocess.Popen", side_effect=AssertionError("synthetic admission spawned a process")), \
            patch("os.system", side_effect=AssertionError("synthetic admission used a shell")):
        yield


class Watch:
    """Strict in-memory authorities, not a substitute for physical admission."""

    def __init__(self, fixture):
        self.fixture = fixture
        self.hashes, self.buffers, self.trees, self.memberships = {}, {}, {}, {}
        self.denied = set()
        self.close_calls = 0

    def read(self, path, expected=None):
        path = stable(path)
        if path not in self.fixture.memory:
            raise ValueError("synthetic unknown immutable input: " + str(path))
        raw = self.fixture.memory[path]
        actual = sha(raw)
        if expected is not None and actual != expected:
            raise ValueError("synthetic expected input hash mismatch")
        if path in self.hashes and self.hashes[path] != actual:
            raise ValueError("synthetic input drift")
        self.hashes[path] = actual
        if path.suffix == ".py":
            self.buffers[path] = raw
        return raw

    def structured(self, path, expected=None):
        return json.loads(self.read(path, expected), object_pairs_hook=unique_object)

    def tree(self, root, artifacts):
        root = stable(root)
        actual = {path.relative_to(root).as_posix(): sha(raw)
                  for path, raw in self.fixture.memory.items() if path.is_relative_to(root)}
        same(actual, artifacts, "complete synthetic tree")
        self.trees[root] = dict(artifacts)
        self.memberships[root] = set(artifacts)
        for name, expected in artifacts.items():
            self.read(root / name, expected)

    def close(self):
        self.close_calls += 1
        if self.fixture.fail_close:
            raise ValueError("synthetic closing refusal")
        for path, expected in tuple(self.hashes.items()):
            self.read(path, expected)
        for root, artifacts in tuple(self.trees.items()):
            self.tree(root, artifacts)


def descriptor(root, first, second):
    return dict(Build=str(root), ReceiptSha256=first * 64, ArtifactsSha256=second * 64)


class Fixture:
    """Invented receipts and mocked validators; binary files only test aliasing."""

    def __init__(self, root):
        self.root, self.events, self.memory = root, [], dict(source_buffers)
        self.fail_close = False
        self.sources = {path: self.memory[path] for path in (SUBJECT, CONTRACT, RUNNER, CAPTURE, LEGACY)}
        self.outer = Watch(self)
        self.current_descriptor = descriptor(root / "inventory", "A", "B")
        self.current = dict(Bundle=dict(Root=root / "inventory", Descriptor=self.current_descriptor),
            SourceInventorySha256=SOURCE_SHA, Required=dict(RequiredCellCount=2774))
        self.args = SimpleNamespace(inventory=self.current_descriptor["Build"],
            inventory_receipt_sha256="A" * 64, inventory_artifacts_sha256="B" * 64,
            output_dir=str(root / "output"))
        self.bundles, self.environments, self.catalogs = {}, {}, {}
        self.git, self.interpreter = root / "installed/Git/cmd/git.exe", root / "host/python.exe"
        self.memory[self.git], self.memory[self.interpreter] = b"synthetic Git provenance", b"synthetic host"
        self.ledger = root / "inventory/inputs/FREERTOS_ASM_PARITY.md"
        self.memory[self.ledger] = b"# Synthetic captured master ledger\nNot root evidence.\n"
        policy = ROOT / legacy.POLICY
        self.memory[policy] = b"synthetic policy, never interpreted"
        fixed = {
            legacy.PRODUCER: b"# synthetic immutable recipe, never executed\n",
            "tools/fixtures/cm3_lto_protocol/protocol.py": b"# synthetic fixed helper\n",
        }
        for relative, raw in fixed.items():
            self.memory[ROOT / relative] = raw
        self.api = SimpleNamespace(regular=stable, checked_path=checked_path, digest_text=digest,
            same=same, unique_object=unique_object, COHORT=capture.COHORT)
        self.recipe = SimpleNamespace(SyntheticRecipe=True)

        for side, receipt, manifest in (("Native", "C", "D"), ("Reference", "E", "F")):
            prefix, build = side.lower(), root / side.lower()
            build.mkdir()
            capture_descriptor = descriptor(build, receipt, manifest)
            for field, value in (("build", str(build)), ("receipt_sha256", receipt * 64),
                                 ("artifacts_sha256", manifest * 64)):
                setattr(self.args, prefix + "_" + field, value)
            seed_descriptor = descriptor(root / (prefix + "-seed"), "1" if side == "Native" else "3",
                                         "2" if side == "Native" else "4")
            model = capture.select(prefix, "Os-lto")
            result = dict(model)
            result.update(Status="PASS", Scope=model["Scope"], CaptureContract=capture.CONTRACT,
                CurrentCaptureRoute=model["Route"], SourceInventorySha256=SOURCE_SHA,
                Error=None, PrimaryError=None, ClosingErrors=[], InputClosureVerified=True,
                OutputSealVerified=True, Linkage="direct", LTO=True, RequiredCellSatisfied=False,
                RequiredCellsSatisfied=0, RequiredCellCount=2774, SeedMode="O2", SeedSide=side,
                SavedMachineObjects=2, FinalExecutableLinks=2,
                Sources=[dict(Object=str(build / ("objects/%02d-synthetic.o" % i)))
                         for i in range(model["TranslationUnits"])],
                Links=[dict(Kind="ordinary"), dict(Kind="emit-relocs")],
                TwinLoadImageCompared=True, TwinLoadImageIdentical=True,
                TwinAllocatedSectionsIdentical=True, TwinLoadImages=dict(Identical=True),
                Commands=[dict(State="TERMINAL", Status="PASS", Exit=0, TimedOut=False, Error=None)
                          for _ in range(model["DriverCommands"])],
                ReferenceBuilt=side == "Reference", ReferenceCommit=legacy.PIN,
                OptimizationTransform=dict(Original="-O2", Captured="-Os", OtherSeedFlagsUnchanged=True),
                CaptureProducer=dict(Path=str(CAPTURE), Sha256=sha(self.sources[CAPTURE])),
                CurrentInventory=copy.deepcopy(self.current_descriptor),
                SourceInventoryReceipt=str(self.current["Bundle"]["Root"]),
                SeedBuild=seed_descriptor["Build"], SeedReceiptSha256=seed_descriptor["ReceiptSha256"],
                SeedArtifactsSha256=seed_descriptor["ArtifactsSha256"], SeedAuthority=copy.deepcopy(seed_descriptor))
            result.update(dict.fromkeys(capture.NONCLAIMS, False))
            roles = dict(Machine=build / "emit-relocs/image.elf.ltrans0.ltrans.o",
                Final=build / "emit-relocs/image.elf", Disassembly=build / "emit-relocs/image.elf.dis",
                LinkMap=build / "emit-relocs/image.map", Startup=Path(result["Sources"][-1]["Object"]),
                Plain=build / "ordinary/image.elf", MachineDisassembly=build / "emit-relocs/image.elf.ltrans0.ltrans.o.dis")
            artifacts = {}
            for role, path in roles.items():
                path.parent.mkdir(parents=True, exist_ok=True)
                raw = (side + ":" + role + ":synthetic not ELF\n").encode("ascii")
                path.write_bytes(raw)
                self.memory[path] = raw
                artifacts[path.relative_to(build).as_posix()] = sha(raw)
            original = root / "source-inputs" / prefix / "provider.py"
            copied = build / "inputs/provider.py"
            self.memory[original] = self.memory[copied] = b"# synthetic source, not executed\n"
            artifacts[copied.relative_to(build).as_posix()] = sha(self.memory[copied])
            catalog = dict(Files=[dict(Original=str(original), Captured=str(copied), Sha256=sha(self.memory[copied]))],
                           Watched=[dict(Path=str(original), Sha256=sha(self.memory[original]))])
            self.catalogs[side] = catalog
            self.memory[build / "inputs.json"] = encoded(catalog)
            artifacts["inputs.json"] = sha(self.memory[build / "inputs.json"])
            result["ClosingFilesVerified"] = 1
            self.bundles[side] = dict(Root=build, Result=result, Artifacts=artifacts, Descriptor=capture_descriptor)
            guard, closure = Watch(self), Watch(self)
            helper = Path(seed_descriptor["Build"]) / "source/synthetic-seed.py"
            self.memory[helper] = b"# synthetic Seed buffer, not executed\n"
            closure.tree(helper.parent, {helper.name: sha(self.memory[helper])})
            guard.read(helper)
            originals = {self.ledger: dict(Sha256=sha(self.memory[self.ledger]))}
            if side == "Reference":
                originals[self.git] = dict(Sha256=sha(self.memory[self.git]))
                closure.read(self.git)
            seed = SimpleNamespace(root=Path(seed_descriptor["Build"]), inventory=root / "inventory",
                closure=closure, buffers={helper: self.memory[helper]}, originals=originals,
                commands=[dict(Label="reference git rev-parse", Argv=[str(self.git)]) for _ in range(2)])
            self.environments[side] = dict(Watch=guard, Seed=seed, Current=self.current,
                Group=dict(Descriptor=seed_descriptor), Producer=copy.deepcopy(result["CaptureProducer"]))

        fixture = self

        class Base(legacy.Witness):
            def __init__(self, args):
                raise AssertionError("old constructor must not run")

            def _commands(self, side, group, producer):
                fixture.events.append("commands:" + side)
                if producer is not fixture.recipe:
                    raise AssertionError("fixed recipe identity lost")
                if fixture.command_error:
                    raise ValueError("synthetic inherited command rejection")

            def _physical(self, path):
                return (1, list(fixture.memory).index(path) + 1, 1)

        self.command_error = False
        self.legacy = SimpleNamespace(__file__=str(LEGACY), ROOT=ROOT, Witness=Base, stable=stable,
            FIXED={name: sha(raw) for name, raw in fixed.items()}, PRODUCER=legacy.PRODUCER,
            POLICY=legacy.POLICY, POLICY_SHA=sha(self.memory[policy]), PIN=legacy.PIN, sys=sys,
            load=Mock(return_value=self.recipe), interpreter_path=Mock(return_value=self.interpreter))
        self.admission = SimpleNamespace(snapshot=Mock(side_effect=self.snapshot), bundle=Mock(side_effect=self.bundle),
            require_inventory_binding=Mock(side_effect=self.inventory_binding))
        self.replay = SimpleNamespace(checked_path=checked_path, digest=digest,
                                     Admission=Mock(return_value=self.admission))
        self.capture = SimpleNamespace(__file__=str(CAPTURE), ROOT=ROOT,
            load_environment=Mock(return_value=(dict(api=self.api, replay=self.replay), self.outer)),
            select=capture.select, require_capture=Mock(wraps=capture.require_capture),
            prepare=Mock(side_effect=self.prepare), CombinedClosure=capture.CombinedClosure)

    def snapshot(self, selected, *, current=False):
        self.events.append("snapshot")
        same(selected, self.current_descriptor, "caller inventory descriptor")
        if current is not True:
            raise AssertionError("independent current inventory required")
        return self.current

    def bundle(self, selected):
        for side, bundle in self.bundles.items():
            if selected["Build"] == bundle["Descriptor"]["Build"]:
                self.events.append("bundle:" + side)
                same(selected, bundle["Descriptor"], "caller capture descriptor")
                return bundle
        raise ValueError("synthetic foreign capture")

    def inventory_binding(self, bundle, current, *, required=False):
        self.events.append("binding:" + bundle["Result"]["SeedSide"])
        if required is not True:
            raise AssertionError("capture inventory admission must be mandatory")
        same(bundle["Result"]["SourceInventorySha256"], current["SourceInventorySha256"], "nested inventory")

    def prepare(self, args):
        side = args.side.capitalize()
        self.events.append("prepare:" + side)
        environment = self.environments[side]
        wanted = environment["Group"]["Descriptor"]
        same(vars(args), dict(side=side.lower(), mode="Os-lto", seed_build=wanted["Build"],
            seed_receipt_sha256=wanted["ReceiptSha256"], seed_artifacts_sha256=wanted["ArtifactsSha256"],
            inventory=self.current_descriptor["Build"], inventory_receipt_sha256="A" * 64,
            inventory_artifacts_sha256="B" * 64, output_dir=self.args.output_dir), "prepared Seed arguments")
        return environment

    def update_catalog(self, side):
        bundle = self.bundles[side]
        path = bundle["Root"] / "inputs.json"
        self.memory[path] = encoded(self.catalogs[side])
        bundle["Artifacts"]["inputs.json"] = sha(self.memory[path])

    def construct(self):
        return subject.witness_type(self.legacy, self.capture, extra_sources=self.sources)(self.args)

    def rejected(self, case, mutate, pattern=None):
        mutate(self)
        before = {path.relative_to(self.root).as_posix() for path in self.root.rglob("*")}
        try:
            self.construct()
        except (ValueError, KeyError, TypeError) as error:
            if pattern is not None:
                case.assertRegex(str(error), pattern)
        else:
            case.fail("invalid synthetic admission accepted")
        case.assertEqual({path.relative_to(self.root).as_posix() for path in self.root.rglob("*")}, before)


class AdmissionTests(unittest.TestCase):
    def cases(self, variants):
        for name, mutate in variants:
            with self.subTest(rejected=name), tempfile.TemporaryDirectory() as directory:
                Fixture(Path(directory)).rejected(self, mutate)

    def test_factory_inherits_complete_replay_without_overrides(self):
        selected = {path: source_buffers[path] for path in (SUBJECT, CONTRACT, RUNNER, CAPTURE, LEGACY)}
        derived = subject.witness_type(legacy, capture, extra_sources=selected)
        self.assertEqual(derived.__bases__, (legacy.Witness,))
        methods = {name for name, value in derived.__dict__.items() if callable(value)}
        self.assertEqual(methods, {"__init__"})
        for name in ("_buffer", "_tree", "_roles", "_commands", "_physical", "_read", "_seal", "close", "run"):
            self.assertIs(getattr(derived, name), getattr(legacy.Witness, name))

    def test_factory_requires_fixed_module_names_and_complete_immutable_sources(self):
        with tempfile.TemporaryDirectory() as directory:
            f = Fixture(Path(directory))
            for removed in tuple(f.sources):
                with self.subTest(missing=removed), self.assertRaisesRegex(ValueError, "buffers required"):
                    subject.witness_type(f.legacy, f.capture,
                        extra_sources={path: raw for path, raw in f.sources.items() if path != removed})
            for value in (None, {}, [], {str(SUBJECT): bytearray(b"not immutable")}):
                with self.subTest(shape=repr(value)), self.assertRaises(ValueError):
                    subject.witness_type(f.legacy, f.capture, extra_sources=value)
            duplicate = dict(f.sources)
            duplicate[str(SUBJECT)] = duplicate[SUBJECT]
            with self.assertRaisesRegex(ValueError, "unique immutable"):
                subject.witness_type(f.legacy, f.capture, extra_sources=duplicate)
            for item, field, replacement in ((f.legacy, "__file__", str(ROOT / "foreign.py")),
                    (f.capture, "__file__", str(ROOT / "foreign.py")), (f.capture, "ROOT", f.root)):
                with self.subTest(field=field), patch.object(item, field, replacement):
                    with self.assertRaisesRegex(ValueError, "fixed module source identities"):
                        subject.witness_type(f.legacy, f.capture, extra_sources=f.sources)
            derived = subject.witness_type(f.legacy, f.capture, extra_sources=f.sources)
            f.sources.clear()
            with self.assertRaisesRegex(ValueError, "must not run"):
                # The copied source map must survive caller mutation; this sentinel
                # is reached only after the factory has retained its own mapping.
                with patch.object(f.capture, "load_environment", side_effect=ValueError("must not run")):
                    derived(f.args)
            self.assertFalse((f.root / "output").exists())

    def test_constructor_admits_inventory_captures_and_prepares_both_seeds(self):
        with tempfile.TemporaryDirectory() as directory:
            f = Fixture(Path(directory))
            derived = subject.witness_type(f.legacy, f.capture, extra_sources=f.sources)
            f.sources.clear()
            witness = derived(f.args)
            self.assertIs(witness.replay_api, f.replay)
            self.assertEqual(f.events, ["snapshot", "bundle:Native", "binding:Native", "bundle:Reference",
                "binding:Reference", "prepare:Native", "prepare:Reference", "commands:Native", "commands:Reference"])
            f.admission.snapshot.assert_called_once_with(f.current_descriptor, current=True)
            self.assertEqual(f.admission.bundle.call_count, 2)
            self.assertTrue(all(call.kwargs == {"required": True}
                                for call in f.admission.require_inventory_binding.call_args_list))
            self.assertEqual(f.capture.prepare.call_count, 2)
            self.assertEqual([call.args[1] for call in f.capture.require_capture.call_args_list],
                             [capture.select("native", "Os-lto"), capture.select("reference", "Os-lto")])
            self.assertTrue(all(call.kwargs == {"sealed": True}
                                for call in f.capture.require_capture.call_args_list))
            self.assertEqual(list(witness.groups), ["Native", "Reference"])
            self.assertEqual(len(witness.identities), len(witness.watch.hashes))
            for side in ("Native", "Reference"):
                group, environment = witness.groups[side], f.environments[side]
                self.assertIs(group["Seed"], environment["Seed"])
                self.assertEqual(list(group["Roles"]), list(legacy.ROLES))
                self.assertEqual(group["Package"], environment["Seed"].root / "python/elftools")
                self.assertIn(environment["Seed"].root / "source", f.outer.trees)
                self.assertGreater(environment["Seed"].closure.close_calls, 0)
            self.assertEqual(witness.groups["Native"]["MasterLedgerBytes"],
                             witness.groups["Reference"]["MasterLedgerBytes"])
            self.assertEqual(witness.expected, {"results.json", "artifacts.json"})
            self.assertEqual(witness.report["Status"], "FAIL")
            self.assertEqual(witness.report["Mode"], "Os-lto")
            self.assertEqual(witness.report["RequiredCellCount"], 2774)
            self.assertIs(type(witness.report["RequiredCellsSatisfied"]), int)
            self.assertEqual(witness.report["RequiredCellsSatisfied"], 0)
            for field in ("RequiredCellSatisfied", "CanonicalProtocolValidated", "FinalRootRelocationProof",
                          "FullABIProof", "PolicyEquivalence", "OriginalTranslationUnitOwnership",
                          "ProducerCompilersReexecuted", "MutantsReexecuted", "GlobalFreezeQualified"):
                self.assertIs(witness.report[field], False)
            self.assertFalse(witness.output.exists())

    def test_caller_descriptors_and_literal_hash_types_rejected(self):
        variants = []
        for prefix in ("inventory", "native", "reference"):
            for suffix in ("receipt_sha256", "artifacts_sha256"):
                field = prefix + "_" + suffix
                for value in ("0" * 64, True, "bad"):
                    variants.append((field + repr(value),
                                     lambda f, field=field, value=value: setattr(f.args, field, value)))
        variants.extend((prefix + " foreign root", lambda f, prefix=prefix:
            setattr(f.args, prefix + "_build", str(f.root / "foreign"))) for prefix in ("native", "reference"))
        self.cases(variants)

    def test_inventory_cut_plan_and_nested_authority_rejected(self):
        self.cases((
            ("foreign current fingerprint", lambda f: f.current.update(SourceInventorySha256="0" * 64)),
            ("float plan count", lambda f: f.current["Required"].update(RequiredCellCount=2774.0)),
            ("bool plan count", lambda f: f.current["Required"].update(RequiredCellCount=True)),
            ("missing planned key", lambda f: f.current["Required"].update(RequiredCellCount=2773)),
            ("nested E8", lambda f: f.bundles["Reference"]["Result"].update(SourceInventorySha256="8" * 64)),
            ("current descriptor hash", lambda f: f.bundles["Native"]["Result"]["CurrentInventory"].update(ReceiptSha256="0" * 64)),
            ("current descriptor extra", lambda f: f.bundles["Native"]["Result"]["CurrentInventory"].update(Extra=True)),
            ("inventory path", lambda f: f.bundles["Reference"]["Result"].update(SourceInventoryReceipt=str(f.root / "foreign"))),
            ("same capture root", lambda f: f.bundles["Reference"].update(Root=f.bundles["Native"]["Root"])),
        ))

    def test_capture_side_mode_transform_and_literal_nonclaims_rejected(self):
        changes = (("Mode", "O2-lto"), ("Profile", "CM4"), ("SeedMode", "Os"),
            ("SeedSide", "native"), ("LTO", 1), ("FinalExecutableLinks", 2.0),
            ("RequiredCellsSatisfied", False), ("RequiredCellCount", 2774.0),
            ("OutputSealVerified", False), ("SourceIRProof", True), ("OriginalTranslationUnitOwnership", True),
            ("CanonicalProtocolValidated", True), ("Error", "not successful"),
            ("CaptureProducer", dict(Path=str(CAPTURE), Sha256="0" * 64)),
            ("OptimizationTransform", dict(Original="-O2", Captured="-Os", OtherSeedFlagsUnchanged=1)),
            ("OptimizationTransform", dict(Original="-O2", Captured="-O3", OtherSeedFlagsUnchanged=True)))
        self.cases([(field, lambda f, field=field, value=value:
            f.bundles["Native"]["Result"].update({field: value})) for field, value in changes] + [
            ("reference pin", lambda f: f.bundles["Reference"]["Result"].update(ReferenceCommit="0" * 40)),
            ("incomplete commands", lambda f: f.bundles["Native"]["Result"]["Commands"].pop()),
            ("pending attempt", lambda f: f.bundles["Reference"]["Result"]["Commands"][0].update(State="ATTEMPT")),
        ])

    def test_prepared_seed_authorities_sources_and_inventory_rejected(self):
        self.cases((
            ("seed metadata hash", lambda f: f.bundles["Native"]["Result"]["SeedAuthority"].update(ReceiptSha256="0" * 64)),
            ("seed descriptor extra", lambda f: f.bundles["Reference"]["Result"]["SeedAuthority"].update(Extra=True)),
            ("foreign seed build", lambda f: f.bundles["Reference"]["Result"].update(SeedBuild=str(f.root / "old-seed"))),
            ("different prepared inventory", lambda f: f.environments["Reference"].update(Current=dict(Bundle=dict(Descriptor={})))),
            ("different prepared seed", lambda f: f.environments["Native"].update(Group=dict(Descriptor={}))),
            ("different prepared producer", lambda f: f.environments["Reference"].update(Producer={})),
            ("foreign seed inventory", lambda f: setattr(f.environments["Reference"]["Seed"], "inventory", f.root / "other")),
        ))

    def test_capture_catalogs_require_unique_bound_original_and_captured_bytes(self):
        def catalog_change(f, change):
            change(f.catalogs["Reference"])
            f.update_catalog("Reference")

        self.cases((
            ("duplicate provider", lambda f: catalog_change(f, lambda c: c["Files"].append(copy.deepcopy(c["Files"][0])))),
            ("empty provider catalog", lambda f: catalog_change(f, lambda c: c.update(Files=[]))),
            ("extra provider key", lambda f: catalog_change(f, lambda c: c["Files"][0].update(Extra=True))),
            ("foreign original", lambda f: catalog_change(f, lambda c: c["Files"][0].update(Original=str(f.root / "unknown.py")))),
            ("foreign captured", lambda f: catalog_change(f, lambda c: c["Files"][0].update(Captured=str(f.root / "outside.py")))),
            ("captured hash mismatch", lambda f: catalog_change(f, lambda c: c["Files"][0].update(Sha256="0" * 64))),
            ("original changed", lambda f: f.memory.update({Path(f.catalogs["Reference"]["Files"][0]["Original"]): b"changed"})),
            ("captured changed", lambda f: f.memory.update({Path(f.catalogs["Reference"]["Files"][0]["Captured"]): b"changed"})),
        ))

    def test_closing_catalog_counts_and_watched_members_exact(self):
        def catalog_change(f, change):
            change(f.catalogs["Native"])
            f.update_catalog("Native")

        self.cases((
            ("float closing count", lambda f: f.bundles["Native"]["Result"].update(ClosingFilesVerified=1.0)),
            ("bool closing count", lambda f: f.bundles["Native"]["Result"].update(ClosingFilesVerified=True)),
            ("wrong closing count", lambda f: f.bundles["Native"]["Result"].update(ClosingFilesVerified=2)),
            ("empty watched", lambda f: catalog_change(f, lambda c: c.update(Watched=[]))),
            ("duplicate watched", lambda f: catalog_change(f, lambda c: c["Watched"].append(copy.deepcopy(c["Watched"][0])))),
            ("extra watched field", lambda f: catalog_change(f, lambda c: c["Watched"][0].update(Extra=True))),
            ("watched hash", lambda f: catalog_change(f, lambda c: c["Watched"][0].update(Sha256="0" * 64))),
        ))

    def test_same_master_ledger_and_distinct_machines_required(self):
        def same_machine(f):
            n = f.bundles["Native"]["Root"] / "emit-relocs/image.elf.ltrans0.ltrans.o"
            r = f.bundles["Reference"]["Root"] / "emit-relocs/image.elf.ltrans0.ltrans.o"
            f.memory[r] = f.memory[n]
            f.bundles["Reference"]["Artifacts"][r.relative_to(f.bundles["Reference"]["Root"]).as_posix()] = sha(f.memory[r])

        self.cases((
            ("unowned master ledger", lambda f: f.environments["Reference"]["Seed"].originals.pop(f.ledger)),
            ("changed ledger pin", lambda f: f.environments["Reference"]["Seed"].originals[f.ledger].update(Sha256="0" * 64)),
            ("ledger byte drift", lambda f: f.memory.update({f.ledger: b"different master ledger"})),
            ("same machine bytes", same_machine),
        ))

    def test_cross_role_hardlinks_and_role_escape_rejected(self):
        def alias(f):
            first = f.bundles["Native"]["Root"] / "emit-relocs/image.elf.dis"
            other = f.bundles["Reference"]["Root"] / "emit-relocs/image.elf.dis"
            other.unlink()
            os.link(first, other)

        self.cases((
            ("physical cross-side alias", alias),
            ("startup escaped capture", lambda f: f.bundles["Native"]["Result"]["Sources"][-1].update(
                Object=str(f.bundles["Reference"]["Root"] / "emit-relocs/image.elf"))),
            ("swapped twin order", lambda f: f.bundles["Native"]["Result"]["Links"].reverse()),
        ))

    def test_fixed_helper_bootstrap_and_seed_buffers_remain_bound(self):
        def changed_seed_buffer(f):
            seed = f.environments["Reference"]["Seed"]
            path = next(iter(seed.buffers))
            seed.buffers[path] = b"different declared buffer"

        self.cases((
            ("executed adapter source", lambda f: f.memory.update({SUBJECT: b"different adapter"})),
            ("fixed source pin", lambda f: f.memory.update({ROOT / f.legacy.PRODUCER: b"different recipe"})),
            ("policy pin", lambda f: f.memory.update({ROOT / f.legacy.POLICY: b"different policy"})),
            ("Seed buffer mismatch", changed_seed_buffer),
        ))

    def test_output_overlap_and_existing_output_rejected(self):
        self.cases((
            ("repository", lambda f: setattr(f.args, "output_dir", str(ROOT / "never-created-admission-test"))),
            ("capture descendant", lambda f: setattr(f.args, "output_dir", str(f.bundles["Native"]["Root"] / "new-output"))),
            ("seed descendant", lambda f: setattr(f.args, "output_dir", str(f.environments["Reference"]["Seed"].root / "source/new-output"))),
            ("explicit denied tree", lambda f: (f.outer.denied.add(f.root / "denied"),
                 setattr(f.args, "output_dir", str(f.root / "denied/new-output")))),
            ("existing output", lambda f: (f.root / "output").mkdir()),
        ))

    def test_inherited_command_and_final_close_fail_before_output(self):
        self.cases((
            ("inherited recipe rejection", lambda f: setattr(f, "command_error", True)),
            ("closing refusal", lambda f: setattr(f, "fail_close", True)),
            ("missing Git provenance", lambda f: f.environments["Reference"]["Seed"].commands.pop()),
            ("unowned Git", lambda f: f.environments["Reference"]["Seed"].originals.pop(f.git)),
        ))


def main(cli=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(cli)
    output, temporary = stable(args.output_dir), Path(tempfile.gettempdir()).resolve()
    if (output.exists() or args.output_dir.is_symlink() or not output.is_relative_to(temporary)
            or output.is_relative_to(ROOT) or ROOT.is_relative_to(output)):
        parser.error("fresh external TEMP output directory required")
    report = dict(Status="FAIL", Tests=0, ExpectedTestMethods=EXPECTED_METHODS, Failures=0, Errors=0, Skipped=0,
        Scope="PURE_SYNTHETIC_CURRENT_CM3_OS_LTO_ADMISSION_CONTROLS_ONLY", SyntheticInputs=True,
        AdmissionAndSeedPreparationMocked=True, CommandReplayMocked=True, ActualCaptureAdmitted=False,
        ActualELFTested=False, ActualParserExecuted=False, ToolInvocations=0, NativeCommandsExecuted=0,
        Qualification=False, CanonicalProtocolValidated=False, FinalRootRelocationProof=False,
        FullABIProof=False, PolicyEquivalence=False, CpuExecution=False, BoardExecution=False,
        GlobalFreezeQualified=False, RequiredCellSatisfied=False, RequiredCellsSatisfied=0,
        SourceHashes={}, SourceDrift=[], ClosingFilesVerified=0, SourceClosureVerified=False)
    paths = (Path(__file__).resolve(), SUBJECT, CONTRACT, RUNNER, CAPTURE, LEGACY)
    try:
        if sys.flags.optimize or not __debug__:
            raise ValueError("unoptimized host Python required")
        global subject, capture, legacy, source_buffers
        source_buffers = {path: path.read_bytes() for path in paths}
        report["SourceHashes"] = {str(path): sha(raw) for path, raw in source_buffers.items()}
        if sha(source_buffers[SUBJECT]) != SUBJECT_SHA or sha(source_buffers[CONTRACT]) != CONTRACT_SHA:
            raise ValueError("assigned frozen adapter and contract bytes required")
        with no_processes():
            subject = module("_synthetic_current_os_admission", SUBJECT, source_buffers[SUBJECT])
            capture = module("_synthetic_current_capture_predicates", CAPTURE, source_buffers[CAPTURE])
            legacy = module("_synthetic_legacy_os_interfaces", LEGACY, source_buffers[LEGACY])
            suite = unittest.defaultTestLoader.loadTestsFromTestCase(AdmissionTests)
            if suite.countTestCases() != EXPECTED_METHODS:
                raise ValueError("exactly fourteen bounded admission controls required")
            result = unittest.TextTestRunner(verbosity=2).run(suite)
        report.update(Tests=result.testsRun, Failures=len(result.failures), Errors=len(result.errors),
            Skipped=len(result.skipped), FailureDetails=[dict(Test=str(case), Detail=detail)
                for case, detail in result.failures + result.errors])
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
        report["SourceClosureVerified"] = len(report["SourceHashes"]) == len(paths) and not report["SourceDrift"]
        if not report["SourceClosureVerified"]:
            report["Status"] = "FAIL"
    output.mkdir(parents=True, exist_ok=False)
    target = output / "results.json"
    target.write_bytes(encoded(report))
    print("Receipt:", target, sha(target.read_bytes()))
    return 0 if report["Status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
