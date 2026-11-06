"""Pure synthetic constructor controls, not actual reference-seed admission.

All seed files, closures, validators and qualified helper stages are mocked.
Only these test/adapter sources and two pinned legacy sources are read as
host data. No compiler, target, producer or real Seed constructor is run.
"""
import argparse
import ast
from contextlib import nullcontext
import copy
import hashlib
import json
import os
from pathlib import Path, PureWindowsPath
import re
import sys
import tempfile
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import patch


HERE = Path(__file__).absolute().parent
REPO = HERE.parents[2]
ADAPTER = HERE / "admission.py"
LEGACY = HERE.with_name("cm3_reference_lto_transport") / "admission.py"
LOADER = HERE.with_name("cm3_final_roots") / "reference_witness.py"
BUFFERS = {}
a = legacy = None
PHASES = ("validate_scope", "validate_inventory", "validate_commands", "validate_reference",
          "validate_recipe", "validate_sources", "validate_links", "validate_prelink")


def need(ok, message):
    if not ok:
        raise ValueError(message)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")


def sha(raw):
    return hashlib.sha256(raw).hexdigest().upper()


def same(left, right, message):
    need(encoded(left) == encoded(right), message)


def digest(value):
    need(type(value) is str and re.fullmatch("[A-F0-9]{64}", value) is not None, "literal SHA256")
    return value


def checked(path, must_exist=True):
    need(isinstance(path, (str, Path)), "literal path")
    return Path(os.path.abspath(os.fspath(path)))


def portable(name):
    need(type(name) is str and name and "\\" not in name and not PureWindowsPath(name).drive
         and not Path(name).is_absolute() and all(p not in ("", ".", "..") for p in name.split("/")), "portable member")
    return Path(name)


class Closure:
    def __init__(self, fixture):
        self.f = fixture
        self.reads, self.trees = [], []
        self.closed = False

    def read(self, path, expected=None):
        path = checked(path)
        self.reads.append((path, expected))
        need(path in self.f.payload, "unknown synthetic input")
        value = self.f.payload[path]
        if expected is not None:
            need(sha(value) == digest(expected), "synthetic authenticated hash mismatch")
        return value

    def structured(self, path, expected):
        return json.loads(self.read(path, expected))

    def tree(self, root, hashes):
        root = checked(root)
        self.trees.append(root)
        actual = {p.relative_to(root).as_posix() for p in self.f.payload if p.is_relative_to(root)}
        same(sorted(actual), sorted(hashes), "synthetic complete tree")
        for name, value in hashes.items():
            self.read(root / portable(name), value)

    def close(self):
        self.f.events.append("close")
        need(not self.f.close_failure, "synthetic closing failure")
        self.closed = True


class Fixture:
    def __init__(self):
        self.base = Path(tempfile.gettempdir()).absolute() / "cm3-current-seed-synthetic-only"
        self.root, self.inventory = self.base / "caller-seed", self.base / "inventory"
        self.interpreter, self.api_path = self.base / "python/python.exe", self.base / "api/probe.py"
        self.events, self.closures, self.loaded = [], [], []
        self.fail_phase, self.close_failure, self.extra_helper_read = None, False, None
        self.payload = dict(BUFFERS)
        self.payload[self.interpreter] = b"synthetic interpreter, not executable"
        self.payload[self.api_path] = b"synthetic trusted API boundary"
        module = self.root / "source/synthetic.py"
        origin = REPO / "synthetic.py"
        inv_result = encoded({"SyntheticInventory": True})
        inv_manifest = encoded({"Artifacts": {"results.json": sha(inv_result)}})
        records = ((origin, module, b"immutable = True\n"),
                   (self.inventory / "results.json", self.root / "inventory-result.json", inv_result),
                   (self.inventory / "artifacts.json", self.root / "inventory-manifest.json", inv_manifest))
        self.inputs = {"Files": [], "Generated": {str(self.root / "fixture/generated.h"): sha(b"generated\n")}}
        self.members = []
        for original, captured, raw in records:
            self.payload[original] = self.payload[captured] = raw
            self.inputs["Files"].append(dict(Original=str(original), Captured=str(captured), Sha256=sha(raw)))
            self.members.append(captured)
        generated = self.root / "fixture/generated.h"
        self.payload[generated] = b"generated\n"
        self.members.append(generated)
        self.result = {"SourceInventoryReceipt": str(self.inventory)}
        self.args = SimpleNamespace(reference_build=str(self.root), reference_receipt_sha256=None,
                                    reference_artifacts_sha256=None, output_dir=str(self.base / "fresh-output"))
        self.api = SimpleNamespace(need=need, same=same, digest_text=digest, sha=sha,
            regular=checked, checked_path=checked, portable_name=portable, REPO=REPO, __file__=str(self.api_path),
            Closure=self.closure, load_buffer=self.load_buffer)
        self.refresh()
        parent = a.seed_type(legacy)
        fixture = self

        class Traced(parent):
            def module(self, relative):
                fixture.events.append("module:" + relative)
                if relative == legacy.CLASSIC + "run.py":
                    return SimpleNamespace(interpreter_path=lambda: fixture.interpreter_path())
                return SimpleNamespace()

        for name in PHASES:
            def phase(seed, name=name):
                fixture.events.append(name)
                need(fixture.fail_phase != name, "synthetic phase failure: " + name)
                if name == "validate_commands":
                    seed.tool_root = fixture.base / "tools"
                if name == "validate_reference":
                    seed.reference_root = fixture.base / "freertos"
            setattr(Traced, name, phase)
        self.seed_class = Traced

    def refresh(self):
        self.payload[self.root / "results.json"] = encoded(self.result)
        self.payload[self.root / "inputs.json"] = encoded(self.inputs)
        self.manifest = {"Artifacts": {p.relative_to(self.root).as_posix(): sha(self.payload[p])
            for p in [*self.members, self.root / "results.json", self.root / "inputs.json"]}}
        self.args.reference_receipt_sha256 = sha(self.payload[self.root / "results.json"])
        self.seal_manifest()

    def seal_manifest(self):
        raw = encoded(self.manifest)
        self.payload[self.root / "artifacts.json"] = raw
        self.args.reference_artifacts_sha256 = sha(raw)

    def closure(self):
        value = Closure(self)
        self.closures.append(value)
        return value

    def interpreter_path(self):
        self.events.append("interpreter")
        return self.interpreter

    def load_buffer(self, name, path, raw):
        need(name == "cm3_reference_lto_immutable_loader" and checked(path) == LOADER
             and raw == BUFFERS[LOADER], "only authenticated synthetic loader boundary")
        self.events.append("loader")
        self.loaded.append((name, checked(path), sha(raw)))
        fixture = self

        class Frozen:
            def __init__(self, buffers):
                self.buffers = dict(buffers)

            def active(self):
                return nullcontext()

            def load(self, name, path):
                # Exercise the inherited immutable-read callback, not Python execution.
                raw = Path(path).read_bytes()
                if fixture.extra_helper_read is not None:
                    Path(fixture.extra_helper_read).read_bytes()
                return SimpleNamespace(Buffer=raw)

        return SimpleNamespace(FrozenSources=Frozen)

    def admit(self):
        with patch.object(Path, "exists", return_value=False), patch.object(Path, "mkdir") as mkdir:
            try:
                return self.seed_class(self.api, self.args)
            finally:
                mkdir.assert_not_called()


class AdmissionTests(unittest.TestCase):
    def test_factory_is_pure_and_every_nonconstructor_method_is_inherited(self):
        with patch.object(Path, "read_bytes", side_effect=AssertionError("factory I/O")):
            derived = a.seed_type(legacy)
        self.assertEqual({k for k, v in derived.__dict__.items() if callable(v)}, {"__init__"})
        for name, method in legacy.Seed.__dict__.items():
            if callable(method) and name != "__init__":
                self.assertIs(getattr(derived, name), method)
        self.assertEqual(legacy.RECEIPT_SHA256, "9B605CEC54DE39C55662B6AAA2FAC260647C54F63AC903890FB9717EE3C3C2EC")

    def test_constructor_uses_caller_descriptors_and_preserves_phase_order(self):
        f = Fixture()
        seed = f.admit()
        expected = [PHASES[0], "loader", *("module:" + p for p in (legacy.CLASSIC + "run.py", legacy.RECIPE,
                    legacy.MODEL, legacy.PROCESS, legacy.REFERENCE)), *PHASES[1:], "interpreter", "close"]
        self.assertEqual(f.events, expected)
        self.assertNotEqual(seed.root, legacy.SEED)
        self.assertIsInstance(seed, legacy.Seed)
        self.assertTrue(seed.closure.closed)
        self.assertEqual(seed.closure.trees, [f.root, f.inventory])
        reads = dict(seed.closure.reads)
        self.assertEqual(reads[ADAPTER], sha(BUFFERS[ADAPTER]))
        self.assertEqual(reads[LEGACY], a.LEGACY_SHA256)
        self.assertEqual(seed.loader_evidence, dict(Path=str(LOADER), Sha256=legacy.LOADER_SHA256))

    def test_invalid_descriptor_shapes_fail_before_seed_authentication(self):
        for field, values in (("reference_build", (None, False, [])),
                              ("reference_receipt_sha256", (None, True, 1, "bad", "a" * 64)),
                              ("reference_artifacts_sha256", ([], False, "0" * 63, "G" * 64))):
            for value in values:
                f = Fixture()
                setattr(f.args, field, value)
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    f.admit()
                self.assertFalse(f.loaded)

    def test_arbitrary_well_formed_hashes_do_not_authenticate(self):
        for field in ("reference_receipt_sha256", "reference_artifacts_sha256"):
            f = Fixture()
            setattr(f.args, field, "0" * 64)
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "hash mismatch"):
                f.admit()
            self.assertFalse(f.events)

    def test_manifest_requires_nonempty_portable_typed_hashes_and_receipt_binding(self):
        for bad in ({}, [], {"../escape": "A" * 64}, {"C:/escape": "A" * 64},
                    {"results.json": False}, {"results.json": "0" * 64}):
            f = Fixture()
            f.manifest["Artifacts"] = bad
            f.seal_manifest()
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                f.admit()
            self.assertFalse(f.events)

    def test_inputs_and_generated_members_are_mandatory(self):
        for key, bad in (("Files", []), ("Files", {}), ("Generated", {}), ("Generated", [])):
            f = Fixture()
            f.inputs[key] = bad
            f.refresh()
            with self.subTest(key=key, bad=bad), self.assertRaises(ValueError):
                f.admit()
            self.assertFalse(f.events)

    def test_duplicate_original_escape_and_original_capture_drift_fail(self):
        for mutation in ("duplicate", "escape", "original-drift", "capture-drift"):
            f = Fixture()
            row = f.inputs["Files"][0]
            if mutation == "duplicate":
                f.inputs["Files"].append(copy.deepcopy(row))
            elif mutation == "escape":
                row["Captured"] = str(f.base / "outside.py")
            else:
                path = Path(row["Original"] if mutation == "original-drift" else row["Captured"])
                f.payload[path] += b"changed"
            f.refresh()
            with self.subTest(mutation=mutation), self.assertRaises((ValueError, KeyError)):
                f.admit()
            self.assertFalse(f.events)

    def test_complete_inventory_original_members_and_hashes_are_required(self):
        f = Fixture()
        f.inputs["Files"].pop(1)
        f.refresh()
        with self.assertRaisesRegex(ValueError, "omitted reference inventory input"):
            f.admit()
        self.assertFalse(f.events)
        f = Fixture()
        inventory = f.inventory / "results.json"
        f.payload[inventory] = b"changed original inventory result"
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            f.admit()

    def test_initial_output_denials_precede_helper_loading(self):
        for select in (lambda f: f.root, lambda f: f.root / "nested", lambda f: f.root.parent,
                       lambda f: f.inventory, lambda f: REPO / "new-output"):
            f = Fixture()
            f.args.output_dir = str(select(f))
            with self.subTest(output=f.args.output_dir), self.assertRaisesRegex(ValueError, "overlaps"):
                f.admit()
            self.assertFalse(f.events)

    def test_every_validator_failure_stops_later_phases_and_closing(self):
        for name in PHASES:
            f = Fixture()
            f.fail_phase = name
            with self.subTest(phase=name), self.assertRaisesRegex(ValueError, "synthetic phase failure"):
                f.admit()
            self.assertEqual([v for v in f.events if v in PHASES], list(PHASES[:PHASES.index(name) + 1]))
            self.assertNotIn("close", f.events)

    def test_final_tool_interpreter_and_reference_output_denials_precede_close(self):
        for folder in ("tools", "python", "freertos", "api"):
            f = Fixture()
            f.args.output_dir = str(f.base / folder / "new-output")
            with self.subTest(folder=folder), self.assertRaisesRegex(ValueError, "overlaps"):
                f.admit()
            self.assertIn("validate_prelink", f.events)
            self.assertNotIn("close", f.events)

    def test_legacy_source_pin_and_adapter_closing_buffer_are_watched(self):
        f = Fixture()
        f.payload[LEGACY] += b"changed"
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            f.admit()
        self.assertFalse(f.events)
        f = Fixture()
        original = f.api.load_buffer

        def change_adapter(*args):
            f.payload[ADAPTER] += b"changed"
            return original(*args)

        f.api.load_buffer = change_adapter
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            f.admit()
        self.assertNotIn("close", f.events)

    def test_inherited_helper_reader_has_no_unknown_disk_fallback(self):
        f = Fixture()
        seed = f.admit()
        loaded = legacy.Seed.module(seed, "synthetic.py")
        self.assertEqual(loaded.Buffer, f.payload[f.root / "source/synthetic.py"])
        f.extra_helper_read = f.base / "unknown.py"
        with self.assertRaisesRegex(ValueError, "outside authenticated immutable buffers"):
            legacy.Seed.module(seed, "synthetic.py")

    def test_close_failure_propagates_without_return_or_qualification(self):
        f = Fixture()
        f.close_failure = True
        with self.assertRaisesRegex(ValueError, "synthetic closing failure"):
            f.admit()
        self.assertFalse(f.closures[0].closed)
        tree = ast.parse(BUFFERS[ADAPTER])
        forbidden = {"mkdir", "write_bytes", "write_text", "Popen", "run", "exec", "system"}
        calls = [n.func.attr if isinstance(n.func, ast.Attribute) else n.func.id
                 for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, (ast.Attribute, ast.Name))]
        self.assertFalse(forbidden.intersection(calls))


def load_module(name, path, raw):
    module = ModuleType(name)
    module.__file__ = str(path)
    sys.modules[name] = module
    exec(compile(raw, str(path), "exec"), module.__dict__)
    return module


def main(argv=None):
    global a, legacy, BUFFERS
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args(argv)
    output = checked(args.output_dir)
    need(not output.exists() and not output.is_relative_to(REPO) and not REPO.is_relative_to(output), "fresh external report directory")
    paths = (Path(__file__).absolute(), ADAPTER, LEGACY, LOADER)
    BUFFERS = {path: path.read_bytes() for path in paths}
    hashes = {str(path): sha(raw) for path, raw in BUFFERS.items()}
    a = load_module("cm3_current_admission_under_test", ADAPTER, BUFFERS[ADAPTER])
    need(hashes[str(LEGACY)] == a.LEGACY_SHA256, "fixed legacy test authority")
    legacy = load_module("cm3_current_admission_legacy", LEGACY, BUFFERS[LEGACY])
    need(hashes[str(LOADER)] == legacy.LOADER_SHA256, "fixed mocked loader source authority")
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(AdmissionTests)
    with patch("subprocess.Popen", side_effect=AssertionError("subprocess forbidden")), \
         patch("subprocess.run", side_effect=AssertionError("subprocess forbidden")):
        result = unittest.TextTestRunner(verbosity=2).run(suite)
    drift = [str(path) for path in paths if sha(path.read_bytes()) != hashes[str(path)]]
    success = result.wasSuccessful() and not result.skipped and not drift
    report = dict(Status="PASS" if success else "FAIL", TestsRun=result.testsRun, Failures=len(result.failures),
        Errors=len(result.errors), Skipped=len(result.skipped), SourceHashes=hashes, SourceDrift=drift,
        Scope="SYNTHETIC_CONSTRUCTOR_AND_INHERITANCE_CONTROLS_ONLY", ActualSeedAdmission=False,
        HelperExecutionMocked=True, CompilerExecution=False, TargetExecution=False, Qualification=False)
    output.mkdir(parents=True)
    (output / "results.json").write_bytes(encoded(report) + b"\n")
    print(json.dumps(report, sort_keys=True))
    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())
