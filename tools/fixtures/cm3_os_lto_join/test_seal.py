"""Pure host sealing controls using generated TEMP files, not retained captures."""

import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import traceback
from types import MethodType, SimpleNamespace
import unittest
from unittest.mock import patch


sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
WITNESS = HERE / "witness.py"
EXPECTED_METHODS = 5
subject = None


def sha(data):
    return hashlib.sha256(data).hexdigest().upper()


class FakeClosure:
    def __init__(self, api):
        self.api, self.hashes = api, {}

    def read(self, path, expected=None):
        path = self.api.regular(path)
        raw = path.read_bytes()
        digest = sha(raw)
        if expected is not None and digest != expected:
            raise ValueError("synthetic recorded hash mismatch: " + str(path))
        if path in self.hashes and self.hashes[path] != digest:
            raise ValueError("synthetic closing hash drift: " + str(path))
        self.hashes[path] = digest
        return raw

    def close(self):
        for path, expected in list(self.hashes.items()):
            self.read(path, expected)


class FakeApi:
    def __init__(self):
        self.save_hook = self.files_hook = None
        self.saved, self.enumerations = [], 0

    @staticmethod
    def regular(path):
        path = Path(path)
        if path.is_symlink() or not path.is_file():
            raise ValueError("synthetic regular-file rejection: " + str(path))
        return path.resolve()

    @staticmethod
    def digest_text(value):
        if type(value) is not str or re.fullmatch(r"[0-9a-fA-F]{64}", value) is None:
            raise ValueError("synthetic digest rejection")
        return value.upper()

    @staticmethod
    def same(actual, expected, label):
        if actual != expected:
            raise ValueError("synthetic value mismatch: " + label)

    @staticmethod
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("synthetic duplicate JSON key")
            result[key] = value
        return result

    def save(self, path, value):
        self.saved.append(path.name)
        # Match the real helper: default platform newline translation matters.
        path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="ascii")
        if self.save_hook is not None:
            self.save_hook(path, value)

    def files_under(self, root):
        self.enumerations += 1
        if self.files_hook is not None:
            self.files_hook(root, self.enumerations)
        return {path.relative_to(root).as_posix(): path for path in sorted(root.rglob("*")) if path.is_file()}


class SealTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="synthetic-os-join-seal-")
        self.addCleanup(temporary.cleanup)
        self.base, self.counter = Path(temporary.name).resolve(), 0

    def fixture(self):
        self.counter += 1
        output = self.base / ("case-" + str(self.counter))
        output.mkdir()
        api = FakeApi()
        value = SimpleNamespace(
            output=output, api=api, watch=FakeClosure(api), groups={}, identities={},
            provenance_git=self.base / "unused-git.exe",
            expected={"results.json", "artifacts.json"},
            report=dict(Status=subject.PASS, Qualification=False, RequiredCellSatisfied=False,
                        RequiredCellsSatisfied=0, CpuExecution=False, GlobalFreezeQualified=False))
        for name in ("_physical", "_bind_control_files", "_seal", "close"):
            setattr(value, name, MethodType(getattr(subject.Witness, name), value))
        return value

    def file(self, value, relative="controls/Native/case/Machine.o", raw=b"synthetic machine", declared=True):
        path = value.output / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        if declared:
            value.expected.add(relative)
        return path

    def row(self, value, path, identity=True):
        result = dict(Path=str(path), Sha256=sha(path.read_bytes()))
        if identity:
            result["PhysicalIdentity"] = dict(zip(("Device", "FileId", "Links"), value._physical(path)))
        return result

    @staticmethod
    def bind(value, row):
        value._bind_control_files([dict(Files=[row])])

    def test_platform_default_write_text_save_seals_exact_intended_receipt(self):
        value = self.fixture()
        path = self.file(value)
        value._seal()
        raw = (value.output / "results.json").read_bytes()
        expected = (json.dumps(value.report, indent=2, sort_keys=True) + "\n").replace("\n", os.linesep).encode("ascii")
        self.assertEqual(raw, expected)
        self.assertEqual(json.loads(raw), value.report)
        self.assertIs(value.report["OutputSealVerified"], True)
        self.assertIs(value.report["Qualification"], False)
        self.assertEqual(value.sealed["results.json"], sha(expected))
        self.assertEqual(value.sealed[path.relative_to(value.output).as_posix()], sha(path.read_bytes()))
        manifest = (value.output / "artifacts.json").read_bytes()
        self.assertEqual(json.loads(manifest), dict(Artifacts=value.sealed))
        self.assertEqual(value.manifest_sha, sha(manifest))
        self.assertEqual(set(value.sealed), value.expected - {"artifacts.json"})

    def test_save_hook_receipt_substitution_rejects_before_hash_learning(self):
        for replacement in ("semantic", "formatting"):
            with self.subTest(replacement=replacement):
                value = self.fixture()
                self.file(value)

                def substitute(path, report):
                    if path.name == "results.json":
                        changed = dict(report, Qualification=True) if replacement == "semantic" else report
                        path.write_text(json.dumps(changed) + "\n", encoding="ascii")

                value.api.save_hook = substitute
                with self.assertRaisesRegex(ValueError, "written receipt bytes differ from intended serialized report"):
                    value._seal()
                self.assertFalse(hasattr(value, "sealed"))
                self.assertFalse((value.output / "artifacts.json").exists())
                self.assertEqual(value.api.saved, ["results.json"])

    def test_enumeration_substitution_cannot_relearn_receipt_hash(self):
        value = self.fixture()
        self.file(value)

        def substitute(root, count):
            if count == 2:
                path = root / "results.json"
                changed = dict(json.loads(path.read_bytes()), Qualification=True)
                path.write_text(json.dumps(changed, indent=2, sort_keys=True) + "\n", encoding="ascii")

        value.api.files_hook = substitute
        with self.assertRaisesRegex(ValueError, "post-manifest output closure"):
            value._seal()
        intended = (json.dumps(value.report, indent=2, sort_keys=True) + "\n").replace("\n", os.linesep).encode("ascii")
        actual = (value.output / "results.json").read_bytes()
        self.assertNotEqual(sha(actual), sha(intended))
        self.assertEqual(value.sealed["results.json"], sha(intended))
        self.assertEqual(json.loads((value.output / "artifacts.json").read_bytes())["Artifacts"]["results.json"], sha(intended))
        self.assertEqual(value.api.saved, ["results.json", "artifacts.json"])

    def test_control_hash_binds_at_return_and_rejects_later_drift(self):
        for mutation in ("changed-before-bind", "deleted-before-bind", "wrong-recorded-hash", "invalid-digest"):
            with self.subTest(mutation=mutation):
                value = self.fixture()
                path = self.file(value)
                row = self.row(value, path)
                if mutation == "changed-before-bind":
                    path.write_bytes(b"substituted machine")
                elif mutation == "deleted-before-bind":
                    path.unlink()
                else:
                    row["Sha256"] = "0" * 64 if mutation == "wrong-recorded-hash" else True
                with self.assertRaisesRegex(ValueError, "hash mismatch|regular-file rejection|digest rejection"):
                    self.bind(value, row)
                self.assertNotIn(path, value.identities)
                self.assertNotIn(path, value.watch.hashes)
        value = self.fixture()
        path = self.file(value)
        row = self.row(value, path, identity=False)
        self.bind(value, row)
        self.assertEqual(value.watch.hashes[path], row["Sha256"])
        value.close()
        path.write_bytes(b"changed after successful outer binding")
        with self.assertRaisesRegex(ValueError, "recorded hash mismatch"):
            value.close()

    def test_control_physical_identity_and_predetermined_private_roles(self):
        value = self.fixture()
        path = self.file(value)
        row = self.row(value, path)
        self.bind(value, row)
        identity = tuple(row["PhysicalIdentity"][key] for key in ("Device", "FileId", "Links"))
        self.assertEqual(value.identities[path], identity)
        value.close()
        with patch.object(value, "_physical", return_value=(identity[0], identity[1] + 1, identity[2])):
            with self.assertRaisesRegex(ValueError, "input physical identity drift"):
                value.close()
        for mutation in ("outside-controls", "undeclared", "outside-output", "wrong-role-hash",
                         "wrong-identity", "bool-identity", "malformed-identity", "previous-identity"):
            with self.subTest(mutation=mutation):
                value = self.fixture()
                path = self.file(value)
                row = self.row(value, path)
                expected = "control-returned physical identity"
                if mutation == "outside-controls":
                    row = self.row(value, self.file(value, "inputs/Machine.o"))
                    expected = "predetermined private output"
                elif mutation == "undeclared":
                    row = self.row(value, self.file(value, "controls/unplanned.o", declared=False))
                    expected = "predetermined private output"
                elif mutation == "outside-output":
                    foreign = self.base / "foreign.o"
                    foreign.write_bytes(b"foreign generated file")
                    row = self.row(value, foreign)
                    expected = "predetermined private output"
                elif mutation == "wrong-role-hash":
                    other = self.file(value, "controls/Native/case/Final.elf", b"different final bytes")
                    row["Path"] = str(other)
                    expected = "recorded hash mismatch"
                elif mutation == "wrong-identity":
                    row["PhysicalIdentity"]["FileId"] += 1
                elif mutation == "bool-identity":
                    row["PhysicalIdentity"]["Device"] = True
                elif mutation == "malformed-identity":
                    row["PhysicalIdentity"] = []
                else:
                    actual = value._physical(path)
                    value.identities[path] = (actual[0], actual[1] + 1, actual[2])
                    expected = "control physical identity changed before outer binding"
                with self.assertRaisesRegex(ValueError, expected):
                    self.bind(value, row)


def load_subject(data):
    name = "synthetic_os_join_seal_subject"
    spec = importlib.util.spec_from_file_location(name, WITNESS)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    exec(compile(data, str(WITNESS), "exec"), module.__dict__)
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
        Status="FAIL", Scope="PURE_HOST_SYNTHETIC_OS_JOIN_SEAL_AND_CONTROL_BINDING_ONLY",
        Tests=0, ExpectedTestMethods=EXPECTED_METHODS, Failures=0, Errors=0, Skipped=0,
        SourceHashes={}, SourceDrift=[], SourceClosureVerified=False, ClosingFilesVerified=0,
        SyntheticInputs=True, GeneratedTemporaryFiles=True, ActualCaptureTested=False,
        ActualELFTested=False, WitnessConstructorExecuted=False, ToolInvocations=0,
        NativeCommandsExecuted=0, Qualification=False, CanonicalProtocolValidated=False,
        FinalElfProof=False, FinalReferenceParity=False, FullABIProof=False,
        CompleteObjectProof=False, KernelRuntimeProof=False, CpuExecution=False,
        BoardExecution=False, GlobalFreezeQualified=False,
        RequiredCellSatisfied=False, RequiredCellsSatisfied=0)
    try:
        if sys.flags.optimize or not __debug__:
            raise ValueError("optimized interpreter unsupported")
        buffers = {path: path.read_bytes() for path in (Path(__file__).resolve(), WITNESS)}
        report["SourceHashes"] = {str(path): sha(data) for path, data in buffers.items()}
        global subject
        with patch("subprocess.Popen", side_effect=AssertionError("pure seal controls cannot spawn processes")), \
                patch("os.system", side_effect=AssertionError("pure seal controls cannot execute tools")):
            subject = load_subject(buffers[WITNESS])
            with patch.object(subject.Witness, "__init__", side_effect=AssertionError("constructor forbidden")):
                suite = unittest.defaultTestLoader.loadTestsFromTestCase(SealTests)
                if suite.countTestCases() != EXPECTED_METHODS:
                    raise ValueError("exact five synthetic seal methods required")
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
        report["SourceClosureVerified"] = len(report["SourceHashes"]) == 2 and not report["SourceDrift"]
        if not report["SourceClosureVerified"]:
            report["Status"] = "FAIL"
    output.mkdir(parents=True, exist_ok=False)
    target = output / "results.json"
    target.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="ascii")
    print("Receipt:", target, sha(target.read_bytes()))
    return 0 if report["Status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
