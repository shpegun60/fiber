"""Pure synthetic Watch/seal controls; no ELF, compiler or target execution."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("classic_final_join_pure", HERE / "join.py")
join = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(join)


def sha(data):
    return hashlib.sha256(data).hexdigest().upper()


class TemporaryFixture(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="classic-final-join-pure-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.output = self.root / "output"
        self.output.mkdir()
        self.original = self.root / "source.bin"
        self.original.write_bytes(b"synthetic immutable input\n")
        self.watch = join.Watch(self.output)

    def capture(self):
        self.watch.read(self.original, capture=True)
        return self.watch.copies[self.original]


class WatchTests(TemporaryFixture):
    def test_unchanged_capture_and_close(self):
        data = self.original.read_bytes()
        captured = self.capture()
        self.assertEqual(captured.read_bytes(), data)
        self.assertEqual(self.watch.hashes[self.original], sha(data))
        self.assertEqual(self.watch.copied(self.original), captured)
        self.assertEqual(len(self.watch.copies), 1)
        self.watch.close()

    def test_structured_hash_parse_and_copy_use_one_buffer(self):
        self.original.write_bytes(b'{"synthetic": true}\n')
        buffer = b'{"synthetic": false}\n'
        with patch.object(Path, "read_bytes", return_value=buffer) as read:
            self.assertEqual(self.watch.structured(self.original), {"synthetic": False})
            read.assert_called_once_with()
        self.assertEqual(self.watch.hashes[self.original], sha(buffer))
        self.assertEqual(self.watch.copies[self.original].read_bytes(), buffer)

    def test_input_change_rejects_at_close(self):
        self.capture()
        self.original.write_bytes(b"changed original")
        with self.assertRaisesRegex(ValueError, "input hash mismatch"):
            self.watch.close()

    def test_input_deletion_rejects_at_close(self):
        self.capture()
        self.original.unlink()
        with self.assertRaisesRegex(ValueError, "regular non-symlink"):
            self.watch.close()

    def test_capture_change_rejects_at_close(self):
        self.capture().write_bytes(b"changed capture")
        with self.assertRaisesRegex(ValueError, "captured input changed"):
            self.watch.close()

    def test_artifact_addition_rejects_at_close(self):
        artifacts = self.root / "producer"
        artifacts.mkdir()
        (artifacts / "original.bin").write_bytes(b"artifact")
        self.watch.membership(artifacts, {"original.bin"})
        (artifacts / "late.bin").write_bytes(b"late addition")
        with self.assertRaisesRegex(ValueError, "artifact membership mismatch"):
            self.watch.close()

    def test_artifact_deletion_rejects_at_close(self):
        artifacts = self.root / "producer"
        artifacts.mkdir()
        original = artifacts / "original.bin"
        original.write_bytes(b"artifact")
        self.watch.membership(artifacts, {"original.bin"})
        original.unlink()
        with self.assertRaisesRegex(ValueError, "artifact membership mismatch"):
            self.watch.close()


class SealTests(TemporaryFixture):
    def setUp(self):
        super().setUp()
        self.capture()
        self.report = join.scope_report("CM4", "O2")
        self.report["Status"] = "PASS"

    def assert_nonpromotion(self, report):
        for name in ("FinalReferenceParity", "InstructionEquivalence", "PolicyEquivalence",
                     "CompleteObjectProof", "ArchiveExtraction", "LTO", "CpuExecution",
                     "BoardExecution", "GlobalFreezeQualified"):
            self.assertIs(report[name], False, name)
        for name in ("RequiredCellsSatisfied", "NativeCommandsExecuted"):
            self.assertIs(type(report[name]), int, name)
            self.assertEqual(report[name], 0, name)

    def assert_manifest(self):
        inventory = json.loads((self.output / "artifacts.json").read_bytes())["Artifacts"]
        actual = {path.relative_to(self.output).as_posix(): sha(path.read_bytes())
                  for path in self.output.rglob("*")
                  if path.is_file() and path.name != "artifacts.json"}
        self.assertEqual(inventory, actual)

    def assert_rollback(self):
        self.assertIs(self.report["OutputSealVerified"], False)
        self.assertEqual(self.report["Status"], "FAIL")
        retained = json.loads((self.output / "results.json").read_bytes())
        self.assertEqual(retained["Status"], "FAIL")
        self.assertIs(retained["OutputSealVerified"], False)
        self.assert_nonpromotion(retained)
        self.assert_manifest()

    def after_manifest_write(self, mutate):
        original_write = Path.write_bytes
        fired = []

        def write(path, data):
            result = original_write(path, data)
            if path == self.output / "artifacts.json" and not fired:
                fired.append(True)
                mutate()
            return result

        with patch.object(Path, "write_bytes", write):
            self.assertFalse(join.seal(self.output, self.report, self.watch))
        self.assertEqual(fired, [True])
        self.assert_rollback()

    def test_unchanged_output_seals_exact_membership_and_hashes(self):
        self.assertTrue(join.seal(self.output, self.report, self.watch))
        self.assertEqual(self.report["Status"], "PASS")
        self.assertIs(self.report["OutputSealVerified"], True)
        self.assertEqual(self.report["ClosingFilesVerified"], 1)
        self.assertEqual(len(self.report["Inputs"]), 1)
        self.assert_nonpromotion(self.report)
        self.assert_manifest()

    def test_original_drift_before_publication_rolls_back(self):
        self.original.write_bytes(b"changed before seal")
        self.assertFalse(join.seal(self.output, self.report, self.watch))
        self.assert_rollback()

    def test_original_drift_after_write_rolls_back(self):
        self.after_manifest_write(lambda: self.original.write_bytes(b"late original change"))

    def test_capture_drift_after_write_rolls_back(self):
        captured = self.watch.copies[self.original]
        self.after_manifest_write(lambda: captured.write_bytes(b"late capture change"))

    def test_report_mutation_after_write_rolls_back(self):
        self.after_manifest_write(lambda: (self.output / "results.json").write_bytes(b"changed report"))

    def test_report_deletion_after_write_rolls_back(self):
        self.after_manifest_write(lambda: (self.output / "results.json").unlink())

    def test_output_addition_after_write_rolls_back(self):
        self.after_manifest_write(lambda: (self.output / "late.bin").write_bytes(b"late output"))

    def write_failure(self, name):
        original_write = Path.write_bytes
        attempted = []

        def write(path, data):
            if path == self.output / name:
                attempted.append(name)
                raise OSError("synthetic " + name + " write failure")
            return original_write(path, data)

        with patch.object(Path, "write_bytes", write):
            self.assertFalse(join.seal(self.output, self.report, self.watch))
        self.assertEqual(attempted, [name])
        self.assertIn("write failure", self.report["Error"])
        self.assert_rollback()

    def test_report_write_error_recovers_failed_receipt(self):
        self.write_failure("results.json")

    def test_manifest_write_error_recovers_failed_receipt(self):
        self.write_failure("artifacts.json")

    def test_failed_run_cannot_be_promoted_by_successful_seal(self):
        self.report.update(Status="FAIL", Error="synthetic admission rejection")
        self.assertFalse(join.seal(self.output, self.report, self.watch))
        retained = json.loads((self.output / "results.json").read_bytes())
        self.assertEqual(retained["Status"], "FAIL")
        self.assertEqual(retained["Error"], "synthetic admission rejection")
        self.assert_nonpromotion(retained)
        self.assert_manifest()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args(argv)
    if sys.flags.optimize:
        parser.error("unoptimized Python required")
    output = args.report.resolve()
    repo = HERE.parents[2]
    if output.exists() or output.is_relative_to(repo):
        parser.error("fresh external report required")
    sources = (Path(__file__).resolve(), HERE / "join.py")
    hashes = {str(path): sha(path.read_bytes()) for path in sources}
    suite = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(case)
                               for case in (WatchTests, SealTests))
    with patch.object(subprocess, "Popen", side_effect=AssertionError("process execution forbidden")):
        result = unittest.TextTestRunner(verbosity=2).run(suite)
    drift = [name for name, value in hashes.items() if sha(Path(name).read_bytes()) != value]
    report = dict(Status="PASS" if result.wasSuccessful() and not drift else "FAIL", Tests=result.testsRun,
                  Failures=len(result.failures), Errors=len(result.errors), Skipped=len(result.skipped),
                  Scope="PURE_SYNTHETIC_WATCH_AND_OUTPUT_SEAL_ONLY", SourceHashes=hashes, SourceDrift=drift,
                  NativeCommandsExecuted=0, RequiredCellsSatisfied=0, CPUProof=False, GlobalProof=False,
                  FailureDetails=[dict(Test=str(case), Detail=detail) for case, detail in result.failures + result.errors])
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="ascii")
    print(report["Status"], report["Tests"], str(output))
    return 0 if report["Status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
