"""Pure CM3 join input-closure/output-seal controls; no ELF or CPU execution."""
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
SOURCE = HERE / "join.py"
SOURCE_BYTES = SOURCE.read_bytes()
SPEC = importlib.util.spec_from_file_location("cm3_join_seal_controls", SOURCE)
join = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = join
exec(compile(SOURCE_BYTES, str(SOURCE), "exec"), join.__dict__)


def sha(data):
    return hashlib.sha256(data).hexdigest().upper()


class ClosureControls(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="cm3-final-join-seal-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.output = self.root / "output"
        self.output.mkdir()
        self.original = self.root / "input.bin"
        self.original.write_bytes(b"synthetic immutable input\n")
        self.watch = join.Watch(self.output)
        self.watch.read(self.original, capture=True)
        self.copy = self.watch.copies[self.original]
        self.report = join.scope_report("CM3", "O2")
        self.report["Status"] = "PASS"

    def manifest(self):
        recorded = json.loads((self.output / "artifacts.json").read_bytes())["Artifacts"]
        actual = {path.relative_to(self.output).as_posix(): sha(path.read_bytes())
                  for path in self.output.rglob("*")
                  if path.is_file() and path.name != "artifacts.json"}
        self.assertEqual(recorded, actual)

    def failed(self):
        self.assertFalse(join.seal(self.output, self.report, self.watch))
        self.assertEqual(self.report["Status"], "FAIL")
        self.assertIs(self.report["OutputSealVerified"], False)
        retained = json.loads((self.output / "results.json").read_bytes())
        self.assertEqual(retained["Status"], "FAIL")
        self.assertIs(retained["OutputSealVerified"], False)
        for key in ("FinalReferenceParity", "InstructionEquivalence", "PolicyEquivalence",
                    "CompleteObjectProof", "ArchiveExtraction", "LTO", "CpuExecution",
                    "BoardExecution", "GlobalFreezeQualified"):
            self.assertIs(retained[key], False, key)
        self.assertEqual(retained["RequiredCellsSatisfied"], 0)
        self.assertEqual(retained["NativeCommandsExecuted"], 0)
        self.manifest()

    def after_manifest(self, change):
        write = Path.write_bytes
        fired = []

        def intercept(path, data):
            result = write(path, data)
            if path == self.output / "artifacts.json" and not fired:
                fired.append(True)
                change()
            return result

        with patch.object(Path, "write_bytes", intercept):
            self.failed()
        self.assertEqual(fired, [True])

    def test_unchanged_inputs_and_exact_output_membership_pass(self):
        self.assertTrue(join.seal(self.output, self.report, self.watch))
        self.assertIs(self.report["OutputSealVerified"], True)
        self.assertEqual(self.report["ClosingFilesVerified"], 1)
        self.assertEqual(self.report["Status"], "PASS")
        self.manifest()

    def test_original_drift_before_seal_fails(self):
        self.original.write_bytes(b"changed original")
        self.failed()

    def test_original_deleted_before_seal_fails(self):
        self.original.unlink()
        self.failed()

    def test_captured_drift_before_seal_fails(self):
        self.copy.write_bytes(b"changed capture")
        self.failed()

    def test_original_drift_after_manifest_fails(self):
        self.after_manifest(lambda: self.original.write_bytes(b"late original"))

    def test_capture_drift_after_manifest_fails(self):
        self.after_manifest(lambda: self.copy.write_bytes(b"late capture"))

    def test_report_drift_after_manifest_fails(self):
        self.after_manifest(lambda: (self.output / "results.json").write_bytes(b"late report"))

    def test_report_deletion_after_manifest_fails(self):
        self.after_manifest(lambda: (self.output / "results.json").unlink())

    def test_late_output_member_fails(self):
        self.after_manifest(lambda: (self.output / "unexpected.bin").write_bytes(b"late artifact"))

    def test_producer_late_member_fails(self):
        producer = self.root / "producer"
        producer.mkdir()
        (producer / "original").write_bytes(b"artifact")
        self.watch.membership(producer, {"original"})
        (producer / "late").write_bytes(b"late addition")
        self.failed()

    def test_producer_missing_member_fails(self):
        producer = self.root / "producer"
        producer.mkdir()
        original = producer / "original"
        original.write_bytes(b"artifact")
        self.watch.membership(producer, {"original"})
        original.unlink()
        self.failed()

    def test_failed_receipt_cannot_be_promoted_by_sealing(self):
        self.report.update(Status="FAIL", Error="synthetic rejection")
        self.assertFalse(join.seal(self.output, self.report, self.watch))
        retained = json.loads((self.output / "results.json").read_bytes())
        self.assertEqual(retained["Status"], "FAIL")
        self.assertEqual(retained["Error"], "synthetic rejection")
        self.assertIs(retained["OutputSealVerified"], True)
        self.manifest()

    def test_hash_mismatch_rejected_before_json_parse(self):
        self.original.write_bytes(b"not JSON")
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            self.watch.structured(self.original, "0" * 64)

    def test_duplicate_json_keys_rejected(self):
        duplicate = self.root / "duplicate.json"
        duplicate.write_bytes(b'{"Status":"PASS","Status":"FAIL"}')
        with self.assertRaises(ValueError):
            self.watch.structured(duplicate)

    def test_json_hash_and_parse_use_same_buffer(self):
        other = self.root / "single-buffer.json"
        other.write_bytes(b'{"Value":0}')
        data = b'{"Value":1}'
        with patch.object(Path, "read_bytes", return_value=data) as read:
            self.assertEqual(self.watch.structured(other, sha(data)), {"Value": 1})
            read.assert_called_once_with()
        self.assertEqual(self.watch.hashes[other], sha(data))
        self.assertEqual(self.watch.copies[other].read_bytes(), data)

    def test_output_overlap_rejects_before_creating_directory(self):
        native, reference = self.root / "native", self.root / "reference"
        native.mkdir()
        reference.mkdir()
        output = native / "new-output"
        with self.assertRaises(ValueError):
            join.output_directory(output, native, reference)
        self.assertFalse(output.exists())


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--report", required=True)
    args = parser.parse_args()
    output = Path(args.report).resolve()
    if sys.flags.optimize or output.exists() or not output.is_relative_to(Path(tempfile.gettempdir()).resolve()):
        raise SystemExit("unoptimized Python and fresh TEMP report required")
    sources = (Path(__file__).resolve(), SOURCE, join._SHARED_PATH, join._GENERIC_PATH)
    hashes = {str(path): sha(path.read_bytes()) for path in sources}
    if hashes[str(SOURCE)] != sha(SOURCE_BYTES):
        raise SystemExit("executed join source drift")
    for path, data in ((join._SHARED_PATH, join._SHARED_BYTES), (join._GENERIC_PATH, join._GENERIC_BYTES)):
        if hashes[str(path)] != sha(data):
            raise SystemExit("executed join helper drift")
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(ClosureControls)
    with patch.object(subprocess, "Popen", side_effect=AssertionError("process execution forbidden")):
        result = unittest.TextTestRunner(verbosity=2).run(suite)
    drift = [str(path) for path in sources if sha(path.read_bytes()) != hashes[str(path)]]
    report = dict(Status="PASS" if result.wasSuccessful() and not drift else "FAIL", Tests=result.testsRun,
        Failures=len(result.failures), Errors=len(result.errors), Skipped=len(result.skipped),
        SourceHashes=hashes, SourceDrift=drift, Scope="PURE_CM3_JOIN_CLOSURE_AND_SEAL_ONLY",
        RequiredCellsSatisfied=0, NativeCommandsExecuted=0, CpuExecution=False,
        BoardExecution=False, GlobalFreezeQualified=False,
        FailureDetails=[dict(Test=str(case), Detail=detail) for case, detail in result.failures + result.errors])
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="ascii")
    print(report["Status"], str(output))
    return 0 if report["Status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
