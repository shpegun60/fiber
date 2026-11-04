"""Pure input-identity controls; no compiler, ELF loader or target execution."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("reference_witness_identity", HERE / "reference_witness.py")
witness = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(witness)


class IdentityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="reference-witness-identity-")
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        paths = [self.directory / (str(index) + ".bin") for index in range(9)]
        for index, path in enumerate(paths):
            path.write_bytes(bytes([index]))
        self.inputs = dict(zip(("Prelink", "Final", "Disassembly", "Plain", "LinkMap"), paths[:5]))
        self.providers = [paths[0], *paths[5:8]]
        self.spare = paths[8]

    def rejected(self):
        with self.assertRaisesRegex(ValueError, "reference-final-witness:"):
            witness.require_input_identity(self.inputs, self.providers)

    def test_intentional_prelink_provider_overlap_only(self):
        self.assertEqual(len(witness.require_input_identity(self.inputs, self.providers)), 8)

    def test_same_path_twins_reject(self):
        self.inputs["Plain"] = self.inputs["Final"]
        self.rejected()

    def test_hard_link_twins_reject(self):
        alias = self.directory / "alias.bin"
        os.link(self.inputs["Final"], alias)
        self.inputs["Plain"] = alias
        self.rejected()

    def test_cross_role_same_path_reject(self):
        self.inputs["LinkMap"] = self.inputs["Disassembly"]
        self.rejected()

    def test_cross_role_hard_link_reject(self):
        alias = self.directory / "alias.bin"
        os.link(self.inputs["Disassembly"], alias)
        self.inputs["LinkMap"] = alias
        self.rejected()

    def test_provider_cross_role_reject(self):
        self.providers[-1] = self.inputs["Final"]
        self.rejected()

    def test_provider_hard_link_reject(self):
        alias = self.directory / "alias.bin"
        os.link(self.providers[-1], alias)
        self.providers[-2] = alias
        self.rejected()

    def test_duplicate_provider_reject(self):
        self.providers[-1] = self.providers[-2]
        self.rejected()

    def test_missing_prelink_provider_reject(self):
        self.providers[0] = self.spare
        self.rejected()

    def test_extra_role_reject(self):
        self.inputs["Unexpected"] = self.spare
        self.rejected()

    def test_empty_providers_reject(self):
        self.providers = []
        self.rejected()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", required=True)
    args = parser.parse_args()
    if sys.flags.optimize:
        raise SystemExit("unoptimized Python required")
    output = Path(args.report).resolve()
    if output.exists():
        raise SystemExit("fresh report required")
    hashes = {str(path): hashlib.sha256(path.read_bytes()).hexdigest().upper()
              for path in (Path(__file__).resolve(), HERE / "reference_witness.py")}
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(IdentityTests))
    drift = [path for path, value in hashes.items() if hashlib.sha256(Path(path).read_bytes()).hexdigest().upper() != value]
    report = dict(Status="PASS" if result.wasSuccessful() and not drift else "FAIL", Controls=result.testsRun,
                  Failures=len(result.failures), Errors=len(result.errors), SourceHashes=hashes, SourceDrift=drift,
                  NativeCommandsExecuted=0, CPUProof=False, FinalParity=False, GlobalProof=False)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="ascii")
    return 0 if report["Status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
