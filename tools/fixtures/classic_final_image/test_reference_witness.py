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
from unittest.mock import patch

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


class OutputTests(unittest.TestCase):
    def test_fresh_external_directory_is_not_created_by_admission(self):
        with tempfile.TemporaryDirectory(prefix="reference-witness-output-") as root:
            candidate = Path(root) / "fresh"
            self.assertEqual(witness.require_output_directory(candidate), candidate.resolve())
            self.assertFalse(candidate.exists())

    def test_repo_descendants_and_ancestors_reject_without_writes(self):
        repo = HERE.parents[2]
        for candidate in (repo, HERE / "never-create-witness-output", repo.parent, repo.anchor):
            with self.subTest(path=str(candidate)), patch.object(Path, "mkdir") as mkdir:
                with self.assertRaisesRegex(ValueError, "external to repository"):
                    witness.require_output_directory(candidate)
                mkdir.assert_not_called()

    def test_existing_external_directory_rejects(self):
        with tempfile.TemporaryDirectory(prefix="reference-witness-output-") as root:
            with self.assertRaisesRegex(ValueError, "fresh output"):
                witness.require_output_directory(root)

    def test_main_rejects_before_mkdir_reader_or_input_access(self):
        with tempfile.TemporaryDirectory(prefix="reference-witness-output-") as root:
            for candidate in (HERE / "never-create-witness-output", Path(root)):
                argv = []
                for name in ("prelink-object", "final-elf", "disassembly", "plain-elf", "link-map", "provider-object"):
                    argv.extend(("--" + name, "not-an-input"))
                argv.extend(("--output-dir", str(candidate)))
                with self.subTest(path=str(candidate)), patch.object(Path, "mkdir") as mkdir, \
                     patch.object(witness, "load") as load, patch.object(witness, "digest") as digest:
                    with self.assertRaisesRegex(ValueError, "external to repository|fresh output"):
                        witness.main(argv)
                    mkdir.assert_not_called()
                    load.assert_not_called()
                    digest.assert_not_called()


class SelectionTests(unittest.TestCase):
    def test_all_ten_complete_root_totals(self):
        for mode in ("O0", "Og", "O2", "Os", "O3"):
            extra_bytes, extra_instructions = (6, 3) if mode == "O0" else (0, 0)
            for profile, size, instructions in (("CM4", 164, 48), ("CM7", 168, 50)):
                with self.subTest(profile=profile, mode=mode):
                    self.assertEqual(witness.selection(profile, mode),
                                     (size + extra_bytes, instructions + extra_instructions))

    def test_foreign_profiles_modes_and_nonstring_values_reject(self):
        for profile, mode in (("CM0", "O2"), ("CM3", "O2"), ("CM55", "O2"), ("CM4", "Ofast"),
                              ("CM4", "O2-LTO"), ("CM7", ""), (True, "O2"), ("CM4", 2),
                              (None, "O2"), ("CM7", None)):
            with self.subTest(profile=profile, mode=mode):
                with self.assertRaisesRegex(ValueError, "only CM4/CM7"):
                    witness.selection(profile, mode)


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
    suite = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(case)
                               for case in (IdentityTests, OutputTests, SelectionTests))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    drift = [path for path, value in hashes.items() if hashlib.sha256(Path(path).read_bytes()).hexdigest().upper() != value]
    report = dict(Status="PASS" if result.wasSuccessful() and not drift else "FAIL", Controls=result.testsRun,
                  Failures=len(result.failures), Errors=len(result.errors), SourceHashes=hashes, SourceDrift=drift,
                  NativeCommandsExecuted=0, CPUProof=False, FinalParity=False, GlobalProof=False)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="ascii")
    return 0 if report["Status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
