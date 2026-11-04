"""Pure CM0 final-witness admission/seal controls, no ELF or target proof."""
import argparse
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
SPEC = importlib.util.spec_from_file_location("cm0_witness_controlled", HERE / "reference_witness.py")
w = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = w
SPEC.loader.exec_module(w)


class Controls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.frozen = self.root / "frozen"
        self.frozen.mkdir()
        self.inputs = {key: self.frozen / (key + suffix) for key, suffix in
            (("Port", ".o"), ("Asm", ".o"), ("Final", ".elf"), ("Plain", ".elf"), ("Disassembly", ".dis"), ("LinkMap", ".map"))}
        self.providers = [self.inputs["Port"], self.inputs["Asm"], *(self.frozen / (name + ".o") for name in ("provider", "consumer", "startup"))]
        for path in set(self.inputs.values()) | set(self.providers):
            path.write_bytes(b"not ELF; metadata controls only")

    def test_exact_profiles_modes_root_sizes(self):
        self.assertEqual(w.ROOTS, ("vStartFirstTask", "SVC_Handler", "vPortSVCHandler_C", "vRestoreContextOfFirstTask", "PendSV_Handler"))
        for profile in w.PROFILES:
            for mode in w.MODES:
                self.assertEqual(w.selection(profile, mode), 206 if mode == "O0" else 164)
        for profile, mode in ((True, "O2"), (None, "O2"), ("CM4", "O2"), ("CM0", True), ("CM0", "O1"), ("CM0", "O2-LTO")):
            with self.assertRaisesRegex(ValueError, "exact three profiles"):
                w.selection(profile, mode)

    def test_exact_nine_physical_input_roles(self):
        originals = w.require_input_identity(self.inputs, self.providers)
        self.assertEqual(len(originals), 9)
        self.assertEqual(set(originals), set(self.inputs.values()) | set(self.providers))

    def test_missing_extra_duplicate_provider_rejects(self):
        for providers in (self.providers[:-1], self.providers + [self.providers[-1]],
                          self.providers[1:] + [self.inputs["Final"]]):
            with self.assertRaisesRegex(ValueError, "five providers"):
                w.require_input_identity(self.inputs, providers)
        changed = dict(self.inputs, Other=self.inputs["Port"])
        with self.assertRaisesRegex(ValueError, "six input roles"):
            w.require_input_identity(changed, self.providers)

    def test_same_twin_path_rejects(self):
        changed = dict(self.inputs, Plain=self.inputs["Final"])
        with self.assertRaisesRegex(ValueError, "five providers"):
            w.require_input_identity(changed, self.providers)

    def test_hard_link_alias_rejects(self):
        link = self.frozen / "alias.elf"
        os.link(self.inputs["Final"], link)
        changed = dict(self.inputs, Plain=link)
        with self.assertRaisesRegex(ValueError, "distinct physical"):
            w.require_input_identity(changed, self.providers)

    def test_regular_file_and_protected_input_before_access(self):
        self.assertEqual(w.regular(self.inputs["Port"]), self.inputs["Port"].resolve())
        for name in ("cm33f_secure_transfer_reference", "m55_secure_closed_parity", "test_cm33f_secure_transfer_reference.ps1"):
            with patch.object(Path, "lstat", side_effect=AssertionError("protected input accessed")):
                with self.assertRaisesRegex(ValueError, "protected input"):
                    w.regular(self.root / name / "never-open")

    def test_output_is_external_fresh_and_disjoint(self):
        originals = w.require_input_identity(self.inputs, self.providers)
        target = self.root / "fresh"
        self.assertEqual(w.require_output_directory(target, originals), target.resolve())
        self.assertFalse(target.exists())
        for path in (HERE / "new", HERE.parents[2], self.frozen / "new", self.root):
            with self.assertRaisesRegex(ValueError, "fresh external|frozen input"):
                w.require_output_directory(path, originals)

    def test_output_reparse_rejects_before_resolve(self):
        original = Path.lstat
        target = self.root / "fresh"
        def altered(path):
            info = original(path)
            if path == self.root:
                from types import SimpleNamespace
                return SimpleNamespace(st_file_attributes=0x400, st_mode=info.st_mode)
            return info
        with patch.object(Path, "lstat", altered):
            with self.assertRaisesRegex(ValueError, "output reparse"):
                w.require_output_directory(target, list(self.inputs.values()))

    def test_fixed_seventeen_mutation_classes_and_reasons(self):
        self.assertEqual(len(w.CASES), 17)
        self.assertEqual(len({row[0] for row in w.CASES}), 17)
        self.assertEqual(sum(row[2] == "TwinComparison" for row in w.CASES), 2)
        for name, root, stage, reason in w.CASES:
            self.assertIn(root, w.ROOTS)
            self.assertIn(stage, ("Root", "TwinComparison"))
            self.assertTrue(reason)
        for mode in w.MODES:
            cases = w.mutation_cases(mode)
            self.assertEqual(len(cases), 19 if mode == "O0" else 17)
            self.assertEqual(len({row[0] for row in cases}), len(cases))
        for mode in (None, True, "O2-LTO"):
            with self.assertRaisesRegex(ValueError, "ordinary mutation mode"):
                w.mutation_cases(mode)

    def make_output(self):
        output = self.root / "out"
        output.mkdir()
        (output / "captured").write_bytes(b"retained payload")
        return output

    def assert_failed_seal(self, output):
        report = json.loads((output / "results.json").read_bytes())
        self.assertEqual(report["Status"], "FAIL")
        self.assertIn("artifact finalization", report["Error"])
        manifest = json.loads((output / "artifacts.json").read_bytes())
        self.assertEqual(manifest["Artifacts"], w.artifact_inventory(output))

    def test_positive_output_seal(self):
        output = self.make_output()
        self.assertTrue(w.finish(output, dict(Status="PASS")))
        self.assertEqual(json.loads((output / "artifacts.json").read_bytes())["Artifacts"], w.artifact_inventory(output))

    def test_late_addition_rolls_back_pass(self):
        output, count, actual = self.make_output(), 0, w.artifact_inventory
        def injected(path):
            nonlocal count
            count += 1
            if count == 2:
                (path / "late").write_bytes(b"added")
            return actual(path)
        with patch.object(w, "artifact_inventory", injected):
            self.assertFalse(w.finish(output, dict(Status="PASS")))
        self.assert_failed_seal(output)

    def test_late_mutation_rolls_back_pass(self):
        output, count, actual = self.make_output(), 0, w.artifact_inventory
        def injected(path):
            nonlocal count
            count += 1
            if count == 2:
                (path / "captured").write_bytes(b"changed")
            return actual(path)
        with patch.object(w, "artifact_inventory", injected):
            self.assertFalse(w.finish(output, dict(Status="PASS")))
        self.assert_failed_seal(output)

    def test_late_deletion_rolls_back_pass(self):
        output, count, actual = self.make_output(), 0, w.artifact_inventory
        def injected(path):
            nonlocal count
            count += 1
            if count == 2:
                (path / "captured").unlink()
            return actual(path)
        with patch.object(w, "artifact_inventory", injected):
            self.assertFalse(w.finish(output, dict(Status="PASS")))
        self.assert_failed_seal(output)

    def test_one_shot_manifest_write_error_rolls_back_pass(self):
        output, count, actual = self.make_output(), 0, Path.write_text
        def injected(path, *args, **kwargs):
            nonlocal count
            if path.name == "artifacts.json":
                count += 1
                if count == 1:
                    raise OSError("injected manifest error")
            return actual(path, *args, **kwargs)
        with patch.object(Path, "write_text", injected):
            self.assertFalse(w.finish(output, dict(Status="PASS")))
        self.assert_failed_seal(output)


def main():
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--report", required=True)
    args = parser.parse_args()
    report = Path(args.report).resolve()
    if report.exists() or not report.is_relative_to(Path(tempfile.gettempdir()).resolve()):
        raise SystemExit("fresh report inside TEMP required")
    sources = (Path(__file__).resolve(), HERE / "reference_witness.py")
    hashes = {str(path): w.digest(path) for path in sources}
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(Controls)
    with patch("subprocess.Popen", side_effect=AssertionError("native launch forbidden")):
        result = unittest.TextTestRunner(verbosity=2).run(suite)
    drift = [str(path) for path in sources if w.digest(path) != hashes[str(path)]]
    value = dict(Status="PASS" if result.wasSuccessful() and not drift else "FAIL", Tests=result.testsRun,
        Failures=len(result.failures), Errors=len(result.errors), Skipped=len(result.skipped), SourceHashes=hashes, SourceDrift=drift,
        NativeCommandsExecuted=0, ActualElfMutations=0, CPUProof=False, BoardExecution=False, GlobalProof=False,
        FailureDetails=[dict(Test=str(case), Detail=detail) for case, detail in result.failures + result.errors])
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="ascii")
    print(value["Status"], value["Tests"], str(report))
    return 0 if value["Status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
