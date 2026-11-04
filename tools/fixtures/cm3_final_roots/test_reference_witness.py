"""Pure CM3 witness admission controls; no compiler, ELF replay or target."""
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


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    exec(compile(path.read_bytes(), str(path), "exec"), module.__dict__)
    return module


witness = load("cm3_witness_controls", HERE / "reference_witness.py")
paths = load("cm3_witness_path_controls", witness.SUPPORT[1])
mutations = load("cm3_witness_mutation_controls", witness.SUPPORT[0])


class SelectionControls(unittest.TestCase):
    def test_five_exact_modes(self):
        for mode in witness.MODES:
            self.assertEqual(witness.selection("CM3", mode), (142, 42) if mode == "O0" else (136, 39))

    def test_no_profile_fallthrough(self):
        for profile in ("CM0", "CM4", "CM7", "cm3", "CM3 ", "", None, 3, True):
            with self.subTest(profile=profile), self.assertRaises(ValueError):
                witness.selection(profile, "O2")

    def test_no_mode_alias_or_lto(self):
        for mode in ("-O2", "o2", "O1", "O2LTO", "O2 ", None, 2, True):
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                witness.selection("CM3", mode)

    def test_scope_starts_fail_closed(self):
        result = witness.scope("CM3", "O2")
        self.assertEqual(result["Status"], "FAIL")
        self.assertEqual(result["Scope"], "CM3_REFERENCE_THREE_PRELINK_BOUND_FINAL_ROOTS_ONLY")
        self.assertIs(type(result["RequiredCellsSatisfied"]), int)
        self.assertEqual(result["RequiredCellsSatisfied"], 0)
        for key in ("FinalParity", "GlobalProof", "CPUProof", "BoardExecution"):
            self.assertIs(result[key], False)
        self.assertEqual(result["NativeCommandsExecuted"], 0)
        self.assertEqual(result["PositiveRoots"], [])
        self.assertEqual(result["Mutants"], [])

    def test_scope_lists_are_independent(self):
        left, right = witness.scope("CM3", "O2"), witness.scope("CM3", "O2")
        left["Mutants"].append("synthetic control")
        self.assertEqual(right["Mutants"], [])

    def test_fixed_mutation_roots_and_count(self):
        self.assertEqual(len(mutations.CASES), 13)
        self.assertEqual(len({row[0] for row in mutations.CASES}), 13)
        self.assertEqual({row[1] for row in mutations.CASES}, set(witness.ROOTS))

    def test_only_two_twin_structure_cases(self):
        self.assertEqual({row[0] for row in mutations.CASES if row[2] == "TwinComparison"},
                         {"NOBITS-slot-over-file-backed-text", "RAM-owner-not-writable"})
        self.assertTrue(all(row[2] in ("Root", "TwinComparison") for row in mutations.CASES))


class IdentityControls(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="cm3-witness-controls-")
        self.root = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)
        self.inputs = {name: self.root / (name + ".input") for name in
                       ("Prelink", "Final", "Disassembly", "Plain", "LinkMap")}
        self.providers = [self.inputs["Prelink"], *(self.root / (name + ".o") for name in
                                                ("providers", "consumer", "startup"))]
        for path in set(self.inputs.values()) | set(self.providers):
            path.write_bytes(b"synthetic identity only")

    def test_exact_order_and_one_intended_overlap(self):
        originals = witness.require_input_identity(self.inputs, self.providers)
        self.assertEqual(len(originals), 8)
        self.assertEqual(originals[:5], list(self.inputs.values()))
        self.assertEqual(originals[5:], self.providers[1:])

    def test_missing_or_extra_input_role(self):
        for inputs in ({k: v for k, v in self.inputs.items() if k != "LinkMap"},
                       dict(self.inputs, Asm=self.providers[1])):
            with self.assertRaises(ValueError):
                witness.require_input_identity(inputs, self.providers)

    def test_role_path_alias(self):
        changed = dict(self.inputs, Plain=self.inputs["Final"])
        with self.assertRaises(ValueError):
            witness.require_input_identity(changed, self.providers)

    def test_provider_duplicate_or_wrong_count(self):
        for providers in (self.providers[:3], self.providers + [self.inputs["Final"]],
                          self.providers[:3] + [self.providers[1]]):
            with self.assertRaises(ValueError):
                witness.require_input_identity(self.inputs, providers)

    def test_prelink_must_be_first_provider(self):
        with self.assertRaises(ValueError):
            witness.require_input_identity(self.inputs, self.providers[1:] + self.providers[:1])

    def test_no_tuple_provider_alias(self):
        with self.assertRaises(ValueError):
            witness.require_input_identity(self.inputs, tuple(self.providers))

    def test_extra_role_provider_overlap(self):
        changed = [*self.providers[:3], self.inputs["Final"]]
        with self.assertRaises(ValueError):
            witness.require_input_identity(self.inputs, changed)

    def test_hardlink_alias_rejected(self):
        alias = self.root / "hardlink.input"
        os.link(self.inputs["Final"], alias)
        with self.assertRaises(ValueError):
            witness.require_input_identity(dict(self.inputs, Plain=alias), self.providers)

    def test_output_cannot_modify_input_membership(self):
        with self.assertRaises(ValueError):
            paths.require_output_directory(self.root / "new-output", list(self.inputs.values()))

    def test_output_existing_rejected(self):
        with self.assertRaises(ValueError):
            paths.require_output_directory(self.root, list(self.inputs.values()))

    def test_repository_output_rejected(self):
        with self.assertRaises(ValueError):
            paths.require_output_directory(HERE / "must-not-be-written", list(self.inputs.values()))

    def test_fresh_external_sibling_accepted_without_write(self):
        candidate = self.root.parent / (self.root.name + "-fresh")
        self.assertFalse(candidate.exists())
        self.assertEqual(paths.require_output_directory(candidate, list(self.inputs.values())), candidate.resolve())
        self.assertFalse(candidate.exists())

    def test_cli_alias_rejects_before_any_write(self):
        candidate = self.root.parent / (self.root.name + "-cli-fresh")
        argv = ["--prelink-object", str(self.inputs["Prelink"]), "--final-elf", str(self.inputs["Final"]),
                "--disassembly", str(self.inputs["Disassembly"]), "--plain-elf", str(self.inputs["Final"]),
                "--link-map", str(self.inputs["LinkMap"]), "--output-dir", str(candidate)]
        for provider in self.providers:
            argv.extend(("--provider-object", str(provider)))
        self.assertFalse(candidate.exists())
        with self.assertRaisesRegex(ValueError, "distinct roles"):
            witness.main(argv)
        self.assertFalse(candidate.exists())


class FrozenSourceControls(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="cm3-frozen-source-controls-")
        self.root = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)

    def test_changed_source_never_supplies_executed_bytes(self):
        source = self.root / "source.py"
        original = b"VALUE = 'authenticated A'\n"
        source.write_bytes(original)
        frozen = witness.FrozenSources({source: original})
        source.write_bytes(b"VALUE = 'unexpected B'\n")
        module = frozen.load("cm3_frozen_control_changed", source)
        source.write_bytes(original)
        self.assertEqual(module.VALUE, "authenticated A")
        self.assertEqual(frozen.executed[0]["Sha256"], witness.sha(original))
        self.assertEqual(witness.digest(source), witness.sha(original))

    def test_nested_legacy_spec_load_uses_bound_buffer(self):
        source, nested = self.root / "outer.py", self.root / "nested.py"
        outer = (b"import importlib.util\nfrom pathlib import Path\n"
                 b"spec = importlib.util.spec_from_file_location('cm3_nested_control', Path(__file__).with_name('nested.py'))\n"
                 b"child = importlib.util.module_from_spec(spec)\nspec.loader.exec_module(child)\nVALUE = child.VALUE\n")
        inner = b"VALUE = 7\n"
        source.write_bytes(outer)
        nested.write_bytes(b"VALUE = 42\n")
        frozen = witness.FrozenSources({source: outer, nested: inner})
        with frozen.active():
            module = frozen.load("cm3_outer_frozen_control", source)
        self.assertEqual(module.VALUE, 7)
        self.assertEqual({row["Path"] for row in frozen.executed}, {str(source), str(nested)})
        self.assertEqual(frozen.executed[1]["Sha256"], witness.sha(inner))

    def test_unknown_source_load_rejects(self):
        source, unknown = self.root / "known.py", self.root / "unknown.py"
        unknown.write_bytes(b"raise AssertionError('must never execute')\n")
        frozen = witness.FrozenSources({source: b"VALUE = 1\n"})
        with frozen.active(), self.assertRaisesRegex(ValueError, "source closure"):
            spec = importlib.util.spec_from_file_location("cm3_unknown_control", unknown)
            spec.loader.exec_module(importlib.util.module_from_spec(spec))
        self.assertEqual(frozen.executed, [])

    def test_mutable_buffers_rejected(self):
        with self.assertRaisesRegex(ValueError, "immutable source buffers"):
            witness.FrozenSources({self.root / "source.py": bytearray(b"VALUE=1\n")})


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--report", required=True)
    args = parser.parse_args()
    report_path = Path(args.report).resolve()
    if sys.flags.optimize or report_path.exists() or not report_path.is_relative_to(Path(tempfile.gettempdir()).resolve()):
        raise SystemExit("unoptimized Python and fresh TEMP report required")
    sources = (Path(__file__), HERE / "reference_witness.py", *witness.SUPPORT)
    hashes = {str(path): witness.digest(path) for path in sources}
    suite = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(case)
                              for case in (SelectionControls, IdentityControls, FrozenSourceControls))
    with patch("subprocess.Popen", side_effect=AssertionError("pure controls cannot execute tools")):
        result = unittest.TextTestRunner(verbosity=2).run(suite)
    drift = [str(path) for path in sources if witness.digest(path) != hashes[str(path)]]
    report = dict(Status="PASS" if result.wasSuccessful() and not drift else "FAIL", Tests=result.testsRun,
        Errors=len(result.errors), Failures=len(result.failures), Skipped=len(result.skipped),
        ToolInvocations=0, NativeCommandsExecuted=0, RequiredCellsSatisfied=0, FinalParity=False,
        CPUProof=False, BoardExecution=False, GlobalProof=False, ActualELFMutations=False,
        SourceHashes=hashes, SourceDrift=drift,
        FailureDetails=[dict(Test=str(case), Detail=detail) for case, detail in result.failures + result.errors])
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="ascii")
    print(report["Status"], str(report_path))
    return 0 if report["Status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
