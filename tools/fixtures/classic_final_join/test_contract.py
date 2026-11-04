"""Pure join contract controls; no parser import, compiler or target execution."""
import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("final_join_contract", HERE / "join.py")
join = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(join)


class ContractTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="final-join-contract-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.native, self.reference, self.output = [self.root / name for name in ("native", "reference", "output")]
        self.native.mkdir()
        self.reference.mkdir()
        self.output.mkdir()

    def test_duplicate_json_keys_reject(self):
        path = self.root / "duplicate.json"
        path.write_bytes(b'{"Status": "FAIL", "Status": "PASS"}')
        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            join.Watch(self.output).structured(path)

    def test_only_exact_uppercase_hashes_admit(self):
        self.assertEqual(join.digest_text("A" * 64), "A" * 64)
        for value in ("a" * 64, "A" * 63, "G" * 64, True, 64, None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                join.digest_text(value)

    def test_output_must_be_fresh_external_and_separate(self):
        candidate = self.root / "fresh"
        self.assertEqual(join.output_directory(candidate, self.native, self.reference), candidate)
        self.assertFalse(candidate.exists())
        for candidate in (self.output, self.root, self.native / "child", self.reference / "child", join.REPO / "never-create"):
            with self.subTest(path=str(candidate)), self.assertRaises(ValueError):
                join.output_directory(candidate, self.native, self.reference)

    def test_same_and_nested_build_directories_reject(self):
        nested = self.native / "nested"
        nested.mkdir()
        for reference in (self.native, nested):
            with self.subTest(path=str(reference)), self.assertRaises(ValueError):
                join.output_directory(self.root / "fresh", self.native, reference)

    def test_artifact_traversal_and_ambiguous_paths_reject(self):
        (self.native / "one").write_bytes(b"ok")
        self.assertEqual(join.relative_file(self.native, "one"), self.native / "one")
        for name in ("../one", "./one", "/one", "one\\child", "one/../one", "", None):
            with self.subTest(name=name), self.assertRaises(ValueError):
                join.relative_file(self.native, name)

    def test_physical_roles_preserve_only_prelink_overlap(self):
        files = [self.root / (str(index) + ".bin") for index in range(6)]
        for index, path in enumerate(files):
            path.write_bytes(bytes([index]))
        roles = dict(zip(("Prelink", "Final", "Plain", "Disassembly", "LinkMap"), files[:5]))
        providers = [files[0], files[5]]
        join.physical_roles(roles, providers)
        for broken in (dict(roles, Plain=roles["Final"]), dict(roles, LinkMap=providers[-1])):
            with self.assertRaises(ValueError):
                join.physical_roles(broken, providers)
        alias = self.root / "hardlink"
        alias.hardlink_to(roles["Final"])
        with self.assertRaisesRegex(ValueError, "physical input alias"):
            join.physical_roles(dict(roles, Plain=alias), providers)

    def codegen(self):
        artifact = dict(compile_flags=["-mcpu=cortex-m4", "-mthumb", "-mfloat-abi=hard", "-mfpu=fpv4-sp-d16"])
        flags = [*artifact["compile_flags"], "-O2", "-g0"]
        row = dict(Source="source.c", Object="source.o", CompileFlags=flags)
        result = dict(Sources=[row], Commands=[dict(Argv=["gcc", *flags, "-c", "source.c", "-o", "source.o"])])
        return result, artifact

    def test_actual_codegen_binding(self):
        result, artifact = self.codegen()
        join.require_codegen_records(result, artifact, "O2")
        for mode in ("Og", "O0", "O3", "Os"):
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                join.require_codegen_records(result, artifact, mode)

    def test_codegen_overrides_and_actual_command_substitutions_reject(self):
        original, artifact = self.codegen()
        for flag in ("-O3", "-flto", "-march=armv8-m.main", "-mcpu=cortex-m7", "-mfpu=fpv5-d16", "-mfloat-abi=soft"):
            broken = copy.deepcopy(original)
            broken["Sources"][0]["CompileFlags"].append(flag)
            with self.subTest(flag=flag), self.assertRaises(ValueError):
                join.require_codegen_records(broken, artifact, "O2")
        for mutation in ("missing", "duplicate", "flags", "object"):
            broken = copy.deepcopy(original)
            if mutation == "missing":
                broken["Commands"] = []
            elif mutation == "duplicate":
                broken["Commands"] *= 2
            elif mutation == "flags":
                broken["Commands"][0]["Argv"][1] = "-mcpu=cortex-m7"
            else:
                broken["Commands"][0]["Argv"][-1] = "foreign.o"
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                join.require_codegen_records(broken, artifact, "O2")

    def auth_args(self):
        values = dict(native_build=str(self.native), reference_build=str(self.reference), profile="CM4", mode="O2")
        for side, root in (("native", self.native), ("reference", self.reference)):
            for field, name in (("receipt", "results.json"), ("artifacts", "artifacts.json")):
                data = b"{}\n"
                (root / name).write_bytes(data)
                values[side + "_" + field + "_sha256"] = join.digest(data)
        return SimpleNamespace(**values)

    def test_all_four_hashes_authenticate_before_parser_loading(self):
        args = self.auth_args()
        with patch.object(join, "load_api", side_effect=RuntimeError("parser boundary reached")) as loader:
            with self.assertRaisesRegex(RuntimeError, "parser boundary reached"):
                join.run(args, self.output, join.Watch(self.output))
            loader.assert_called_once()
        for field in ("native_receipt_sha256", "native_artifacts_sha256", "reference_receipt_sha256", "reference_artifacts_sha256"):
            broken = copy.copy(args)
            setattr(broken, field, "0" * 64)
            with self.subTest(field=field), patch.object(join, "load_api") as loader:
                with self.assertRaisesRegex(ValueError, "input hash mismatch"):
                    join.run(broken, self.output, join.Watch(self.output))
                loader.assert_not_called()

    def test_scope_never_claims_execution_or_equivalence(self):
        for profile in join.PROFILES:
            for mode in join.MODES:
                row = join.scope_report(profile, mode)
                self.assertEqual(row["Status"], "FAIL")
                self.assertIs(type(row["RequiredCellsSatisfied"]), int)
                self.assertEqual(row["RequiredCellsSatisfied"], 0)
                for key in ("FinalReferenceParity", "InstructionEquivalence", "PolicyEquivalence", "CpuExecution", "BoardExecution", "GlobalFreezeQualified"):
                    self.assertIs(row[key], False)

    def test_exact_mechanism_and_difference_assignments(self):
        names = (("first-start", "fiber_port_start_first_context", "prvPortStartFirstTask",
                  ["FAP-COMMON-START", "FAP-COMMON-PROVENANCE"]),
                 ("first-restore", "SVC_Handler", "vPortSVCHandler",
                  ["FAP-COMMON-PROVENANCE", "FAP-COMMON-MASK-RESTORE", "FAP-FP-VALIDATION"]),
                 ("PendSV-FP", "PendSV_Handler", "xPortPendSVHandler",
                  ["FAP-COMMON-SCHEDULER", "FAP-COMMON-PROVENANCE", "FAP-COMMON-MASK-RESTORE", "FAP-FP-VALIDATION"]))
        for profile in join.PROFILES:
            rows = [dict(Name=name, NativeRoot=native, ReferenceRoot=reference,
                         DifferenceIds=ids[:] + (["FAP-CM7-ERRATA-PRIMASK"] if profile == "CM7" and index else []))
                    for index, (name, native, reference, ids) in enumerate(names)]
            join.require_pairings(dict(Mechanisms=rows), profile)
            for mutation in ("missing-row", "duplicate-row", "missing-id", "extra-id", "wrong-assignment", "wrong-root"):
                broken = copy.deepcopy(rows)
                if mutation == "missing-row":
                    broken.pop()
                elif mutation == "duplicate-row":
                    broken[1] = copy.deepcopy(broken[0])
                elif mutation == "missing-id":
                    broken[0]["DifferenceIds"].pop()
                elif mutation == "extra-id":
                    broken[0]["DifferenceIds"].append("UNREVIEWED")
                elif mutation == "wrong-assignment":
                    broken[0]["DifferenceIds"], broken[1]["DifferenceIds"] = broken[1]["DifferenceIds"], broken[0]["DifferenceIds"]
                else:
                    broken[0]["NativeRoot"] = "SVC_Handler"
                with self.subTest(profile=profile, mutation=mutation), self.assertRaises(ValueError):
                    join.require_pairings(dict(Mechanisms=broken), profile)
            for foreign in ("CM0", "", None, True, 7):
                with self.subTest(profile=foreign), self.assertRaises(ValueError):
                    join.require_pairings(dict(Mechanisms=rows), foreign)


def main():
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--report", required=True)
    args = parser.parse_args()
    path = Path(args.report).resolve()
    if path.exists() or sys.flags.optimize:
        raise SystemExit("fresh report / unoptimized Python required")
    hashes = {str(p): hashlib.sha256(p.read_bytes()).hexdigest().upper() for p in (Path(__file__).resolve(), HERE / "join.py")}
    with patch("subprocess.Popen", side_effect=AssertionError("process execution forbidden")):
        result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(ContractTests))
    drift = [p for p, value in hashes.items() if hashlib.sha256(Path(p).read_bytes()).hexdigest().upper() != value]
    report = dict(Status="PASS" if result.wasSuccessful() and not drift else "FAIL", Tests=result.testsRun,
                  Failures=len(result.failures), Errors=len(result.errors), SourceHashes=hashes, SourceDrift=drift,
                  ToolInvocations=0, CpuExecution=False, BoardExecution=False)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="ascii")
    print(report["Status"], str(path))
    return 0 if report["Status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
