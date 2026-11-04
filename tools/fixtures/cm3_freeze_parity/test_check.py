"""Bounded CM3 pure controls and private retained-ELF mutations; no subprocesses."""
from copy import deepcopy
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
import sys
import tempfile
import unittest


HERE = Path(__file__).resolve().parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


check = load("cm3_negative_checker", HERE / "check.py")
reader = load("cm3_negative_reader", HERE.parent / "cm55_tfm_parity/elf.py")
COHORT = "cm3-cortex-m3-soft-nofpu-none-v1-mpu0-p4-b16-aapcs-default"
MODES = ("O0", "Og", "O2", "Os", "O3")
ROOT = None
SOURCES = {}
PAIRS = []
MUTATIONS = []
PURE_MUTATIONS = 0


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest().upper()


class TokenProvider:
    """Unit-test input only; these tests do not claim ELF binding."""
    def __init__(self, protocols, tail=0):
        self.bodies = {name: deepcopy(body) + [("nop", "")] * tail for name, body in protocols.items()}

    def function(self, name, *, literal_islands=False):
        if literal_islands is not True:
            raise AssertionError("structural decoding must be explicit")
        return deepcopy(self.bodies[name])


class PureControls(unittest.TestCase):
    def test_result_contract_and_two_exact_layouts(self):
        for tail in (0, 1):
            result = check.check_pair(TokenProvider(check._NATIVE, tail), TokenProvider(check._REFERENCE, tail))
            self.assertIs(type(result), dict)
            self.assertEqual(result["Verdict"], "CM3-CLOSED-ROOTS-PASS")
            self.assertEqual(result["Roots"], ["fiber_port_start_first_context", "SVC_Handler", "PendSV_Handler"])
            self.assertEqual(result["ClosedBodies"], 6)
            self.assertEqual(len(result["DifferenceIds"]), 6)
            self.assertIn("FAP-CM3-LOCAL-LITERAL-POOLS", result["DifferenceIds"])
            self.assertEqual({row["TailNops"] for row in result["RootEvidence"]}, {tail})
            for key in ("RequiredCellSatisfied", "CompleteObjectProof", "InstructionEquivalence",
                        "CpuExecution", "FinalElfProof", "GlobalFreezeQualified"):
                self.assertIs(result[key], False)
            self.assertIs(result["ReferenceSvcObligation"]["UnreachabilityProven"], False)
            json.dumps(result)

    def test_each_root_rejects_an_extra_instruction(self):
        global PURE_MUTATIONS
        for side, protocols in ((0, check._NATIVE), (1, check._REFERENCE)):
            for name in protocols:
                with self.subTest(side=side, root=name):
                    pair = [TokenProvider(check._NATIVE), TokenProvider(check._REFERENCE)]
                    pair[side].bodies[name].insert(1, ("nop", ""))
                    with self.assertRaises(check.Rejected):
                        check.check_pair(*pair)
                    PURE_MUTATIONS += 1

    def test_every_token_is_checked(self):
        global PURE_MUTATIONS
        for side, protocols in ((0, check._NATIVE), (1, check._REFERENCE)):
            for name, body in protocols.items():
                for index in range(len(body)):
                    with self.subTest(side=side, root=name, token=index):
                        pair = [TokenProvider(check._NATIVE), TokenProvider(check._REFERENCE)]
                        pair[side].bodies[name][index] = ("unexpected", "instruction-or-data")
                        with self.assertRaises(check.Rejected):
                            check.check_pair(*pair)
                        PURE_MUTATIONS += 1

    def test_tail_counts_missing_roots_and_raw_text_reject(self):
        for tail in (2, 3):
            with self.assertRaises(check.Rejected):
                check.check_pair(TokenProvider(check._NATIVE, tail), TokenProvider(check._REFERENCE, tail))
        native, reference = TokenProvider(check._NATIVE, 1), TokenProvider(check._REFERENCE, 1)
        native.bodies["SVC_Handler"].pop()
        with self.assertRaises(check.Rejected):
            check.check_pair(native, reference)
        del native.bodies["PendSV_Handler"]
        with self.assertRaises((KeyError, check.Rejected)):
            check.check_pair(native, reference)
        for value in (None, False, "unbound disassembly", []):
            with self.assertRaises(check.Rejected):
                check.check_pair(value, reference)


class RetainedElfControls(unittest.TestCase):
    def setUp(self):
        self.directory = ROOT / self._testMethodName
        self.directory.mkdir()
        self.obj, self.dis = self.directory / "native.o", self.directory / "native.dis"
        original = SOURCES[("Native", "O0")]
        self.obj.write_bytes(original.read_bytes())
        self.dis.write_bytes(original.with_suffix(".dis").read_bytes())

    def image(self):
        return reader.Object(self.obj, self.dis)

    def symbol(self, name):
        image = self.image()
        return image, next(s for s in image.symbols if s["name"] == name and s["section"])

    def replace_instruction(self, name, address, raw, op, operands):
        image, symbol = self.symbol(name)
        section = image.sections[symbol["section"]]
        data = bytearray(self.obj.read_bytes())
        offset = section[4] + address
        data[offset:offset + len(raw)] = raw
        self.obj.write_bytes(data)
        lines, current, replacements = self.dis.read_text().splitlines(), None, 0
        for index, line in enumerate(lines):
            header = re.fullmatch(r"Disassembly of section (.+):", line)
            if header:
                current = header[1]
            match = re.match(r"^\s*([0-9a-f]+):\s+([0-9a-f]{4}(?:\s+[0-9a-f]{4})?)\s+", line)
            if current == image.names[symbol["section"]] and match and int(match[1], 16) == address:
                words = " ".join("%04x" % struct.unpack_from("<H", raw, i)[0] for i in range(0, len(raw), 2))
                lines[index] = "%x: %s\t%s\t%s" % (address, words, op, operands)
                replacements += 1
        self.assertEqual(replacements, 1)
        self.dis.write_text("\n".join(lines) + "\n", encoding="ascii")

    def reject_pair(self, label, expected_fragment=None):
        try:
            native = self.image()
            reference_path = SOURCES[("Reference", "O0")]
            reference = reader.Object(reference_path, reference_path.with_suffix(".dis"))
            check.check_pair(native, reference)
        except (reader.Rejected, check.Rejected) as error:
            if expected_fragment is not None:
                self.assertIn(expected_fragment, str(error))
            MUTATIONS.append(dict(Name=label, Verdict="EXPECTED-REJECT", Diagnostic=str(error),
                                  ObjectSha256=digest(self.obj), DisassemblySha256=digest(self.dis)))
        else:
            self.fail("mutant accepted: " + label)

    def relocation(self, name, address):
        image, symbol = self.symbol(name)
        for section in image.sections:
            if section[1] != 9 or section[7] != symbol["section"]:
                continue
            for offset in range(section[4], section[4] + section[5], section[9]):
                actual, info = struct.unpack_from("<II", image.data, offset)
                if actual == address:
                    return offset, info
        self.fail("fixture relocation missing")

    def test_five_actual_pairs_complete_and_default_unchanged(self):
        for mode in MODES:
            objects = []
            for side, protocols in (("Native", check._NATIVE), ("Reference", check._REFERENCE)):
                path = SOURCES[(side, mode)]
                image = reader.Object(path, path.with_suffix(".dis"))
                for name, structural in protocols.items():
                    if mode == "O0":
                        with self.assertRaisesRegex(reader.Rejected, "non-trailing naked data"):
                            image.function(name)
                    else:
                        self.assertEqual(image.function(name), [token for token in structural if token[0] != "@literal-island"])
                objects.append(image)
            evidence = check.check_pair(*objects)
            self.assertEqual({row["TailNops"] for row in evidence["RootEvidence"]}, {1 if mode == "O0" else 0})
            self.assertEqual(evidence["ClosedBodies"], 6)
            PAIRS.append(dict(Mode=mode, Evidence=evidence))

    def test_changed_literal_bytes_reject(self):
        image, symbol = self.symbol("fiber_port_start_first_context")
        data = bytearray(image.data)
        data[image.sections[symbol["section"]][4] + 100] ^= 1
        self.obj.write_bytes(data)
        self.reject_pair("changed-referenced-data", "complete protocol mismatch")

    def test_branch_to_tail_has_descriptor_aware_index_and_rejects(self):
        self.replace_instruction("fiber_port_start_first_context", 98, bytes.fromhex("01e0"), "b.n",
                                 "68 <fiber_port_start_first_context+0x68>")
        body = self.image().function("fiber_port_start_first_context", literal_islands=True)
        self.assertEqual(body[33], ("b", "@35"))
        self.assertEqual(body[34][0], "@literal-island")
        self.assertEqual(body[35], ("nop", ""))
        self.reject_pair("branch-target-is-tail-NOP", "complete protocol mismatch")

    def test_extra_instruction_before_pool_rejects(self):
        self.replace_instruction("fiber_port_start_first_context", 70, bytes.fromhex("00bf"), "nop", "")
        self.reject_pair("changed-pre-island-operation", "complete protocol mismatch")

    def test_non_nop_executable_tail_rejects(self):
        self.replace_instruction("fiber_port_start_first_context", 104, bytes.fromhex("0020"), "movs", "r0, #0")
        self.reject_pair("postpool-non-NOP", "unsupported literal-island executable tail")

    def test_bad_literal_relocation_rejects(self):
        offset, info = self.relocation("SVC_Handler", 180)
        data = bytearray(self.obj.read_bytes())
        struct.pack_into("<I", data, offset + 4, (info & ~255) | 3)
        self.obj.write_bytes(data)
        self.reject_pair("bad-literal-relocation", "unsupported literal relocation")

    def test_unconsumed_padding_relocation_rejects(self):
        offset, _ = self.relocation("PendSV_Handler", 200)
        data = bytearray(self.obj.read_bytes())
        struct.pack_into("<I", data, offset, 198)
        self.obj.write_bytes(data)
        self.reject_pair("unconsumed-island-padding-relocation", "unconsumed function relocation")

    def test_disassembly_bytes_must_match_elf(self):
        text = self.dis.read_text()
        self.assertIn("b672", text)
        self.dis.write_text(text.replace("b672", "bf00", 1), encoding="ascii")
        self.reject_pair("disassembly-ELF-byte-disagreement", "disassembly bytes disagree with ELF")

    def test_bad_call_addend_rejects(self):
        self.replace_instruction("fiber_port_start_first_context", 86, bytes.fromhex("fff7ffff"), "bl", "0 <fiber_panic>")
        self.reject_pair("changed-call-addend", "unexpected call addend")


def main():
    global ROOT
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--temp-root", required=True)
    parser.add_argument("--native-root", required=True)
    parser.add_argument("--reference-root", required=True)
    args = parser.parse_args()
    ROOT = Path(args.temp_root).resolve()
    temp = Path(tempfile.gettempdir()).resolve()
    if ROOT == temp or not ROOT.is_relative_to(temp) or ROOT.exists():
        raise SystemExit("explicit fresh TEMP directory required")
    ROOT.mkdir()
    original_hashes = {}
    for side, root_name, verdict in (("Native", args.native_root, "COMPILE-PREFLIGHT-PASS"),
                                     ("Reference", args.reference_root, "REFERENCE-COMPILE-PREFLIGHT-PASS")):
        root = Path(root_name).resolve()
        report = json.loads((root / "results.json").read_text())
        artifacts = json.loads((root / "artifacts.json").read_text())["Artifacts"]
        if report["Verdict"] != verdict:
            raise RuntimeError("closed compile receipt required")
        rows = [row for row in report["Cells"] if row["Cohort"] == COHORT and row["ArtifactRole"] == "runtime"]
        if len(rows) != 5 or {row["Mode"] for row in rows} != set(MODES):
            raise RuntimeError("five selected mode rows required")
        for row in rows:
            obj = Path(row["NativeGroup"])
            if digest(obj) != row["NativeGroupSha256"]:
                raise RuntimeError("object row hash mismatch")
            for path in (obj, obj.with_suffix(".dis")):
                value = digest(path)
                if value != artifacts[path.relative_to(root).as_posix()]:
                    raise RuntimeError("artifact hash mismatch")
                original_hashes[str(path)] = value
            SOURCES[(side, row["Mode"])] = obj
    suite = unittest.TestSuite((unittest.defaultTestLoader.loadTestsFromTestCase(PureControls),
                               unittest.defaultTestLoader.loadTestsFromTestCase(RetainedElfControls)))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    drift = [name for name, expected in original_hashes.items() if digest(name) != expected]
    helpers = (HERE / "check.py", HERE / "test_check.py", HERE.parent / "cm55_tfm_parity/elf.py")
    report = dict(Status="PASS" if result.wasSuccessful() and not drift else "FAIL", Tests=result.testsRun,
        Failures=len(result.failures), Errors=len(result.errors), Skipped=len(result.skipped),
        PureTokenMutationControls=PURE_MUTATIONS, ActualByteMutationControls=MUTATIONS,
        ActualPairs=PAIRS, ClosedBodies=sum(row["Evidence"]["ClosedBodies"] for row in PAIRS),
        MechanismComparisons=sum(len(row["Evidence"]["Mechanisms"]) for row in PAIRS),
        InputHashes=original_hashes, InputDrift=drift, SourceHashes={str(p): digest(p) for p in helpers},
        CompilerExecutions=0, TargetExecutions=0, RequiredCellSatisfied=False, GlobalFreezeQualified=False,
        FailureDetails=[dict(Test=str(case), Traceback=detail) for case, detail in result.failures + result.errors])
    (ROOT / "results.json").write_text(json.dumps(report, indent=2) + "\n", encoding="ascii")
    print(json.dumps(dict(Status=report["Status"], Tests=result.testsRun, Failures=report["Failures"],
        Errors=report["Errors"], PureTokenMutations=PURE_MUTATIONS, ActualByteMutations=len(MUTATIONS),
        Pairs=len(PAIRS), ClosedBodies=report["ClosedBodies"], MechanismComparisons=report["MechanismComparisons"])))
    print("Report: " + str(ROOT / "results.json"))
    return 0 if report["Status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
