"""Bounded classic-FP pure and retained-ELF controls; no subprocesses."""
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


check = load("classic_fp_checker_controls", HERE / "check.py")
reader = load("classic_fp_reader_controls", HERE.parent / "cm55_tfm_parity/elf.py")
COHORTS = {profile: profile.lower() + "-cortex-m" + profile[-1] + "-hard-fpu-eager-v1-mpu0-p4-b16-aapcs-default"
           for profile in ("CM4", "CM7")}
MODES = ("O0", "Og", "O2", "Os", "O3")
ROOT = None
SOURCES = {}
PAIRS = []
MUTATIONS = []
PURE_MUTATIONS = 0


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest().upper()


class TokenProvider:
    """Unit-only protocol input, not ELF-binding evidence."""
    def __init__(self, protocols, tail=0):
        self.bodies = {name: deepcopy(body) + [("nop", "")] * tail for name, body in protocols.items()}

    def function(self, name, *, literal_islands=False):
        if literal_islands is not True:
            raise AssertionError("complete structural decoding must be explicit")
        return deepcopy(self.bodies[name])


def tokens(profile, tail=0):
    return [TokenProvider(check._NATIVE[profile], tail), TokenProvider(check._REFERENCE[profile], tail)]


class PureControls(unittest.TestCase):
    def test_result_and_difference_contract(self):
        for profile in COHORTS:
            for tail in (0, 1):
                result = check.check_pair(*tokens(profile, tail), profile)
                self.assertIs(type(result), dict)
                self.assertEqual(result["Verdict"], "CLASSIC-FP-CLOSED-ROOTS-PASS")
                self.assertEqual(result["Profile"], profile)
                self.assertEqual(result["Roots"], ["fiber_port_start_first_context", "SVC_Handler", "PendSV_Handler"])
                self.assertEqual(result["ClosedBodies"], 6)
                self.assertEqual(result["ProofScope"], "CLASSIC_FP_P4_B16_SIX_CLOSED_ROOT_PROTOCOLS_ONLY")
                expected = {"FAP-COMMON-START", "FAP-COMMON-PROVENANCE", "FAP-COMMON-MASK-RESTORE",
                            "FAP-COMMON-SCHEDULER", "FAP-FP-VALIDATION"}
                if profile == "CM7":
                    expected.add("FAP-CM7-ERRATA-PRIMASK")
                self.assertEqual(set(result["DifferenceIds"]), expected)
                for row in result["Mechanisms"][1:]:
                    self.assertIn("FAP-COMMON-MASK-RESTORE", row["DifferenceIds"])
                    self.assertEqual("FAP-CM7-ERRATA-PRIMASK" in row["DifferenceIds"], profile == "CM7")
                self.assertEqual({row["TailNops"] for row in result["RootEvidence"]}, {tail})
                self.assertIs(type(result["RequiredCellsSatisfied"]), int)
                self.assertEqual(result["RequiredCellsSatisfied"], 0)
                for key in ("RequiredCellSatisfied", "CompleteObjectProof",
                            "InstructionEquivalence", "CpuExecution", "BoardExecution", "FinalElfProof", "GlobalFreezeQualified"):
                    self.assertIs(result[key], False)
                self.assertEqual(result["FPCCRPolicy"]["Status"], "UNRESOLVED-BY-THREE-ROOTS")
                self.assertIs(result["FPCCRPolicy"]["PolicyEquivalenceProven"], False)
                self.assertIs(result["ReferenceSvcObligation"]["HandlerRoutingProven"], False)
                self.assertIs(result["ReferenceSvcObligation"]["UnreachabilityProven"], False)
                json.dumps(result)

    def test_profile_exact_and_cross_profile_reject(self):
        for value in (None, False, 4, "cm4", "CM4F", " CM4", "CM7 ", [], {}):
            with self.subTest(profile=value), self.assertRaises(check.Rejected):
                check.check_pair(*tokens("CM4"), value)
        for profile, other in (("CM4", "CM7"), ("CM7", "CM4")):
            with self.assertRaises(check.Rejected):
                check.check_pair(*tokens(other), profile)
            with self.assertRaises(check.Rejected):
                check.check_pair(tokens(profile)[0], tokens(other)[1], profile)

    def test_every_token_mutation_and_each_extra_instruction_reject(self):
        global PURE_MUTATIONS
        for profile in COHORTS:
            for side, protocols in enumerate((check._NATIVE[profile], check._REFERENCE[profile])):
                for name, body in protocols.items():
                    for index in range(len(body)):
                        with self.subTest(profile=profile, side=side, root=name, token=index):
                            pair = tokens(profile)
                            pair[side].bodies[name][index] = ("unexpected", "instruction-or-data")
                            with self.assertRaises(check.Rejected):
                                check.check_pair(*pair, profile)
                            PURE_MUTATIONS += 1
                    pair = tokens(profile)
                    pair[side].bodies[name].insert(1, ("nop", ""))
                    with self.assertRaises(check.Rejected):
                        check.check_pair(*pair, profile)
                    PURE_MUTATIONS += 1

    def test_tail_missing_roots_and_unbound_input_reject(self):
        for profile in COHORTS:
            for tail in (2, 3):
                with self.assertRaises(check.Rejected):
                    check.check_pair(*tokens(profile, tail), profile)
            pair = tokens(profile, 1)
            pair[0].bodies["SVC_Handler"].pop()
            with self.assertRaisesRegex(check.Rejected, "mixed root tail"):
                check.check_pair(*pair, profile)
            pair = tokens(profile)
            del pair[0].bodies["PendSV_Handler"]
            with self.assertRaises((KeyError, check.Rejected)):
                check.check_pair(*pair, profile)
            for value in (None, False, "unbound disassembly", []):
                with self.assertRaises(check.Rejected):
                    check.check_pair(value, pair[1], profile)


class RetainedElfControls(unittest.TestCase):
    def fixture(self, profile, side="Native"):
        directory = ROOT / (self._testMethodName + "-" + profile + "-" + side)
        directory.mkdir()
        self.profile, self.side = profile, side
        self.obj, self.dis = directory / "mutant.o", directory / "mutant.dis"
        original = SOURCES[(profile, side, "O0")]
        self.obj.write_bytes(original.read_bytes())
        self.dis.write_bytes(original.with_suffix(".dis").read_bytes())

    def image(self):
        return reader.Object(self.obj, self.dis)

    def symbol(self, name):
        image = self.image()
        return image, next(s for s in image.symbols if s["name"] == name and s["section"])

    def replace_instruction(self, name, address, raw, op, operands):
        image, symbol = self.symbol(name)
        data = bytearray(image.data)
        offset = image.sections[symbol["section"]][4] + address
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

    def reject_pair(self, label, fragment=None):
        try:
            pair = []
            for side in ("Native", "Reference"):
                path = SOURCES[(self.profile, side, "O0")]
                pair.append(self.image() if side == self.side else reader.Object(path, path.with_suffix(".dis")))
            check.check_pair(*pair, self.profile)
        except (reader.Rejected, check.Rejected) as error:
            if fragment is not None:
                self.assertIn(fragment, str(error))
            MUTATIONS.append(dict(Profile=self.profile, Side=self.side, Name=label, Verdict="EXPECTED-REJECT",
                Diagnostic=str(error), ObjectSha256=digest(self.obj), DisassemblySha256=digest(self.dis)))
        else:
            self.fail("mutant accepted: " + label)

    def test_ten_actual_pairs_sixty_complete_bodies(self):
        for profile in COHORTS:
            for mode in MODES:
                objects = []
                for side in ("Native", "Reference"):
                    path = SOURCES[(profile, side, mode)]
                    objects.append(reader.Object(path, path.with_suffix(".dis")))
                result = check.check_pair(*objects, profile)
                self.assertEqual({row["TailNops"] for row in result["RootEvidence"]}, {1 if mode == "O0" else 0})
                self.assertEqual(result["ClosedBodies"], 6)
                PAIRS.append(dict(Profile=profile, Mode=mode, Evidence=result))

    def test_changed_literal_bytes_reject(self):
        for profile in COHORTS:
            self.fixture(profile)
            image, symbol = self.symbol("fiber_port_start_first_context")
            data = bytearray(image.data)
            data[image.sections[symbol["section"]][4] + 100] ^= 1
            self.obj.write_bytes(data)
            self.reject_pair("changed-referenced-data", "complete protocol mismatch")

    def test_branch_to_tail_reject(self):
        for profile in COHORTS:
            self.fixture(profile)
            self.replace_instruction("fiber_port_start_first_context", 98, bytes.fromhex("01e0"), "b.n",
                "68 <fiber_port_start_first_context+0x68>")
            body = self.image().function("fiber_port_start_first_context", literal_islands=True)
            self.assertEqual(body[33], ("b", "@35"))
            self.assertEqual(body[34][0], "@literal-island")
            self.assertEqual(body[35], ("nop", ""))
            self.reject_pair("branch-to-tail-NOP", "complete protocol mismatch")

    def test_non_nop_tail_reject(self):
        for profile in COHORTS:
            self.fixture(profile)
            self.replace_instruction("fiber_port_start_first_context", 104, bytes.fromhex("0020"), "movs", "r0, #0")
            self.reject_pair("postpool-non-NOP", "unsupported literal-island executable tail")

    def test_bad_literal_relocation_reject(self):
        for profile in COHORTS:
            self.fixture(profile)
            address = 208 if profile == "CM4" else 228
            offset, info = self.relocation("SVC_Handler", address)
            data = bytearray(self.obj.read_bytes())
            struct.pack_into("<I", data, offset + 4, (info & ~255) | 3)
            self.obj.write_bytes(data)
            self.reject_pair("bad-literal-relocation", "unsupported literal relocation")

    def test_unconsumed_padding_relocation_reject(self):
        for profile, name, address in (("CM4", "PendSV_Handler", 248), ("CM7", "SVC_Handler", 228)):
            self.fixture(profile)
            offset, _ = self.relocation(name, address)
            data = bytearray(self.obj.read_bytes())
            struct.pack_into("<I", data, offset, address - 2)
            self.obj.write_bytes(data)
            self.reject_pair("unconsumed-island-padding-relocation", "unconsumed function relocation")

    def test_disassembly_bytes_must_match_elf(self):
        for profile in COHORTS:
            self.fixture(profile)
            text = self.dis.read_text()
            self.assertIn("b672", text)
            self.dis.write_text(text.replace("b672", "bf00", 1), encoding="ascii")
            self.reject_pair("disassembly-ELF-byte-disagreement", "disassembly bytes disagree with ELF")

    def test_bad_call_addend_reject(self):
        for profile in COHORTS:
            self.fixture(profile)
            self.replace_instruction("fiber_port_start_first_context", 86, bytes.fromhex("fff7ffff"), "bl", "0 <fiber_panic>")
            self.reject_pair("changed-call-addend", "unexpected call addend")

    def test_fp_bit4_predicate_reject(self):
        for profile in COHORTS:
            for side in ("Native", "Reference"):
                self.fixture(profile, side)
                name = "PendSV_Handler" if side == "Native" else "xPortPendSVHandler"
                address = (0x82 if profile == "CM4" else 0x84) if side == "Native" else 0x0c
                self.replace_instruction(name, address, bytes.fromhex("1ef0200f"), "tst.w", "lr, #32")
                self.reject_pair("FP-predicate-bit5-not-bit4", "complete protocol mismatch")

    def test_fp_high_register_transfer_reject(self):
        for profile in COHORTS:
            for side in ("Native", "Reference"):
                self.fixture(profile, side)
                name = "PendSV_Handler" if side == "Native" else "xPortPendSVHandler"
                address = (0x88 if profile == "CM4" else 0x8a) if side == "Native" else 0x12
                op = "vstmdb" if side == "Native" else "vstmdbeq"
                self.replace_instruction(name, address, bytes.fromhex("20ed0f8a"), op, "r0!, {s16-s30}")
                self.reject_pair("FP-save-missing-s31", "complete protocol mismatch")

    def test_fp_software_extent_reject(self):
        for profile in COHORTS:
            self.fixture(profile)
            self.replace_instruction("PendSV_Handler", 0x52 if profile == "CM4" else 0x54,
                bytes.fromhex("3c3b"), "subs", "r3, #60")
            self.reject_pair("FP-software-frame-extent60-not64", "complete protocol mismatch")

    def test_fp_hardware_extent_reject(self):
        for profile in COHORTS:
            self.fixture(profile)
            self.replace_instruction("PendSV_Handler", 0x6a if profile == "CM4" else 0x6c,
                bytes.fromhex("443a"), "subs", "r2, #68")
            self.reject_pair("FP-hardware-frame-extent68-not72", "complete protocol mismatch")

    def test_native_basepri_restore_reject(self):
        for profile in COHORTS:
            self.fixture(profile)
            self.replace_instruction("PendSV_Handler", 0xae if profile == "CM4" else 0xc8,
                bytes.fromhex("82f31188"), "msr", "BASEPRI, r2")
            self.reject_pair("BASEPRI-restore-threshold-not-snapshot", "complete protocol mismatch")

    def test_cm7_primask_restore_reject(self):
        self.fixture("CM7")
        self.replace_instruction("PendSV_Handler", 0xd4, bytes.fromhex("8cf31188"), "msr", "BASEPRI, ip")
        self.reject_pair("CM7-restore-wrong-mask-register", "complete protocol mismatch")


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
    original_hashes, reports = {}, {}
    for side, root_name, verdict in (("Native", args.native_root, "COMPILE-PREFLIGHT-PASS"),
                                     ("Reference", args.reference_root, "REFERENCE-COMPILE-PREFLIGHT-PASS")):
        root = Path(root_name).resolve()
        report = json.loads((root / "results.json").read_text())
        artifacts = json.loads((root / "artifacts.json").read_text())["Artifacts"]
        if report["Verdict"] != verdict or report["InputDrift"]:
            raise RuntimeError("closed compile receipt without input drift required")
        reports[side] = report
        for path in (root / "results.json", root / "artifacts.json"):
            original_hashes[str(path)] = digest(path)
        for profile, cohort in COHORTS.items():
            rows = [row for row in report["Cells"] if row["Cohort"] == cohort and row["ArtifactRole"] == "runtime"]
            if len(rows) != 5 or {row["Mode"] for row in rows} != set(MODES):
                raise RuntimeError("five selected mode rows per profile required")
            for row in rows:
                if row["Status"] != verdict or row["SourceGroup"] != profile:
                    raise RuntimeError("profile/status binding required")
                obj = Path(row["NativeGroup"])
                if not obj.is_relative_to(root) or digest(obj) != row["NativeGroupSha256"]:
                    raise RuntimeError("object row/root hash mismatch")
                for path in (obj, obj.with_suffix(".dis")):
                    value = digest(path)
                    if value != artifacts[path.relative_to(root).as_posix()]:
                        raise RuntimeError("artifact hash mismatch")
                    original_hashes[str(path)] = value
                SOURCES[(profile, side, row["Mode"])] = obj
    if reports["Native"]["SourceInventorySha256"] != reports["Reference"]["SourceInventorySha256"]:
        raise RuntimeError("source snapshot mismatch")
    for profile, cohort in COHORTS.items():
        for mode in MODES:
            selected = [next(row for row in report["Cells"] if row["Cohort"] == cohort
                             and row["ArtifactRole"] == "runtime" and row["Mode"] == mode) for report in reports.values()]
            if selected[0]["CohortSha256"] != selected[1]["CohortSha256"]:
                raise RuntimeError("cohort hash mismatch")
    helpers = (HERE / "check.py", HERE / "test_check.py", HERE.parent / "cm55_tfm_parity/elf.py")
    source_hashes = {str(p): digest(p) for p in helpers}
    suite = unittest.TestSuite((unittest.defaultTestLoader.loadTestsFromTestCase(PureControls),
                               unittest.defaultTestLoader.loadTestsFromTestCase(RetainedElfControls)))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    drift = [name for name, expected in {**original_hashes, **source_hashes}.items() if digest(name) != expected]
    report = dict(Status="PASS" if result.wasSuccessful() and not drift else "FAIL", Tests=result.testsRun,
        Failures=len(result.failures), Errors=len(result.errors), Skipped=len(result.skipped),
        PureTokenMutationControls=PURE_MUTATIONS, ActualByteMutationControls=MUTATIONS,
        ActualPairs=PAIRS, ClosedBodies=sum(row["Evidence"]["ClosedBodies"] for row in PAIRS),
        MechanismComparisons=sum(len(row["Evidence"]["Mechanisms"]) for row in PAIRS),
        InputHashes=original_hashes, InputDrift=drift, SourceHashes=source_hashes,
        CompilerExecutions=0, TargetExecutions=0, RequiredCellSatisfied=False, GlobalFreezeQualified=False,
        FailureDetails=[dict(Test=str(case), Traceback=detail) for case, detail in result.failures + result.errors])
    path = ROOT / "results.json"
    path.write_text(json.dumps(report, indent=2) + "\n", encoding="ascii")
    print(json.dumps(dict(Status=report["Status"], Tests=result.testsRun, Failures=report["Failures"],
        Errors=report["Errors"], PureTokenMutations=PURE_MUTATIONS, ActualByteMutations=len(MUTATIONS),
        Pairs=len(PAIRS), ClosedBodies=report["ClosedBodies"], MechanismComparisons=report["MechanismComparisons"])))
    print("Report: " + str(path))
    print("ReportSha256: " + digest(path))
    return 0 if report["Status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
