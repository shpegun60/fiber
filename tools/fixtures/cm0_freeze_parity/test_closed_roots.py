"""Bounded CM0 closed-protocol controls; private ELF mutations, no processes."""
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


check = load("cm0_closed_protocol_controls", HERE / "closed_roots.py")
reader = load("cm0_closed_reader_controls", HERE.parent / "cm55_tfm_parity/elf.py")
COHORTS = (
    "cm0-cortex-m0-soft-nofpu-none-v0-mpu0-p2-b0-aapcs-default",
    "cm0-cortex-m0plus-soft-nofpu-none-v0-mpu0-p2-b0-aapcs-default",
    "cm0-cortex-m0plus-soft-nofpu-none-v1-mpu0-p2-b0-aapcs-default",
)
MODES = ("O0", "Og", "O2", "Os", "O3")
ROOT = None
SOURCES = {}
PAIRS = []
MUTATIONS = []
TOKEN_MUTATIONS = 0
STRUCTURAL_MUTATIONS = 0


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest().upper()


class TokenProvider:
    """Pure unit-test input only; never presented as ELF-binding evidence."""
    def __init__(self, bodies):
        self.bodies = deepcopy(bodies)

    def function(self, name, *, literal_islands=False, thumb1_tail_nop=False):
        if literal_islands is not True or thumb1_tail_nop is not True:
            raise AssertionError("both structural reader options must be explicit")
        return deepcopy(self.bodies[name])


def tokens(mode):
    protocols = check._protocols(mode)
    return [TokenProvider(protocols[side]) for side in ("Native", "Reference")]


class PureControls(unittest.TestCase):
    def test_exact_result_schema_and_padding(self):
        expected_roots = {
            "Native": ["fiber_port_start_first_context", "SVC_Handler", "PendSV_Handler"],
            "Reference": ["vStartFirstTask", "SVC_Handler", "vPortSVCHandler_C",
                          "vRestoreContextOfFirstTask", "PendSV_Handler"],
        }
        expected_differences = {"FAP-COMMON-START", "FAP-COMMON-PROVENANCE", "FAP-COMMON-MASK-RESTORE",
                                "FAP-COMMON-SCHEDULER", "FAP-CM0-STAGED-FRAME"}
        self.assertEqual({side: list(names) for side, names in check.ROOTS.items()}, expected_roots)
        self.assertEqual(check.DIFFERENCES, expected_differences)
        for mode in MODES:
            result = check.check_pair(*tokens(mode), mode)
            self.assertIs(type(result), dict)
            self.assertEqual(result["Verdict"], "CM0-CLOSED-ROOTS-PASS")
            self.assertEqual(result["ProofScope"], "CM0_P2_NO_MPU_EIGHT_CLOSED_ROOT_PROTOCOLS_ONLY")
            self.assertEqual(result["Roots"], expected_roots)
            self.assertEqual(result["Mode"], mode)
            self.assertEqual(result["ClosedBodies"], 8)
            self.assertEqual(set(result["DifferenceIds"]), expected_differences)
            self.assertEqual(len(result["DifferenceIds"]), 5)
            evidence = result["RootEvidence"]
            self.assertEqual([(row["Side"], row["Name"]) for row in evidence],
                [(side, name) for side, names in expected_roots.items() for name in names])
            self.assertEqual([row["LiteralIslands"] for row in evidence], [1, 1, 1, 0, 0, 0, 0, 0])
            self.assertEqual([row["TailNops"] for row in evidence],
                [1, 1, 1, 3, 5, 0, 4, 2] if mode == "O0" else [0, 0, 0, 2, 4, 0, 3, 1])
            for row in evidence:
                self.assertIs(type(row["Tokens"]), int)
                self.assertGreater(row["Tokens"], 0)
                self.assertRegex(row["BodySha256"], r"^[0-9A-F]{64}$")
            self.assertIs(type(result["RequiredCellsSatisfied"]), int)
            self.assertEqual(result["RequiredCellsSatisfied"], 0)
            for key in ("RequiredCellSatisfied", "PolicyEquivalence", "CompleteObjectProof", "CSourceSemanticProof",
                        "InstructionEquivalence", "CpuExecution", "BoardExecution", "FinalElfProof", "GlobalFreezeQualified"):
                self.assertIs(result[key], False)
            self.assertIs(result["ReferenceSvcObligation"]["HandlerRoutingProven"], False)
            self.assertIs(result["ReferenceSvcObligation"]["UnreachabilityProven"], False)
            self.assertIs(result["FirstRestoreDifference"]["InitialRegisterValueEquivalenceProven"], False)
            self.assertIn("BASEPRI-NOT-APPLICABLE", result["SchedulerThreshold"])
            self.assertEqual(result["Mechanisms"][1]["ReferenceRoots"],
                ["SVC_Handler", "vPortSVCHandler_C", "vRestoreContextOfFirstTask"])
            self.assertIn("FAP-COMMON-MASK-RESTORE", result["Mechanisms"][2]["DifferenceIds"])
            json.dumps(result)

    def test_exact_mode_and_distinct_layout_binding(self):
        for value in (None, False, 0, "O1", "-O2", "o0", "O2 ", " Os", [], {}):
            with self.subTest(mode=value), self.assertRaises(check.Rejected):
                check.check_pair(*tokens("O2"), value)
        for actual, declared in (("O0", "O2"), ("O2", "O0"), ("Os", "O2"), ("O2", "Os")):
            with self.subTest(actual=actual, declared=declared), self.assertRaises(check.Rejected):
                check.check_pair(*tokens(actual), declared)

    def test_every_token_in_every_mode_is_consumed(self):
        global TOKEN_MUTATIONS
        for mode in MODES:
            for side_index, (side, bodies) in enumerate(check._protocols(mode).items()):
                for name, body in bodies.items():
                    for index in range(len(body)):
                        with self.subTest(mode=mode, side=side, root=name, token=index):
                            pair = tokens(mode)
                            pair[side_index].bodies[name][index] = ("unexpected", "instruction-or-literal")
                            with self.assertRaises(check.Rejected):
                                check.check_pair(*pair, mode)
                            TOKEN_MUTATIONS += 1

    def test_each_root_extra_instruction_and_truncation_reject(self):
        global STRUCTURAL_MUTATIONS
        for mode in MODES:
            for side_index, (side, bodies) in enumerate(check._protocols(mode).items()):
                for name in bodies:
                    for mutation in ("insert", "truncate"):
                        with self.subTest(mode=mode, side=side, root=name, mutation=mutation):
                            pair = tokens(mode)
                            if mutation == "insert":
                                pair[side_index].bodies[name].insert(1, ("nop", ""))
                            else:
                                pair[side_index].bodies[name].pop()
                            with self.assertRaises(check.Rejected):
                                check.check_pair(*pair, mode)
                            STRUCTURAL_MUTATIONS += 1

    def test_missing_roots_bad_decoder_result_and_unbound_input_reject(self):
        for side_index, side in enumerate(("Native", "Reference")):
            for name in check.ROOTS[side]:
                pair = tokens("O2")
                del pair[side_index].bodies[name]
                with self.assertRaises((KeyError, check.Rejected)):
                    check.check_pair(*pair, "O2")
            pair = tokens("O2")
            pair[side_index].bodies[check.ROOTS[side][0]] = False
            with self.assertRaises(check.Rejected):
                check.check_pair(*pair, "O2")
        for value in (None, False, "unbound text", []):
            with self.assertRaises(check.Rejected):
                check.check_pair(value, tokens("O2")[1], "O2")


class RetainedByteControls(unittest.TestCase):
    def fixture(self, side="Native", mode="O0"):
        directory = ROOT / self._testMethodName
        directory.mkdir()
        self.side, self.mode = side, mode
        self.obj, self.dis = directory / "mutant.o", directory / "mutant.dis"
        original = SOURCES[(COHORTS[0], side, mode)]
        self.obj.write_bytes(original.read_bytes())
        self.dis.write_bytes(original.with_suffix(".dis").read_bytes())

    def image(self):
        return reader.Object(self.obj, self.dis)

    def symbol(self, name):
        image = self.image()
        return image, next(s for s in image.symbols if s["name"] == name and s["section"])

    def replace_instruction(self, name, address, raw, op, operands):
        image, symbol = self.symbol(name)
        self.assertEqual(len(image.instructions[(symbol["section"], address)][2]), len(raw))
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
                path = SOURCES[(COHORTS[0], side, self.mode)]
                pair.append(self.image() if side == self.side else reader.Object(path, path.with_suffix(".dis")))
            check.check_pair(*pair, self.mode)
        except (reader.Rejected, check.Rejected) as error:
            if fragment is not None:
                self.assertIn(fragment, str(error))
            MUTATIONS.append(dict(Side=self.side, Mode=self.mode, Name=label, Verdict="EXPECTED-REJECT",
                Diagnostic=str(error), ObjectSha256=digest(self.obj), DisassemblySha256=digest(self.dis)))
        else:
            self.fail("mutant accepted: " + label)

    def test_all_fifteen_pairs_one_hundred_twenty_bodies(self):
        for cohort in COHORTS:
            for mode in MODES:
                objects = []
                for side in ("Native", "Reference"):
                    path = SOURCES[(cohort, side, mode)]
                    objects.append(reader.Object(path, path.with_suffix(".dis")))
                evidence = check.check_pair(*objects, mode)
                self.assertEqual(evidence["ClosedBodies"], 8)
                self.assertEqual(len(evidence["RootEvidence"]), 8)
                PAIRS.append(dict(Cohort=cohort, Mode=mode, Evidence=evidence))

    def test_changed_referenced_literal(self):
        self.fixture()
        image, symbol = self.symbol("fiber_port_start_first_context")
        data = bytearray(image.data)
        data[image.sections[symbol["section"]][4] + 96] ^= 1
        self.obj.write_bytes(data)
        self.reject_pair("changed-ICSR-literal", "complete protocol mismatch")

    def test_branch_to_in_symbol_thumb1_tail(self):
        self.fixture()
        self.replace_instruction("fiber_port_start_first_context", 0x5e, bytes.fromhex("03e0"), "b.n",
            "68 <fiber_port_start_first_context+0x68>")
        body = self.image().function("fiber_port_start_first_context", literal_islands=True, thumb1_tail_nop=True)
        self.assertEqual(body[33], ("b", "@35"))
        self.assertEqual(body[34][0], "@literal-island")
        self.assertEqual(body[35], check._NOP)
        self.reject_pair("branch-to-46c0-tail", "complete protocol mismatch")

    def test_postpool_non_nop(self):
        self.fixture()
        self.replace_instruction("fiber_port_start_first_context", 104, bytes.fromhex("0020"), "movs", "r0, #0")
        self.reject_pair("postpool-non-NOP", "unsupported literal-island executable tail")

    def test_other_self_move_is_not_allowed_tail(self):
        self.fixture()
        self.replace_instruction("fiber_port_start_first_context", 104, bytes.fromhex("c946"), "mov", "r9, r9")
        self.reject_pair("postpool-self-move-r9-not-exact46c0", "unsupported literal-island executable tail")

    def test_bad_literal_relocation(self):
        self.fixture()
        offset, info = self.relocation("SVC_Handler", 180)
        data = bytearray(self.obj.read_bytes())
        struct.pack_into("<I", data, offset + 4, (info & ~255) | 3)
        self.obj.write_bytes(data)
        self.reject_pair("unsupported-literal-relocation-kind", "unsupported literal relocation")

    def test_unconsumed_padding_relocation(self):
        self.fixture()
        offset, _ = self.relocation("SVC_Handler", 180)
        data = bytearray(self.obj.read_bytes())
        struct.pack_into("<I", data, offset, 178)
        self.obj.write_bytes(data)
        self.reject_pair("unconsumed-island-padding-relocation", "unconsumed function relocation")

    def test_disassembly_must_bind_actual_bytes(self):
        self.fixture()
        text = self.dis.read_text()
        self.assertIn("b672", text)
        self.dis.write_text(text.replace("b672", "46c0", 1), encoding="ascii")
        self.reject_pair("disassembly-ELF-byte-disagreement", "disassembly bytes disagree with ELF")

    def test_call_addend(self):
        self.fixture()
        self.replace_instruction("fiber_port_start_first_context", 0x52, bytes.fromhex("fff7ffff"), "bl", "0 <fiber_panic>")
        self.reject_pair("bad-call-addend", "unexpected call addend")

    def test_actual_svc_immediate(self):
        self.fixture()
        self.replace_instruction("fiber_port_start_first_context", 0x4e, bytes.fromhex("47df"), "svc", "71")
        self.reject_pair("wrong-native-start-SVC", "complete protocol mismatch")

    def test_native_svc_restore_call_relocation_target(self):
        self.fixture()
        offset, info = self.relocation("SVC_Handler", 0x66)
        image = self.image()
        target = next(i for i, symbol in enumerate(image.symbols) if symbol["name"] == "fiber_panic")
        data = bytearray(image.data)
        struct.pack_into("<I", data, offset + 4, (target << 8) | (info & 255))
        self.obj.write_bytes(data)
        self.reject_pair("retargeted-ELF-validation-call", "complete protocol mismatch")

    def test_staged_high_register_save(self):
        self.fixture()
        self.replace_instruction("PendSV_Handler", 0x78, bytes.fromhex("70c0"), "stmia", "r0!, {r4-r6}")
        self.reject_pair("save-missing-staged-r11", "complete protocol mismatch")

    def test_frame_extent(self):
        self.fixture()
        self.replace_instruction("PendSV_Handler", 0x48, bytes.fromhex("203b"), "subs", "r3, #32")
        self.reject_pair("software-extent32-not36", "complete protocol mismatch")

    def test_prior_primask_restore(self):
        self.fixture()
        self.replace_instruction("PendSV_Handler", 0x94, bytes.fromhex("82f31088"), "msr", "PRIMASK, r2")
        self.reject_pair("PRIMASK-restore-wrong-register", "complete protocol mismatch")

    def test_reference_dispatcher_literal_addend(self):
        self.fixture("Reference")
        image, symbol = self.symbol("SVC_Handler")
        data = bytearray(image.data)
        struct.pack_into("<I", data, image.sections[symbol["section"]][4] + 0x24, 1)
        self.obj.write_bytes(data)
        self.reject_pair("SVC-dispatch-C-entry-addend", "complete protocol mismatch")

    def test_reference_first_restore_skip(self):
        self.fixture("Reference")
        self.replace_instruction("vRestoreContextOfFirstTask", 0x0e, bytes.fromhex("1c30"), "adds", "r0, #28")
        self.reject_pair("first-restore-skip28-not32", "complete protocol mismatch")

    def test_reference_c_stacked_pc_offset(self):
        self.fixture("Reference", "O2")
        self.replace_instruction("vPortSVCHandler_C", 2, bytes.fromhex("4369"), "ldr", "r3, [r0, #20]")
        self.reject_pair("C-dispatch-stacked-PC-offset20-not24", "complete protocol mismatch")

    def test_reference_c_svc_number(self):
        self.fixture("Reference", "O2")
        self.replace_instruction("vPortSVCHandler_C", 8, bytes.fromhex("632b"), "cmp", "r3, #99")
        self.reject_pair("C-dispatch-SVC99-not100", "complete protocol mismatch")

    def test_reference_c_o0_assert_loop_escape(self):
        self.fixture("Reference")
        self.replace_instruction("vPortSVCHandler_C", 0x2c, bytes.fromhex("ffe7"), "b.n",
            "2e <vPortSVCHandler_C+0x2e>")
        self.reject_pair("C-O0-failed-assert-escapes-loop", "complete protocol mismatch")

    def test_reference_c_o0_epilogue(self):
        self.fixture("Reference")
        self.replace_instruction("vPortSVCHandler_C", 0x32, bytes.fromhex("03b0"), "add", "sp, #12")
        self.reject_pair("C-O0-wrong-stack-deallocation", "complete protocol mismatch")

    def test_reference_c_os_branch_polarity(self):
        self.fixture("Reference", "Os")
        self.replace_instruction("vPortSVCHandler_C", 0x0a, bytes.fromhex("02d0"), "beq.n",
            "12 <vPortSVCHandler_C+0x12>")
        self.reject_pair("C-Os-inverted-assert-branch", "complete protocol mismatch")


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
        for cohort in COHORTS:
            rows = [row for row in report["Cells"] if row["Cohort"] == cohort and row["ArtifactRole"] == "runtime"]
            if len(rows) != 5 or {row["Mode"] for row in rows} != set(MODES):
                raise RuntimeError("exactly five selected modes per p2 cohort required")
            for row in rows:
                if row["Status"] != verdict or row["SourceGroup"] != "CM0":
                    raise RuntimeError("profile/status binding required")
                obj = Path(row["NativeGroup"])
                if not obj.is_relative_to(root) or digest(obj) != row["NativeGroupSha256"]:
                    raise RuntimeError("object row/root hash mismatch")
                for path in (obj, obj.with_suffix(".dis")):
                    value = digest(path)
                    if value != artifacts[path.relative_to(root).as_posix()]:
                        raise RuntimeError("artifact hash mismatch")
                    original_hashes[str(path)] = value
                SOURCES[(cohort, side, row["Mode"])] = obj
    if reports["Native"]["SourceInventorySha256"] != reports["Reference"]["SourceInventorySha256"]:
        raise RuntimeError("source snapshot mismatch")
    for cohort in COHORTS:
        for mode in MODES:
            selected = [next(row for row in report["Cells"] if row["Cohort"] == cohort
                             and row["ArtifactRole"] == "runtime" and row["Mode"] == mode) for report in reports.values()]
            if selected[0]["CohortSha256"] != selected[1]["CohortSha256"]:
                raise RuntimeError("cohort hash mismatch")
    helpers = (HERE / "closed_roots.py", HERE / "test_closed_roots.py", HERE.parent / "cm55_tfm_parity/elf.py")
    source_hashes = {str(path): digest(path) for path in helpers}
    preserved = {str(HERE / name): digest(HERE / name) for name in ("check.py", "run.py", "README.md")}
    suite = unittest.TestSuite((unittest.defaultTestLoader.loadTestsFromTestCase(PureControls),
                               unittest.defaultTestLoader.loadTestsFromTestCase(RetainedByteControls)))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    drift = [name for name, expected in {**original_hashes, **source_hashes, **preserved}.items() if digest(name) != expected]
    complete = len(PAIRS) == 15 and len(MUTATIONS) == 20
    report = dict(Status="PASS" if result.wasSuccessful() and complete and not drift else "FAIL", Tests=result.testsRun,
        Failures=len(result.failures), Errors=len(result.errors), Skipped=len(result.skipped),
        PureTokenMutationControls=TOKEN_MUTATIONS, PureStructuralMutationControls=STRUCTURAL_MUTATIONS,
        ActualByteMutationControls=MUTATIONS, ActualPairs=PAIRS,
        ClosedBodies=sum(row["Evidence"]["ClosedBodies"] for row in PAIRS),
        MechanismComparisons=sum(len(row["Evidence"]["Mechanisms"]) for row in PAIRS),
        InputHashes=original_hashes, InputDrift=drift, SourceHashes=source_hashes, PreservedFileHashes=preserved,
        CompilerExecutions=0, TargetExecutions=0, RequiredCellSatisfied=False, RequiredCellsSatisfied=0,
        PolicyEquivalence=False, CSourceSemanticProof=False, GlobalFreezeQualified=False,
        FailureDetails=[dict(Test=str(case), Traceback=detail) for case, detail in result.failures + result.errors])
    path = ROOT / "results.json"
    path.write_text(json.dumps(report, indent=2) + "\n", encoding="ascii")
    print(json.dumps(dict(Status=report["Status"], Tests=result.testsRun, Failures=report["Failures"], Errors=report["Errors"],
        PureTokenMutations=TOKEN_MUTATIONS, PureStructuralMutations=STRUCTURAL_MUTATIONS,
        ActualByteMutations=len(MUTATIONS), Pairs=len(PAIRS), ClosedBodies=report["ClosedBodies"],
        MechanismComparisons=report["MechanismComparisons"])))
    print("Report: " + str(path))
    print("ReportSha256: " + digest(path))
    return 0 if report["Status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
