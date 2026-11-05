"""Pure synthetic controls for reference CM3 LTO canonical composition.

FakeDecoded returns copied source-transcribed expectations, not decoded ELF.
FakeTransport supplies synthetic records, not independently proved transport.
Only the unchanged checker runs; no ELF reader, tools or target is exercised.
"""
import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import traceback
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
PROTOCOL = HERE / "protocol.py"
CHECKER = HERE.parent / "cm3_freeze_parity/check.py"
PROTOCOL_SHA256 = "200B277D03DF4236FE887907F732BC2A26898D8C15C1544D917B3DC3CF6BF798"
CHECKER_SHA256 = "F0D9CD4F48912FB6E5455AA365BF73FFCF356BAFAD922B3A73ACA992A616A11A"
ROOTS = ("prvPortStartFirstTask", "vPortSVCHandler", "xPortPendSVHandler")
LAYOUT = ((ROOTS[0], 0, 32, 10), (ROOTS[1], 64, 36, 10), (ROOTS[2], 128, 68, 19))
PREFIX_SIZE = 64
PAYLOAD_SIZE = 256
EXPECTED_METHODS = 18
p = c = None


def sha(data):
    return hashlib.sha256(data).hexdigest().upper()


def token_sha(tokens):
    return sha(json.dumps(tokens, separators=(",", ":"), ensure_ascii=True).encode("ascii"))


def module(name, path, data):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    sys.modules[name] = result
    exec(compile(data, str(path), "exec"), result.__dict__)
    return result


class FakeDecoded:
    def __init__(self):
        self.tokens = copy.deepcopy(c._REFERENCE)
        self.symbols, self.calls = [], []
        payload = bytearray((index * 11 + 5) % 256 for index in range(PAYLOAD_SIZE))
        for name, offset, size, _ in LAYOUT:
            self.symbols.append(dict(name=name, value=offset | 1, size=size,
                                     info=0x02 if name == ROOTS[0] else 0x12, section=1))
            for op, value in self.tokens[name]:
                if op == "@literal-island":
                    island = json.loads(value)
                    raw = bytes.fromhex(island["Bytes"])
                    start = offset + island["Offset"]
                    payload[start:start + len(raw)] = raw
        self.data = b"SYNTHETIC-REFERENCE-NOT-ELF".ljust(PREFIX_SIZE, b"\x7f") + bytes(payload)
        self.sections = [(0,) * 10, (0, 1, 6, 0, PREFIX_SIZE, len(payload), 0, 0, 4, 0)]

    def read(self, section, address, size):
        if (type(section) is not int or section != 1 or type(address) is not int
                or type(size) is not int or address < 0 or size < 0 or address + size > PAYLOAD_SIZE):
            raise ValueError("synthetic section bounds")
        return self.data[PREFIX_SIZE + address:PREFIX_SIZE + address + size]

    def function(self, name, *, literal_islands=False):
        if literal_islands is not True:
            raise AssertionError("complete synthetic literal-island view required")
        self.calls.append(name)
        return self.tokens[name]


class FakeTransport:
    def __init__(self, decoded):
        self.machine = SimpleNamespace(data=decoded.data)
        self.calls, self.records = [], {}
        for name, offset, size, count in LAYOUT:
            body = decoded.read(1, offset, size)
            references = []
            if name == ROOTS[1]:
                references = [dict(Offset=32, Kind=2, Symbol="pxCurrentTCB", Addend=0)]
            elif name == ROOTS[2]:
                references = [dict(Offset=28, Kind=10, Symbol="vTaskSwitchContext", Addend=-4),
                              dict(Offset=64, Kind=2, Symbol="pxCurrentTCB", Addend=0)]
            self.records[name] = dict(Name=name, Size=size, InstructionCount=count,
                MachineBodySha256=sha(body), BodySha256=sha(b"synthetic applied final:" + body),
                References=references, DefinitionOrigins=[],
                RootOrigin=dict(Name=name, Provider="C:/synthetic-reference/machine.o",
                    ProviderSha256=sha(decoded.data), InputSection=".text", InputSectionIndex=1,
                    SymbolOffset=offset, Size=size, GeneratedMachineOriginBound=True),
                GeneratedMachineBoundRootPreservation=True, CanonicalProtocolValidated=False,
                OriginalTranslationUnitOwnership=False, SourceToMachineSemanticProof=False,
                FinalReferenceParity=False, FullABIProof=False, PolicyEquivalence=False,
                CpuExecution=False, BoardExecution=False, RequiredCellsSatisfied=0, GlobalFreezeQualified=False)

    def function(self, name):
        self.calls.append(name)
        return self.records[name]


class Fixture:
    def __init__(self):
        self.decoded = FakeDecoded()
        self.transport = FakeTransport(self.decoded)

    def check(self, checker=None):
        return p.check_reference(self.decoded, self.transport, c if checker is None else checker)

    def symbol(self, name=ROOTS[1]):
        return next(row for row in self.decoded.symbols if row["name"] == name)

    def rebind_bytes(self, data):
        self.decoded.data = self.transport.machine.data = data
        for name, offset, size, _ in LAYOUT:
            record = self.transport.records[name]
            body = self.decoded.read(1, offset, size)
            record["MachineBodySha256"] = sha(body)
            record["BodySha256"] = sha(b"synthetic applied final:" + body)
            record["RootOrigin"]["ProviderSha256"] = sha(data)


class ProtocolTests(unittest.TestCase):
    def rejects(self, fixture):
        with self.assertRaises((p.Rejected, c.Rejected)):
            fixture.check()

    def test_three_reference_roots_hash_domains_and_nonclaims(self):
        fixture = Fixture()
        result = fixture.check()
        self.assertEqual(result["Status"], "REFERENCE-CANONICAL-PASS-NOT-PAIRED-QUALIFIED")
        self.assertEqual(result["Scope"], "REFERENCE_CM3_O2_LTO_THREE_CANONICAL_PROTOCOLS_ONLY")
        self.assertIs(result["CanonicalProtocolValidated"], True)
        self.assertIs(result["OriginalTransportRecordsUnmodified"], True)
        self.assertIs(type(result["ClosedBodies"]), int)
        self.assertEqual(result["ClosedBodies"], 3)
        for key in ("RequiredCellsSatisfied", "SemanticProjections"):
            self.assertIs(type(result[key]), int)
            self.assertEqual(result[key], 0)
        for key in ("SourceToMachineSemanticProof", "FinalReferenceParity", "FullABIProof", "PolicyEquivalence",
                    "CompleteObjectProof", "CpuExecution", "BoardExecution", "GlobalFreezeQualified"):
            self.assertIs(result[key], False)
        self.assertEqual([row["Name"] for row in result["Roots"]], list(ROOTS))
        self.assertEqual(fixture.decoded.calls, list(ROOTS))
        self.assertEqual(fixture.transport.calls, list(ROOTS))
        for root, matched in zip(result["Roots"], result["MatchEvidence"]):
            self.assertEqual(root["RawCanonicalTokens"], c._REFERENCE[root["Name"]])
            self.assertEqual(root["RawTokenSha256"], token_sha(root["RawCanonicalTokens"]))
            self.assertEqual(matched["BodySha256"], root["RawTokenSha256"])
            self.assertEqual(matched["Side"], "Reference")
            self.assertEqual(matched["TailNops"], 0)
            self.assertEqual(root["ProjectionEvidence"], [])
            self.assertIs(root["TransportRecord"]["CanonicalProtocolValidated"], False)
            self.assertNotEqual(root["RawTokenSha256"], root["MachineBodySha256"])
            self.assertNotEqual(root["RawTokenSha256"], root["FinalBodySha256"])
            self.assertEqual(root["MachineProviderSha256"], sha(fixture.decoded.data))
            self.assertEqual(root["HashDomains"], dict(MachineRoot="SHA256-UNAPPLIED-MACHINE-FUNCTION-BYTES",
                FinalRoot="SHA256-APPLIED-FINAL-FUNCTION-BYTES", Canonical="SHA256-JSON-TOKENS"))

    def test_evidence_tokens_and_transport_records_are_deep_copied(self):
        fixture = Fixture()
        before = copy.deepcopy((fixture.decoded.tokens, fixture.transport.records, c._REFERENCE))
        result = fixture.check()
        root = result["Roots"][1]
        self.assertIsNot(root["RawCanonicalTokens"], fixture.decoded.tokens[ROOTS[1]])
        self.assertIsNot(root["TransportRecord"], fixture.transport.records[ROOTS[1]])
        root["RawCanonicalTokens"][0] = ("changed-output", "")
        root["TransportRecord"]["RootOrigin"]["ProviderSha256"] = "changed-output"
        root["TransportRecord"]["References"][0]["Symbol"] = "changed-output"
        self.assertEqual((fixture.decoded.tokens, fixture.transport.records, c._REFERENCE), before)

    def test_composition_is_pure_and_does_not_mutate_input_metadata(self):
        fixture = Fixture()
        before = copy.deepcopy((fixture.decoded.data, fixture.decoded.symbols, fixture.decoded.sections,
                                fixture.decoded.tokens, fixture.transport.records, c._REFERENCE, c._NATIVE))
        with patch("builtins.open", side_effect=AssertionError("pure composition cannot open files")), \
                patch.object(Path, "open", side_effect=AssertionError("pure composition cannot open files")), \
                patch.object(Path, "read_bytes", side_effect=AssertionError("pure composition cannot read files")), \
                patch.object(Path, "read_text", side_effect=AssertionError("pure composition cannot read files")), \
                patch.object(Path, "write_bytes", side_effect=AssertionError("pure composition cannot write files")), \
                patch.object(Path, "write_text", side_effect=AssertionError("pure composition cannot write files")), \
                patch("subprocess.Popen", side_effect=AssertionError("pure composition cannot run processes")):
            fixture.check()
        self.assertEqual((fixture.decoded.data, fixture.decoded.symbols, fixture.decoded.sections,
                          fixture.decoded.tokens, fixture.transport.records, c._REFERENCE, c._NATIVE), before)

    def test_different_or_nonbytes_whole_machine_input_rejects(self):
        for change in ("different", "bytearray"):
            fixture = Fixture()
            fixture.decoded.data = (fixture.decoded.data + b"foreign" if change == "different"
                                    else bytearray(fixture.decoded.data))
            with self.subTest(change=change):
                self.rejects(fixture)

    def test_missing_ambiguous_or_undefined_root_definition_rejects(self):
        for name in ROOTS:
            for change in ("missing", "ambiguous", "undefined"):
                fixture = Fixture()
                symbol = fixture.symbol(name)
                if change == "missing":
                    fixture.decoded.symbols.remove(symbol)
                elif change == "ambiguous":
                    fixture.decoded.symbols.append(copy.deepcopy(symbol))
                else:
                    symbol["section"] = 0
                with self.subTest(name=name, change=change):
                    self.rejects(fixture)

    def test_only_first_root_is_local_and_handlers_must_be_global_functions(self):
        for name in ROOTS:
            wrong = (0x12, 0x22, 0x01) if name == ROOTS[0] else (0x02, 0x22, 0x11)
            for info in wrong:
                fixture = Fixture()
                fixture.symbol(name)["info"] = info
                with self.subTest(name=name, info=info):
                    self.rejects(fixture)

    def test_decoded_symbol_extent_thumb_and_integer_types_are_exact(self):
        changes = (("section", 2), ("section", True), ("section", 1.0), ("info", True), ("info", 18.0),
                   ("size", 34), ("size", True), ("size", 36.0), ("value", 64), ("value", True), ("value", 65.0))
        for key, value in changes:
            fixture = Fixture()
            fixture.symbol()[key] = value
            with self.subTest(key=key, value=value):
                self.rejects(fixture)

    def test_root_origin_identity_hash_extent_and_integer_aliases_reject(self):
        changes = (("Name", ROOTS[1]), ("ProviderSha256", "0" * 64), ("InputSectionIndex", 2),
                   ("InputSectionIndex", True), ("InputSectionIndex", 1.0), ("SymbolOffset", 2),
                   ("SymbolOffset", False), ("SymbolOffset", 0.0), ("Size", 30), ("Size", True),
                   ("Size", 32.0), ("GeneratedMachineOriginBound", False), ("GeneratedMachineOriginBound", 1))
        for key, value in changes:
            fixture = Fixture()
            fixture.transport.records[ROOTS[0]]["RootOrigin"][key] = value
            with self.subTest(key=key, value=value):
                self.rejects(fixture)

    def test_transport_identity_flags_and_numeric_fields_are_strict(self):
        changes = (("Name", ROOTS[2]), ("GeneratedMachineBoundRootPreservation", False),
                   ("GeneratedMachineBoundRootPreservation", 1), ("CanonicalProtocolValidated", True),
                   ("CanonicalProtocolValidated", 0), ("Size", 34), ("Size", True), ("Size", 36.0),
                   ("InstructionCount", True), ("InstructionCount", 10.0))
        for key, value in changes:
            fixture = Fixture()
            fixture.transport.records[ROOTS[1]][key] = value
            with self.subTest(key=key, value=value):
                self.rejects(fixture)

    def test_machine_root_hash_cannot_be_a_foreign_or_token_hash(self):
        for value in ("0" * 64, token_sha(c._REFERENCE[ROOTS[1]])):
            fixture = Fixture()
            fixture.transport.records[ROOTS[1]]["MachineBodySha256"] = value
            with self.subTest(value=value):
                self.rejects(fixture)

    def test_shared_machine_root_drift_still_fails_independent_body_hash(self):
        for name, offset, _, _ in LAYOUT:
            fixture = Fixture()
            data = bytearray(fixture.decoded.data)
            data[PREFIX_SIZE + offset] ^= 1
            fixture.decoded.data = fixture.transport.machine.data = bytes(data)
            for record in fixture.transport.records.values():
                record["RootOrigin"]["ProviderSha256"] = sha(data)
            with self.subTest(name=name), self.assertRaisesRegex(p.Rejected, "complete machine root bytes"):
                fixture.check()

    def test_foreign_roots_and_incomplete_literal_modes_reject(self):
        fixture = Fixture()
        view = p.ReferenceProtocolView(fixture.decoded, fixture.transport)
        for name, mode in (("SVC_Handler", True), ("pxCurrentTCB", True), (ROOTS[0], False),
                           (ROOTS[0], 1), (ROOTS[0], None)):
            with self.subTest(name=name, mode=mode), self.assertRaises(p.Rejected):
                view.function(name, literal_islands=mode)
        self.assertEqual(fixture.decoded.calls, [])
        self.assertEqual(fixture.transport.calls, [])

    def test_rebound_synthetic_body_and_disassembly_token_changes_fail_checker(self):
        changes = ((ROOTS[0], ("svc", "0"), ("svc", "1")),
                   (ROOTS[1], ("orr", "lr,lr,#13"), ("orr", "lr,lr,#9")),
                   (ROOTS[2], ("mov", "r0,#16"), ("mov", "r0,#32")))
        for name, before, after in changes:
            fixture = Fixture()
            index = fixture.decoded.tokens[name].index(before)
            fixture.decoded.tokens[name][index] = after
            data = bytearray(fixture.decoded.data)
            offset = next(offset for root, offset, _, _ in LAYOUT if root == name)
            data[PREFIX_SIZE + offset] ^= 1
            fixture.rebind_bytes(bytes(data))
            with self.subTest(name=name):
                view = p.ReferenceProtocolView(fixture.decoded, fixture.transport)
                self.assertIn(after, view.function(name, literal_islands=True))
                with self.assertRaisesRegex(c.Rejected, "Reference/" + name + "/"):
                    fixture.check()

    def test_malformed_canonical_token_shapes_reject_before_matching(self):
        malformed = ((), [], [("nop",)], [("nop", "", "extra")], [["nop", ""]], [(1, "")], [("nop", False)])
        for tokens in malformed:
            fixture = Fixture()
            fixture.decoded.tokens[ROOTS[1]] = copy.deepcopy(tokens)
            with self.subTest(tokens=tokens), self.assertRaisesRegex(p.Rejected, "canonical tokens"):
                fixture.check()

    def test_complete_raw_tokens_and_named_literals_are_never_projected_or_filtered(self):
        for change in ("missing-island", "extra-token", "truncated", "reordered", "literal-target"):
            fixture = Fixture()
            tokens = fixture.decoded.tokens[ROOTS[1]]
            if change == "missing-island":
                tokens.pop()
            elif change == "extra-token":
                tokens.insert(1, ("nop", ""))
            elif change == "truncated":
                tokens.pop(0)
            elif change == "reordered":
                tokens[0], tokens[1] = tokens[1], tokens[0]
            else:
                index, value = next((index, value) for index, (op, value) in enumerate(tokens) if op == "@literal-island")
                island = json.loads(value)
                island["Relocations"][0]["Target"] = ".bss"
                tokens[index] = ("@literal-island", json.dumps(island, sort_keys=True, separators=(",", ":")))
            with self.subTest(change=change), self.assertRaises(c.Rejected):
                fixture.check()

    def test_nonzero_and_mixed_tail_nops_reject_even_if_matcher_accepts_them(self):
        for names in ((ROOTS[0],), (ROOTS[1], ROOTS[2]), ROOTS):
            fixture = Fixture()
            for name in names:
                fixture.decoded.tokens[name].append(("nop", ""))
            view = p.ReferenceProtocolView(fixture.decoded, fixture.transport)
            for name in names:
                self.assertEqual(c._match(view, "Reference", name, c._REFERENCE[name])["TailNops"], 1)
            with self.subTest(names=names), self.assertRaisesRegex(p.Rejected, "zero post-island tail NOPs"):
                fixture.check()

    def test_wrong_frozen_reference_root_set_or_order_rejects(self):
        for roots in ({}, {name: c._REFERENCE[name] for name in reversed(ROOTS)}, dict(c._REFERENCE, foreign=[])):
            match = Mock(side_effect=c._match)
            checker = SimpleNamespace(_REFERENCE=roots, _match=match)
            with self.subTest(roots=list(roots)), self.assertRaises(p.Rejected):
                Fixture().check(checker)
            match.assert_not_called()

    def test_only_reference_match_runs_without_native_or_paired_credit(self):
        fixture = Fixture()
        match = Mock(side_effect=c._match)
        paired = Mock(side_effect=AssertionError("no paired checker permitted"))
        checker = SimpleNamespace(_REFERENCE=c._REFERENCE, _match=match, check_pair=paired)
        result = fixture.check(checker)
        paired.assert_not_called()
        self.assertEqual(match.call_count, 3)
        self.assertEqual([call.args[1:3] for call in match.call_args_list], [("Reference", name) for name in ROOTS])
        self.assertEqual([call.args[3] for call in match.call_args_list], [c._REFERENCE[name] for name in ROOTS])
        self.assertIs(result["FinalReferenceParity"], False)
        self.assertEqual(result["ClosedBodies"], 3)
        self.assertNotIn("Mechanisms", result)
        self.assertNotIn("DifferenceIds", result)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    output, temporary = args.output_dir.resolve(), Path(tempfile.gettempdir()).resolve()
    if (output.exists() or args.output_dir.is_symlink() or output.is_relative_to(REPO)
            or REPO.is_relative_to(output) or not output.is_relative_to(temporary)):
        parser.error("fresh external TEMP output directory required")
    report = dict(Status="FAIL", Tests=0, ExpectedTestMethods=EXPECTED_METHODS, Failures=0, Errors=0, Skipped=0,
        SourceHashes={}, SourceDrift=[], SourceClosureVerified=False, ClosingFilesVerified=0,
        Scope="PURE_SYNTHETIC_REFERENCE_CM3_LTO_CANONICAL_CONTROLS_ONLY", SyntheticInputs=True,
        ActualELFTested=False, ActualMachineDecoderTested=False, ActualTransportPreservationTested=False,
        FrozenCheckerUsed=False, NativeCommandsExecuted=0, ToolInvocations=0, Qualification=False,
        SourceToMachineSemanticProof=False, FinalReferenceParity=False, FullABIProof=False,
        CompleteObjectProof=False, PolicyEquivalence=False, CpuExecution=False, BoardExecution=False,
        GlobalFreezeQualified=False, RequiredCellsSatisfied=0)
    paths = (Path(__file__).resolve(), PROTOCOL, CHECKER)
    try:
        if sys.flags.optimize or not __debug__:
            raise ValueError("optimized interpreter unsupported")
        buffers = {path: path.read_bytes() for path in paths}
        report["SourceHashes"] = {str(path): sha(data) for path, data in buffers.items()}
        if sha(buffers[PROTOCOL]) != PROTOCOL_SHA256 or sha(buffers[CHECKER]) != CHECKER_SHA256:
            raise ValueError("exact reviewed protocol and unchanged checker source cohort required")
        global p, c
        with patch("subprocess.Popen", side_effect=AssertionError("pure controls cannot execute processes")), \
                patch("os.system", side_effect=AssertionError("pure controls cannot execute processes")):
            p = module("pure_reference_cm3_lto_protocol", PROTOCOL, buffers[PROTOCOL])
            c = module("pure_reference_cm3_frozen_checker", CHECKER, buffers[CHECKER])
            report["FrozenCheckerUsed"] = True
            suite = unittest.defaultTestLoader.loadTestsFromTestCase(ProtocolTests)
            count = suite.countTestCases()
            if count != EXPECTED_METHODS:
                raise ValueError("exact 18 synthetic control methods required")
            result = unittest.TextTestRunner(verbosity=2).run(suite)
        report.update(Tests=result.testsRun, Failures=len(result.failures), Errors=len(result.errors), Skipped=len(result.skipped),
            FailureDetails=[dict(Test=str(case), Detail=detail) for case, detail in result.failures + result.errors])
        if result.wasSuccessful() and result.testsRun == count and not result.skipped:
            report["Status"] = "PASS"
    except Exception:
        report.update(Status="FAIL", Error=traceback.format_exc(), Errors=report["Errors"] + 1)
    finally:
        for path, value in report["SourceHashes"].items():
            try:
                if sha(Path(path).read_bytes()) != value:
                    report["SourceDrift"].append(path)
                else:
                    report["ClosingFilesVerified"] += 1
            except OSError:
                report["SourceDrift"].append(path)
        report["SourceClosureVerified"] = len(report["SourceHashes"]) == 3 and not report["SourceDrift"]
        if not report["SourceClosureVerified"]:
            report["Status"] = "FAIL"
    output.mkdir(parents=True, exist_ok=False)
    target = output / "results.json"
    target.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="ascii")
    print("Receipt:", target, sha(target.read_bytes()))
    return 0 if report["Status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
