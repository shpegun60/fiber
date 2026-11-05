"""Pure synthetic controls for native CM3 LTO canonical role projection.

The fake decoder returns source-transcribed checker tokens, not decoded ELF.
The fake transport supplies metadata, not independently proved preservation.
Actual ELF, producer closure and machine semantics are not tested here.
"""
import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
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
ROOTS = ("fiber_port_start_first_context", "SVC_Handler", "PendSV_Handler")
SLOT = "fiber_internal_runtime_current_context_slot"
SECTION = ".bss.fiber_runtime_current_context_slot"
LAYOUT = ((ROOTS[0], 32, 104, 34), (ROOTS[1], 160, 184, 64), (ROOTS[2], 384, 204, 72))
CALLS = {
    ROOTS[0]: ((0x56, "fiber_panic"), (0x5E, "fiber_panic")),
    ROOTS[1]: ((0x72, "fiber_port_context_validate_restore"), (0x9E, "fiber_panic"),
               (0xA6, "fiber_panic"), (0xAE, "fiber_panic")),
    ROOTS[2]: ((0x34, "fiber_port_context_validate_save_current"),
               (0x82, "fiber_port_scheduler_pick_next_from_pendsv"),
               (0xB0, "fiber_panic"), (0xB8, "fiber_panic"), (0xC0, "fiber_panic")),
}
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


def descriptor(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


class FakeDecoded:
    def __init__(self):
        self.tokens = copy.deepcopy(c._NATIVE)
        self.symbols, self.calls = [], []
        payload = bytearray((index * 7 + 3) % 256 for index in range(768))
        for name, offset, size, _ in LAYOUT:
            self.symbols.append(dict(name=name, value=offset | 1, size=size, info=0x12, section=1))
            for index, (op, value) in enumerate(self.tokens[name]):
                if op == "ldr" and "=" + SLOT + "+0" in value:
                    self.tokens[name][index] = (op, value.replace(SLOT, SECTION))
                elif op == "@literal-island":
                    island = json.loads(value)
                    raw = bytes.fromhex(island["Bytes"])
                    payload[offset + island["Offset"]:offset + island["Offset"] + len(raw)] = raw
                    for relocation in island["Relocations"]:
                        if relocation["Target"] == SLOT:
                            relocation["Target"] = SECTION
                    self.tokens[name][index] = (op, descriptor(island))
        self.data = b"SYNTHETIC-NOT-ELF".ljust(64, b"\x7f") + bytes(payload)
        self.sections = [(0,) * 10, (0, 1, 6, 0, 64, len(payload), 0, 0, 4, 0)]

    def read(self, section, address, size):
        if type(section) is not int or section != 1 or address < 0 or size < 0 or address + size > self.sections[1][5]:
            raise ValueError("synthetic section bounds")
        return self.data[64 + address:64 + address + size]

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
            references = [dict(Offset=site, Kind=10, Symbol=symbol, Addend=-4) for site, symbol in CALLS[name]]
            origins = []
            if name != ROOTS[0]:
                site = 0xB4 if name == ROOTS[1] else 0xC8
                origin = dict(Name=SLOT, Provider="C:/synthetic/machine.o", ProviderSha256=sha(decoded.data),
                    InputSection=SECTION, InputSectionIndex=2, SectionAddress=0x20000480, SectionSize=4,
                    SymbolOffset=0, Size=4, Entry=0x20000480, OutputSection=".bss", OutputSectionIndex=3,
                    OutputSectionOffset=0x480, GeneratedMachineOriginBound=True)
                original = dict(name="", kind="STT_SECTION", binding="STB_LOCAL", visibility="STV_DEFAULT",
                                size=0, section=2, value=0)
                final = dict(original, section=3, value=0x20000000)
                references.append(dict(Offset=site, Kind=2, Symbol=SLOT, Addend=0, OriginalBytes="00000000",
                    OriginalTargetSection=SECTION, FinalTargetSection=".bss", Binding="STB_LOCAL",
                    ResolvedValue=origin["Entry"], Bytes=struct.pack("<I", origin["Entry"]).hex(),
                    OriginalRelocationSymbol=original, FinalRelocationSymbol=final))
                origins.append(origin)
            self.records[name] = dict(Name=name, Size=size, InstructionCount=count, MachineBodySha256=sha(body),
                BodySha256=sha(b"synthetic final bytes:" + body), References=references, DefinitionOrigins=origins,
                RootOrigin=dict(Name=name, Provider="C:/synthetic/machine.o", ProviderSha256=sha(decoded.data),
                    InputSection=".text", InputSectionIndex=1, SymbolOffset=offset, Size=size,
                    GeneratedMachineOriginBound=True), GeneratedMachineBoundRootPreservation=True,
                CanonicalProtocolValidated=False, OriginalTranslationUnitOwnership=False,
                SourceToMachineSemanticProof=False, FinalReferenceParity=False, PolicyEquivalence=False,
                CpuExecution=False, BoardExecution=False, RequiredCellsSatisfied=0, GlobalFreezeQualified=False)

    def function(self, name):
        self.calls.append(name)
        return self.records[name]


class Fixture:
    def __init__(self):
        self.decoded = FakeDecoded()
        self.transport = FakeTransport(self.decoded)

    def check(self, checker=None):
        return p.check_native(self.decoded, self.transport, c if checker is None else checker)

    def slot(self, name=ROOTS[1]):
        return next(row for row in self.transport.records[name]["References"] if row["Kind"] == 2)

    def island(self, name=ROOTS[1]):
        index, value = next((index, value) for index, (op, value) in enumerate(self.decoded.tokens[name]) if op == "@literal-island")
        return index, json.loads(value)

    def set_island(self, name, value):
        index, _ = self.island(name)
        self.decoded.tokens[name][index] = ("@literal-island", descriptor(value))

    def rebind_bytes(self, data):
        self.decoded.data = self.transport.machine.data = data
        for name, offset, size, _ in LAYOUT:
            record = self.transport.records[name]
            body = self.decoded.read(1, offset, size)
            record["MachineBodySha256"] = sha(body)
            record["BodySha256"] = sha(b"synthetic final bytes:" + body)
            record["RootOrigin"]["ProviderSha256"] = sha(data)
            for origin in record["DefinitionOrigins"]:
                origin["ProviderSha256"] = sha(data)


class ProtocolTests(unittest.TestCase):
    def rejects(self, fixture):
        with self.assertRaises((p.Rejected, c.Rejected)):
            fixture.check()

    def test_synthetic_three_root_projection_and_scope(self):
        fixture = Fixture()
        result = fixture.check()
        self.assertEqual(result["Status"], "NATIVE-CANONICAL-PASS-NOT-REFERENCE-QUALIFIED")
        self.assertEqual(result["Scope"], "NATIVE_CM3_O2_LTO_THREE_CANONICAL_PROTOCOLS_ONLY")
        self.assertIs(result["CanonicalProtocolValidated"], True)
        self.assertEqual(result["ClosedBodies"], 3)
        self.assertIs(type(result["RequiredCellsSatisfied"]), int)
        self.assertEqual(result["RequiredCellsSatisfied"], 0)
        self.assertEqual([row["Name"] for row in result["Roots"]], list(ROOTS))
        self.assertEqual([len(row["ProjectionEvidence"]) for row in result["Roots"]], [0, 1, 1])
        for key in ("SourceToMachineSemanticProof", "FinalReferenceParity", "FullABIProof", "PolicyEquivalence",
                    "CompleteObjectProof", "CpuExecution", "BoardExecution", "GlobalFreezeQualified"):
            self.assertIs(result[key], False)
        for root in result["Roots"]:
            self.assertEqual(root["ProjectedCanonicalTokens"], c._NATIVE[root["Name"]])
            self.assertIs(root["TransportRecord"]["CanonicalProtocolValidated"], False)
            for evidence in root["ProjectionEvidence"]:
                self.assertEqual(evidence["Kind"], "PROVED_SECTION_TO_LOGICAL_SLOT_ROLE_ONLY")
                for key in ("OriginalRelocationSymbol", "FinalRelocationSymbol"):
                    self.assertEqual(evidence["Reference"][key]["name"], "")

    def test_projection_is_pure_and_does_not_mutate_decoder_transport_or_checker(self):
        fixture = Fixture()
        before = copy.deepcopy((fixture.decoded.data, fixture.decoded.symbols, fixture.decoded.sections,
                                fixture.decoded.tokens, fixture.transport.records, c._NATIVE, c._REFERENCE, p.SITES))
        with patch("builtins.open", side_effect=AssertionError("pure projection must not open files")), \
                patch.object(Path, "open", side_effect=AssertionError("pure projection must not open files")), \
                patch.object(Path, "read_bytes", side_effect=AssertionError("pure projection must not read files")), \
                patch.object(Path, "write_bytes", side_effect=AssertionError("pure projection must not write files")), \
                patch("subprocess.Popen", side_effect=AssertionError("pure projection must not run processes")):
            fixture.check()
        after = (fixture.decoded.data, fixture.decoded.symbols, fixture.decoded.sections,
                 fixture.decoded.tokens, fixture.transport.records, c._NATIVE, c._REFERENCE, p.SITES)
        self.assertEqual(after, before)
        self.assertEqual(fixture.transport.calls, list(ROOTS))
        self.assertEqual(fixture.decoded.calls, list(ROOTS))

    def test_raw_and_projected_token_hashes_are_not_body_byte_hashes(self):
        result = Fixture().check()
        for root, match in zip(result["Roots"], result["MatchEvidence"]):
            self.assertEqual(root["RawTokenSha256"], token_sha(root["RawCanonicalTokens"]))
            self.assertEqual(root["ProjectedTokenSha256"], token_sha(root["ProjectedCanonicalTokens"]))
            self.assertEqual(match["BodySha256"], root["ProjectedTokenSha256"])
            self.assertNotEqual(root["MachineBodySha256"], root["ProjectedTokenSha256"])
            self.assertNotEqual(root["FinalBodySha256"], root["ProjectedTokenSha256"])
            self.assertEqual(root["HashDomains"], dict(MachineRoot="SHA256-UNAPPLIED-MACHINE-FUNCTION-BYTES",
                FinalRoot="SHA256-APPLIED-FINAL-FUNCTION-BYTES", Canonical="SHA256-JSON-TOKENS"))

    def test_different_whole_machine_bytes_or_nonbytes_decoder_input_rejects(self):
        for change in ("different", "nonbytes"):
            fixture = Fixture()
            fixture.decoded.data = fixture.decoded.data + b"foreign" if change == "different" else bytearray(fixture.decoded.data)
            with self.subTest(change=change):
                self.rejects(fixture)

    def test_unique_defined_root_symbol_is_required(self):
        for change in ("missing", "duplicate", "undefined"):
            fixture = Fixture()
            if change == "missing":
                fixture.decoded.symbols.pop(1)
            elif change == "duplicate":
                fixture.decoded.symbols.append(copy.deepcopy(fixture.decoded.symbols[1]))
            else:
                fixture.decoded.symbols[1]["section"] = 0
            with self.subTest(change=change):
                self.rejects(fixture)

    def test_symbol_kind_binding_size_section_and_thumb_entry_are_exact(self):
        for key, value in (("info", 2), ("info", 0x22), ("size", 182), ("size", True),
                           ("section", True), ("section", 2), ("value", 160)):
            fixture = Fixture()
            fixture.decoded.symbols[1][key] = value
            with self.subTest(key=key, value=value):
                self.rejects(fixture)

    def test_root_origin_provider_section_offset_size_and_bound_flag_are_required(self):
        for key, value in (("Name", ROOTS[2]), ("ProviderSha256", "0" * 64), ("InputSectionIndex", 2),
                           ("SymbolOffset", 162), ("Size", 182), ("GeneratedMachineOriginBound", 1)):
            fixture = Fixture()
            fixture.transport.records[ROOTS[1]]["RootOrigin"][key] = value
            with self.subTest(key=key, value=value):
                self.rejects(fixture)

    def test_transport_record_identity_and_literal_proof_flags_are_required(self):
        for key, value in (("Name", ROOTS[2]), ("GeneratedMachineBoundRootPreservation", False),
                           ("GeneratedMachineBoundRootPreservation", 1), ("CanonicalProtocolValidated", True),
                           ("CanonicalProtocolValidated", 0)):
            fixture = Fixture()
            fixture.transport.records[ROOTS[1]][key] = value
            with self.subTest(key=key, value=value):
                self.rejects(fixture)

    def test_machine_body_hash_cannot_be_replaced_by_token_or_foreign_hash(self):
        for value in ("0" * 64, token_sha(c._NATIVE[ROOTS[1]])):
            fixture = Fixture()
            fixture.transport.records[ROOTS[1]]["MachineBodySha256"] = value
            with self.subTest(value=value):
                self.rejects(fixture)

    def test_changed_root_body_is_rejected_even_if_whole_machine_is_shared(self):
        fixture = Fixture()
        data = bytearray(fixture.decoded.data)
        data[64 + 160] ^= 1
        fixture.decoded.data = fixture.transport.machine.data = bytes(data)
        for record in fixture.transport.records.values():
            record["RootOrigin"]["ProviderSha256"] = sha(data)
        self.rejects(fixture)

    def test_unknown_root_or_nonliteral_island_view_is_rejected(self):
        fixture = Fixture()
        view = p.NativeProtocolView(fixture.decoded, fixture.transport)
        for name, option in (("fiber_panic", True), (ROOTS[0], False), (ROOTS[0], 1)):
            with self.subTest(name=name, option=option), self.assertRaises(p.Rejected):
                view.function(name, literal_islands=option)

    def test_coherent_synthetic_constant_changes_pass_binding_but_fail_protocol(self):
        changes = ((ROOTS[0], ("svc", "70"), ("svc", "71")),
                   (ROOTS[1], ("cmp", "r3,#70"), ("cmp", "r3,#71")),
                   (ROOTS[2], ("movs", "r2,#16"), ("movs", "r2,#32")))
        for name, before, after in changes:
            fixture = Fixture()
            index = fixture.decoded.tokens[name].index(before)
            fixture.decoded.tokens[name][index] = after
            data = bytearray(fixture.decoded.data)
            root_offset = next(offset for root, offset, _, _ in LAYOUT if root == name)
            data[64 + root_offset] ^= 1
            fixture.rebind_bytes(bytes(data))
            with self.subTest(name=name):
                view = p.NativeProtocolView(fixture.decoded, fixture.transport)
                self.assertIn(after, view.function(name, literal_islands=True))
                with self.assertRaises(c.Rejected):
                    fixture.check()

    def test_single_tail_nop_is_rejected_even_when_frozen_matcher_accepts_it(self):
        for all_roots in (False, True):
            fixture = Fixture()
            names = ROOTS if all_roots else (ROOTS[0],)
            for name in names:
                fixture.decoded.tokens[name].append(("nop", ""))
            view = p.NativeProtocolView(fixture.decoded, fixture.transport)
            for name in names:
                self.assertEqual(c._match(view, "Native", name, c._NATIVE[name])["TailNops"], 1)
            with self.subTest(all_roots=all_roots), self.assertRaisesRegex(p.Rejected, "zero tail NOPs"):
                fixture.check()

    def test_extra_instruction_or_changed_branch_index_is_not_ignored(self):
        for change in ("extra", "branch"):
            fixture = Fixture()
            tokens = fixture.decoded.tokens[ROOTS[0]]
            if change == "extra":
                tokens.insert(0, ("nop", ""))
            else:
                index = tokens.index(("bne", "@31"))
                tokens[index] = ("bne", "@30")
            with self.subTest(change=change), self.assertRaises(c.Rejected):
                fixture.check()

    def test_missing_slot_ldr_or_literal_descriptor_rejects(self):
        for change in ("ldr", "island"):
            fixture = Fixture()
            tokens = fixture.decoded.tokens[ROOTS[1]]
            if change == "ldr":
                index = next(index for index, (op, value) in enumerate(tokens) if op == "ldr" and SECTION in value)
            else:
                index = fixture.island()[0]
            tokens.pop(index)
            with self.subTest(change=change):
                self.rejects(fixture)

    def test_missing_or_additional_abs32_projection_rejects(self):
        for change in ("missing", "duplicate", "first-start"):
            fixture = Fixture()
            reference = fixture.slot()
            if change == "missing":
                fixture.transport.records[ROOTS[1]]["References"].remove(reference)
            else:
                name = ROOTS[0] if change == "first-start" else ROOTS[1]
                fixture.transport.records[name]["References"].append(copy.deepcopy(reference))
            with self.subTest(change=change):
                self.rejects(fixture)

    def test_additional_section_label_or_slot_load_cannot_be_projected(self):
        for change in ("load", "foreign-token", "first-start"):
            fixture = Fixture()
            name = ROOTS[0] if change == "first-start" else ROOTS[1]
            fixture.decoded.tokens[name].insert(0, ("ldr", "r0,=" + SECTION + "+0") if change != "foreign-token"
                                                 else ("mov", "r0," + SECTION))
            with self.subTest(change=change):
                self.rejects(fixture)

    def test_wrong_slot_reference_fields_are_rejected(self):
        for key, value in (("Offset", 184), ("Kind", 10), ("Symbol", "foreign_slot"), ("Addend", 4),
                           ("OriginalBytes", "04000000"), ("OriginalTargetSection", ".bss.foreign"),
                           ("FinalTargetSection", ".data"), ("Binding", "STB_GLOBAL"), ("Bytes", "00000020"),
                           ("ResolvedValue", 0x20000484)):
            fixture = Fixture()
            fixture.slot()[key] = value
            with self.subTest(key=key, value=value):
                self.rejects(fixture)

    def test_slot_addend_and_raw_symbol_size_cannot_be_boolean_zero_aliases(self):
        for change in ("addend", "raw-size"):
            fixture = Fixture()
            if change == "addend":
                fixture.slot()["Addend"] = False
            else:
                fixture.slot()["OriginalRelocationSymbol"]["size"] = False
            with self.subTest(change=change):
                self.rejects(fixture)

    def test_missing_duplicate_or_foreign_slot_origin_rejects(self):
        for change in ("missing", "duplicate", "foreign"):
            fixture = Fixture()
            origins = fixture.transport.records[ROOTS[1]]["DefinitionOrigins"]
            if change == "missing":
                origins.clear()
            elif change == "duplicate":
                origins.append(copy.deepcopy(origins[0]))
            else:
                origins[0]["Name"] = "foreign_slot"
            with self.subTest(change=change):
                self.rejects(fixture)

    def test_slot_origin_must_bind_provider_sections_extent_and_value(self):
        for key, value in (("GeneratedMachineOriginBound", 1), ("ProviderSha256", "0" * 64),
                           ("InputSection", ".bss.foreign"), ("OutputSection", ".data"), ("Size", 8),
                           ("SectionSize", 8), ("SymbolOffset", 4), ("Entry", 0x20000484),
                           ("InputSectionIndex", 4), ("OutputSectionIndex", 4), ("OutputSectionOffset", 0x484)):
            fixture = Fixture()
            fixture.transport.records[ROOTS[1]]["DefinitionOrigins"][0][key] = value
            with self.subTest(key=key, value=value):
                self.rejects(fixture)

    def test_raw_empty_section_names_and_exact_section_symbol_roles_are_required(self):
        for target in ("OriginalRelocationSymbol", "FinalRelocationSymbol"):
            for key, value in (("name", SLOT), ("name", SECTION), ("kind", "STT_OBJECT"),
                               ("binding", "STB_GLOBAL"), ("visibility", "STV_HIDDEN"), ("size", 4),
                               ("section", 9), ("value", 4)):
                fixture = Fixture()
                fixture.slot()[target][key] = value
                with self.subTest(target=target, key=key, value=value):
                    self.rejects(fixture)

    def test_descriptor_offsets_bytes_links_kinds_targets_and_shape_are_not_discarded(self):
        for change in ("offset", "bytes", "instruction", "reference-offset", "kind", "target", "extra", "missing", "order"):
            fixture = Fixture()
            _, island = fixture.island()
            if change == "offset":
                island["Offset"] += 4
            elif change == "bytes":
                island["Bytes"] = "01000000"
            elif change == "instruction":
                island["References"][0]["Instruction"] += 2
            elif change == "reference-offset":
                island["References"][0]["Offset"] += 2
            elif change == "kind":
                island["Relocations"][0]["Kind"] = 10
            elif change == "target":
                island["Relocations"][0]["Target"] = SLOT
            elif change == "extra":
                island["Ignored"] = True
            elif change == "missing":
                del island["Relocations"]
            else:
                island["References"] *= 2
                island["References"].reverse()
            fixture.set_island(ROOTS[1], island)
            with self.subTest(change=change):
                self.rejects(fixture)

    def test_duplicate_descriptor_key_is_not_silently_last_wins(self):
        fixture = Fixture()
        index, _ = fixture.island()
        op, value = fixture.decoded.tokens[ROOTS[1]][index]
        fixture.decoded.tokens[ROOTS[1]][index] = (op, value[:-1] + ',"Offset":180}')
        self.rejects(fixture)

    def test_pendsv_alignment_padding_and_literal_width_remain_complete(self):
        for value in ("00000000", "010000000000", "0000000000000000"):
            fixture = Fixture()
            _, island = fixture.island(ROOTS[2])
            island["Bytes"] = value
            fixture.set_island(ROOTS[2], island)
            with self.subTest(value=value):
                self.rejects(fixture)

    def test_returned_tokens_and_evidence_do_not_alias_input_records(self):
        fixture = Fixture()
        before = copy.deepcopy((fixture.decoded.tokens, fixture.transport.records))
        view = p.NativeProtocolView(fixture.decoded, fixture.transport)
        tokens = view.function(ROOTS[1], literal_islands=True)
        tokens[0] = ("nop", "")
        view.evidence[ROOTS[1]]["ProjectionEvidence"][0]["Reference"]["OriginalRelocationSymbol"]["name"] = "changed output"
        self.assertEqual((fixture.decoded.tokens, fixture.transport.records), before)
        self.assertEqual(view.function(ROOTS[1], literal_islands=True), c._NATIVE[ROOTS[1]])

    def test_native_composition_never_calls_paired_checker_or_fabricates_reference_credit(self):
        fixture = Fixture()
        match = Mock(side_effect=c._match)
        paired = Mock(side_effect=AssertionError("no reference-side substitute permitted"))
        checker = SimpleNamespace(_NATIVE=c._NATIVE, _match=match, check_pair=paired)
        result = fixture.check(checker)
        paired.assert_not_called()
        self.assertEqual(match.call_count, 3)
        self.assertEqual([call.args[1:3] for call in match.call_args_list], [("Native", name) for name in ROOTS])
        self.assertIs(result["FinalReferenceParity"], False)
        self.assertEqual(result["ClosedBodies"], 3)
        self.assertNotIn("Mechanisms", result)
        self.assertNotIn("DifferenceIds", result)

    def test_wrong_checker_root_set_or_order_is_rejected_without_patching_globals(self):
        for roots in ({}, {name: c._NATIVE[name] for name in reversed(ROOTS)}, dict(c._NATIVE, foreign=[])):
            checker = SimpleNamespace(_NATIVE=roots, _match=c._match)
            with self.subTest(roots=list(roots)), self.assertRaises(p.Rejected):
                Fixture().check(checker)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    output = args.output_dir.resolve()
    if output.exists() or output.is_relative_to(REPO) or not output.is_relative_to(Path(tempfile.gettempdir()).resolve()):
        parser.error("fresh external TEMP output directory required")
    report = dict(Status="FAIL", Tests=0, Failures=0, Errors=0, Skipped=0, SourceHashes={}, SourceDrift=[],
        Scope="PURE_SYNTHETIC_CM3_LTO_CANONICAL_PROJECTION_CONTROLS_ONLY", SyntheticInputs=True,
        ActualELFTested=False, ActualMachineDecoderTested=False, ActualTransportPreservationTested=False,
        ToolInvocations=0, NativeCommandsExecuted=0, SourceToMachineSemanticProof=False, FinalReferenceParity=False,
        FullABIProof=False, PolicyEquivalence=False, CpuExecution=False, BoardExecution=False,
        GlobalFreezeQualified=False, RequiredCellsSatisfied=0)
    paths = (Path(__file__).resolve(), PROTOCOL, CHECKER)
    try:
        if sys.flags.optimize or not __debug__:
            raise ValueError("optimized interpreter unsupported")
        buffers = {path: path.read_bytes() for path in paths}
        report["SourceHashes"] = {str(path): sha(data) for path, data in buffers.items()}
        global p, c
        with patch("subprocess.Popen", side_effect=AssertionError("pure controls cannot execute processes")):
            p = module("pure_cm3_lto_protocol", PROTOCOL, buffers[PROTOCOL])
            c = module("pure_cm3_frozen_protocol_checker", CHECKER, buffers[CHECKER])
            suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
            count = suite.countTestCases()
            if not count:
                raise ValueError("nonempty pure projection controls required")
            result = unittest.TextTestRunner(verbosity=2).run(suite)
        report.update(Tests=result.testsRun, Failures=len(result.failures), Errors=len(result.errors), Skipped=len(result.skipped),
            FailureDetails=[dict(Test=str(case), Detail=detail) for case, detail in result.failures + result.errors])
        report["SourceDrift"] = [str(path) for path in paths if not path.is_file() or sha(path.read_bytes()) != report["SourceHashes"][str(path)]]
        if result.wasSuccessful() and result.testsRun == count > 0 and not result.skipped and not report["SourceDrift"]:
            report["Status"] = "PASS"
    except Exception:
        report.update(Status="FAIL", Error=traceback.format_exc(), Errors=report["Errors"] + 1)
    output.mkdir(parents=True, exist_ok=False)
    target = output / "results.json"
    target.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="ascii")
    print("Receipt:", target, sha(target.read_bytes()))
    return 0 if report["Status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
