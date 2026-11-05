"""Pure synthetic CM3 LTO adapter units; no real ELF, tool or CPU qualification.

Fake ELF metadata and synthetic Thumb bodies exercise adapter validation. The
unchanged core body/address decoder is compiled from its captured source AST;
no reader globals are patched and no parser package or external tool is used.
"""
import argparse
import ast
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys
import tempfile
import traceback
from types import MethodType, SimpleNamespace
import unittest
from unittest.mock import Mock, patch


sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
ADAPTER = HERE / "native.py"
CORE = HERE.parent / "classic_final_image/elf.py"
SVC, PENDSV, START = "SVC_Handler", "PendSV_Handler", "fiber_port_start_first_context"
PANIC = "fiber_panic"
RESTORE = "fiber_port_context_validate_restore"
SAVE = "fiber_port_context_validate_save_current"
SCHEDULE = "fiber_port_scheduler_pick_next_from_pendsv"
SLOT = "fiber_internal_runtime_current_context_slot"
SLOT_SECTION = ".bss.fiber_runtime_current_context_slot"
BASE, RAM, DISPLACEMENT = 0x08000100, 0x20000000, 0x20
ROOT_MODEL = {SVC: (0, 184, 64), PENDSV: (184, 204, 72), START: (388, 104, 34)}
SITES = {
    SVC: ((0x72, 10, RESTORE), (0x9E, 10, PANIC), (0xA6, 10, PANIC), (0xAE, 10, PANIC), (0xB4, 2, SLOT)),
    PENDSV: ((0x34, 10, SAVE), (0x82, 10, SCHEDULE), (0xB0, 10, PANIC), (0xB8, 10, PANIC),
             (0xC0, 10, PANIC), (0xC8, 2, SLOT)),
    START: ((0x56, 10, PANIC), (0x5E, 10, PANIC)),
}
CALLEE_OFFSETS = {PANIC: 492, RESTORE: 494, SAVE: 496, SCHEDULE: 498}
n = decoder = None


def sha(data):
    return hashlib.sha256(data).hexdigest().upper()


def load_sources(buffers):
    global n, decoder
    tree = ast.parse(buffers[CORE], filename=str(CORE))
    functions = {"require", "sha256", "_signed", "_width", "_address_form"}
    constants = {"CONDITIONS", "ORDINARY"}
    chosen = []
    found = set()
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in functions:
            chosen.append(node)
            found.add(node.name)
        elif isinstance(node, ast.ClassDef) and node.name == "Rejected":
            chosen.append(node)
            found.add(node.name)
        elif isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id in constants for target in node.targets):
            chosen.append(node)
            found.update(target.id for target in node.targets if isinstance(target, ast.Name))
        elif isinstance(node, ast.ClassDef) and node.name == "FinalImage":
            methods = [item for item in node.body if isinstance(item, ast.FunctionDef) and item.name == "_body"]
            if len(methods) != 1:
                raise ValueError("one unchanged core _body required")
            chosen.append(ast.ClassDef(name="BodyOnly", bases=[], keywords=[], body=methods, decorator_list=[], type_params=[]))
            found.add("_body")
    if found != functions | constants | {"Rejected", "_body"}:
        raise ValueError("exact generic decoder dependency set required")
    namespace = dict(hashlib=hashlib, struct=struct, __name__="synthetic_cm3_lto_core")
    exec(compile(ast.fix_missing_locations(ast.Module(body=chosen, type_ignores=[])), str(CORE), "exec"), namespace)
    decoder = SimpleNamespace(**namespace)
    spec = importlib.util.spec_from_file_location("synthetic_cm3_lto_adapter", ADAPTER)
    n = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = n
    exec(compile(buffers[ADAPTER], str(ADAPTER), "exec"), n.__dict__)


def bl(place, target):
    """Independent fixture encoder, matching the existing frozen test helper."""
    delta = target - place - 4
    if delta % 2 or not -(1 << 24) <= delta < 1 << 24:
        raise ValueError("synthetic BL range")
    value = delta & ((1 << 25) - 1)
    sign, i1, i2 = value >> 24, (value >> 23) & 1, (value >> 22) & 1
    return struct.pack("<HH", 0xF000 | (sign << 10) | ((value >> 12) & 1023),
        0xD000 | ((1 ^ i1 ^ sign) << 13) | ((1 ^ i2 ^ sign) << 11) | ((value >> 1) & 2047))


def symbol(name, section, value, size, *, kind="STT_FUNC", binding="STB_GLOBAL"):
    return dict(name=name, section=section, value=value, size=size, kind=kind,
                binding=binding, visibility="STV_DEFAULT", index=0)


def section(name, *, address=0, size=0, flags=6, kind="SHT_PROGBITS"):
    return SimpleNamespace(name=name, header=SimpleNamespace(sh_addr=address, sh_size=size,
        sh_flags=flags, sh_type=kind, sh_addralign=4))


class FakeELF:
    def __init__(self, *, final, payload, symbols, slot_name, slot_size, slot_address, points):
        self.final, self.payload, self.symbols = final, bytearray(payload), symbols
        self.sections = [section("", flags=0), section(".text", address=BASE if final else 0, size=len(payload)),
            section(slot_name, address=slot_address, size=slot_size, flags=3, kind="SHT_NOBITS")]
        self.names = [item.name for item in self.sections]
        self.relocations, self.points = {}, list(points)
        self.loads = [dict(Vaddr=BASE, MemorySize=len(payload), FileSize=len(payload), Flags=5),
                      dict(Vaddr=slot_address, MemorySize=slot_size, FileSize=0, Flags=6)] if final else []

    @property
    def data(self):
        return (b"FAKE-FINAL:" if self.final else b"FAKE-INPUT:") + bytes(self.payload)

    def section_read(self, index, offset, size):
        decoder.require(index == 1 and 0 <= offset <= offset + size <= len(self.payload), "FAKE", "bounded fake text read")
        return bytes(self.payload[offset:offset + size])

    def mapping(self, index, address):
        origin = BASE if self.final else 0
        offset = address - origin
        decoder.require(index == 1 and 0 <= offset < len(self.payload), "FAKE", "bounded fake mapping")
        previous = [(at, kind) for at, kind in self.points if at <= offset]
        decoder.require(bool(previous), "FAKE", "missing fake mapping")
        boundary = min((at for at, _ in self.points if at > offset), default=len(self.payload))
        return previous[-1][1], origin + boundary


class Fixture:
    def __init__(self):
        self.rows, self.data_ranges = {}, {}
        before, after = bytearray(500), bytearray(502)
        points = []
        for name, (start, size, count) in ROOT_MODEL.items():
            sites = SITES[name]
            has_pool = any(kind == 2 for _, kind, _ in sites)
            code_end = size - (4 if has_pool else 0)
            reserved = {off: (4, "bl", target) for off, kind, target in sites if kind == 10}
            if has_pool:
                reserved[0] = (2, "ldr", code_end)
            reserved[code_end - 2] = (2, "bx", "lr")
            wide = (code_end - 2 * count) // 2 - sum(kind == 10 for _, kind, _ in sites)
            rows, offset = [], 0
            while offset < code_end:
                if offset in reserved:
                    width, op, operand = reserved[offset]
                elif wide and offset + 2 not in reserved:
                    width, op, operand = 4, "isb", "sy"
                    wide -= 1
                else:
                    width, op, operand = 2, "nop", ""
                if op == "bl":
                    source = bl(start + offset, start + offset)
                    target = BASE + CALLEE_OFFSETS[operand]
                    final, text = bl(BASE + start + offset, target), "%x <%s>" % (target, operand)
                elif op == "ldr":
                    immediate = code_end - ((offset + 4) & ~3)
                    source = final = struct.pack("<H", 0x4800 | (immediate // 4))
                    text = "r0, [pc, #%d]" % immediate
                else:
                    source = final = {"isb": bytes.fromhex("bff36f8f"), "nop": bytes.fromhex("00bf"),
                                      "bx": bytes.fromhex("7047")}[op]
                    text = operand
                before[start + offset:start + offset + width] = source
                after[start + offset:start + offset + width] = final
                rows.append((offset, width, op, text))
                offset += width
            if len(rows) != count or wide or offset != code_end:
                raise ValueError("independent synthetic body geometry")
            if has_pool:
                struct.pack_into("<I", after, start + code_end, RAM + DISPLACEMENT)
            self.rows[name] = rows
            self.data_ranges[name] = [(code_end, size)] if has_pool else []
            points.append((start, "t"))
            if has_pool:
                points.append((start + code_end, "d"))
        for offset in CALLEE_OFFSETS.values():
            before[offset:offset + 2] = bytes.fromhex("7047")
            after[offset:offset + 2] = bytes.fromhex("7047")
        after[500:502] = bytes.fromhex("7047")
        points.append((492, "t"))
        source_symbols = [symbol(name, 1, offset | 1, size) for name, (offset, size, _) in ROOT_MODEL.items()]
        source_symbols += [symbol(name, 1, offset | 1, 2) for name, offset in CALLEE_OFFSETS.items()]
        source_symbols.append(symbol(SLOT, 2, 0, 4, kind="STT_OBJECT", binding="STB_LOCAL"))
        final_symbols = copy.deepcopy(source_symbols)
        for item in final_symbols:
            item["value"] += RAM + DISPLACEMENT if item["name"] == SLOT else BASE
        self.machine = FakeELF(final=False, payload=before, symbols=source_symbols, slot_name=SLOT_SECTION,
                               slot_size=4, slot_address=0, points=points)
        self.final = FakeELF(final=True, payload=after, symbols=final_symbols, slot_name=".bss",
                             slot_size=DISPLACEMENT + 4, slot_address=RAM, points=points)
        self.startup = FakeELF(final=False, payload=b"\x70\x47", symbols=[], slot_name=".bss", slot_size=0, slot_address=0, points=[(0, "t")])
        self.machine_id, self.startup_id = "C:/synthetic/actual-ltrans.o", "C:/synthetic/native-startup.o"
        self.provider_objects = {self.machine_id: "captured-machine.o", self.startup_id: "captured-startup.o"}
        self.image = SimpleNamespace(prelink=self.machine, final=self.final,
            providers={self.machine_id: self.machine, self.startup_id: self.startup},
            placements={(self.machine_id, ".text"): (BASE, 500), (self.machine_id, SLOT_SECTION): (RAM + DISPLACEMENT, 4)},
            link_map_hash=sha(b"synthetic whole-section placement map"), instructions={})
        self.image._body = MethodType(decoder.BodyOnly._body, self.image)
        self.core = SimpleNamespace(require=decoder.require, sha256=decoder.sha256, CONDITIONS=decoder.CONDITIONS,
            ORDINARY=decoder.ORDINARY, FinalImage=Mock(return_value=self.image))
        for name, (start, _, _) in ROOT_MODEL.items():
            for offset, width, op, text in self.rows[name]:
                address = BASE + start + offset
                self.image.instructions[(1, address)] = (op, text, bytes(after[start + offset:start + offset + width]))
            for offset, kind, target in SITES[name]:
                if kind == 10:
                    source_target, final_target = self.sym(self.machine, target), self.sym(self.final, target)
                else:
                    source_target = symbol("", 2, 0, 0, kind="STT_SECTION", binding="STB_LOCAL")
                    final_target = symbol("", 2, RAM, 0, kind="STT_SECTION", binding="STB_LOCAL")
                self.machine.relocations[(1, start + offset)] = (kind, copy.deepcopy(source_target))
                self.final.relocations[(1, start + offset)] = (kind, copy.deepcopy(final_target))

    @staticmethod
    def sym(elf, name):
        return next(item for item in elf.symbols if item["name"] == name)

    def reader(self, **kwargs):
        return n.NativeCM3LTOImage(self.core, "machine.o", "image.elf", "image.dis",
            provider_objects=kwargs.get("provider_objects", self.provider_objects), link_map=kwargs.get("link_map", "image.map"))

    def instruction_bytes(self, name, offset, raw, *, both=False, op=None, operands=None):
        start = ROOT_MODEL[name][0]
        self.final.payload[start + offset:start + offset + len(raw)] = raw
        if both:
            self.machine.payload[start + offset:start + offset + len(raw)] = raw
        key = (1, BASE + start + offset)
        old = self.image.instructions[key]
        self.image.instructions[key] = (old[0] if op is None else op, old[1] if operands is None else operands, bytes(raw))


class AdapterTests(unittest.TestCase):
    def rejected(self, fixture, *, name=SVC, match=None):
        with self.assertRaises(decoder.Rejected) as caught:
            fixture.reader().function(name)
        if match:
            self.assertIn(match, str(caught.exception))

    def test_three_synthetic_complete_bodies_and_thirteen_fixed_references(self):
        fixture = Fixture()
        reader = fixture.reader()
        proofs = [reader.function(name) for name in ROOT_MODEL]
        self.assertEqual(sum(row["Size"] for row in proofs), 492)
        self.assertEqual(sum(row["InstructionCount"] for row in proofs), 170)
        refs = [ref for row in proofs for ref in row["References"]]
        self.assertEqual((len(refs), sum(ref["Kind"] == 10 for ref in refs), sum(ref["Kind"] == 2 for ref in refs)), (13, 11, 2))
        for row in proofs:
            self.assertEqual([(ref["Offset"], ref["Kind"], ref["Symbol"]) for ref in row["References"]], list(SITES[row["Name"]]))
            self.assertIs(row["GeneratedMachineBoundRootPreservation"], True)
            for key in ("OriginalTranslationUnitOwnership", "CanonicalProtocolValidated", "FinalReferenceParity",
                        "PolicyEquivalence", "CpuExecution", "BoardExecution", "GlobalFreezeQualified"):
                self.assertIs(row[key], False)
            self.assertIs(type(row["RequiredCellsSatisfied"]), int)
            self.assertEqual(row["RequiredCellsSatisfied"], 0)
            for origin in row["DefinitionOrigins"]:
                self.assertIs(origin["CalleeBodyProof"], False)

    def test_generic_dependency_is_explicit_soft_and_not_globally_patched(self):
        fixture = Fixture()
        original = (decoder.require, decoder.ORDINARY, decoder.CONDITIONS, decoder.BodyOnly._body)
        fixture.reader().function(SVC)
        fixture.core.FinalImage.assert_called_once_with("machine.o", "image.elf", "image.dis",
            provider_objects=fixture.provider_objects, link_map="image.map", float_abi="soft")
        self.assertEqual((decoder.require, decoder.ORDINARY, decoder.CONDITIONS, decoder.BodyOnly._body), original)

    def test_only_declared_roots_are_callable(self):
        for name in (PANIC, SLOT, "xPortPendSVHandler", "", None):
            with self.subTest(name=name):
                self.rejected(Fixture(), name=name, match="LTO-SCOPE")

    def test_provider_count_and_map_are_required_before_generic_constructor(self):
        for providers in (None, {}, [], {"one": "one.o"}, {"a": "a.o", "b": "b.o", "c": "c.o"}):
            fixture = Fixture()
            with self.subTest(providers=providers), self.assertRaises(decoder.Rejected):
                fixture.reader(provider_objects=providers)
            fixture.core.FinalImage.assert_not_called()
        fixture = Fixture()
        with self.assertRaises(decoder.Rejected):
            fixture.reader(link_map=None)
        fixture.core.FinalImage.assert_not_called()

    def test_missing_or_duplicate_actual_machine_provider_rejects(self):
        for duplicate in (False, True):
            fixture = Fixture()
            if duplicate:
                fixture.image.providers[fixture.startup_id] = fixture.machine
            else:
                fixture.image.providers[fixture.machine_id] = fixture.startup
            with self.subTest(duplicate=duplicate), self.assertRaises(decoder.Rejected):
                fixture.reader()

    def test_gimple_section_or_missing_final_rel_membership_rejects(self):
        fixture = Fixture()
        fixture.machine.sections.append(section(".gnu.lto_.fake"))
        with self.assertRaises(decoder.Rejected):
            fixture.reader()
        fixture = Fixture()
        fixture.final.relocations.clear()
        with self.assertRaises(decoder.Rejected):
            fixture.reader()

    def test_raw_section_name_is_empty_and_labels_stay_separate(self):
        fixture = Fixture()
        proof = fixture.reader().function(SVC)
        ref = proof["References"][-1]
        self.assertEqual((ref["OriginalRelocationSymbol"]["name"], ref["FinalRelocationSymbol"]["name"]), ("", ""))
        self.assertEqual((ref["OriginalTargetSection"], ref["FinalTargetSection"]), (SLOT_SECTION, ".bss"))
        self.assertEqual(ref["ResolvedValue"], RAM + DISPLACEMENT)
        slot = next(row for row in proof["DefinitionOrigins"] if row["Name"] == SLOT)
        self.assertEqual((slot["SymbolOffset"], slot["OutputSectionOffset"], slot["SectionSize"]), (0, DISPLACEMENT, 4))

    def test_section_targets_reject_pretty_names_wrong_role_or_wrong_base(self):
        for final in (False, True):
            for key, value in (("name", SLOT_SECTION if not final else ".bss"), ("kind", "STT_OBJECT"),
                               ("binding", "STB_GLOBAL"), ("visibility", "STV_HIDDEN"), ("section", 1),
                               ("value", 4 if not final else RAM + DISPLACEMENT), ("size", 4)):
                fixture = Fixture()
                elf = fixture.final if final else fixture.machine
                kind, target = elf.relocations[(1, 0xB4)]
                target[key] = value
                with self.subTest(final=final, key=key):
                    self.rejected(fixture, match="LTO-SLOT")

    def test_slot_definition_requires_exact_local_object_metadata(self):
        for key, value in (("binding", "STB_GLOBAL"), ("binding", "STB_WEAK"), ("kind", "STT_FUNC"),
                           ("visibility", "STV_HIDDEN"), ("size", 8), ("section", True), ("value", 1)):
            fixture = Fixture()
            fixture.sym(fixture.machine, SLOT)[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(decoder.Rejected):
                fixture.reader()._symbol(fixture.machine, SLOT)

    def test_dedicated_input_slot_section_name_offset_and_size_are_exact(self):
        for change in ("name", "offset", "size", "type", "permissions"):
            fixture = Fixture()
            header = fixture.machine.sections[2].header
            if change == "name":
                fixture.machine.sections[2].name = ".bss.other"
            elif change == "offset":
                fixture.sym(fixture.machine, SLOT)["value"], header.sh_size = 4, 8
            elif change == "size":
                header.sh_size = 8
            elif change == "type":
                header.sh_type = "SHT_PROGBITS"
            else:
                header.sh_flags = 7
            with self.subTest(change=change), self.assertRaises(decoder.Rejected):
                fixture.reader()._symbol(fixture.machine, SLOT)

    def test_slot_full_map_placement_is_mandatory_not_only_name_or_bss_membership(self):
        for placement in (None, (RAM + DISPLACEMENT, 3), (RAM + DISPLACEMENT, 8), (RAM + 4, 4)):
            fixture = Fixture()
            key = (fixture.machine_id, SLOT_SECTION)
            if placement is None:
                del fixture.image.placements[key]
            else:
                fixture.image.placements[key] = placement
            with self.subTest(placement=placement), self.assertRaises(decoder.Rejected):
                fixture.reader()._definition(SLOT)

    def test_final_slot_requires_output_bss_local_binding_nobits_and_alignment(self):
        for change in ("name", "binding", "type", "alignment"):
            fixture = Fixture()
            slot = fixture.sym(fixture.final, SLOT)
            if change == "name":
                fixture.final.sections[2].name = ".bss.alias"
            elif change == "binding":
                slot["binding"] = "STB_GLOBAL"
            elif change == "type":
                fixture.final.sections[2].header.sh_type = "SHT_PROGBITS"
            else:
                slot["value"] += 1
                fixture.final.sections[2].header.sh_size += 4
                fixture.final.loads[1]["MemorySize"] += 4
            with self.subTest(change=change), self.assertRaises(decoder.Rejected):
                fixture.reader()._symbol(fixture.final, SLOT)

    def test_coherent_slot_retarget_to_other_valid_bss_cannot_defeat_map(self):
        fixture = Fixture()
        fixture.sym(fixture.final, SLOT)["value"] = RAM + 4
        struct.pack_into("<I", fixture.final.payload, 0xB4, RAM + 4)
        self.rejected(fixture, match="LTO-ORIGIN")

    def test_function_and_slot_load_permissions_and_coverage_are_checked(self):
        for name, load_index, flags in ((SVC, 0, 4), (SLOT, 1, 4), (SLOT, 1, 7)):
            fixture = Fixture()
            fixture.final.loads[load_index]["Flags"] = flags
            with self.subTest(name=name, flags=flags), self.assertRaises(decoder.Rejected):
                fixture.reader()._symbol(fixture.final, name)
        for name, index in ((SVC, 0), (SLOT, 1)):
            fixture = Fixture()
            fixture.final.loads[index]["MemorySize"] = 1
            with self.subTest(name=name), self.assertRaises(decoder.Rejected):
                fixture.reader()._symbol(fixture.final, name)

    def test_duplicate_load_coverage_rejects(self):
        fixture = Fixture()
        fixture.final.loads.append(copy.deepcopy(fixture.final.loads[1]))
        with self.assertRaises(decoder.Rejected):
            fixture.reader()._symbol(fixture.final, SLOT)

    def test_cross_name_function_and_slot_overlapping_aliases_reject(self):
        for name in (SVC, SLOT):
            fixture = Fixture()
            peer = copy.deepcopy(fixture.sym(fixture.final, name))
            peer["name"] = "unrelated_alias"
            fixture.final.symbols.append(peer)
            with self.subTest(name=name), self.assertRaises(decoder.Rejected):
                fixture.reader()._symbol(fixture.final, name)

    def test_entry_must_be_thumb_mapped_in_both_images(self):
        for final in (False, True):
            fixture = Fixture()
            elf = fixture.final if final else fixture.machine
            elf.points[0] = (0, "d")
            with self.subTest(final=final), self.assertRaises(decoder.Rejected):
                fixture.reader()._symbol(elf, SVC)

    def test_duplicate_definition_owner_or_section_name_rejects(self):
        for change in ("machine-symbol", "final-symbol", "owner", "section"):
            fixture = Fixture()
            if change == "machine-symbol":
                fixture.machine.symbols.append(copy.deepcopy(fixture.sym(fixture.machine, SVC)))
            elif change == "final-symbol":
                fixture.final.symbols.append(copy.deepcopy(fixture.sym(fixture.final, SVC)))
            elif change == "owner":
                fixture.startup.symbols.append(copy.deepcopy(fixture.sym(fixture.machine, SVC)))
            else:
                fixture.machine.names.append(".text")
            with self.subTest(change=change), self.assertRaises(decoder.Rejected):
                fixture.reader()._definition(SVC)

    def test_root_whole_input_section_map_size_and_displacement_reject(self):
        for placement in ((BASE, 499), (BASE, 501), (BASE + 4, 500)):
            fixture = Fixture()
            fixture.image.placements[(fixture.machine_id, ".text")] = placement
            with self.subTest(placement=placement), self.assertRaises(decoder.Rejected):
                fixture.reader()._definition(SVC)

    def test_coherent_callee_symbol_and_bl_retarget_is_bound_to_original_placement(self):
        fixture = Fixture()
        target = fixture.sym(fixture.final, RESTORE)
        target["value"] = (BASE + 500) | 1
        fixture.final.relocations[(1, 0x72)] = (10, copy.deepcopy(target))
        address = target["value"] & ~1
        fixture.instruction_bytes(SVC, 0x72, bl(BASE + 0x72, address), operands="%x <%s>" % (address, RESTORE))
        self.rejected(fixture, match="LTO-ORIGIN")

    def test_missing_extra_or_rekinded_reference_membership_rejects(self):
        for change in ("missing", "extra", "kind"):
            fixture = Fixture()
            if change == "missing":
                fixture.final.relocations.pop((1, 0x72))
            elif change == "extra":
                fixture.machine.relocations[(1, 2)] = (10, copy.deepcopy(fixture.sym(fixture.machine, PANIC)))
                fixture.final.relocations[(1, 2)] = (10, copy.deepcopy(fixture.sym(fixture.final, PANIC)))
            else:
                fixture.final.relocations[(1, 0x72)] = (2, fixture.final.relocations[(1, 0x72)][1])
            with self.subTest(change=change):
                self.rejected(fixture, match="LTO-RELOC")

    def test_original_bl_addend_must_be_minus_four(self):
        fixture = Fixture()
        fixture.machine.payload[0x72:0x76] = bl(0x72, 0x76)
        self.rejected(fixture, match="LTO-RELOC")

    def test_applied_bl_bits_cannot_retarget_to_other_allowed_callee(self):
        fixture = Fixture()
        address = BASE + CALLEE_OFFSETS[SAVE]
        fixture.instruction_bytes(SVC, 0x72, bl(BASE + 0x72, address), operands="%x <%s>" % (address, SAVE))
        self.rejected(fixture, match="LTO-RELOC")

    def test_coherent_allowed_callee_swap_at_wrong_fixed_site_rejects(self):
        fixture = Fixture()
        fixture.machine.relocations[(1, 0x72)] = (10, copy.deepcopy(fixture.sym(fixture.machine, SAVE)))
        fixture.final.relocations[(1, 0x72)] = (10, copy.deepcopy(fixture.sym(fixture.final, SAVE)))
        address = BASE + CALLEE_OFFSETS[SAVE]
        fixture.instruction_bytes(SVC, 0x72, bl(BASE + 0x72, address), operands="%x <%s>" % (address, SAVE))
        self.rejected(fixture, match="LTO-RELOC")

    def test_original_abs32_addend_and_final_output_displacement_are_exact(self):
        for original, value in ((True, 4), (False, RAM), (False, RAM + DISPLACEMENT + 4)):
            fixture = Fixture()
            elf = fixture.machine if original else fixture.final
            struct.pack_into("<I", elf.payload, 0xB4, value)
            with self.subTest(original=original, value=value):
                self.rejected(fixture, match="LTO-SLOT")

    def test_nonrelocation_byte_mutation_is_not_authorized_by_matching_metadata(self):
        fixture = Fixture()
        fixture.instruction_bytes(SVC, 2, bytes.fromhex("bff34f8f"), op="dsb", operands="sy")
        self.rejected(fixture, match="LTO-PRESERVATION")

    def test_disassembly_bytes_mnemonic_and_address_operands_must_agree(self):
        for change in ("bytes", "pc-use", "fp", "branch-text", "literal-register"):
            fixture = Fixture()
            offset = 0x72 if change == "branch-text" else 0 if change == "literal-register" else 2
            key = (1, BASE + offset)
            op, operands, raw = fixture.image.instructions[key]
            if change == "bytes":
                raw = bytes.fromhex("00bf")
            elif change == "pc-use":
                op, operands = "mov", "r0, pc"
            elif change == "fp":
                op = "vadd"
            elif change == "branch-text":
                operands = "%x" % (BASE + CALLEE_OFFSETS[RESTORE] + 4)
            else:
                operands = operands.replace("r0", "r1")
            fixture.image.instructions[key] = (op, operands, raw)
            with self.subTest(change=change):
                self.rejected(fixture, match="LTO-DECODE")

    def test_extra_interior_and_mismatched_data_disassembly_records_reject(self):
        for offset, record in ((3, ("nop", "", bytes.fromhex("00bf"))), (0xB4, (".word", "0", bytes(4)))):
            fixture = Fixture()
            fixture.image.instructions[(1, BASE + offset)] = record
            with self.subTest(offset=offset):
                self.rejected(fixture, match="LTO-DECODE")

    def test_bounded_literal_data_disassembly_record_is_not_an_extra_instruction(self):
        fixture = Fixture()
        fixture.image.instructions[(1, BASE + 0xB4)] = (".word", hex(RAM + DISPLACEMENT), struct.pack("<I", RAM + DISPLACEMENT))
        self.assertEqual(fixture.reader().function(SVC)["InstructionCount"], 64)

    def test_coherent_branch_into_data_is_not_an_instruction_boundary(self):
        fixture = Fixture()
        offset, destination = 90, 180
        raw = struct.pack("<H", 0xE000 | ((destination - offset - 4) // 2))
        fixture.instruction_bytes(SVC, offset, raw, both=True, op="b", operands="%x" % (BASE + destination))
        self.rejected(fixture, match="LTO-DECODE")

    def test_changed_mapping_or_missing_instruction_record_rejects(self):
        fixture = Fixture()
        fixture.final.points[1] = (178, "d")
        self.rejected(fixture)
        fixture = Fixture()
        fixture.image.instructions.pop((1, BASE + 2))
        self.rejected(fixture, match="LTO-DECODE")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    output = args.output_dir.resolve()
    if output.exists() or output.is_relative_to(REPO) or not output.is_relative_to(Path(tempfile.gettempdir()).resolve()):
        parser.error("fresh external TEMP output directory required")
    report = dict(Status="FAIL", Tests=0, Failures=0, Errors=0, Skipped=0, SourceHashes={}, SourceDrift=[],
        Scope="PURE_SYNTHETIC_CM3_LTO_READER_UNIT_CONTROLS_ONLY", SyntheticInputs=True, ActualELFTested=False,
        ToolInvocations=0, NativeCommandsExecuted=0, GeneratedMachineBoundRootPreservation=False,
        CanonicalProtocolValidated=False, OriginalTranslationUnitOwnership=False, FinalReferenceParity=False,
        PolicyEquivalence=False, CpuExecution=False, BoardExecution=False, RequiredCellsSatisfied=0, GlobalFreezeQualified=False)
    paths = [Path(__file__).resolve(), ADAPTER, CORE]
    try:
        if sys.flags.optimize or not __debug__:
            raise ValueError("optimized Python unsupported")
        buffers = {path: path.read_bytes() for path in paths}
        report["SourceHashes"] = {str(path): sha(data) for path, data in buffers.items()}
        with patch("subprocess.Popen", side_effect=AssertionError("pure controls cannot execute a process")):
            load_sources(buffers)
            suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
            count = suite.countTestCases()
            if not count:
                raise ValueError("nonempty synthetic controls required")
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
