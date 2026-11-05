"""Pure synthetic reference CM3 LTO adapter units; no actual ELF qualification.

Fake metadata and small Thumb bodies exercise the adapter. Only unchanged core
body/address helpers are compiled from captured AST; no ELF parser runs.
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
ADAPTER = HERE / "reference.py"
CORE = HERE.parent / "classic_final_image/elf.py"
START, SVC, PENDSV = "prvPortStartFirstTask", "vPortSVCHandler", "xPortPendSVHandler"
SLOT, CALLEE = "pxCurrentTCB", "vTaskSwitchContext"
BASE, RAM, BSS_BASE, SLOT_ADDRESS = 0x434, 0x20000000, 0x20000008, 0x20000010
TEXT_SIZE, CALLEE_OFFSET = 0x24C, 0xE8
ROOT_MODEL = {START: (0x78, 32, 10), SVC: (0x54, 36, 10), PENDSV: (0x98, 68, 19)}
SITES = {START: (), SVC: ((32, 2, SLOT),), PENDSV: ((28, 10, CALLEE), (64, 2, SLOT))}
r = decoder = None


def sha(data):
    return hashlib.sha256(data).hexdigest().upper()


def load_sources(buffers):
    global r, decoder
    functions, constants = {"require", "sha256", "_signed", "_width", "_address_form"}, {"CONDITIONS", "ORDINARY"}
    chosen, found = [], set()
    for node in ast.parse(buffers[CORE], filename=str(CORE)).body:
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
                raise ValueError("one unchanged core body helper required")
            chosen.append(ast.ClassDef(name="BodyOnly", bases=[], keywords=[], body=methods, decorator_list=[], type_params=[]))
            found.add("_body")
    if found != functions | constants | {"Rejected", "_body"}:
        raise ValueError("exact captured generic helper set required")
    namespace = dict(hashlib=hashlib, struct=struct, __name__="synthetic_reference_lto_core")
    exec(compile(ast.fix_missing_locations(ast.Module(body=chosen, type_ignores=[])), str(CORE), "exec"), namespace)
    decoder = SimpleNamespace(**namespace)
    spec = importlib.util.spec_from_file_location("synthetic_reference_lto_adapter", ADAPTER)
    r = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = r
    exec(compile(buffers[ADAPTER], str(ADAPTER), "exec"), r.__dict__)


def bl(place, target):
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
    def __init__(self, final, payload, symbols, points):
        self.final, self.payload, self.symbols, self.points = final, bytearray(payload), symbols, sorted(points)
        self.sections = [section("", flags=0), section(".text", address=BASE if final else 0, size=len(payload)),
            section(".bss", address=RAM if final else 0, size=20 if final else 12, flags=3, kind="SHT_NOBITS")]
        self.names, self.relocations = [item.name for item in self.sections], {}
        self.loads = [dict(Vaddr=BASE, MemorySize=len(payload), FileSize=len(payload), Flags=5),
                      dict(Vaddr=RAM, MemorySize=20, FileSize=0, Flags=6)] if final else []

    @property
    def data(self):
        return (b"SYNTHETIC-FINAL:" if self.final else b"SYNTHETIC-MACHINE:") + bytes(self.payload)

    def section_read(self, index, offset, size):
        decoder.require(index == 1 and 0 <= offset <= offset + size <= len(self.payload), "SYNTHETIC", "text bounds")
        return bytes(self.payload[offset:offset + size])

    def mapping(self, index, address):
        origin = BASE if self.final else 0
        offset = address - origin
        decoder.require(index == 1 and 0 <= offset < len(self.payload), "SYNTHETIC", "mapping bounds")
        previous = [(at, kind) for at, kind in self.points if at <= offset]
        decoder.require(bool(previous), "SYNTHETIC", "missing mapping")
        return previous[-1][1], origin + min((at for at, _ in self.points if at > offset), default=len(self.payload))


class Fixture:
    def __init__(self):
        before, after, points = bytearray(TEXT_SIZE), bytearray(TEXT_SIZE), [(0, "t")]
        self.rows = {}
        for name, (start, size, count) in ROOT_MODEL.items():
            code_end, pool = (26, 28) if name == START else ((32, 32) if name == SVC else (62, 64))
            reserved = {0: (2, "ldr", pool), code_end - 2: (2, "bx", "lr")}
            if name == PENDSV:
                reserved[28] = (4, "bl", CALLEE)
            wide = (code_end - 2 * count) // 2 - int(name == PENDSV)
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
                    applied = bl(BASE + start + offset, BASE + CALLEE_OFFSET)
                    text = "%x <%s>" % (BASE + CALLEE_OFFSET, CALLEE)
                elif op == "ldr":
                    immediate = pool - ((offset + 4) & ~3)
                    source = applied = struct.pack("<H", 0x4800 | (immediate // 4))
                    text = "r0, [pc, #%d]" % immediate
                else:
                    source = applied = {"isb": bytes.fromhex("bff36f8f"), "nop": bytes.fromhex("00bf"), "bx": bytes.fromhex("7047")}[op]
                    text = operand
                before[start + offset:start + offset + width] = source
                after[start + offset:start + offset + width] = applied
                rows.append((offset, width, op, text))
                offset += width
            if len(rows) != count or offset != code_end or wide:
                raise ValueError("independent synthetic reference body geometry")
            if name == START:
                struct.pack_into("<I", before, start + pool, 0xE000ED08)
                struct.pack_into("<I", after, start + pool, 0xE000ED08)
            else:
                struct.pack_into("<I", after, start + pool, SLOT_ADDRESS)
            self.rows[name] = rows
            points.extend(((start, "t"), (start + code_end, "d")))
            if pool != code_end:
                points.append((start + pool, "d"))
        before[CALLEE_OFFSET:CALLEE_OFFSET + 12] = after[CALLEE_OFFSET:CALLEE_OFFSET + 12] = bytes.fromhex("00bf") * 5 + bytes.fromhex("7047")
        points.append((CALLEE_OFFSET, "t"))
        originals = [symbol(name, 1, start | 1, size, binding="STB_LOCAL" if name == START else "STB_GLOBAL")
                     for name, (start, size, _) in ROOT_MODEL.items()]
        originals += [symbol(CALLEE, 1, CALLEE_OFFSET | 1, 12), symbol(SLOT, 2, 8, 4, kind="STT_OBJECT"),
                      symbol("unrelated_bss_zero", 2, 0, 4, kind="STT_OBJECT"), symbol("unrelated_bss_four", 2, 4, 4, kind="STT_OBJECT")]
        applied = copy.deepcopy(originals)
        for row in applied:
            row["value"] += BSS_BASE if row["kind"] == "STT_OBJECT" else BASE
        self.machine, self.final = FakeELF(False, before, originals, points), FakeELF(True, after, applied, points)
        self.startup = FakeELF(False, b"\x70\x47", [], [(0, "t")])
        self.machine_id, self.startup_id = "C:/synthetic/reference-ltrans.o", "C:/synthetic/reference-startup.o"
        self.provider_objects = {self.machine_id: "captured-machine.o", self.startup_id: "captured-startup.o"}
        self.image = SimpleNamespace(prelink=self.machine, final=self.final,
            providers={self.machine_id: self.machine, self.startup_id: self.startup},
            placements={(self.machine_id, ".text"): (BASE, TEXT_SIZE), (self.machine_id, ".bss"): (BSS_BASE, 12)},
            link_map_hash=sha(b"synthetic whole merged reference section map"), instructions={})
        self.image._body = MethodType(decoder.BodyOnly._body, self.image)
        self.core = SimpleNamespace(require=decoder.require, sha256=decoder.sha256, CONDITIONS=decoder.CONDITIONS,
            ORDINARY=decoder.ORDINARY, FinalImage=Mock(return_value=self.image))
        for name, (start, _, _) in ROOT_MODEL.items():
            for offset, width, op, text in self.rows[name]:
                self.image.instructions[1, BASE + start + offset] = (op, text, bytes(after[start + offset:start + offset + width]))
            for offset, kind, target in SITES[name]:
                self.machine.relocations[1, start + offset] = kind, copy.deepcopy(self.sym(self.machine, target))
                self.final.relocations[1, start + offset] = kind, copy.deepcopy(self.sym(self.final, target))

    @staticmethod
    def sym(elf, name):
        return next(row for row in elf.symbols if row["name"] == name)

    def reader(self, **kwargs):
        return r.ReferenceCM3LTOImage(self.core, "machine.o", "final.elf", "final.dis",
            provider_objects=kwargs.get("provider_objects", self.provider_objects), link_map=kwargs.get("link_map", "final.map"))

    def instruction(self, name, offset, raw, *, both=False, op=None, operands=None):
        start = ROOT_MODEL[name][0]
        self.final.payload[start + offset:start + offset + len(raw)] = raw
        if both:
            self.machine.payload[start + offset:start + offset + len(raw)] = raw
        key = 1, BASE + start + offset
        old = self.image.instructions[key]
        self.image.instructions[key] = old[0] if op is None else op, old[1] if operands is None else operands, bytes(raw)


class AdapterTests(unittest.TestCase):
    def rejected(self, fixture, name=SVC, match=None):
        with self.assertRaises(decoder.Rejected) as caught:
            fixture.reader().function(name)
        if match:
            self.assertIn(match, str(caught.exception))

    def test_three_synthetic_complete_roots_retain_reference_identity_and_nonclaims(self):
        fixture = Fixture()
        reader = fixture.reader()
        records = [reader.function(name) for name in (START, SVC, PENDSV)]
        self.assertEqual([row["Name"] for row in records], [START, SVC, PENDSV])
        self.assertEqual(sum(row["Size"] for row in records), 136)
        self.assertEqual(sum(row["InstructionCount"] for row in records), 39)
        self.assertEqual([len(row["MappedData"]) for row in records], [2, 1, 2])
        refs = [ref for row in records for ref in row["References"]]
        self.assertEqual(len(refs), 3)
        self.assertEqual([(ref["Symbol"], ref["Kind"], ref["Addend"]) for ref in refs],
                         [(SLOT, 2, 0), (CALLEE, 10, -4), (SLOT, 2, 0)])
        for row in records:
            self.assertIs(row["GeneratedMachineBoundRootPreservation"], True)
            for key in ("OriginalTranslationUnitOwnership", "CanonicalProtocolValidated", "FinalReferenceParity",
                        "FullABIProof", "PolicyEquivalence", "CpuExecution", "BoardExecution", "GlobalFreezeQualified"):
                self.assertIs(row[key], False)
            self.assertIs(type(row["RequiredCellsSatisfied"]), int)
            self.assertEqual(row["RequiredCellsSatisfied"], 0)
        for ref in (refs[0], refs[2]):
            self.assertEqual(ref["OriginalRelocationSymbol"]["name"], SLOT)
            self.assertEqual(ref["OriginalRelocationSymbol"]["kind"], "STT_OBJECT")
            self.assertEqual(ref["OriginalRelocationSymbol"]["value"], 8)
            self.assertEqual(ref["FinalRelocationSymbol"]["value"], SLOT_ADDRESS)
        origin = reader._definition(SLOT)
        self.assertEqual((origin["InputSection"], origin["SectionSize"], origin["SymbolOffset"], origin["Entry"]),
                         (".bss", 12, 8, SLOT_ADDRESS))
        self.assertIs(origin["CalleeBodyProof"], False)

    def test_core_dependency_is_explicit_soft_and_qualified_globals_are_unchanged(self):
        fixture = Fixture()
        roots, sites = copy.deepcopy(r.ROOTS), copy.deepcopy(r.SITES)
        ordinary, conditions, body = decoder.ORDINARY, decoder.CONDITIONS, decoder.BodyOnly._body
        fixture.reader().function(PENDSV)
        fixture.core.FinalImage.assert_called_once_with("machine.o", "final.elf", "final.dis",
            provider_objects=fixture.provider_objects, link_map="final.map", float_abi="soft")
        self.assertEqual(r.ROOTS, roots)
        self.assertEqual(r.SITES, sites)
        self.assertIs(decoder.ORDINARY, ordinary)
        self.assertIs(decoder.CONDITIONS, conditions)
        self.assertIs(decoder.BodyOnly._body, body)
        self.assertEqual(roots, {START: (32, 10, 0), SVC: (36, 10, 1), PENDSV: (68, 19, 2)})

    def test_unknown_roots_and_incomplete_provider_envelopes_reject(self):
        for name in ("SVC_Handler", "fiber_port_start_first_context", SLOT, CALLEE, ""):
            with self.subTest(name=name):
                self.rejected(Fixture(), name, "REF-LTO-SCOPE")
        for providers in (None, [], {}, {"one": "a"}, {"one": "a", "two": "b", "three": "c"}):
            fixture = Fixture()
            with self.subTest(providers=providers), self.assertRaisesRegex(decoder.Rejected, "REF-LTO-ORIGIN"):
                fixture.reader(provider_objects=providers)
            fixture.core.FinalImage.assert_not_called()
        fixture = Fixture()
        with self.assertRaisesRegex(decoder.Rejected, "REF-LTO-ORIGIN"):
            fixture.reader(link_map=None)
        fixture.core.FinalImage.assert_not_called()

    def test_machine_provider_ir_substitution_and_missing_final_rel_reject(self):
        for change in ("no-machine", "two-machines", "ir", "no-final-rel"):
            fixture = Fixture()
            if change == "no-machine":
                fixture.image.providers[fixture.machine_id] = fixture.startup
            elif change == "two-machines":
                fixture.image.providers[fixture.startup_id] = fixture.machine
            elif change == "ir":
                fixture.machine.sections.append(section(".gnu.lto_fake"))
            else:
                fixture.final.relocations.clear()
            with self.subTest(change=change), self.assertRaises(decoder.Rejected):
                fixture.reader()

    def test_first_start_is_local_and_other_definitions_are_exact_global(self):
        for final in (False, True):
            for name in (START, SVC, PENDSV, SLOT, CALLEE):
                for binding in ("STB_WEAK", "STB_GLOBAL" if name == START else "STB_LOCAL"):
                    fixture = Fixture()
                    elf = fixture.final if final else fixture.machine
                    fixture.sym(elf, name)["binding"] = binding
                    with self.subTest(final=final, name=name, binding=binding):
                        with self.assertRaisesRegex(decoder.Rejected, "REF-LTO-SYMBOL"):
                            fixture.reader()._symbol(elf, name)

    def test_definition_kind_visibility_extent_and_thumb_membership_are_exact(self):
        for final in (False, True):
            for key, value in (("kind", "STT_OBJECT"), ("visibility", "STV_HIDDEN"), ("section", True),
                               ("section", 0), ("section", 99), ("size", 0), ("size", 35), ("value", 0)):
                fixture = Fixture()
                elf = fixture.final if final else fixture.machine
                fixture.sym(elf, SVC)[key] = value
                with self.subTest(final=final, key=key, value=value):
                    with self.assertRaisesRegex(decoder.Rejected, "REF-LTO-SYMBOL"):
                        fixture.reader()._symbol(elf, SVC)
            fixture = Fixture()
            elf = fixture.final if final else fixture.machine
            fixture.sym(elf, SVC)["value"] &= ~1
            with self.subTest(final=final, change="no-thumb"):
                with self.assertRaisesRegex(decoder.Rejected, "REF-LTO-SYMBOL"):
                    fixture.reader()._symbol(elf, SVC)

    def test_shared_input_bss_slot_extent_offset_and_storage_are_not_native_assumptions(self):
        for change in ("offset-zero", "offset-four", "extent", "dedicated-name", "progbits", "size", "alignment"):
            fixture = Fixture()
            slot, storage = fixture.sym(fixture.machine, SLOT), fixture.machine.sections[2]
            if change == "offset-zero":
                fixture.machine.symbols = [slot] + [row for row in fixture.machine.symbols if row["kind"] != "STT_OBJECT"]
                slot["value"] = 0
            elif change == "offset-four":
                fixture.machine.symbols = [slot] + [row for row in fixture.machine.symbols if row["kind"] != "STT_OBJECT"]
                slot["value"] = 4
            elif change == "extent":
                storage.header.sh_size = 16
            elif change == "dedicated-name":
                storage.name = ".bss.pxCurrentTCB"
            elif change == "progbits":
                storage.header.sh_type = "SHT_PROGBITS"
            elif change == "size":
                slot["size"] = 2
            else:
                slot["value"], slot["size"] = 9, 2
            with self.subTest(change=change), self.assertRaises(decoder.Rejected):
                fixture.reader()._symbol(fixture.machine, SLOT)

    def test_final_slot_has_unique_complete_writable_nonexecuting_zero_fill_load(self):
        for change in ("absent", "duplicate", "partial", "readonly", "executable", "file-backed"):
            fixture = Fixture()
            load = fixture.final.loads[1]
            if change == "absent":
                fixture.final.loads.pop()
            elif change == "duplicate":
                fixture.final.loads.append(dict(load))
            elif change == "partial":
                load["MemorySize"] = 19
            elif change == "readonly":
                load["Flags"] = 4
            elif change == "executable":
                load["Flags"] = 7
            else:
                load["FileSize"] = 17
            with self.subTest(change=change), self.assertRaisesRegex(decoder.Rejected, "REF-LTO-SYMBOL"):
                fixture.reader()._symbol(fixture.final, SLOT)
        fixture = Fixture()
        fixture.final.loads[1]["FileSize"] = 16
        self.assertEqual(fixture.reader()._symbol(fixture.final, SLOT)["value"], SLOT_ADDRESS)

    def test_function_entries_need_thumb_mapping_and_executable_load_coverage(self):
        for change in ("input-data", "final-data", "arm", "no-load", "nonexec", "duplicate-load"):
            fixture = Fixture()
            elf = fixture.machine if change == "input-data" else fixture.final
            if change in ("input-data", "final-data", "arm"):
                elf.points = [(at, "a" if change == "arm" else "d") if at == ROOT_MODEL[SVC][0] else (at, kind)
                              for at, kind in elf.points]
            elif change == "no-load":
                elf.loads.pop(0)
            elif change == "nonexec":
                elf.loads[0]["Flags"] = 4
            else:
                elf.loads.append(dict(elf.loads[0]))
            with self.subTest(change=change), self.assertRaisesRegex(decoder.Rejected, "REF-LTO-SYMBOL"):
                fixture.reader()._symbol(elf, SVC)

    def test_whole_merged_section_map_and_unique_owner_bind_the_root_offset(self):
        for change in ("missing", "size", "address", "duplicate-section", "second-owner", "coherent-root-shift"):
            fixture = Fixture()
            key = fixture.machine_id, ".text"
            if change == "missing":
                fixture.image.placements.pop(key)
            elif change == "size":
                fixture.image.placements[key] = BASE, TEXT_SIZE - 4
            elif change == "address":
                fixture.image.placements[key] = BASE + 4, TEXT_SIZE
            elif change == "duplicate-section":
                fixture.machine.names.append(".text")
            elif change == "second-owner":
                fixture.startup.symbols.append(copy.deepcopy(fixture.sym(fixture.machine, SVC)))
            else:
                fixture.sym(fixture.final, SVC)["value"] -= 2
            with self.subTest(change=change), self.assertRaisesRegex(decoder.Rejected, "REF-LTO-ORIGIN"):
                fixture.reader()._definition(SVC)

    def test_duplicate_definitions_and_positive_size_cross_name_aliases_reject(self):
        for final in (False, True):
            for name in (SVC, SLOT):
                for alias in (False, True):
                    fixture = Fixture()
                    elf = fixture.final if final else fixture.machine
                    row = copy.deepcopy(fixture.sym(elf, name))
                    if alias:
                        row["name"] += "_alias"
                    elf.symbols.append(row)
                    with self.subTest(final=final, name=name, alias=alias):
                        with self.assertRaisesRegex(decoder.Rejected, "REF-LTO-SYMBOL"):
                            fixture.reader()._symbol(elf, name)

    def test_named_abs32_requires_zero_addend_and_exact_applied_global_slot(self):
        start, pool = ROOT_MODEL[SVC][0], 32
        for change in ("addend", "wrong-address", "section-symbol", "foreign-name", "target-metadata"):
            fixture = Fixture()
            if change == "addend":
                struct.pack_into("<I", fixture.machine.payload, start + pool, 4)
            elif change == "wrong-address":
                struct.pack_into("<I", fixture.final.payload, start + pool, BSS_BASE)
            else:
                target = fixture.machine.relocations[1, start + pool][1]
                if change == "section-symbol":
                    target.update(name="", kind="STT_SECTION", binding="STB_LOCAL", value=0, size=0)
                elif change == "foreign-name":
                    target["name"] = "fiber_internal_runtime_current_context_slot"
                else:
                    target["value"] = 4
            with self.subTest(change=change):
                self.rejected(fixture, match="REF-LTO-SLOT" if change in ("addend", "wrong-address") else "REF-LTO-RELOC")

    def test_coherent_slot_and_bl_retarget_still_fail_independent_map_origin(self):
        fixture = Fixture()
        final_slot = fixture.sym(fixture.final, SLOT)
        final_slot["value"] = RAM + 4
        for name in (SVC, PENDSV):
            offset = 32 if name == SVC else 64
            site = ROOT_MODEL[name][0] + offset
            struct.pack_into("<I", fixture.final.payload, site, final_slot["value"])
            fixture.final.relocations[1, site] = 2, copy.deepcopy(final_slot)
        self.assertEqual(struct.unpack_from("<I", fixture.final.payload, ROOT_MODEL[SVC][0] + 32)[0], final_slot["value"])
        self.rejected(fixture, match="REF-LTO-ORIGIN")
        fixture = Fixture()
        target = fixture.sym(fixture.final, CALLEE)
        target["value"] += 2
        place = BASE + ROOT_MODEL[PENDSV][0] + 28
        raw = bl(place, target["value"] & ~1)
        fixture.instruction(PENDSV, 28, raw, op="bl", operands="%x <%s>" % (target["value"] & ~1, CALLEE))
        fixture.final.relocations[1, ROOT_MODEL[PENDSV][0] + 28] = 10, copy.deepcopy(target)
        self.assertEqual(decoder._address_form(raw, place)[1], target["value"] & ~1)
        self.rejected(fixture, PENDSV, "REF-LTO-ORIGIN")

    def test_bl_original_minus_four_and_applied_destination_and_text_are_exact(self):
        source_place = ROOT_MODEL[PENDSV][0] + 28
        final_place = BASE + source_place
        for change in ("zero-addend", "minus-two", "destination", "text"):
            fixture = Fixture()
            if change in ("zero-addend", "minus-two"):
                fixture.machine.payload[source_place:source_place + 4] = bl(source_place, source_place + (4 if change == "zero-addend" else 2))
            elif change == "destination":
                address = BASE + ROOT_MODEL[SVC][0]
                fixture.instruction(PENDSV, 28, bl(final_place, address), op="bl", operands="%x" % address)
            else:
                key = 1, final_place
                op, _, raw = fixture.image.instructions[key]
                fixture.image.instructions[key] = op, "%x" % (BASE + CALLEE_OFFSET + 2), raw
            with self.subTest(change=change):
                self.rejected(fixture, PENDSV, "REF-LTO-DECODE" if change == "text" else "REF-LTO-RELOC")

    def test_missing_extra_rekinded_wrong_site_and_unrelocated_calls_reject(self):
        for change in ("missing", "extra", "kind", "site", "unrelocated-call"):
            fixture = Fixture()
            site = ROOT_MODEL[SVC][0] + 32
            if change == "missing":
                fixture.final.relocations.pop((1, site))
            elif change == "extra":
                fixture.machine.relocations[1, site - 4] = 2, copy.deepcopy(fixture.sym(fixture.machine, SLOT))
                fixture.final.relocations[1, site - 4] = 2, copy.deepcopy(fixture.sym(fixture.final, SLOT))
            elif change == "kind":
                fixture.final.relocations[1, site] = 10, fixture.final.relocations[1, site][1]
            elif change == "site":
                for elf in (fixture.machine, fixture.final):
                    elf.relocations[1, site - 4] = elf.relocations.pop((1, site))
            else:
                source = ROOT_MODEL[SVC][0] + 2
                fixture.machine.payload[source:source + 4] = bl(source, source)
                fixture.instruction(SVC, 2, bl(BASE + source, BASE + source),
                                    op="bl", operands="%x" % (BASE + source))
            with self.subTest(change=change):
                self.rejected(fixture, match="REF-LTO-DECODE" if change == "unrelocated-call" else "REF-LTO-RELOC")

    def test_nonrelocation_body_extent_and_one_nop_tail_cannot_be_discarded(self):
        fixture = Fixture()
        fixture.instruction(SVC, 2, bytes.fromhex("bff34f8f"), op="dsb", operands="sy")
        self.rejected(fixture, match="REF-LTO-PRESERVATION")
        fixture = Fixture()
        for elf in (fixture.machine, fixture.final):
            fixture.sym(elf, SVC)["size"] -= 2
        self.rejected(fixture, match="REF-LTO-PRESERVATION")
        fixture = Fixture()
        end = ROOT_MODEL[PENDSV][0] + ROOT_MODEL[PENDSV][1]
        for elf in (fixture.machine, fixture.final):
            fixture.sym(elf, PENDSV)["size"] += 2
            elf.points = sorted(elf.points + [(end, "t")])
            elf.payload[end:end + 2] = bytes.fromhex("00bf")
        fixture.image.instructions[1, BASE + end] = "nop", "", bytes.fromhex("00bf")
        self.rejected(fixture, PENDSV, "REF-LTO-PRESERVATION")

    def test_mapping_literal_alignment_padding_and_branch_into_data_are_complete(self):
        fixture = Fixture()
        fixture.final.points = [(at - 2, kind) if at == ROOT_MODEL[SVC][0] + 32 else (at, kind)
                                for at, kind in fixture.final.points]
        self.rejected(fixture, match="REF-LTO-PRESERVATION")
        fixture = Fixture()
        for elf in (fixture.machine, fixture.final):
            elf.payload[ROOT_MODEL[START][0] + 26] = 1
        self.rejected(fixture, START, "REF-LTO-DECODE")
        fixture = Fixture()
        offset, destination = 24, 28
        raw = struct.pack("<H", 0xE000 | ((destination - offset - 4) // 2))
        fixture.instruction(START, offset, raw, both=True, op="b", operands="%x" % (BASE + ROOT_MODEL[START][0] + destination))
        self.rejected(fixture, START, "REF-LTO-DECODE")

    def test_instruction_and_extra_data_records_fail_with_typed_decode_rejection(self):
        start = ROOT_MODEL[SVC][0]
        for change in ("missing", "bytes", "pc", "fp", "register", "interior", "bad-data", "none-data"):
            fixture = Fixture()
            key = 1, BASE + start + (0 if change == "register" else 2)
            op, operands, raw = fixture.image.instructions[key]
            if change == "missing":
                fixture.image.instructions.pop(key)
            elif change == "bytes":
                fixture.image.instructions[key] = op, operands, bytes.fromhex("00bf")
            elif change == "pc":
                fixture.image.instructions[key] = "mov", "r0, pc", raw
            elif change == "fp":
                fixture.image.instructions[key] = "vadd", "s0, s0, s1", raw
            elif change == "register":
                fixture.image.instructions[key] = op, operands.replace("r0", "r1"), raw
            elif change == "interior":
                fixture.image.instructions[1, BASE + start + 3] = "nop", "", bytes.fromhex("00bf")
            else:
                fixture.image.instructions[1, BASE + start + 32] = None if change == "none-data" else (".word", "0", bytes(4))
            with self.subTest(change=change):
                self.rejected(fixture, match="REF-LTO-DECODE")
        fixture = Fixture()
        fixture.image.instructions[1, BASE + start + 32] = ".word", hex(SLOT_ADDRESS), struct.pack("<I", SLOT_ADDRESS)
        self.assertEqual(fixture.reader().function(SVC)["InstructionCount"], 10)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    output = args.output_dir.resolve()
    if output.exists() or output.is_relative_to(REPO) or not output.is_relative_to(Path(tempfile.gettempdir()).resolve()):
        parser.error("fresh external TEMP output directory required")
    report = dict(Status="FAIL", Tests=0, Failures=0, Errors=0, Skipped=0, SourceHashes={}, SourceDrift=[],
        Scope="PURE_SYNTHETIC_REFERENCE_CM3_LTO_READER_UNIT_CONTROLS_ONLY", SyntheticInputs=True,
        ActualELFTested=False, ActualParserExecuted=False, ToolInvocations=0, NativeCommandsExecuted=0,
        GeneratedMachineBoundRootPreservation=False, CanonicalProtocolValidated=False,
        OriginalTranslationUnitOwnership=False, FinalReferenceParity=False, FullABIProof=False,
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
