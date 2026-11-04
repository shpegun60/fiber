"""Synthetic controls and opt-in retained-witness mutations, never CPU proof.

Optional --prelink-object/--final-elf/--disassembly/--plain-elf checks an
already-built witness. This file never launches a subprocess or native tool.
"""

import argparse
from enum import Enum
import hashlib
import importlib.util
from io import BytesIO
import json
from pathlib import Path
import re
import struct
import sys
import tempfile
import unittest


sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("classic_final_image_reader", HERE / "elf.py")
reader = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(reader)
ROOT = "fiber_port_start_first_context"
PANIC = "fiber_panic"
SLOT = "fiber_internal_runtime_current_context_slot"
BASE = 0x08000100
RAM = 0x20000000


def branch_link(place, target):
    displacement = target - (place + 4)
    if displacement % 2 or not -(1 << 24) <= displacement < (1 << 24):
        raise ValueError("test BL range")
    value = displacement & ((1 << 25) - 1)
    sign, i1, i2 = value >> 24, (value >> 23) & 1, (value >> 22) & 1
    first = 0xF000 | (sign << 10) | ((value >> 12) & 1023)
    second = 0xD000 | ((1 ^ i1 ^ sign) << 13) | ((1 ^ i2 ^ sign) << 11) | ((value >> 1) & 2047)
    return struct.pack("<HH", first, second)


def elf_bytes(*, final, body, relocations, maps, extra_symbols=(), root_binding=1,
              panic_binding=2, root_size=24, flags=None, entry=None,
              load_flags=5, mem_extra=0, vector=True, mapping_kind=0,
              slot_size=4, slot_flags=3):
    """Construct a deliberately small valid ELF, without assembler/linker use."""
    text = bytes(body) + bytes(256 - len(body)) + bytes.fromhex("704700bf")
    sections = [dict(name="", kind=0, flags=0, addr=0, data=b"", align=0)]
    sections += [dict(name=".text", kind=1, flags=6, addr=BASE if final else 0,
                      data=text, align=4),
                 dict(name=".bss", kind=8, flags=slot_flags, addr=RAM if final else 0,
                      data=b"", size=4, align=4)]
    if final and vector:
        sections.append(dict(name=".isr_vector", kind=1, flags=2, addr=0x08000000,
                             data=struct.pack("<II", RAM + 4096, BASE | 1), align=4))
    symbols = [dict(name="", value=0, size=0, binding=0, kind=0, section=0)]
    for number, (offset, kind) in enumerate(maps):
        symbols.append(dict(name="$" + kind + ".fixture" + str(number),
                            value=(BASE if final else 0) + offset, size=0,
                            binding=0, kind=mapping_kind, section=1))
    symbols.append(dict(name="$t.callee", value=(BASE if final else 0) + 256, size=0,
                        binding=0, kind=0, section=1))
    local_count = len(symbols)
    symbols += [dict(name=ROOT, value=(BASE if final else 0) | 1,
                     size=root_size, binding=root_binding, kind=2, section=1),
                dict(name=PANIC, value=((BASE if final else 0) + 256) | 1,
                     size=2, binding=panic_binding, kind=2, section=1),
                dict(name=SLOT, value=RAM if final else 0, size=slot_size,
                     binding=1, kind=1, section=2)]
    symbols.extend(dict(item) for item in extra_symbols)
    known = {item["name"] for item in symbols}
    for _, _, name in relocations:
        if name not in known:
            symbols.append(dict(name=name, value=0, size=0, binding=1, kind=0, section=0))
            known.add(name)
    strings = bytearray(b"\0")
    symbol_bytes = bytearray()
    numbers = {}
    for index, item in enumerate(symbols):
        name_offset = len(strings) if item["name"] else 0
        if item["name"]:
            strings.extend(item["name"].encode("ascii") + b"\0")
        numbers[item["name"]] = index
        symbol_bytes.extend(struct.pack("<IIIBBH", name_offset, item["value"], item["size"],
                                        (item["binding"] << 4) | item["kind"], 0, item["section"]))
    sym_index = len(sections)
    sections.append(dict(name=".symtab", kind=2, flags=0, addr=0, data=bytes(symbol_bytes),
                         align=4, entsize=16, link=sym_index + 1, info=local_count))
    sections.append(dict(name=".strtab", kind=3, flags=0, addr=0, data=bytes(strings), align=1))
    if relocations:
        reloc_data = b"".join(struct.pack("<II", offset + (BASE if final else 0),
                                          (numbers[name] << 8) | kind)
                              for offset, kind, name in relocations)
        sections.append(dict(name=".rel.text", kind=9, flags=0, addr=0, data=reloc_data,
                             align=4, entsize=8, link=sym_index, info=1))
    section_names = bytearray(b"\0")
    for section in sections[1:]:
        section["name_offset"] = len(section_names)
        section_names.extend(section["name"].encode("ascii") + b"\0")
    shstr_name = len(section_names)
    section_names.extend(b".shstrtab\0")
    sections.append(dict(name=".shstrtab", name_offset=shstr_name, kind=3, flags=0,
                         addr=0, data=bytes(section_names), align=1))
    output = bytearray(0x1000 if final else 52)
    if final:
        end = BASE - 0x08000000 + len(text)
        output.extend(bytes(end))
    for section in sections:
        if section["flags"] & 2 and final:
            section["offset"] = 0x1000 + (section["addr"] - 0x08000000) if section["kind"] != 8 else 0x1000 + ((end + 3) & ~3)
            if section["kind"] != 8:
                at = section["offset"]
                output[at:at + len(section["data"])] = section["data"]
        else:
            alignment = section["align"] or 1
            output.extend(bytes((-len(output)) % alignment))
            section["offset"] = len(output) if section["kind"] else 0
            output.extend(section["data"])
    output.extend(bytes((-len(output)) % 4))
    section_offset = len(output)
    for section in sections:
        output.extend(struct.pack("<10I", section.get("name_offset", 0), section["kind"],
                                  section["flags"], section["addr"], section["offset"],
                                  section.get("size", len(section["data"])), section.get("link", 0),
                                  section.get("info", 0), section["align"], section.get("entsize", 0)))
    ident = b"\x7fELF\x01\x01\x01" + bytes(9)
    header = struct.pack("<16sHHIIIIIHHHHHH", ident, 2 if final else 1, 40, 1,
                         (BASE | 1) if entry is None and final else (entry or 0),
                         52 if final else 0, section_offset,
                         (0x05000400 if final else 0x05000000) if flags is None else flags,
                         52, 32 if final else 0, 2 if final else 0, 40, len(sections), len(sections) - 1)
    output[:52] = header
    if final:
        output[52:84] = struct.pack("<8I", 1, 0x1000, 0x08000000, 0x08000000,
                                     end, end + mem_extra, load_flags, 4)
        output[84:116] = struct.pack("<8I", 1, 0x1000 + ((end + 3) & ~3), RAM, RAM, 0, 4, 6, 4)
    return bytes(output)


class Fixture:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.source = bytearray.fromhex("002003d0fff7feff00e000bf01487047fee7000000000000")
        self.body = bytearray(self.source)
        self.call_target = BASE + 256
        self.body[4:8] = branch_link(BASE + 4, self.call_target)
        struct.pack_into("<I", self.body, 20, RAM)
        self.source_options = dict(maps=[(0, "t"), (18, "d")],
                                   relocations=[(4, 10, PANIC), (20, 2, SLOT)])
        self.final_options = dict(maps=[(0, "t"), (18, "d")],
                                  relocations=[(4, 10, PANIC), (20, 2, SLOT)])
        self.dis_overrides = {}
        self.omitted = set()
        self.extra_dis = []

    def write(self):
        self.prelink = self.directory / "prelink.o"
        self.final = self.directory / "emit.elf"
        self.plain = self.directory / "plain.elf"
        self.dis = self.directory / "emit.dis"
        self.link_map = self.directory / "emit.map"
        self.prelink.write_bytes(elf_bytes(final=False, body=self.source, **self.source_options))
        self.final.write_bytes(elf_bytes(final=True, body=self.body, **self.final_options))
        plain_options = dict(self.final_options, relocations=[])
        self.plain.write_bytes(elf_bytes(final=True, body=self.body, **plain_options))
        rows = [(0, 2, "movs", "r0, #0"), (2, 2, "beq.n", hex(BASE + 12)[2:]),
                (4, 4, "bl", hex(self.call_target)[2:] + " <fiber_panic>"),
                (8, 2, "b.n", hex(BASE + 12)[2:]), (10, 2, "nop", ""),
                (12, 2, "ldr", "r0, [pc, #4]"), (14, 2, "bx", "lr"),
                (16, 2, "b.n", hex(BASE + 16)[2:]), (18, 2, ".short", "0"),
                (20, 4, ".word", hex(RAM))]
        lines = ["Disassembly of section .text:"]
        for offset, size, op, operands in rows:
            if offset in self.omitted:
                continue
            raw = self.body[offset:offset + size]
            words = ("%08x" % struct.unpack("<I", raw)[0] if op == ".word" else
                     " ".join("%04x" % value for value in struct.unpack("<" + "H" * (size // 2), raw)))
            line = "%08x: %s %s %s" % (BASE + offset, words, op, operands)
            lines.append(self.dis_overrides.get(offset, line))
        lines.extend(self.extra_dis)
        self.dis.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
        self.link_map.write_text("Linker script and memory map\n"
                                 " .text 0x%x 0x104 %s\n .bss 0x%x 0x4 %s\n"
                                 % (BASE, self.prelink.resolve().as_posix(), RAM, self.prelink.resolve().as_posix()),
                                 encoding="utf-8", newline="\n")
        return self

    def image(self):
        return reader.FinalImage(self.prelink, self.final, self.dis,
                                 provider_objects={str(self.prelink.resolve()): self.prelink},
                                 link_map=self.link_map)


class ContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="classic-final-reader-")
        self.addCleanup(self.temp.cleanup)
        self.fixture = Fixture(self.temp.name)

    def test_complete_weak_panic(self):
        f = self.fixture.write()
        proof = f.image().function(ROOT)
        self.assertTrue(proof["Complete"] and proof["PrelinkBoundRootPreservation"])
        self.assertEqual((proof["Size"], proof["InstructionCount"]), (24, 8))
        self.assertEqual([item["Addend"] for item in proof["References"]], [-4, 0])
        self.assertEqual(proof["References"][0]["Binding"], "STB_WEAK")
        self.assertEqual(proof["Instructions"][2]["Target"], BASE + 256)
        self.assertEqual(proof["Instructions"][5]["Target"], BASE + 20)
        self.assertEqual(proof["LiteralIslands"][0]["Offset"], 18)
        self.assertEqual(proof["LiteralIslands"][0]["Bytes"], "000000000020")
        self.assertEqual(f.image().read(BASE, 24), bytes(f.body))
        self.assertTrue(reader.compare_load_images(f.plain, f.final)["Identical"])

    def test_global_panic(self):
        self.fixture.final_options["panic_binding"] = 1
        self.assertEqual(self.fixture.write().image().function(ROOT)["References"][0]["Binding"], "STB_GLOBAL")

    def test_metadata_only_change(self):
        f = self.fixture.write()
        f.plain.write_bytes(f.plain.read_bytes() + b"nonload metadata")
        self.assertTrue(reader.compare_load_images(f.plain, f.final)["Identical"])

    def test_identical_twins_do_not_authorize_instruction_mutation(self):
        self.fixture.body[0:2] = bytes.fromhex("0120")
        f = self.fixture.write()
        self.assertTrue(reader.compare_load_images(f.plain, f.final)["Identical"])
        with self.assertRaisesRegex(reader.Rejected, "PRESERVATION"):
            f.image().function(ROOT)

    def test_identical_twins_do_not_authorize_call_mutation(self):
        self.fixture.call_target += 2
        self.fixture.body[4:8] = branch_link(BASE + 4, self.fixture.call_target)
        f = self.fixture.write()
        self.assertTrue(reader.compare_load_images(f.plain, f.final)["Identical"])
        with self.assertRaisesRegex(reader.Rejected, "RELOC"):
            f.image().function(ROOT)

    def test_identical_twins_do_not_authorize_literal_mutation(self):
        struct.pack_into("<I", self.fixture.body, 20, RAM + 4)
        f = self.fixture.write()
        self.assertTrue(reader.compare_load_images(f.plain, f.final)["Identical"])
        with self.assertRaisesRegex(reader.Rejected, "RELOC"):
            f.image().function(ROOT)

    def test_identical_twins_do_not_authorize_symbol_mutation(self):
        self.fixture.final_options["root_binding"] = 2
        f = self.fixture.write()
        self.assertTrue(reader.compare_load_images(f.plain, f.final)["Identical"])
        with self.assertRaisesRegex(reader.Rejected, "SYMBOL"):
            f.image().function(ROOT)

    def test_identical_twins_do_not_authorize_relocation_mutation(self):
        self.fixture.final_options["relocations"][0] = (4, 30, PANIC)
        f = self.fixture.write()
        self.assertTrue(reader.compare_load_images(f.plain, f.final)["Identical"])
        with self.assertRaisesRegex(reader.Rejected, "RELOC"):
            f.image().function(ROOT)

    def test_backward_and_high_displacement_bl(self):
        for place, target in ((0x08001000, 0x08000000), (0x08000000, 0x08FFFFFE),
                              (0x09000000, 0x08000004), (0x08000002, 0x08000006)):
            self.assertEqual(reader._address_form(branch_link(place, target), place)[1], target)

    def test_branch_bits_not_aligned_pc(self):
        self.assertEqual(reader._address_form(bytes.fromhex("00e0"), BASE + 2)[1], BASE + 6)
        self.assertEqual(reader._address_form(bytes.fromhex("fed1"), BASE + 2)[1], BASE + 2)
        self.assertEqual(reader._address_form(bytes.fromhex("0048"), BASE + 2)[1], BASE + 4)

    def test_no_bss_byte_reads(self):
        image = self.fixture.write().image()
        with self.assertRaisesRegex(reader.Rejected, "file-backed"):
            image.read(RAM, 4)

    def test_unknown_root(self):
        with self.assertRaisesRegex(reader.Rejected, "SCOPE"):
            self.fixture.write().image().function("fiber_panic")

    def test_local_branch_interior_rejected_even_when_bytes_match(self):
        f = self.fixture
        f.source[2:4] = f.body[2:4] = bytes.fromhex("00d0")
        f.dis_overrides[2] = "%08x: d000 beq %x" % (BASE + 2, BASE + 6)
        with self.assertRaisesRegex(reader.Rejected, "instruction boundary"):
            f.write().image().function(ROOT)

    def test_local_branch_data_rejected_even_when_bytes_match(self):
        f = self.fixture
        f.source[2:4] = f.body[2:4] = bytes.fromhex("06d0")
        f.dis_overrides[2] = "%08x: d006 beq %x" % (BASE + 2, BASE + 18)
        with self.assertRaisesRegex(reader.Rejected, "instruction boundary"):
            f.write().image().function(ROOT)

    def test_literal_outside_root_rejected_even_when_bytes_match(self):
        f = self.fixture
        f.source[12:14] = f.body[12:14] = bytes.fromhex("0248")
        f.dis_overrides[12] = "%08x: 4802 ldr r0, [pc, #8]" % (BASE + 12)
        with self.assertRaisesRegex(reader.Rejected, "bounded mapped data"):
            f.write().image().function(ROOT)


def _alias(name, value, size=2):
    return dict(name=name, value=value, size=size, binding=1, kind=2, section=1)


def _patch_header(path, offset, fmt, value):
    data = bytearray(path.read_bytes())
    struct.pack_into(fmt, data, offset, value)
    path.write_bytes(data)


def _negative(name, mutate, expected):
    def control(self):
        f = self.fixture
        mutate(f)
        f.write()
        with self.assertRaisesRegex(reader.Rejected, expected):
            f.image().function(ROOT)
    control.__name__ = "test_reject_" + name
    setattr(ContractTests, control.__name__, control)


_negative("source_addend", lambda f: f.source.__setitem__(slice(4, 8), branch_link(4, 2)), "addend")
_negative("source_literal_addend", lambda f: struct.pack_into("<I", f.source, 20, 4), "ABS32")
_negative("missing_final_relocation", lambda f: f.final_options["relocations"].pop(), "membership")
_negative("missing_original_relocation", lambda f: f.source_options["relocations"].pop(), "membership")
_negative("foreign_call", lambda f: f.final_options["relocations"].__setitem__(0, (4, 10, "foreign")), "identity")
_negative("duplicate_relocation", lambda f: f.final_options["relocations"].append((4, 10, PANIC)), "duplicate")
_negative("unsupported_relocation", lambda f: [options["relocations"].__setitem__(0, (4, 30, PANIC)) for options in (f.source_options, f.final_options)], "unsupported")
_negative("overlapping_relocation", lambda f: [options["relocations"].append((6, 2, SLOT)) for options in (f.source_options, f.final_options)], "overlap|aligned")
_negative("instruction_interior_relocation", lambda f: [options["relocations"].__setitem__(0, (6, 10, PANIC)) for options in (f.source_options, f.final_options)], "overlap|boundary")
_negative("root_alias", lambda f: f.final_options.update(extra_symbols=[_alias("alias", BASE | 1, 24)]), "alias")
_negative("callee_alias", lambda f: f.final_options.update(extra_symbols=[_alias("alias", (BASE + 256) | 1)]), "alias")
_negative("interior_callee_alias", lambda f: f.final_options.update(extra_symbols=[_alias("alias", (BASE + 254) | 1, 4)]), "alias")
_negative("missing_mapping", lambda f: f.final_options.update(maps=[(18, "d")]), "mapping")
_negative("mapping_conflict", lambda f: f.final_options["maps"].append((0, "d")), "conflicting")
_negative("mapping_type", lambda f: f.final_options.update(mapping_kind=1), "mapping")
_negative("arm_mapping", lambda f: f.final_options["maps"].__setitem__(0, (0, "a")), "Thumb")
_negative("changed_mapping_extent", lambda f: f.final_options["maps"].__setitem__(1, (20, "d")), "mapping|extent")
_negative("changed_root_extent", lambda f: f.final_options.update(root_size=22), "extent")
_negative("non_executable_load", lambda f: f.final_options.update(load_flags=4), "not executable")
_negative("unwritable_slot", lambda f: f.final_options.update(slot_flags=2), "writable")
_negative("executable_slot", lambda f: f.final_options.update(slot_flags=7), "writable")
_negative("wrong_slot_size", lambda f: f.final_options.update(slot_size=2), "size/alignment")
_negative("soft_float_final_flags", lambda f: f.final_options.update(flags=0x05000200), "ABI flags")
_negative("foreign_abi_flags", lambda f: f.final_options.update(flags=0x05000401), "ABI flags")
_negative("missing_instruction", lambda f: f.omitted.add(10), "instruction")
_negative("raw_disagreement", lambda f: f.dis_overrides.update({0: "%08x: 2001 movs r0, #1" % BASE}), "disassembly")
_negative("wrong_branch_text", lambda f: f.dis_overrides.update({2: "%08x: d003 beq %x" % (BASE + 2, BASE + 10)}), "target")
_negative("wrong_condition_text", lambda f: f.dis_overrides.update({2: "%08x: d003 bne %x" % (BASE + 2, BASE + 12)}), "mnemonic")
_negative("wrong_call_text", lambda f: f.dis_overrides.update({4: "%08x: %04x %04x bl %x" % (BASE + 4, *struct.unpack("<HH", f.body[4:8]), BASE + 258)}), "target")
_negative("wrong_literal_text", lambda f: f.dis_overrides.update({12: "%08x: 4801 ldr r0, [pc, #8]" % (BASE + 12)}), "operand")
_negative("wrong_literal_register", lambda f: f.dis_overrides.update({12: "%08x: 4801 ldr r1, [pc, #4]" % (BASE + 12)}), "operand")
_negative("wrong_bx_text", lambda f: f.dis_overrides.update({14: "%08x: 4770 bx r0" % (BASE + 14)}), "BX LR")
_negative("extra_interior_disassembly", lambda f: f.extra_dis.append("%08x: f000 movs r0,#0" % (BASE + 6)), "interior")
_negative("duplicate_disassembly", lambda f: f.extra_dis.append("%08x: 2000 movs r0,#0" % BASE), "duplicate")
_negative("data_raw_disagreement", lambda f: f.dis_overrides.update({20: "%08x: 20000004 .word 0x20000004" % (BASE + 20)}), "mismatched")
_negative("unsupported_text_pc", lambda f: f.dis_overrides.update({0: "%08x: 2000 mov pc, r0" % BASE}), "PC use")


class TwinTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="classic-final-twins-")
        self.addCleanup(self.temp.cleanup)
        self.f = Fixture(self.temp.name).write()

    def test_entry(self):
        _patch_header(self.f.plain, 24, "<I", BASE + 3)
        with self.assertRaisesRegex(reader.Rejected, "entry"):
            reader.compare_load_images(self.f.plain, self.f.final)

    def test_segment_flags(self):
        _patch_header(self.f.plain, 52 + 24, "<I", 4)
        with self.assertRaisesRegex(reader.Rejected, "geometry"):
            reader.compare_load_images(self.f.plain, self.f.final)

    def test_zero_fill_extent(self):
        _patch_header(self.f.plain, 84 + 20, "<I", 8)
        with self.assertRaisesRegex(reader.Rejected, "geometry"):
            reader.compare_load_images(self.f.plain, self.f.final)

    def test_writable_owner_required_in_both_twins(self):
        for path in (self.f.plain, self.f.final):
            _patch_header(path, 84 + 24, "<I", 4)
        with self.assertRaisesRegex(reader.Rejected, "writable allocated section owner lacks PF_W"):
            reader.compare_load_images(self.f.plain, self.f.final)
        with self.assertRaisesRegex(reader.Rejected, "writable allocated section owner lacks PF_W"):
            self.f.image()

    def test_vector_bytes(self):
        data = bytearray(self.f.plain.read_bytes())
        data[0x1000] ^= 8
        self.f.plain.write_bytes(data)
        with self.assertRaisesRegex(reader.Rejected, "bytes"):
            reader.compare_load_images(self.f.plain, self.f.final)

    def test_loaded_padding(self):
        data = bytearray(self.f.plain.read_bytes())
        data[0x1020] = 1
        self.f.plain.write_bytes(data)
        with self.assertRaisesRegex(reader.Rejected, "bytes"):
            reader.compare_load_images(self.f.plain, self.f.final)

    def test_overlapping_loads(self):
        _patch_header(self.f.plain, 84 + 8, "<I", BASE)
        with self.assertRaisesRegex(reader.Rejected, "overlapping"):
            reader.compare_load_images(self.f.plain, self.f.final)

    def test_truncated_elf(self):
        self.f.plain.write_bytes(self.f.plain.read_bytes()[:128])
        with self.assertRaises(reader.Rejected):
            reader.compare_load_images(self.f.plain, self.f.final)

    def test_wrong_elf_type(self):
        _patch_header(self.f.plain, 16, "<H", 1)
        with self.assertRaisesRegex(reader.Rejected, "ET_EXEC"):
            reader.compare_load_images(self.f.plain, self.f.final)


class EncodingTests(unittest.TestCase):
    def test_reject_cbz(self):
        with self.assertRaisesRegex(reader.Rejected, "CBZ"):
            reader._address_form(bytes.fromhex("00b1"), BASE)

    def test_reject_bw(self):
        with self.assertRaisesRegex(reader.Rejected, "B.W"):
            reader._address_form(bytes.fromhex("fff7febf"), BASE)

    def test_reject_conditional_t32(self):
        with self.assertRaisesRegex(reader.Rejected, "conditional"):
            reader._address_form(bytes.fromhex("00f00080"), BASE)

    def test_reject_ldr_t32(self):
        with self.assertRaisesRegex(reader.Rejected, "literal"):
            reader._address_form(bytes.fromhex("dff80000"), BASE)

    def test_reject_blx(self):
        with self.assertRaisesRegex(reader.Rejected, "BLX"):
            reader._address_form(bytes.fromhex("00f000e8"), BASE)

    def test_reject_register_branch(self):
        with self.assertRaisesRegex(reader.Rejected, "BX LR"):
            reader._address_form(bytes.fromhex("0047"), BASE)

    def test_reject_wrong_width(self):
        with self.assertRaisesRegex(reader.Rejected, "width"):
            reader._address_form(bytes.fromhex("00f0"), BASE)


def _digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest().upper()


def _edit(path, offset, replacement, edits):
    data = bytearray(path.read_bytes())
    before = bytes(data[offset:offset + len(replacement)])
    if len(before) != len(replacement) or before == replacement:
        raise ValueError("mutation must change an existing bounded field")
    data[offset:offset + len(replacement)] = replacement
    path.write_bytes(data)
    edits.append(dict(File=str(path), Offset=offset, Before=before.hex(), After=replacement.hex()))


def _structured(path):
    return reader.ELFFile(BytesIO(path.read_bytes()))


def _symbol_field(path, name, field):
    elf = _structured(path)
    matches = []
    for table in elf.iter_sections():
        if isinstance(table, reader.SymbolTableSection) and table.header.sh_type == "SHT_SYMTAB":
            for index, symbol in enumerate(table.iter_symbols()):
                if symbol.name == name and symbol.entry.st_shndx != "SHN_UNDEF":
                    matches.append((table.header.sh_offset + index * table.header.sh_entsize, symbol.entry))
    if len(matches) != 1:
        raise ValueError("mutation needs one defined symbol " + name)
    offset, entry = matches[0]
    delta, fmt = {"value": (4, "<I"), "size": (8, "<I"), "info": (12, "<B")}[field]
    return offset + delta, fmt, entry


def _patch_symbol(path, name, field, value, edits):
    offset, fmt, _ = _symbol_field(path, name, field)
    _edit(path, offset, struct.pack(fmt, value), edits)


def _patch_vma(path, address, replacement, edits):
    elf = _structured(path)
    matches = [segment for segment in elf.iter_segments() if segment.header.p_type == "PT_LOAD"
               and segment.header.p_vaddr <= address
               and address + len(replacement) <= segment.header.p_vaddr + segment.header.p_filesz]
    if len(matches) != 1:
        raise ValueError("mutation needs one file-backed VMA")
    h = matches[0].header
    _edit(path, h.p_offset + address - h.p_vaddr, replacement, edits)


def _patch_prelink(path, root, offset, replacement, edits):
    elf = _structured(path)
    _, _, symbol = _symbol_field(path, root, "value")
    section = elf.get_section(symbol.st_shndx)
    _edit(path, section.header.sh_offset + (symbol.st_value & ~1) + offset, replacement, edits)


def _patch_disassembly(path, section_name, address, raw, op, operands):
    lines = path.read_text(encoding="utf-8").splitlines()
    selected, count = False, 0
    for index, line in enumerate(lines):
        heading = re.fullmatch(r"Disassembly of section (.+):", line)
        if heading:
            selected = heading[1] == section_name
        match = re.match(r"^\s*([0-9a-fA-F]+):\s+", line)
        if not selected or match is None or int(match[1], 16) != address:
            continue
        words = ("%08x" % struct.unpack("<I", raw)[0] if op == ".word" else
                 " ".join("%04x" % half for half in struct.unpack("<" + "H" * (len(raw) // 2), raw)))
        lines[index] = " %x:\t%s\t%s\t%s" % (address, words, op, operands)
        count += 1
    if count != 1:
        raise ValueError("mutation needs one disassembly record")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")


def _patch_relocation(path, place, *, kind=None, symbol=None, edits):
    elf = _structured(path)
    matches = []
    for section in elf.iter_sections():
        if not isinstance(section, reader.RelocationSection):
            continue
        table = elf.get_section(section.header.sh_link)
        for index, relocation in enumerate(section.iter_relocations()):
            if relocation.entry.r_offset == place:
                old = relocation.entry.r_info
                if symbol is None:
                    symbol_index = relocation.entry.r_info_sym
                else:
                    symbols = [i for i, item in enumerate(table.iter_symbols()) if item.name == symbol
                               and item.entry.st_shndx != "SHN_UNDEF"]
                    if len(symbols) != 1:
                        raise ValueError("mutation needs one replacement relocation symbol")
                    symbol_index = symbols[0]
                new_kind = relocation.entry.r_info_type if kind is None else kind
                matches.append((section.header.sh_offset + index * section.header.sh_entsize + 4,
                                (symbol_index << 8) | new_kind, old))
    if len(matches) != 1:
        raise ValueError("mutation needs one applied relocation")
    offset, value, _ = matches[0]
    _edit(path, offset, struct.pack("<I", value), edits)


def _mutate_witness(name, files, baseline, proofs, edits):
    first = proofs[ROOT]
    svc = proofs["SVC_Handler"]
    root_call = next(item for item in first["References"] if item["Kind"] == 10)
    slot = next(item for item in svc["References"] if item["Kind"] == 2)
    twins = (files["Final"], files["Plain"])
    section = baseline.final.names[baseline.final.symbol(ROOT, "STT_FUNC", root=True)["section"]]
    if name == "ordinary-byte":
        instruction = next(item for item in first["Instructions"] if item["Mnemonic"] == "movs"
                           and len(bytes.fromhex(item["Bytes"])) == 2
                           and struct.unpack("<H", bytes.fromhex(item["Bytes"]))[0] & 0xF800 == 0x2000)
        half = struct.unpack("<H", bytes.fromhex(instruction["Bytes"]))[0] ^ 1
        raw = struct.pack("<H", half)
        address = first["Address"] + instruction["Offset"]
        for path in twins:
            _patch_vma(path, address, raw, edits)
        _patch_disassembly(files["Disassembly"], section, address, raw, "movs",
                           "r%d, #%d" % ((half >> 8) & 7, half & 255))
    elif name == "BL-target-plus-two":
        raw = branch_link(root_call["Place"], root_call["ResolvedValue"] + 2)
        for path in twins:
            _patch_vma(path, root_call["Place"], raw, edits)
        _patch_disassembly(files["Disassembly"], section, root_call["Place"], raw, "bl",
                           "%x <%s+0x2>" % (root_call["ResolvedValue"] + 2, root_call["Symbol"]))
    elif name == "slot-ABS32-plus-four":
        raw = struct.pack("<I", slot["ResolvedValue"] + 4)
        for path in twins:
            _patch_vma(path, slot["Place"], raw, edits)
        svc_section = baseline.final.names[baseline.final.symbol("SVC_Handler", "STT_FUNC", root=True)["section"]]
        _patch_disassembly(files["Disassembly"], svc_section, slot["Place"], raw, ".word",
                           "0x%x" % (slot["ResolvedValue"] + 4))
    elif name == "applied-REL-kind":
        _patch_relocation(files["Final"], root_call["Place"], kind=30, edits=edits)
    elif name == "applied-REL-target":
        _patch_relocation(files["Final"], root_call["Place"],
                          symbol="fiber_port_context_validate_restore", edits=edits)
    elif name == "original-BL-addend":
        _patch_prelink(files["Prelink"], ROOT, root_call["Offset"], branch_link(0, 2), edits)
    elif name == "original-slot-addend":
        _patch_prelink(files["Prelink"], "SVC_Handler", slot["Offset"], struct.pack("<I", 4), edits)
    elif name == "root-weak-binding":
        for path in twins:
            _patch_symbol(path, ROOT, "info", 0x22, edits)
    elif name == "root-size":
        for path in twins:
            _patch_symbol(path, ROOT, "size", first["Size"] - 2, edits)
    elif name == "mapping-boundary":
        address = svc["Address"] + svc["LiteralIslands"][0]["Offset"]
        for path in twins:
            elf = _structured(path)
            matches = []
            for table in elf.iter_sections():
                if isinstance(table, reader.SymbolTableSection):
                    matches.extend(table.header.sh_offset + i * table.header.sh_entsize + 4
                                   for i, item in enumerate(table.iter_symbols())
                                   if re.fullmatch(r"\$d(?:\..*)?", item.name)
                                   and item.entry.st_value == address)
            if not matches:
                raise ValueError("mutation needs actual data mapping boundary")
            for offset in matches:
                _edit(path, offset, struct.pack("<I", address - 2), edits)
    elif name == "callee-symbol-and-BL-padding-retarget":
        occupied = [(item["value"] & ~1, (item["value"] & ~1) + item["size"])
                    for item in baseline.final.symbols if item["kind"] == "STT_FUNC"
                    and type(item["section"]) is int and item["section"] > 0]
        candidates = [(sec, address) for (sec, address), record in baseline.instructions.items()
                      if record is not None and record[0] == "nop"
                      and record[2] in (b"\x00\xbf", b"\xc0\x46")
                      and not any(a < address + 2 and address < b for a, b in occupied)
                      and baseline.final.mapping(sec, address)[0] == "t"
                      and any(load["Flags"] & 1 and load["Vaddr"] <= address
                              and address + 2 <= load["Vaddr"] + load["FileSize"]
                              for load in baseline.final.loads)]
        if not candidates:
            raise ValueError("no real unowned Thumb NOP padding for origin regression")
        _, address = min(candidates, key=lambda item: item[1])
        for path in twins:
            _patch_symbol(path, PANIC, "value", address | 1, edits)
            _patch_symbol(path, PANIC, "size", 2, edits)
        for proof in proofs.values():
            owner = baseline.final.names[baseline.final.symbol(proof["Name"], "STT_FUNC", root=True)["section"]]
            for call in proof["References"]:
                if call["Kind"] == 10 and call["Symbol"] == PANIC:
                    raw = branch_link(call["Place"], address)
                    for path in twins:
                        _patch_vma(path, call["Place"], raw, edits)
                    _patch_disassembly(files["Disassembly"], owner, call["Place"], raw, "bl",
                                       "%x <fiber_panic>" % address)
    elif name == "NOBITS-slot-over-file-backed-text":
        # Structurally invalid twins must be rejected by the ELF/twin checker,
        # even though their PT_LOAD descriptors and file bytes remain equal.
        for path in twins:
            elf = _structured(path)
            _, _, symbol = _symbol_field(path, SLOT, "value")
            section_index = symbol.st_shndx
            section_header = elf.get_section(section_index).header
            text_header = elf.get_section_by_name(section).header
            address = (text_header.sh_addr + 3) & ~3
            if address + section_header.sh_size > text_header.sh_addr + text_header.sh_size:
                raise ValueError("no bounded text range for NOBITS regression")
            _patch_symbol(path, SLOT, "value", address, edits)
            _edit(path, elf.header.e_shoff + section_index * elf.header.e_shentsize + 12,
                  struct.pack("<I", address), edits)
        for proof in proofs.values():
            owner = baseline.final.names[baseline.final.symbol(proof["Name"], "STT_FUNC", root=True)["section"]]
            for reference in proof["References"]:
                if reference["Kind"] == 2 and reference["Symbol"] == SLOT:
                    raw = struct.pack("<I", address)
                    for path in twins:
                        _patch_vma(path, reference["Place"], raw, edits)
                    _patch_disassembly(files["Disassembly"], owner, reference["Place"], raw,
                                       ".word", "0x%x" % address)
    elif name == "RAM-owner-not-writable":
        for path in twins:
            elf = _structured(path)
            matches = [(index, segment.header) for index, segment in enumerate(elf.iter_segments())
                       if segment.header.p_type == "PT_LOAD" and segment.header.p_vaddr <= slot["ResolvedValue"]
                       and slot["ResolvedValue"] + 4 <= segment.header.p_vaddr + segment.header.p_memsz]
            if len(matches) != 1 or not matches[0][1].p_flags & 2:
                raise ValueError("mutation needs one writable SLOT owner")
            index, header = matches[0]
            _edit(path, elf.header.e_phoff + index * elf.header.e_phentsize + 24,
                  struct.pack("<I", header.p_flags & ~2), edits)
    else:
        raise ValueError("unknown retained-witness mutation")


def _actual_witness(witness, provider_paths, link_map, directory, *, float_abi="hard"):
    report = dict(Status="FAIL", Scope="PRELINK_BOUND_ROOT_PRESERVATION_AND_SYMBOL_ORIGIN_ONLY",
                  PositiveRoots=[], Mutants=[], InputDrift=[], RequiredCellSatisfied=False,
                  FinalParity=False, CPUProof=False, GlobalProof=False, FloatABI=float_abi)
    inputs = dict(zip(("Prelink", "Final", "Disassembly", "Plain"), witness))
    inputs["LinkMap"] = link_map
    originals = list(dict.fromkeys(Path(path).resolve() for path in (*inputs.values(), *provider_paths)))
    snapshots = {path: path.read_bytes() for path in originals}
    captured = directory / "witness-inputs"
    captured.mkdir()
    copies = {}
    for number, (path, data) in enumerate(snapshots.items()):
        target = captured / ("%02d-" % number + path.name)
        target.write_bytes(data)
        copies[path] = target
    source_hashes = {str(path): hashlib.sha256(data).hexdigest().upper() for path, data in snapshots.items()}
    report["Inputs"] = [dict(Original=str(path), Captured=str(copies[path]), Sha256=source_hashes[str(path)])
                        for path in originals]
    files = {key: copies[Path(path).resolve()] for key, path in inputs.items()}
    providers = {str(Path(path).resolve()): copies[Path(path).resolve()] for path in provider_paths}
    try:
        image = reader.FinalImage(files["Prelink"], files["Final"], files["Disassembly"],
                                  provider_objects=providers, link_map=files["LinkMap"], float_abi=float_abi)
        report["Twins"] = reader.compare_load_images(files["Plain"], files["Final"])
        proofs = {name: image.function(name) for name in sorted(reader.ROOTS)}
        report["PositiveRoots"] = list(proofs.values())
        cases = [("ordinary-byte", ROOT, "PRESERVATION:non-relocation bytes changed"),
                 ("BL-target-plus-two", ROOT, "RELOC:applied BL destination"),
                 ("slot-ABS32-plus-four", "SVC_Handler", "RELOC:applied ABS32 word"),
                 ("applied-REL-kind", ROOT, "RELOC:relocation kind/identity"),
                 ("applied-REL-target", ROOT, "RELOC:relocation kind/identity"),
                 ("original-BL-addend", ROOT, "RELOC:only original BL addend"),
                 ("original-slot-addend", "SVC_Handler", "RELOC:only current-slot ABS32"),
                 ("root-weak-binding", ROOT, "SYMBOL:invalid definition"),
                 ("root-size", ROOT, "PRESERVATION:root extent changed"),
                 ("mapping-boundary", "SVC_Handler", "PRESERVATION:mapping/layout changed"),
                 ("callee-symbol-and-BL-padding-retarget", ROOT, "ORIGIN:original section/offset/size"),
                 ("NOBITS-slot-over-file-backed-text", "SVC_Handler", "ELF:overlapping allocated sections"),
                 ("RAM-owner-not-writable", "SVC_Handler", "ELF:writable allocated section owner lacks PF_W")]
        for name, root, expected in cases:
            case_directory = directory / "mutants" / name
            case_directory.mkdir(parents=True)
            case = {}
            for key, path in files.items():
                target = case_directory / (key + path.suffix)
                target.write_bytes(path.read_bytes())
                case[key] = target
            case_providers = dict(providers)
            for identity, path in tuple(case_providers.items()):
                if path == files["Prelink"]:
                    case_providers[identity] = case["Prelink"]
            record = dict(Name=name, Root=root, Expected=expected, Status="FAIL",
                          TwinComparisonPass=False, ReaderRejected=False, Edits=[])
            report["Mutants"].append(record)
            try:
                _mutate_witness(name, case, image, proofs, record["Edits"])
                if not record["Edits"]:
                    raise ValueError("mutation did not edit ELF bytes")
                stage = "TwinComparison"
                try:
                    reader.compare_load_images(case["Plain"], case["Final"])
                    record["TwinComparisonPass"] = True
                    stage = "FinalImage"
                    mutated = reader.FinalImage(case["Prelink"], case["Final"], case["Disassembly"],
                                                provider_objects=case_providers, link_map=case["LinkMap"],
                                                float_abi=float_abi)
                    stage = "Root"
                    mutated.function(root)
                except reader.Rejected as error:
                    record.update(ReaderRejected=True, Rejection=str(error), Stage=stage)
                    expected_stage = "TwinComparison" if name.startswith(("NOBITS-", "RAM-")) else "Root"
                    if stage == expected_stage and re.search(expected, str(error)):
                        record["Status"] = "PASS"
            except Exception as error:
                record["Error"] = type(error).__name__ + ": " + str(error)
            record["Files"] = [dict(Path=str(path), Sha256=_digest(path)) for path in case.values()]
        report["MutantControls"] = len(report["Mutants"])
        report["MutantsPassed"] = sum(item["Status"] == "PASS" for item in report["Mutants"])
        report["PositiveRootCount"] = len(proofs)
        report["RootBytes"] = sum(item["Size"] for item in proofs.values())
        report["Instructions"] = sum(item["InstructionCount"] for item in proofs.values())
        report["AppliedReferences"] = sum(len(item["References"]) for item in proofs.values())
        if report["MutantsPassed"] == len(cases):
            report["Status"] = "PASS"
    except Exception as error:
        report["Error"] = type(error).__name__ + ": " + str(error)
    finally:
        closing = {}
        for path in originals:
            try:
                closing[str(path)] = _digest(path)
            except OSError:
                closing[str(path)] = None
        report["ClosingInputHashes"] = closing
        report["InputDrift"] = [str(path) for path in originals if closing[str(path)] != source_hashes[str(path)]]
        report["CapturedInputDrift"] = [str(path) for path in originals
                                         if _digest(copies[path]) != source_hashes[str(path)]]
        report["MutantFileDrift"] = [entry["Path"] for item in report["Mutants"] for entry in item.get("Files", [])
                                      if _digest(entry["Path"]) != entry["Sha256"]]
        if report["InputDrift"] or report["CapturedInputDrift"] or report["MutantFileDrift"]:
            report["Status"] = "FAIL"
    return report


class OriginTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="classic-final-origin-")
        self.addCleanup(self.temp.cleanup)
        self.f = Fixture(self.temp.name).write()

    def test_map_is_required(self):
        f = self.f
        image = reader.FinalImage(f.prelink, f.final, f.dis,
                                  provider_objects={str(f.prelink.resolve()): f.prelink})
        with self.assertRaisesRegex(reader.Rejected, "ORIGIN:explicit"):
            image.function(ROOT)

    def test_providers_are_required(self):
        with self.assertRaisesRegex(reader.Rejected, "ORIGIN:map needs"):
            reader.FinalImage(self.f.prelink, self.f.final, self.f.dis, link_map=self.f.link_map)

    def test_two_line_placement(self):
        f = self.f
        f.link_map.write_text(f.link_map.read_text().replace(" .text 0x", " .text\n                0x"), encoding="utf-8")
        self.assertTrue(f.image().function(ROOT)["RootOrigin"]["SymbolOriginBound"])

    def test_discarded_input_not_used(self):
        f = self.f
        f.link_map.write_text("Discarded input sections\n .text 0x0 0x104 /foreign.o\n" + f.link_map.read_text(), encoding="utf-8")
        self.assertTrue(f.image().function(ROOT)["RootOrigin"]["SymbolOriginBound"])

    def test_duplicate_placement(self):
        f = self.f
        f.link_map.write_text(f.link_map.read_text() + f.link_map.read_text().splitlines()[1] + "\n", encoding="utf-8")
        with self.assertRaisesRegex(reader.Rejected, "ORIGIN:duplicate"):
            f.image()

    def test_no_map_marker(self):
        self.f.link_map.write_text("Discarded input sections\n", encoding="utf-8")
        with self.assertRaisesRegex(reader.Rejected, "ORIGIN:unique GNU"):
            self.f.image()

    def test_wrong_placement_size(self):
        self.f.link_map.write_text(self.f.link_map.read_text().replace("0x104", "0x108"), encoding="utf-8")
        with self.assertRaisesRegex(reader.Rejected, "ORIGIN:original section/offset/size"):
            self.f.image().function(ROOT)

    def test_slot_uses_independent_placement(self):
        self.f.link_map.write_text(self.f.link_map.read_text().replace(".bss 0x20000000", ".bss 0x20000004"), encoding="utf-8")
        with self.assertRaisesRegex(reader.Rejected, "ORIGIN:original section/offset/size.*" + SLOT):
            self.f.image().function(ROOT)

    def test_missing_placement(self):
        self.f.link_map.write_text("Linker script and memory map\n", encoding="utf-8")
        with self.assertRaisesRegex(reader.Rejected, "ORIGIN:missing original"):
            self.f.image().function(ROOT)

    def test_foreign_provider_identity(self):
        f = self.f
        image = reader.FinalImage(f.prelink, f.final, f.dis,
                                  provider_objects={str(f.prelink.with_name("foreign.o").resolve()): f.prelink},
                                  link_map=f.link_map)
        with self.assertRaisesRegex(reader.Rejected, "ORIGIN:missing original"):
            image.function(ROOT)

    def test_duplicate_definition(self):
        f = self.f
        image = reader.FinalImage(f.prelink, f.final, f.dis,
                                  provider_objects={str(f.prelink.resolve()): f.prelink,
                                                    str(f.prelink.with_name("second.o").resolve()): f.prelink},
                                  link_map=f.link_map)
        with self.assertRaisesRegex(reader.Rejected, "ORIGIN:unique original definition"):
            image.function(ROOT)

    def test_root_provider_byte_binding(self):
        f = self.f
        provider = f.directory / "other.o"
        data = bytearray(f.prelink.read_bytes())
        data[60] ^= 1
        provider.write_bytes(data)
        image = reader.FinalImage(f.prelink, f.final, f.dis,
                                  provider_objects={str(f.prelink.resolve()): provider}, link_map=f.link_map)
        with self.assertRaisesRegex(reader.Rejected, "ORIGIN:root provider differs"):
            image.function(ROOT)

    def test_consistent_callee_retarget_uses_fixed_map(self):
        f = self.f
        edits = []
        destination = BASE + 258
        raw = branch_link(BASE + 4, destination)
        for path in (f.final, f.plain):
            _patch_symbol(path, PANIC, "value", destination | 1, edits)
            _patch_vma(path, BASE + 4, raw, edits)
        _patch_disassembly(f.dis, ".text", BASE + 4, raw, "bl", "%x <fiber_panic>" % destination)
        self.assertTrue(reader.compare_load_images(f.plain, f.final)["Identical"])
        with self.assertRaisesRegex(reader.Rejected, "ORIGIN:original section/offset/size.*fiber_panic"):
            f.image().function(ROOT)

    def test_consistent_NOBITS_alias_rejected(self):
        f = self.f
        edits = []
        for path in (f.final, f.plain):
            elf = _structured(path)
            _patch_symbol(path, SLOT, "value", BASE, edits)
            _patch_vma(path, BASE + 20, struct.pack("<I", BASE), edits)
            _edit(path, elf.header.e_shoff + 2 * elf.header.e_shentsize + 12,
                  struct.pack("<I", BASE), edits)
        _patch_disassembly(f.dis, ".text", BASE + 20, struct.pack("<I", BASE), ".word", "0x%x" % BASE)
        with self.assertRaisesRegex(reader.Rejected, "ELF:overlapping allocated sections"):
            reader.compare_load_images(f.plain, f.final)


class PaddingMutantTests(unittest.TestCase):
    def padding_fixture(self, raw, *, abi="hard", mnemonic="nop", owned=False, data=False):
        temp = tempfile.TemporaryDirectory(prefix="classic-final-padding-")
        self.addCleanup(temp.cleanup)
        f = Fixture(temp.name)
        if abi == "soft":
            f.final_options["flags"] = 0x05000200
        address = BASE + 26
        f.source_options["maps"].extend(((26, "t"), (28, "d")))
        f.final_options["maps"].extend(((26, "d" if data else "t"), (28, "d")))
        f.extra_dis.append("%08x: %04x %s" % (address, struct.unpack("<H", raw)[0], mnemonic))
        if owned:
            f.final_options["extra_symbols"] = [_alias("owned_padding", address | 1)]
        f.write()
        # Keep the selected padding outside all functions and give the
        # synthetic callee a nontrivial size for the real size-to-two mutant.
        for path in (f.prelink, f.final, f.plain):
            _patch_symbol(path, PANIC, "size", 4, [])
        for path in (f.final, f.plain):
            _patch_vma(path, address, raw, [])
        image = reader.FinalImage(f.prelink, f.final, f.dis,
                                  provider_objects={str(f.prelink.resolve()): f.prelink},
                                  link_map=f.link_map, float_abi=abi)
        proof = image.function(ROOT)
        # This small synthetic root carries both reference kinds needed by
        # the mutation helper; no additional production root is fabricated.
        proofs = {ROOT: proof, "SVC_Handler": dict(proof, References=[
            item for item in proof["References"] if item["Kind"] == 2])}
        files = dict(Final=f.final, Plain=f.plain, Disassembly=f.dis)
        return f, image, proofs, files

    def require_origin_rejection(self, raw, abi):
        f, image, proofs, files = self.padding_fixture(raw, abi=abi)
        edits = []
        _mutate_witness("callee-symbol-and-BL-padding-retarget", files, image, proofs, edits)
        self.assertTrue(edits)
        self.assertTrue(reader.compare_load_images(f.plain, f.final)["Identical"])
        mutated = reader.FinalImage(f.prelink, f.final, f.dis,
                                    provider_objects={str(f.prelink.resolve()): f.prelink},
                                    link_map=f.link_map, float_abi=abi)
        with self.assertRaisesRegex(reader.Rejected, "ORIGIN:original section/offset/size.*fiber_panic"):
            mutated.function(ROOT)

    def test_exact_bf00_padding_mutant(self):
        self.require_origin_rejection(bytes.fromhex("00bf"), "hard")

    def test_exact_46c0_padding_mutant(self):
        self.require_origin_rejection(bytes.fromhex("c046"), "soft")

    def require_no_padding(self, raw, **kwargs):
        _, image, proofs, files = self.padding_fixture(raw, **kwargs)
        edits = []
        with self.assertRaisesRegex(ValueError, "no real unowned Thumb NOP padding"):
            _mutate_witness("callee-symbol-and-BL-padding-retarget", files, image, proofs, edits)
        self.assertEqual(edits, [])

    def test_nearby_46c1_not_padding(self):
        self.require_no_padding(bytes.fromhex("c146"))

    def test_46c0_requires_nop_record(self):
        self.require_no_padding(bytes.fromhex("c046"), mnemonic="mov r8, r8")

    def test_46c0_function_owned_not_padding(self):
        self.require_no_padding(bytes.fromhex("c046"), owned=True)

    def test_46c0_data_mapped_not_padding(self):
        self.require_no_padding(bytes.fromhex("c046"), data=True)


class WideConditionalTests(unittest.TestCase):
    @staticmethod
    def encode(displacement, condition=1):
        if displacement % 2 or not -(1 << 20) <= displacement < (1 << 20):
            raise ValueError("test B T3 displacement")
        value = displacement & ((1 << 21) - 1)
        first = 0xF000 | (((value >> 20) & 1) << 10) | (condition << 6) | ((value >> 12) & 63)
        second = 0x8000 | (((value >> 18) & 1) << 13) | (((value >> 19) & 1) << 11) | ((value >> 1) & 2047)
        return struct.pack("<HH", first, second)

    def fixture(self, raw, *, target=BASE + 12, mnemonic="bne.w"):
        temp = tempfile.TemporaryDirectory(prefix="classic-final-bne-")
        self.addCleanup(temp.cleanup)
        f = Fixture(temp.name)
        # Replace two adjacent T16 instructions by one local T32 branch. This
        # is synthetic coverage of decoder logic, never a production protocol.
        f.source[8:12] = f.body[8:12] = raw
        f.omitted.add(10)
        first, second = struct.unpack("<HH", raw)
        f.dis_overrides[8] = "%08x: %04x %04x %s %x" % (BASE + 8, first, second, mnemonic, target)
        return f.write()

    def test_observed_cm7_example(self):
        form = reader._address_form(struct.pack("<HH", 0xF040, 0x8081), 6)
        self.assertEqual(form[:2], ("bne", 0x10C))

    def test_zero_displacement(self):
        self.assertEqual(reader._address_form(self.encode(0), BASE)[1], BASE + 4)

    def test_negative_displacement(self):
        self.assertEqual(reader._address_form(self.encode(-8), BASE)[1], BASE - 4)

    def test_positive_range_limit(self):
        self.assertEqual(reader._address_form(self.encode((1 << 20) - 2), BASE)[1], BASE + 4 + (1 << 20) - 2)

    def test_negative_range_limit(self):
        self.assertEqual(reader._address_form(self.encode(-(1 << 20)), BASE)[1], BASE + 4 - (1 << 20))

    def test_j1_direct_not_inverted(self):
        self.assertEqual(reader._address_form(struct.pack("<HH", 0xF040, 0xA000), BASE)[1], BASE + 4 + (1 << 18))

    def test_j2_direct_not_inverted(self):
        self.assertEqual(reader._address_form(struct.pack("<HH", 0xF040, 0x8800), BASE)[1], BASE + 4 + (1 << 19))

    def test_pc_not_word_aligned(self):
        self.assertEqual(reader._address_form(self.encode(0), BASE + 2)[1], BASE + 6)

    def test_complete_preserved_body(self):
        f = self.fixture(self.encode(0))
        self.assertTrue(reader.compare_load_images(f.plain, f.final)["Identical"])
        proof = f.image().function(ROOT)
        branch = next(item for item in proof["Instructions"] if item["Offset"] == 8)
        self.assertEqual((branch["Mnemonic"], branch["Target"]), ("bne", BASE + 12))
        self.assertEqual(proof["InstructionCount"], 7)

    def test_branch_into_instruction_interior(self):
        f = self.fixture(self.encode(-6), target=BASE + 6)
        with self.assertRaisesRegex(reader.Rejected, "instruction boundary"):
            f.image().function(ROOT)

    def test_branch_into_data(self):
        f = self.fixture(self.encode(6), target=BASE + 18)
        with self.assertRaisesRegex(reader.Rejected, "instruction boundary"):
            f.image().function(ROOT)

    def test_branch_outside_root(self):
        f = self.fixture(self.encode(244), target=BASE + 256)
        with self.assertRaisesRegex(reader.Rejected, "instruction boundary"):
            f.image().function(ROOT)

    def test_wrong_text_target(self):
        f = self.fixture(self.encode(0), target=BASE + 14)
        with self.assertRaisesRegex(reader.Rejected, "target disagrees"):
            f.image().function(ROOT)

    def test_wrong_text_condition(self):
        f = self.fixture(self.encode(0), mnemonic="beq.w")
        with self.assertRaisesRegex(reader.Rejected, "mnemonic disagrees"):
            f.image().function(ROOT)

    def test_other_wide_conditions_not_admitted(self):
        for condition in (0, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13):
            with self.subTest(condition=condition), self.assertRaisesRegex(reader.Rejected, "only T32 BNE.W"):
                reader._address_form(self.encode(0, condition), BASE)

    def test_reserved_condition_14_not_branch(self):
        f = self.fixture(self.encode(0, 14))
        with self.assertRaisesRegex(reader.Rejected, "unsupported/reserved conditional"):
            f.image().function(ROOT)

    def test_reserved_condition_15_not_branch(self):
        f = self.fixture(self.encode(0, 15))
        with self.assertRaisesRegex(reader.Rejected, "unsupported/reserved conditional"):
            f.image().function(ROOT)

    def test_malformed_first_halfword(self):
        f = self.fixture(struct.pack("<HH", 0xE840, 0x8000))
        with self.assertRaisesRegex(reader.Rejected, "unsupported/reserved conditional"):
            f.image().function(ROOT)

    def test_unconditional_bw_still_rejected(self):
        with self.assertRaisesRegex(reader.Rejected, "B.W unsupported"):
            reader._address_form(struct.pack("<HH", 0xF040, 0x9000), BASE)

    def test_blx_still_rejected(self):
        with self.assertRaisesRegex(reader.Rejected, "BLX immediate unsupported"):
            reader._address_form(struct.pack("<HH", 0xF040, 0xC000), BASE)

    def test_truncated_wide_branch(self):
        with self.assertRaisesRegex(reader.Rejected, "width"):
            reader._address_form(struct.pack("<H", 0xF040), BASE)

    def test_related_system_encodings_unchanged(self):
        for raw in ("eff30583", "eff3108c", "83f31188", "bff34f8f", "bff36f8f"):
            with self.subTest(raw=raw):
                self.assertIsNone(reader._address_form(bytes.fromhex(raw), BASE))


class FloatABITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="classic-final-float-")
        self.addCleanup(self.temp.cleanup)
        self.f = Fixture(self.temp.name)

    def image(self, abi):
        f = self.f.write()
        return reader.FinalImage(f.prelink, f.final, f.dis,
                                 provider_objects={str(f.prelink.resolve()): f.prelink},
                                 link_map=f.link_map, float_abi=abi)

    def test_default_remains_hard(self):
        image = self.f.write().image()
        self.assertEqual(image.float_abi, "hard")
        self.assertTrue(image.function(ROOT)["PrelinkBoundRootPreservation"])

    def test_soft_does_not_admit_arbitrary_mnemonic(self):
        self.f.final_options["flags"] = 0x05000200
        self.f.dis_overrides[0] = "%08x: 2000 it eq" % BASE
        with self.assertRaisesRegex(reader.Rejected, "DECODE:unsupported instruction"):
            self.image("soft").function(ROOT)

    def test_soft_bx_still_requires_lr(self):
        self.f.final_options["flags"] = 0x05000200
        self.f.source[14:16] = self.f.body[14:16] = bytes.fromhex("1047")
        self.f.dis_overrides[14] = "%08x: 4710 bx r2" % (BASE + 14)
        with self.assertRaisesRegex(reader.Rejected, "BX.*LR|BX.*lr"):
            self.image("soft").function(ROOT)

    def test_soft_does_not_admit_wide_unconditional_branch(self):
        with self.assertRaisesRegex(reader.Rejected, "unsupported"):
            reader._address_form(bytes.fromhex("00f000b8"), BASE)


def _float_flags_case(name, abi, before, after, accepted=False):
    def control(self):
        self.f.source_options["flags"] = 0x05000000 | before
        self.f.final_options["flags"] = 0x05000000 | after
        if accepted:
            image = self.image(abi)
            self.assertEqual(image.float_abi, abi)
            self.assertTrue(image.function(ROOT)["PrelinkBoundRootPreservation"])
            self.assertTrue(reader.compare_load_images(self.f.plain, self.f.final)["Identical"])
        else:
            with self.assertRaisesRegex(reader.Rejected, "ELF:prelink/final ABI flags differ"):
                self.image(abi)
    control.__name__ = "test_" + abi + "_" + name
    setattr(FloatABITests, control.__name__, control)


for _abi, _bit, _foreign in (("soft", 0x200, 0x400), ("hard", 0x400, 0x200)):
    _float_flags_case("prelink_unset", _abi, 0, _bit, True)
    _float_flags_case("prelink_declared", _abi, _bit, _bit, True)
    _float_flags_case("prelink_foreign", _abi, _foreign, _bit)
    _float_flags_case("prelink_both", _abi, 0x600, _bit)
    _float_flags_case("final_neither", _abi, 0, 0)
    _float_flags_case("final_foreign", _abi, 0, _foreign)
    _float_flags_case("final_both", _abi, 0, 0x600)
    _float_flags_case("final_clears_declared", _abi, _bit, 0)
    _float_flags_case("final_adds_other_flag", _abi, 0, _bit | 1)
    _float_flags_case("final_drops_other_flag", _abi, 1, _bit)


class _ABIEnum(Enum):
    HARD = "hard"


class _ABIStringEnum(str, Enum):
    SOFT = "soft"


def _invalid_float_abi(name, value):
    def control(self):
        # Invalid declarations must fail before any input path is read.
        with self.assertRaisesRegex(reader.Rejected, "SCOPE:float_abi"):
            reader.FinalImage(None, None, None, float_abi=value)
    control.__name__ = "test_invalid_abi_" + name
    setattr(FloatABITests, control.__name__, control)


for _name, _value in (("true", True), ("false", False), ("none", None),
                      ("integer", 0), ("float", 0.0), ("bytes", b"soft"),
                      ("list", ["hard"]), ("mapping", {"abi": "soft"}),
                      ("enum", _ABIEnum.HARD), ("string_enum", _ABIStringEnum.SOFT),
                      ("softfp", "softfp"), ("empty", ""), ("case", "Soft")):
    _invalid_float_abi(_name, _value)


def _soft_form_case(name, raw, op, operands, variation):
    def control(self):
        abi = "hard" if variation == "hard" else "soft"
        self.f.final_options["flags"] = 0x05000400 if abi == "hard" else 0x05000200
        body = bytes.fromhex(raw)
        if variation == "wrong_bits":
            body = bytes((body[0] ^ 1, body[1]))
        if variation == "wrong_operands":
            operands_used = operands.replace("r0", "r1") if "r0" in operands else "r2, r3"
        else:
            operands_used = operands
        self.f.source[0:2] = self.f.body[0:2] = body
        self.f.dis_overrides[0] = "%08x: %04x %s %s" % (
            BASE, struct.unpack("<H", body)[0], op, operands_used)
        if variation == "soft":
            proof = self.image(abi).function(ROOT)
            self.assertEqual(proof["Instructions"][0]["Mnemonic"], op)
            self.assertEqual(proof["Instructions"][0]["Bytes"], raw)
            self.assertEqual(proof["InstructionCount"], 8)
        else:
            with self.assertRaisesRegex(reader.Rejected, "DECODE:unsupported instruction"):
                self.image(abi).function(ROOT)
    control.__name__ = "test_cm0_" + name + "_" + variation
    setattr(FloatABITests, control.__name__, control)


for _name, _raw, _op, _operands in (
        ("adds", "1430", "adds", "r0, #20"),
        ("mvns", "d243", "mvns", "r2, r2"),
        ("stmia_low", "f8c0", "stmia", "r0!, {r3, r4, r5, r6, r7}"),
        ("stmia_high", "f0c0", "stmia", "r0!, {r4, r5, r6, r7}")):
    for _variation in ("soft", "hard", "wrong_bits", "wrong_operands"):
        _soft_form_case(_name, _raw, _op, _operands, _variation)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--prelink-object", type=Path)
    parser.add_argument("--final-elf", type=Path)
    parser.add_argument("--disassembly", type=Path)
    parser.add_argument("--plain-elf", type=Path)
    parser.add_argument("--provider-object", type=Path, action="append", default=[])
    parser.add_argument("--link-map", type=Path)
    parser.add_argument("--float-abi", choices=("soft", "hard"), default="hard")
    args = parser.parse_args()
    witness = (args.prelink_object, args.final_elf, args.disassembly, args.plain_elf)
    if any(witness) and (not all(witness) or not args.provider_object or not args.link_map or not args.output_dir):
        parser.error("witness controls need all four witness paths, --provider-object, --link-map and fresh --output-dir")
    if not any(witness) and (args.provider_object or args.link_map):
        parser.error("provider/map options require the four witness paths")
    if args.output_dir:
        args.output_dir = args.output_dir.resolve()
        if args.output_dir.is_relative_to(HERE.parents[2]):
            parser.error("generated receipts must be outside the repository")
        args.output_dir.mkdir(parents=True, exist_ok=False)
    paths = [HERE / "elf.py", Path(__file__).resolve()]
    initial = {str(path): hashlib.sha256(path.read_bytes()).hexdigest().upper() for path in paths}
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__]))
    report = dict(Status="PASS" if result.wasSuccessful() else "FAIL", PureControls=result.testsRun,
                  Failures=len(result.failures), Errors=len(result.errors), SourceHashes=initial,
                  RequiredCellSatisfied=False, FinalParity=False, CPUProof=False, GlobalProof=False)
    if any(witness):
        try:
            report["Witness"] = _actual_witness(witness, args.provider_object, args.link_map, args.output_dir,
                                                float_abi=args.float_abi)
            if report["Witness"]["Status"] != "PASS":
                report["Status"] = "FAIL"
        except Exception as error:
            report.update(Status="FAIL", WitnessError=type(error).__name__ + ": " + str(error))
    report["SourceDrift"] = [str(path) for path in paths
                             if hashlib.sha256(path.read_bytes()).hexdigest().upper() != initial[str(path)]]
    if report["SourceDrift"]:
        report["Status"] = "FAIL"
    if args.output_dir:
        output = args.output_dir / "results.json"
        output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8", newline="\n")
        print("Receipt:", output, hashlib.sha256(output.read_bytes()).hexdigest().upper())
    print(json.dumps({key: value for key, value in report.items() if key != "Witness"}, sort_keys=True))
    return 0 if report["Status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
