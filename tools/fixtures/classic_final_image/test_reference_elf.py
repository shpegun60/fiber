"""Synthetic pinned-reference reader controls; no compiler, subprocess or CPU.

All ELF inputs are generated in temporary directories. Positive fixtures use
independent explicit instruction rows, not the reader's protocol tables.
"""

import argparse
import ast
from enum import Enum
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest


sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("fixed_reference_reader", HERE / "reference_elf.py")
reader = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(reader)
FIRST, SVC, PENDSV = "prvPortStartFirstTask", "vPortSVCHandler", "xPortPendSVHandler"
SLOT, CALLEE = "pxCurrentTCB", "vTaskSwitchContext"
BASE, RAM = 0x08000100, 0x20000000
ADDRESSES = {FIRST: BASE, SVC: BASE + 64, PENDSV: BASE + 128}
SIZES = {FIRST: 40, SVC: 32, PENDSV: 92}

# Independent fixture descriptions in objdump halfword order. They spell out
# the pinned inline assembly, including the two exact one-instruction IT EQs.
_ROWS = {
    FIRST: """
0 4808 ldr r0, [pc, #32]
2 6800 ldr r0, [r0, #0]
4 6800 ldr r0, [r0, #0]
6 f3808808 msr MSP, r0
10 f04f0000 mov.w r0, #0
14 f3808814 msr CONTROL, r0
18 b662 cpsie i
20 b661 cpsie f
22 f3bf8f4f dsb sy
26 f3bf8f6f isb sy
30 df00 svc 0
32 bf00 nop
""",
    SVC: """
0 4b06 ldr r3, [pc, #24]
2 6819 ldr r1, [r3, #0]
4 6808 ldr r0, [r1, #0]
6 e8b04ff0 ldmia.w r0!, {r4, r5, r6, r7, r8, r9, sl, fp, lr}
10 f3808809 msr PSP, r0
14 f3bf8f6f isb sy
18 f04f0000 mov.w r0, #0
22 f3808811 msr BASEPRI, r0
26 4770 bx lr
""",
    PENDSV: """
0 f3ef8009 mrs r0, PSP
4 f3bf8f6f isb sy
8 4b13 ldr r3, [pc, #76]
10 681a ldr r2, [r3, #0]
12 f01e0f10 tst.w lr, #16
16 bf08 it eq
18 ed208a10 vstmdbeq r0!, {s16-s31}
22 e9204ff0 stmdb r0!, {r4, r5, r6, r7, r8, r9, sl, fp, lr}
26 6010 str r0, [r2, #0]
28 b409 push {r0, r3}
30 f04f0010 mov.w r0, #16
34 f3808811 msr BASEPRI, r0
38 f3bf8f4f dsb sy
42 f3bf8f6f isb sy
46 f7fffffe bl vTaskSwitchContext
50 f04f0000 mov.w r0, #0
54 f3808811 msr BASEPRI, r0
58 bc09 pop {r0, r3}
60 6819 ldr r1, [r3, #0]
62 6808 ldr r0, [r1, #0]
64 e8b04ff0 ldmia.w r0!, {r4, r5, r6, r7, r8, r9, sl, fp, lr}
68 f01e0f10 tst.w lr, #16
72 bf08 it eq
74 ecb08a10 vldmiaeq r0!, {s16-s31}
78 f3808809 msr PSP, r0
82 f3bf8f6f isb sy
86 4770 bx lr
""",
}

# Independently written CM7 r0p1 assembly: BASEPRI entry is enclosed by
# CPSID/CPSIE, moving the call and the pool rather than hiding instructions.
_CM7_ROWS = """
0 f3ef8009 mrs r0, PSP
4 f3bf8f6f isb sy
8 4b14 ldr r3, [pc, #80]
10 681a ldr r2, [r3, #0]
12 f01e0f10 tst.w lr, #16
16 bf08 it eq
18 ed208a10 vstmdbeq r0!, {s16-s31}
22 e9204ff0 stmdb r0!, {r4, r5, r6, r7, r8, r9, sl, fp, lr}
26 6010 str r0, [r2, #0]
28 b409 push {r0, r3}
30 f04f0010 mov.w r0, #16
34 b672 cpsid i
36 f3808811 msr BASEPRI, r0
40 f3bf8f4f dsb sy
44 f3bf8f6f isb sy
48 b662 cpsie i
50 f7fffffe bl vTaskSwitchContext
54 f04f0000 mov.w r0, #0
58 f3808811 msr BASEPRI, r0
62 bc09 pop {r0, r3}
64 6819 ldr r1, [r3, #0]
66 6808 ldr r0, [r1, #0]
68 e8b04ff0 ldmia.w r0!, {r4, r5, r6, r7, r8, r9, sl, fp, lr}
72 f01e0f10 tst.w lr, #16
76 bf08 it eq
78 ecb08a10 vldmiaeq r0!, {s16-s31}
82 f3808809 msr PSP, r0
86 f3bf8f6f isb sy
90 4770 bx lr
"""
_BASE_SIZES = {"CM4": {FIRST: 40, SVC: 32, PENDSV: 92},
               "CM7": {FIRST: 40, SVC: 32, PENDSV: 96}}


def rows(name, profile="CM4", mode="O2"):
    result = []
    text = _CM7_ROWS if profile == "CM7" and name == PENDSV else _ROWS[name]
    for line in text.strip().splitlines():
        offset, words, op, *operand = line.split(maxsplit=3)
        raw = b"".join(struct.pack("<H", int(words[i:i + 4], 16)) for i in range(0, len(words), 4))
        result.append((int(offset), raw, op, operand[0] if operand else ""))
    if mode == "O0":
        result.append((_BASE_SIZES[profile][name], bytes.fromhex("00bf"), "nop", ""))
    return result


def bl(place, target):
    delta = target - place - 4
    if delta % 2 or not -(1 << 24) <= delta < 1 << 24:
        raise ValueError("synthetic BL range")
    value = delta & ((1 << 25) - 1)
    s, i1, i2 = value >> 24, (value >> 23) & 1, (value >> 22) & 1
    return struct.pack("<HH", 0xF000 | (s << 10) | ((value >> 12) & 1023),
                       0xD000 | ((1 ^ i1 ^ s) << 13) | ((1 ^ i2 ^ s) << 11) | ((value >> 1) & 2047))


def symbol(name, section, value=0, size=0, binding=0, kind=0):
    return dict(name=name, section=section, value=value, size=size, binding=binding, kind=kind)


def section(name, data=b"", *, address=0, flags=6, kind=1, size=None):
    return dict(name=name, data=bytes(data), address=address, flags=flags, kind=kind,
                size=len(data) if size is None else size)


def elf_bytes(final, input_sections, input_symbols, relocations, flags):
    sections = [dict(name="", data=b"", address=0, flags=0, kind=0, size=0)]
    sections.extend(dict(item) for item in input_sections)
    indexes = {item["name"]: i for i, item in enumerate(sections)}
    symbols = [symbol("", "")]
    symbols += sorted((dict(item) for item in input_symbols), key=lambda item: item["binding"] != 0)
    numbers = {item["name"]: i for i, item in enumerate(symbols)}
    strings, entries = bytearray(b"\0"), bytearray()
    for item in symbols:
        offset = len(strings) if item["name"] else 0
        if item["name"]:
            strings.extend(item["name"].encode("ascii") + b"\0")
        entries.extend(struct.pack("<IIIBBH", offset, item["value"], item["size"],
                                   (item["binding"] << 4) | item["kind"], 0, indexes[item["section"]]))
    sym_index = len(sections)
    sections += [dict(section(".symtab", entries, flags=0, kind=2), link=sym_index + 1,
                      info=sum(item["binding"] == 0 for item in symbols), entsize=16),
                 section(".strtab", strings, flags=0, kind=3)]
    for target, values in relocations.items():
        if values:
            data = b"".join(struct.pack("<II", off, (numbers[name] << 8) | kind) for off, kind, name in values)
            sections.append(dict(section(".rel" + target, data, flags=0, kind=9),
                                 link=sym_index, info=indexes[target], entsize=8))
    names = bytearray(b"\0")
    for item in sections[1:]:
        item["name_offset"] = len(names)
        names.extend(item["name"].encode("ascii") + b"\0")
    shstr = len(names)
    names.extend(b".shstrtab\0")
    sections.append(dict(section(".shstrtab", names, flags=0, kind=3), name_offset=shstr))
    output = bytearray(0x1000 if final else 52)
    if final:
        file_end = max(item["address"] - 0x08000000 + item["size"] for item in sections
                       if item["flags"] & 2 and item["kind"] != 8)
        output.extend(bytes(file_end))
    for item in sections:
        if final and item["flags"] & 2:
            item["offset"] = 0x1000 + (item["address"] - 0x08000000) if item["kind"] != 8 else 0x1000 + ((file_end + 3) & ~3)
            if item["kind"] != 8:
                at = item["offset"]
                output[at:at + len(item["data"])] = item["data"]
        else:
            output.extend(bytes((-len(output)) % 4))
            item["offset"] = len(output) if item["kind"] else 0
            output.extend(item["data"])
    output.extend(bytes((-len(output)) % 4))
    shoff = len(output)
    for item in sections:
        output.extend(struct.pack("<10I", item.get("name_offset", 0), item["kind"], item["flags"],
                                  item["address"], item["offset"], item["size"], item.get("link", 0),
                                  item.get("info", 0), 4 if item["kind"] else 0, item.get("entsize", 0)))
    output[:52] = struct.pack("<16sHHIIIIIHHHHHH", b"\x7fELF\x01\x01\x01" + bytes(9),
                              2 if final else 1, 40, 1, BASE | 1 if final else 0,
                              52 if final else 0, shoff, flags, 52, 32 if final else 0,
                              2 if final else 0, 40, len(sections), len(sections) - 1)
    if final:
        output[52:84] = struct.pack("<8I", 1, 0x1000, 0x08000000, 0x08000000, file_end, file_end, 5, 4)
        output[84:116] = struct.pack("<8I", 1, 0x1000 + ((file_end + 3) & ~3), RAM, RAM, 0, 4, 6, 4)
    return bytes(output)


class Fixture:
    def __init__(self, directory, *, profile="CM4", mode="O2"):
        self.directory = Path(directory)
        self.profile, self.mode = profile, mode
        self.base_sizes = dict(_BASE_SIZES[profile])
        self.sizes = {name: size + (2 if mode == "O0" else 0) for name, size in self.base_sizes.items()}
        self.final_sizes = dict(self.sizes)
        self.call_offset, self.slot_offset = (46, 88) if profile == "CM4" else (50, 92)
        self.before = {}
        for name in ADDRESSES:
            body = bytearray(self.sizes[name])
            for offset, raw, _, _ in rows(name, profile, mode):
                body[offset:offset + len(raw)] = raw
            self.before[name] = body
        self.before[FIRST][36:40] = struct.pack("<I", 0xE000ED08)
        self.after = {name: bytearray(body) for name, body in self.before.items()}
        self.after[SVC][28:32] = struct.pack("<I", RAM)
        self.after[PENDSV][self.slot_offset:self.slot_offset + 4] = struct.pack("<I", RAM)
        self.after[PENDSV][self.call_offset:self.call_offset + 4] = bl(ADDRESSES[PENDSV] + self.call_offset, BASE + 256)
        self.bindings = {FIRST: 0, SVC: 1, PENDSV: 1}
        self.final_bindings = dict(self.bindings)
        self.maps = {FIRST: 34, SVC: 28, PENDSV: self.slot_offset}
        self.final_maps = dict(self.maps)
        self.first_pool_boundary = self.final_first_pool_boundary = 36
        self.tail_maps = {name: size if mode == "O0" else None for name, size in self.base_sizes.items()}
        self.final_tail_maps = dict(self.tail_maps)
        self.relocs = {FIRST: [], SVC: [(28, 2, SLOT)],
                       PENDSV: [(self.call_offset, 10, CALLEE), (self.slot_offset, 2, SLOT)]}
        self.final_relocs = {name: list(values) for name, values in self.relocs.items()}
        self.text = {}
        self.omitted = set()
        self.extra_dis = []
        self.source_flags, self.final_flags, self.provider_flags = 0x05000000, 0x05000400, 0x05000000
        self.callee_address, self.slot_address = BASE + 256, RAM
        self.callee_binding, self.slot_binding = 1, 1
        self.slot_size = 4

    def write(self):
        self.prelink, self.provider = self.directory / "port.o", self.directory / "link-only.o"
        self.final, self.plain = self.directory / "emit.elf", self.directory / "plain.elf"
        self.dis, self.link_map = self.directory / "emit.dis", self.directory / "emit.map"
        sections, symbols = [], []
        for name, body in self.before.items():
            sec = ".text." + name
            sections.append(section(sec, body))
            symbols.extend((symbol("$t." + name, sec), symbol("$d." + name, sec, self.maps[name]),
                            symbol(name, sec, 1, self.sizes[name], self.bindings[name], 2)))
            if name == FIRST and self.first_pool_boundary is not None:
                symbols.append(symbol("$d.first_pool", sec, self.first_pool_boundary))
            if self.tail_maps[name] is not None:
                symbols.append(symbol("$t.tail." + name, sec, self.tail_maps[name]))
        symbols.extend((symbol(CALLEE, "", binding=1), symbol(SLOT, "", binding=1),
                        symbol("xTaskIncrementTick", "", binding=1)))
        self.prelink.write_bytes(elf_bytes(False, sections, symbols,
                                           {".text." + name: values for name, values in self.relocs.items()}, self.source_flags))
        provider_sections = [section(".text." + CALLEE, bytes.fromhex("704700bf")),
                             section(".bss." + SLOT, flags=3, kind=8, size=4)]
        provider_symbols = [symbol("$t.callee", ".text." + CALLEE),
                            symbol(CALLEE, ".text." + CALLEE, 1, 4, 1, 2),
                            symbol(SLOT, ".bss." + SLOT, 0, 4, 1, 1)]
        self.provider.write_bytes(elf_bytes(False, provider_sections, provider_symbols, {}, self.provider_flags))
        body = bytearray(264)
        symbols, relocs = [], []
        for name, raw in self.after.items():
            address = ADDRESSES[name]
            body[address - BASE:address - BASE + len(raw)] = raw
            symbols.extend((symbol("$t." + name, ".text", address),
                            symbol("$d." + name, ".text", address + self.final_maps[name]),
                            symbol(name, ".text", address | 1, self.final_sizes[name], self.final_bindings[name], 2)))
            if name == FIRST and self.final_first_pool_boundary is not None:
                symbols.append(symbol("$d.first_pool", ".text", address + self.final_first_pool_boundary))
            if self.final_tail_maps[name] is not None:
                symbols.append(symbol("$t.tail." + name, ".text", address + self.final_tail_maps[name]))
            relocs.extend((address + off, kind, target) for off, kind, target in self.final_relocs[name])
        body[256:260] = bytes.fromhex("704700bf")
        symbols.extend((symbol("$t.callee", ".text", BASE + 256),
                        symbol(CALLEE, ".text", self.callee_address | 1, 4, self.callee_binding, 2),
                        symbol(SLOT, ".bss", self.slot_address, self.slot_size, self.slot_binding, 1),
                        symbol("xTaskIncrementTick", ".text", (BASE + 258) | 1, 2, 1, 0)))
        sections = [section(".text", body, address=BASE), section(".bss", address=RAM, flags=3, kind=8, size=4),
                    section(".isr_vector", struct.pack("<II", RAM + 4096, BASE | 1), address=0x08000000, flags=2)]
        self.final.write_bytes(elf_bytes(True, sections, symbols, {".text": relocs}, self.final_flags))
        self.plain.write_bytes(elf_bytes(True, sections, symbols, {}, self.final_flags))
        lines = ["Disassembly of section .text:"]
        for name in ADDRESSES:
            for offset, raw, op, operand in rows(name, self.profile, self.mode):
                if (name, offset) in self.omitted:
                    continue
                op, operand = self.text.get((name, offset), (op, operand))
                raw = self.after[name][offset:offset + len(raw)]
                words = " ".join("%04x" % value for value in struct.unpack("<" + "H" * (len(raw) // 2), raw))
                if op == "bl" and operand == CALLEE:
                    operand = "%x <%s>" % (self.callee_address, CALLEE)
                lines.append("%x: %s %s %s" % (ADDRESSES[name] + offset, words, op, operand))
            begin = {FIRST: 34, SVC: 28, PENDSV: self.slot_offset}[name]
            for offset in range(begin, self.base_sizes[name], 2):
                raw = self.after[name][offset:offset + 2]
                lines.append("%x: %04x .short 0" % (ADDRESSES[name] + offset, struct.unpack("<H", raw)[0]))
        self.dis.write_text("\n".join(lines + self.extra_dis) + "\n", encoding="utf-8", newline="\n")
        placements = ["Linker script and memory map"]
        placements.extend(" .text.%s 0x%x 0x%x %s" % (name, ADDRESSES[name], len(self.before[name]), self.prelink.resolve().as_posix())
                          for name in ADDRESSES)
        placements.extend((" .text.%s 0x%x 0x4 %s" % (CALLEE, BASE + 256, self.provider.resolve().as_posix()),
                           " .bss.%s 0x%x 0x4 %s" % (SLOT, RAM, self.provider.resolve().as_posix())))
        self.link_map.write_text("\n".join(placements) + "\n", encoding="utf-8", newline="\n")
        return self

    def image(self, *, reader_class=None, **kwargs):
        options = dict(provider_objects={str(self.prelink.resolve()): self.prelink,
                                         str(self.provider.resolve()): self.provider}, link_map=self.link_map, mode=self.mode)
        options.update(kwargs)
        reader_class = reader_class or {"CM4": reader.ReferenceCM4FinalImage, "CM7": reader.ReferenceCM7FinalImage}[self.profile]
        return reader_class(self.prelink, self.final, self.dis, **options)


class ReferenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="reference-final-reader-")
        self.addCleanup(self.temp.cleanup)
        self.f = Fixture(self.temp.name)

    def test_complete_three_roots(self):
        f = self.f.write()
        image = f.image()
        proofs = [image.function(name) for name in ADDRESSES]
        self.assertEqual([item["InstructionCount"] for item in proofs], [12, 9, 27])
        self.assertEqual(sum(item["Size"] for item in proofs), 164)
        self.assertEqual(sum(len(item["References"]) for item in proofs), 3)
        self.assertEqual([item["Binding"] for proof in proofs for item in proof["References"]], ["STB_GLOBAL"] * 3)
        self.assertTrue(reader.compare_load_images(f.plain, f.final)["Identical"])
        for proof in proofs:
            self.assertTrue(proof["Complete"] and proof["PrelinkBoundRootPreservation"])
            self.assertEqual(image.read(proof["Address"], proof["Size"]), bytes(f.after[proof["Name"]]))
            for key in ("RequiredCellSatisfied", "FinalParity", "KernelRuntimeProof", "CPUProof", "GlobalProof",
                        "SourcePinBindingVerified", "CohortBindingVerified"):
                self.assertIs(proof[key], False)

    def test_exact_it_eq_pairs(self):
        proof = self.f.write().image().function(PENDSV)
        instructions = {item["Offset"]: item for item in proof["Instructions"]}
        for off, raw, op in ((16, "08bf", "it"), (18, "20ed108a", "vstmdbeq"),
                             (72, "08bf", "it"), (74, "b0ec108a", "vldmiaeq")):
            self.assertEqual((instructions[off]["Bytes"], instructions[off]["Mnemonic"]), (raw, op))

    def test_exact_data_mapping_boundaries_preserved(self):
        image = self.f.write().image()
        first = image.function(FIRST)
        self.assertEqual(first["DataMappings"], [dict(Offset=34, Size=2, Bytes="0000"),
                                                 dict(Offset=36, Size=4, Bytes="08ed00e0")])
        self.assertEqual(first["LiteralIslands"], [dict(Offset=34, Bytes="000008ed00e0",
            References=[dict(Instruction=0, Offset=2)])])
        for name, offset in ((SVC, 28), (PENDSV, 88)):
            self.assertEqual(image.function(name)["DataMappings"], [dict(Offset=offset, Size=4, Bytes="00000020")])

    def test_export_identity(self):
        self.assertIs(reader.core, reader.native)
        self.assertIs(reader.Rejected, reader.core.Rejected)
        self.assertIs(reader.compare_load_images, reader.core.compare_load_images)
        self.assertEqual(reader.ROOTS, frozenset(ADDRESSES))

    def test_hard_declared_in_prelinks(self):
        self.f.source_flags = self.f.provider_flags = 0x05000400
        self.assertTrue(self.f.write().image().function(FIRST)["Complete"])

    def test_metadata_only_twins(self):
        f = self.f.write()
        f.plain.write_bytes(f.plain.read_bytes() + b"unloaded metadata")
        self.assertTrue(reader.compare_load_images(f.plain, f.final)["Identical"])

    def test_no_bss_reads(self):
        with self.assertRaisesRegex(reader.Rejected, "file-backed"):
            self.f.write().image().read(RAM, 4)

    def test_missing_map(self):
        with self.assertRaisesRegex(reader.Rejected, "ORIGIN:explicit"):
            self.f.write().image(link_map=None).function(FIRST)

    def test_root_provider_bytes_bound(self):
        f = self.f.write()
        wrong = f.directory / "wrong.o"
        wrong.write_bytes(f.prelink.read_bytes() + b"different captured root provider")
        with self.assertRaisesRegex(reader.Rejected, "ORIGIN:root provider differs"):
            f.image(provider_objects={str(f.prelink.resolve()): wrong,
                                      str(f.provider.resolve()): f.provider}).function(FIRST)

    def test_callee_map_not_mutable_symbol_authority(self):
        self.f.callee_address += 2
        self.f.after[PENDSV][46:50] = bl(ADDRESSES[PENDSV] + 46, self.f.callee_address)
        with self.assertRaisesRegex(reader.Rejected, "ORIGIN:original section/offset/size"):
            self.f.write().image().function(PENDSV)

    def test_no_unsafe_execution_calls(self):
        tree = ast.parse((HERE / "reference_elf.py").read_text())
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                modules = [item.name for item in node.names] if isinstance(node, ast.Import) else [node.module]
                self.assertFalse(set(modules) & {"subprocess", "os", "ctypes"})
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                self.assertNotIn(node.func.id, ("exec", "eval", "compile"))


def negative(name, mutate, root, expected):
    def control(self):
        mutate(self.f)
        f = self.f.write()
        self.assertTrue(reader.compare_load_images(f.plain, f.final)["Identical"])
        with self.assertRaisesRegex(reader.Rejected, expected):
            f.image().function(root)
    control.__name__ = "test_reject_" + name
    setattr(ReferenceTests, control.__name__, control)


def both(f, name, offset, raw):
    for body in (f.before[name], f.after[name]):
        body[offset:offset + len(raw)] = raw


for _root in ADDRESSES:
    for _stage, _attr in (("prelink", "bindings"), ("final", "final_bindings")):
        for _binding in ((1, 2) if _root == FIRST else (0, 2)):
            negative("%s_%s_binding_%d" % (_root, _stage, _binding),
                     lambda f, r=_root, a=_attr, b=_binding: getattr(f, a).__setitem__(r, b), _root, "SYMBOL:")

for _root in ("fiber_port_start_first_context", "SVC_Handler", "PendSV_Handler", CALLEE, SLOT, "vPortEnableVFP"):
    negative("foreign_" + _root, lambda f: None, _root, "SCOPE:")

negative("ordinary_final_byte", lambda f: f.after[FIRST].__setitem__(slice(18, 20), bytes.fromhex("72b6")), FIRST, "PRESERVATION:non-relocation")
negative("BL_destination", lambda f: f.after[PENDSV].__setitem__(slice(46, 50), bl(ADDRESSES[PENDSV] + 46, BASE + 258)), PENDSV, "RELOC:applied BL destination")
negative("BL_addend", lambda f: f.before[PENDSV].__setitem__(slice(46, 50), bl(46, 48)), PENDSV, "RELOC:only original BL addend")
negative("BL_kind", lambda f: f.final_relocs[PENDSV].__setitem__(0, (46, 30, CALLEE)), PENDSV, "RELOC:relocation kind/identity")
negative("BL_target", lambda f: f.final_relocs[PENDSV].__setitem__(0, (46, 10, "xTaskIncrementTick")), PENDSV, "RELOC:relocation kind/identity")
negative("slot_applied", lambda f: f.after[SVC].__setitem__(slice(28, 32), struct.pack("<I", RAM + 4)), SVC, "RELOC:applied ABS32")
negative("slot_addend", lambda f: f.before[SVC].__setitem__(slice(28, 32), struct.pack("<I", 4)), SVC, "RELOC:only current-slot ABS32")
negative("slot_kind", lambda f: f.final_relocs[SVC].__setitem__(0, (28, 10, SLOT)), SVC, "RELOC:relocation kind/identity")
negative("slot_target", lambda f: f.final_relocs[SVC].__setitem__(0, (28, 2, CALLEE)), SVC, "RELOC:relocation kind/identity")
negative("missing_rel", lambda f: f.final_relocs[PENDSV].pop(), PENDSV, "RELOC:relocation membership")
negative("foreign_rel", lambda f: f.relocs[FIRST].append((36, 2, SLOT)), FIRST, "RELOC:relocation membership")
negative("size", lambda f: f.final_sizes.__setitem__(FIRST, 38), FIRST, "PRESERVATION:root extent")
negative("mapping", lambda f: f.final_maps.__setitem__(SVC, 26), SVC, "PRESERVATION:mapping/layout")
for _stage, _attributes in (("prelink", ("first_pool_boundary",)),
                            ("final", ("final_first_pool_boundary",)),
                            ("both", ("first_pool_boundary", "final_first_pool_boundary"))):
    for _name, _boundary in (("missing", None), ("shifted", 38)):
        negative("first_pool_%s_%s" % (_stage, _name),
                 lambda f, attrs=_attributes, boundary=_boundary: [setattr(f, attr, boundary) for attr in attrs],
                 FIRST, "PRESERVATION:mapping/layout")
negative("missing_instruction", lambda f: f.omitted.add((PENDSV, 16)), PENDSV, "DECODE:missing/mismatched")
negative("VTOR", lambda f: both(f, FIRST, 36, struct.pack("<I", 0xE000ED0C)), FIRST, "PROTOCOL:original literal")
negative("literal_padding", lambda f: both(f, FIRST, 34, b"\x01\x00"), FIRST, "PROTOCOL:original literal")
negative("nop_alias_not_CM4", lambda f: both(f, FIRST, 32, bytes.fromhex("c046")), FIRST, "PROTOCOL:original instruction")
for _name, _offset, _raw in (("save_IT_ne", 16, "18bf"), ("restore_IT_ne", 72, "18bf"),
                             ("save_IT_mask", 16, "0cbf"), ("restore_IT_mask", 72, "0cbf"),
                             ("save_IT_missing", 16, "00bf"), ("restore_IT_missing", 72, "00bf"),
                             ("save_base", 18, "21ed108a"), ("restore_base", 74, "b1ec108a"),
                             ("save_registers", 18, "20ed100a"), ("restore_registers", 74, "b0ec100a"),
                             ("save_bit4", 12, "1ef0200f"), ("restore_bit4", 68, "1ef0200f")):
    negative(_name, lambda f, o=_offset, raw=_raw: both(f, PENDSV, o, bytes.fromhex(raw)), PENDSV, "PROTOCOL:original instruction")
for _name, _offset, _op, _operand in (("unpredicated_save", 18, "vstmdb", "r0!, {s16-s31}"),
                                     ("unpredicated_restore", 74, "vldmia", "r0!, {s16-s31}"),
                                     ("ne_save", 18, "vstmdbne", "r0!, {s16-s31}"),
                                     ("ne_restore", 74, "vldmiane", "r0!, {s16-s31}"),
                                     ("IT_text", 16, "it", "ne"),
                                     ("FP_list", 18, "vstmdbeq", "r0!, {s16-s30}"),
                                     ("PSP_text", 78, "msr", "MSP, r0"),
                                     ("BX_text", 86, "bx", "r2")):
    negative(_name, lambda f, o=_offset, op=_op, arg=_operand: f.text.__setitem__((PENDSV, o), (op, arg)),
             PENDSV, "PROTOCOL:")
for _name, _flags in (("soft", 0x05000200), ("neither", 0x05000000), ("both", 0x05000600)):
    negative("final_ABI_" + _name, lambda f, v=_flags: setattr(f, "final_flags", v), FIRST, "ELF:prelink/final ABI")


class ProfileModeTests(unittest.TestCase):
    def fixture(self, profile="CM4", mode="O2"):
        temp = tempfile.TemporaryDirectory(prefix="reference-profile-mode-")
        self.addCleanup(temp.cleanup)
        return Fixture(temp.name, profile=profile, mode=mode)

    def test_default_CM4_still_O2(self):
        f = self.fixture().write()
        image = reader.ReferenceCM4FinalImage(f.prelink, f.final, f.dis,
            provider_objects={str(f.prelink.resolve()): f.prelink, str(f.provider.resolve()): f.provider},
            link_map=f.link_map)
        self.assertEqual((image.profile, image.mode), ("CM4", "O2"))
        self.assertEqual(image.function(PENDSV)["InstructionCount"], 27)

    def test_default_CM7_is_O2(self):
        f = self.fixture("CM7").write()
        image = reader.ReferenceCM7FinalImage(f.prelink, f.final, f.dis,
            provider_objects={str(f.prelink.resolve()): f.prelink, str(f.provider.resolve()): f.provider},
            link_map=f.link_map)
        self.assertEqual((image.profile, image.mode), ("CM7", "O2"))
        self.assertEqual(image.function(PENDSV)["InstructionCount"], 29)

    def test_ordinary_mode_identity_not_inferred_from_bytes(self):
        for profile in ("CM4", "CM7"):
            with self.subTest(profile=profile):
                f = self.fixture(profile).write()
                proof = f.image(mode="Og").function(PENDSV)
                self.assertEqual(proof["Mode"], "Og")
                self.assertIs(proof["ModeBindingVerified"], False)

    def test_no_caller_contract_or_profile_options(self):
        for cls in (reader.ReferenceCM4FinalImage, reader.ReferenceCM7FinalImage):
            for option in ("profile", "protocol", "roots", "callees", "float_abi"):
                with self.subTest(cls=cls.__name__, option=option), self.assertRaises(TypeError):
                    cls(None, None, None, **{option: "CM4"})


def positive_profile_mode(profile, mode):
    def control(self):
        f = self.fixture(profile, mode).write()
        image = f.image()
        proofs = [image.function(name) for name in ADDRESSES]
        tail = int(mode == "O0")
        base_bytes, base_instructions = (164, 48) if profile == "CM4" else (168, 50)
        self.assertEqual(sum(p["Size"] for p in proofs), base_bytes + 6 * tail)
        self.assertEqual(sum(p["InstructionCount"] for p in proofs), base_instructions + 3 * tail)
        self.assertEqual(sum(len(p["References"]) for p in proofs), 3)
        self.assertEqual(image.ROOTS, frozenset(ADDRESSES))
        self.assertTrue(reader.compare_load_images(f.plain, f.final)["Identical"])
        for proof in proofs:
            self.assertEqual((proof["Profile"], proof["Mode"], proof["TailNops"]), (profile, mode, tail))
            self.assertIs(proof["ModeBindingVerified"], False)
            self.assertEqual(proof["Size"], f.sizes[proof["Name"]])
            self.assertEqual(image.read(proof["Address"], proof["Size"]), bytes(f.after[proof["Name"]]))
            if tail:
                last = proof["Instructions"][-1]
                self.assertEqual((last["Offset"], last["Bytes"], last["Mnemonic"], last["Operands"]),
                                 (f.base_sizes[proof["Name"]], "00bf", "nop", ""))
        self.assertEqual([(r["Offset"], r["Kind"]) for r in proofs[2]["References"]],
                         [(46, 10), (88, 2)] if profile == "CM4" else [(50, 10), (92, 2)])
        self.assertEqual(proofs[0]["DataMappings"], [dict(Offset=34, Size=2, Bytes="0000"),
                                                    dict(Offset=36, Size=4, Bytes="08ed00e0")])
        self.assertEqual([(m["Offset"], m["Size"]) for m in proofs[2]["DataMappings"]], [(f.slot_offset, 4)])
    control.__name__ = "test_positive_" + profile + "_" + mode
    setattr(ProfileModeTests, control.__name__, control)


def profile_negative(name, profile, fixture_mode, mutate, root, expected, **selection):
    def control(self):
        f = self.fixture(profile, fixture_mode)
        mutate(f)
        f.write()
        self.assertTrue(reader.compare_load_images(f.plain, f.final)["Identical"])
        with self.assertRaisesRegex(reader.Rejected, expected):
            f.image(**selection).function(root)
    control.__name__ = "test_reject_" + profile + "_" + fixture_mode + "_" + name
    setattr(ProfileModeTests, control.__name__, control)


for _profile in ("CM4", "CM7"):
    for _mode in ("O0", "Og", "O2", "Os", "O3"):
        positive_profile_mode(_profile, _mode)
        profile_negative("wrong_profile", _profile, _mode, lambda f: None, PENDSV, "PRESERVATION:root extent",
            reader_class=reader.ReferenceCM7FinalImage if _profile == "CM4" else reader.ReferenceCM4FinalImage)
    for _mode in ("Og", "O2", "Os", "O3"):
        profile_negative("declared_as_O0", _profile, _mode, lambda f: None, FIRST, "PRESERVATION:root extent", mode="O0")
        profile_negative("O0_declared_as_" + _mode, _profile, "O0", lambda f: None, FIRST, "PRESERVATION:root extent", mode=_mode)


class _ModeEnum(Enum):
    O2 = "O2"


class _StringModeEnum(str, Enum):
    O0 = "O0"


def invalid_mode(profile, name, value):
    def control(self):
        cls = reader.ReferenceCM4FinalImage if profile == "CM4" else reader.ReferenceCM7FinalImage
        with self.assertRaisesRegex(reader.Rejected, "SCOPE:mode must be"):
            cls(None, None, None, mode=value)
    control.__name__ = "test_invalid_mode_" + profile + "_" + name
    setattr(ProfileModeTests, control.__name__, control)


for _profile in ("CM4", "CM7"):
    for _name, _value in (("true", True), ("false", False), ("none", None), ("integer", 0),
                          ("float", 0.0), ("bytes", b"O2"), ("list", ["O2"]), ("dict", {"mode": "O2"}),
                          ("enum", _ModeEnum.O2), ("string_enum", _StringModeEnum.O0),
                          ("O1", "O1"), ("case", "o2"), ("flag", "-O2"), ("empty", "")):
        invalid_mode(_profile, _name, _value)


def tail_mutation(f, root, variant):
    offset = f.base_sizes[root]
    if variant == "wrong_bits":
        both(f, root, offset, bytes.fromhex("c046"))
    elif variant == "wrong_text":
        f.text[(root, offset)] = ("mov", "r8, r8")
    elif variant == "missing_mapping":
        f.tail_maps[root] = f.final_tail_maps[root] = None
    elif variant == "extra_NOP":
        f.before[root].extend(bytes.fromhex("00bf"))
        f.after[root].extend(bytes.fromhex("00bf"))
        f.sizes[root] += 2
        f.final_sizes[root] += 2
    else:
        raise ValueError("unknown synthetic tail mutation")


for _profile in ("CM4", "CM7"):
    for _root in ADDRESSES:
        for _variant in ("wrong_bits", "wrong_text", "missing_mapping", "extra_NOP"):
            profile_negative("tail_" + _root + "_" + _variant, _profile, "O0",
                lambda f, root=_root, variant=_variant: tail_mutation(f, root, variant), _root,
                "PROTOCOL:" if _variant.startswith("wrong_") else "PRESERVATION:")
    for _stage, _attribute in (("prelink", "tail_maps"), ("final", "final_tail_maps")):
        profile_negative("tail_mapping_" + _stage, _profile, "O0",
            lambda f, attr=_attribute: getattr(f, attr).__setitem__(PENDSV, None), PENDSV, "PRESERVATION:mapping/layout")


for _name, _offset, _raw in (("CPSID_missing", 34, "00bf"), ("CPSIE_missing", 48, "00bf"),
                             ("CPSID_wrong", 34, "62b6"), ("CPSIE_wrong", 48, "72b6"),
                             ("threshold_not16", 30, "4ff02000"), ("BASEPRI_register", 36, "81f31188"),
                             ("entry_barrier", 40, "bff36f8f"),
                             ("save_IT_ne", 16, "18bf"), ("restore_IT_ne", 76, "18bf"),
                             ("save_IT_mask", 16, "0cbf"), ("restore_IT_mask", 76, "0cbf"),
                             ("save_FP_registers", 18, "20ed100a"), ("restore_FP_registers", 78, "b0ec100a")):
    profile_negative(_name, "CM7", "O2", lambda f, o=_offset, raw=_raw: both(f, PENDSV, o, bytes.fromhex(raw)),
                     PENDSV, "PROTOCOL:original instruction")

profile_negative("BL_addend", "CM7", "O2", lambda f: f.before[PENDSV].__setitem__(slice(50, 54), bl(50, 52)),
                 PENDSV, "RELOC:only original BL addend")
profile_negative("BL_destination", "CM7", "O2", lambda f: f.after[PENDSV].__setitem__(slice(50, 54), bl(ADDRESSES[PENDSV] + 50, BASE + 258)),
                 PENDSV, "RELOC:applied BL destination")
profile_negative("CM4_call_offset", "CM7", "O2", lambda f: f.relocs[PENDSV].__setitem__(0, (46, 10, CALLEE)),
                 PENDSV, "RELOC:relocation membership")
profile_negative("CM4_pool_offset", "CM7", "O2", lambda f: f.final_relocs[PENDSV].__setitem__(1, (88, 2, SLOT)),
                 PENDSV, "RELOC:relocation membership")
profile_negative("slot_addend", "CM7", "O2", lambda f: f.before[PENDSV].__setitem__(slice(92, 96), struct.pack("<I", 4)),
                 PENDSV, "RELOC:only current-slot ABS32")
profile_negative("slot_applied", "CM7", "O2", lambda f: f.after[PENDSV].__setitem__(slice(92, 96), struct.pack("<I", RAM + 4)),
                 PENDSV, "RELOC:applied ABS32")


def alternate_PMU(f):
    for body in (f.before[PENDSV], f.after[PENDSV]):
        body[90:90] = bytes.fromhex("00b500bd")
    f.sizes[PENDSV] += 4
    f.final_sizes[PENDSV] += 4
    f.maps[PENDSV] = f.final_maps[PENDSV] = 96
    f.relocs[PENDSV][1] = (96, 2, SLOT)
    f.final_relocs[PENDSV][1] = (96, 2, SLOT)


profile_negative("WORKAROUND_PMU_CM001", "CM7", "O2", alternate_PMU, PENDSV, "PRESERVATION:root extent")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args()
    if args.output_dir:
        args.output_dir = args.output_dir.resolve()
        if args.output_dir.is_relative_to(HERE.parents[2]):
            parser.error("generated controls must be outside the repository")
        args.output_dir.mkdir(parents=True, exist_ok=False)
    paths = [HERE / "elf.py", HERE / "test_elf.py", HERE / "reference_elf.py", Path(__file__).resolve()]
    hashes = {str(path): hashlib.sha256(path.read_bytes()).hexdigest().upper() for path in paths}
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__]))
    report = dict(Status="PASS" if result.wasSuccessful() else "FAIL", PureControls=result.testsRun,
                  Failures=len(result.failures), Errors=len(result.errors), SourceHashes=hashes,
                  SourceDrift=[str(path) for path in paths if hashlib.sha256(path.read_bytes()).hexdigest().upper() != hashes[str(path)]],
                  Scope="SYNTHETIC_PINNED_REFERENCE_CM4_CM7_READER_CONTROLS_ONLY", ExpectedFreeRTOSPin=reader.PIN,
                  RequiredCellSatisfied=False, FinalParity=False, KernelRuntimeProof=False, CPUProof=False, GlobalProof=False)
    if report["SourceDrift"]:
        report["Status"] = "FAIL"
    if args.output_dir:
        output = args.output_dir / "results.json"
        output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8", newline="\n")
        print("Receipt:", output, hashlib.sha256(output.read_bytes()).hexdigest().upper())
    print(json.dumps(report, sort_keys=True))
    return 0 if report["Status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
