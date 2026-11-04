"""Synthetic CM3 final-reader controls, not actual compiler/ELF mutants.

Only frozen ELF serialization helpers are reused. CM3 instruction rows, pool
boundaries, symbols and relocation positions below are independent of the
reader's tables. This script never launches a process or executes Arm code.
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
CLASSIC = HERE.parent / "classic_final_image"


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


reader = module("synthetic_cm3_reference_reader", HERE / "reference_elf.py")
helpers = module("synthetic_cm3_elf_serialization", CLASSIC / "test_reference_elf.py")
elf_bytes, section, symbol, bl = helpers.elf_bytes, helpers.section, helpers.symbol, helpers.bl
FIRST, SVC, PENDSV = "prvPortStartFirstTask", "vPortSVCHandler", "xPortPendSVHandler"
SLOT, CALLEE = "pxCurrentTCB", "vTaskSwitchContext"
BASE, RAM = 0x08000100, 0x20000000
ADDRESSES = {FIRST: BASE, SVC: BASE + 64, PENDSV: BASE + 128}
SIZES = {FIRST: 32, SVC: 36, PENDSV: 68}
MODES = ("O0", "Og", "O2", "Os", "O3")
_ROWS = {
    FIRST: """
0 4806 ldr r0, [pc, #24]
2 6800 ldr r0, [r0, #0]
4 6800 ldr r0, [r0, #0]
6 f3808808 msr MSP, r0
10 b662 cpsie i
12 b661 cpsie f
14 f3bf8f4f dsb sy
18 f3bf8f6f isb sy
22 df00 svc 0
24 bf00 nop
""",
    SVC: """
0 4b07 ldr r3, [pc, #28]
2 6819 ldr r1, [r3, #0]
4 6808 ldr r0, [r1, #0]
6 e8b00ff0 ldmia.w r0!, {r4, r5, r6, r7, r8, r9, sl, fp}
10 f3808809 msr PSP, r0
14 f3bf8f6f isb sy
18 f04f0000 mov.w r0, #0
22 f3808811 msr BASEPRI, r0
26 f04e0e0d orr.w lr, lr, #13
30 4770 bx lr
""",
    PENDSV: """
0 f3ef8009 mrs r0, PSP
4 f3bf8f6f isb sy
8 4b0d ldr r3, [pc, #52]
10 681a ldr r2, [r3, #0]
12 e9200ff0 stmdb r0!, {r4, r5, r6, r7, r8, r9, sl, fp}
16 6010 str r0, [r2, #0]
18 b508 push {r3, lr}
20 f04f0010 mov.w r0, #16
24 f3808811 msr BASEPRI, r0
28 f7fffffe bl vTaskSwitchContext
32 f04f0000 mov.w r0, #0
36 f3808811 msr BASEPRI, r0
40 e8bd4008 ldmia.w sp!, {r3, lr}
44 6819 ldr r1, [r3, #0]
46 6808 ldr r0, [r1, #0]
48 e8b00ff0 ldmia.w r0!, {r4, r5, r6, r7, r8, r9, sl, fp}
52 f3808809 msr PSP, r0
56 f3bf8f6f isb sy
60 4770 bx lr
""",
}


def rows(name, mode):
    result = []
    for line in _ROWS[name].strip().splitlines():
        offset, words, op, *operand = line.split(maxsplit=3)
        raw = b"".join(struct.pack("<H", int(words[i:i + 4], 16)) for i in range(0, len(words), 4))
        result.append((int(offset), raw, op, operand[0] if operand else ""))
    if mode == "O0":
        result.append((SIZES[name], bytes.fromhex("00bf"), "nop", ""))
    return result


class Fixture:
    def __init__(self, directory, mode="O2"):
        self.directory, self.mode = Path(directory), mode
        self.sizes = {name: size + 2 * int(mode == "O0") for name, size in SIZES.items()}
        self.final_sizes = dict(self.sizes)
        self.before = {}
        for name in ADDRESSES:
            body = bytearray(self.sizes[name])
            for offset, raw, _, _ in rows(name, mode):
                body[offset:offset + len(raw)] = raw
            self.before[name] = body
        self.before[FIRST][28:32] = struct.pack("<I", 0xE000ED08)
        self.after = {name: bytearray(body) for name, body in self.before.items()}
        self.after[SVC][32:36] = struct.pack("<I", RAM)
        self.after[PENDSV][64:68] = struct.pack("<I", RAM)
        self.after[PENDSV][28:32] = bl(ADDRESSES[PENDSV] + 28, BASE + 256)
        self.bindings = {FIRST: 0, SVC: 1, PENDSV: 1}
        self.final_bindings = dict(self.bindings)
        self.maps = {FIRST: [26, 28], SVC: [32], PENDSV: [62, 64]}
        self.final_maps = {name: list(values) for name, values in self.maps.items()}
        self.tail_maps = {name: size if mode == "O0" else None for name, size in SIZES.items()}
        self.final_tail_maps = dict(self.tail_maps)
        self.suffix = {name: bytes.fromhex("00bf") if mode == "O0" else b"" for name in SIZES}
        self.final_suffix = dict(self.suffix)
        self.relocs = {FIRST: [], SVC: [(32, 2, SLOT)], PENDSV: [(28, 10, CALLEE), (64, 2, SLOT)]}
        self.final_relocs = {name: list(values) for name, values in self.relocs.items()}
        self.text, self.omitted, self.extra_dis = {}, set(), []
        self.source_flags, self.provider_flags, self.final_flags = 0x05000000, 0x05000000, 0x05000200
        self.callee_address, self.slot_address = BASE + 256, RAM
        self.callee_binding, self.slot_binding, self.slot_size = 1, 1, 4
        self.callee_owner, self.slot_owner = 1, 1
        self.extra_final_symbols = []
        self.bss_address, self.ram_flags = RAM, 6
        self.map_callee_address, self.map_slot_address = BASE + 256, RAM

    def write(self):
        self.objects = [self.directory / name for name in ("00-port.o", "01-providers.o", "02-consumer.o", "03-startup.o")]
        self.prelink, self.provider = self.objects[:2]
        self.final, self.plain = self.directory / "emit.elf", self.directory / "plain.elf"
        self.dis, self.link_map = self.directory / "emit.dis", self.directory / "emit.map"
        sections, symbols = [], []
        for name, body in self.before.items():
            sec = ".text." + name
            sections.append(section(sec, bytes(body) + self.suffix[name]))
            symbols.append(symbol("$t." + name, sec))
            symbols.extend(symbol("$d.%s.%d" % (name, i), sec, offset) for i, offset in enumerate(self.maps[name]))
            symbols.append(symbol(name, sec, 1, self.sizes[name], self.bindings[name], 2))
            if self.tail_maps[name] is not None:
                symbols.append(symbol("$t.tail." + name, sec, self.tail_maps[name]))
        symbols.extend((symbol(CALLEE, "", binding=1), symbol(SLOT, "", binding=1),
                        symbol("xTaskIncrementTick", "", binding=1)))
        self.prelink.write_bytes(elf_bytes(False, sections, symbols,
            {".text." + name: values for name, values in self.relocs.items()}, self.source_flags))
        for index, obj in enumerate(self.objects[1:], 1):
            sections, symbols = [], []
            if index == self.callee_owner:
                sec = ".text." + CALLEE
                sections.append(section(sec, bytes.fromhex("704700bf")))
                symbols.extend((symbol("$t.callee", sec), symbol(CALLEE, sec, 1, 4, 1, 2)))
            if index == self.slot_owner:
                sec = ".bss." + SLOT
                sections.append(section(sec, flags=3, kind=8, size=4))
                symbols.append(symbol(SLOT, sec, 0, 4, 1, 1))
            if index != 1:
                sec = ".text.synthetic_aux_%d" % index
                sections.append(section(sec, bytes.fromhex("704700bf")))
                symbols.extend((symbol("$t.aux.%d" % index, sec), symbol("synthetic_aux_%d" % index, sec, 1, 4, 1, 2)))
            obj.write_bytes(elf_bytes(False, sections, symbols, {}, self.provider_flags))
        body, symbols, relocs = bytearray(276), [], []
        for name, raw in self.after.items():
            address = ADDRESSES[name]
            full = bytes(raw) + self.final_suffix[name]
            body[address - BASE:address - BASE + len(full)] = full
            symbols.append(symbol("$t." + name, ".text", address))
            symbols.extend(symbol("$d.%s.%d" % (name, i), ".text", address + offset)
                           for i, offset in enumerate(self.final_maps[name]))
            symbols.append(symbol(name, ".text", address | 1, self.final_sizes[name], self.final_bindings[name], 2))
            if self.final_tail_maps[name] is not None:
                symbols.append(symbol("$t.tail." + name, ".text", address + self.final_tail_maps[name]))
            relocs.extend((address + off, kind, target) for off, kind, target in self.final_relocs[name])
        for index, offset in ((1, 256), (2, 264), (3, 272)):
            body[offset:offset + 4] = bytes.fromhex("704700bf")
            symbols.append(symbol("$t.provider.%d" % index, ".text", BASE + offset))
        symbols.extend((symbol(CALLEE, ".text", self.callee_address | 1, 4, self.callee_binding, 2),
                        symbol(SLOT, ".bss", self.slot_address, self.slot_size, self.slot_binding, 1),
                        symbol("xTaskIncrementTick", ".text", (BASE + 260) | 1, 2, 1, 0)))
        symbols.extend(self.extra_final_symbols)
        sections = [section(".text", body, address=BASE),
                    section(".bss", address=self.bss_address, flags=3, kind=8, size=4),
                    section(".isr_vector", struct.pack("<II", RAM + 4096, BASE | 1), address=0x08000000, flags=2)]
        for path, applied in ((self.final, {".text": relocs}), (self.plain, {})):
            raw = bytearray(elf_bytes(True, sections, symbols, applied, self.final_flags))
            struct.pack_into("<I", raw, 108, self.ram_flags)
            path.write_bytes(raw)
        lines = ["Disassembly of section .text:"]
        for name in ADDRESSES:
            for offset, original_raw, op, operand in rows(name, self.mode):
                if (name, offset) in self.omitted:
                    continue
                op, operand = self.text.get((name, offset), (op, operand))
                raw = self.after[name][offset:offset + len(original_raw)]
                words = " ".join("%04x" % value for value in struct.unpack("<" + "H" * (len(raw) // 2), raw))
                if op == "bl" and operand == CALLEE:
                    operand = "%x <%s>" % (self.callee_address, CALLEE)
                lines.append("%x: %s %s %s" % (ADDRESSES[name] + offset, words, op, operand))
            for offset in range({FIRST: 26, SVC: 32, PENDSV: 62}[name], SIZES[name], 2):
                raw = self.after[name][offset:offset + 2]
                lines.append("%x: %04x .short 0" % (ADDRESSES[name] + offset, struct.unpack("<H", raw)[0]))
        self.dis.write_text("\n".join(lines + self.extra_dis) + "\n", encoding="ascii", newline="\n")
        placements = ["Linker script and memory map"]
        placements.extend(" .text.%s 0x%x 0x%x %s" %
            (name, ADDRESSES[name], len(self.before[name]) + len(self.suffix[name]), self.prelink.resolve().as_posix())
            for name in ADDRESSES)
        placements.extend((" .text.%s 0x%x 0x4 %s" %
                           (CALLEE, self.map_callee_address, self.objects[self.callee_owner].resolve().as_posix()),
                           " .bss.%s 0x%x 0x4 %s" %
                           (SLOT, self.map_slot_address, self.objects[self.slot_owner].resolve().as_posix())))
        placements.extend(" .text.synthetic_aux_%d 0x%x 0x4 %s" %
                          (index, BASE + offset, self.objects[index].resolve().as_posix())
                          for index, offset in ((2, 264), (3, 272)))
        self.link_map.write_text("\n".join(placements) + "\n", encoding="ascii", newline="\n")
        return self

    def image(self, **kwargs):
        options = dict(provider_objects={str(path.resolve()): path for path in self.objects},
                       link_map=self.link_map, mode=self.mode)
        options.update(kwargs)
        return reader.ReferenceCM3FinalImage(self.prelink, self.final, self.dis, **options)


class ReferenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="cm3-reference-final-synthetic-")
        self.addCleanup(self.temp.cleanup)
        self.f = Fixture(self.temp.name)

    def test_default_O2(self):
        f = self.f.write()
        image = reader.ReferenceCM3FinalImage(f.prelink, f.final, f.dis,
            provider_objects={str(path.resolve()): path for path in f.objects}, link_map=f.link_map)
        self.assertEqual((image.profile, image.mode, image.float_abi), ("CM3", "O2", "soft"))
        self.assertEqual(sum(image.function(name)["Size"] for name in ADDRESSES), 136)

    def test_exact_padding_and_pool_mappings(self):
        image = self.f.write().image()
        expected = {FIRST: [(26, 2), (28, 4)], SVC: [(32, 4)], PENDSV: [(62, 2), (64, 4)]}
        for name, mappings in expected.items():
            proof = image.function(name)
            self.assertEqual([(row["Offset"], row["Size"]) for row in proof["DataMappings"]], mappings)
            self.assertEqual(proof["SoftwareFrameWords"], 8)

    def test_exact_frame_and_exception_return(self):
        image = self.f.write().image()
        svc = {row["Offset"]: row for row in image.function(SVC)["Instructions"]}
        pend = {row["Offset"]: row for row in image.function(PENDSV)["Instructions"]}
        self.assertEqual(svc[26]["Bytes"], "4ef00d0e")
        self.assertEqual(svc[6]["Bytes"], "b0e8f00f")
        self.assertEqual((pend[12]["Bytes"], pend[48]["Bytes"]), ("20e9f00f", "b0e8f00f"))

    def test_export_identity(self):
        self.assertIs(reader.core, reader.native)
        self.assertIs(reader.Rejected, reader.core.Rejected)
        self.assertIs(reader.compare_load_images, reader.core.compare_load_images)
        self.assertEqual(reader.ROOTS, frozenset(ADDRESSES))

    def test_soft_declared_prelinks(self):
        self.f.source_flags = self.f.provider_flags = 0x05000200
        self.assertTrue(self.f.write().image().function(FIRST)["Complete"])

    def test_mode_not_inferred_from_identical_bytes(self):
        proof = self.f.write().image(mode="Og").function(PENDSV)
        self.assertEqual(proof["Mode"], "Og")
        self.assertIs(proof["ModeBindingVerified"], False)

    def test_no_configurable_scope(self):
        for key in ("profile", "protocol", "roots", "callees", "float_abi"):
            with self.subTest(key=key), self.assertRaises(TypeError):
                reader.ReferenceCM3FinalImage(None, None, None, **{key: "CM3"})

    def test_reader_has_no_process_or_dynamic_code_calls(self):
        tree = ast.parse((HERE / "reference_elf.py").read_text(encoding="ascii"))
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                modules = [item.name for item in node.names] if isinstance(node, ast.Import) else [node.module]
                self.assertFalse(set(modules) & {"subprocess", "os", "ctypes"})
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                self.assertNotIn(node.func.id, ("exec", "eval", "compile"))

    def test_subclass_not_scope_extension(self):
        class Other(reader.ReferenceCM3FinalImage):
            pass
        with self.assertRaisesRegex(reader.Rejected, "SCOPE:only fixed"):
            Other(None, None, None)

    def test_missing_map(self):
        f = self.f.write()
        with self.assertRaisesRegex(reader.Rejected, "ORIGIN:explicit"):
            f.image(link_map=None)

    def test_missing_provider(self):
        f = self.f.write()
        with self.assertRaisesRegex(reader.Rejected, "ORIGIN:exact four"):
            f.image(provider_objects={str(path.resolve()): path for path in f.objects[:3]})

    def test_extra_provider(self):
        f = self.f.write()
        providers = {str(path.resolve()): path for path in f.objects}
        providers[str(f.directory / "fifth.o")] = f.objects[1]
        with self.assertRaisesRegex(reader.Rejected, "ORIGIN:exact four"):
            f.image(provider_objects=providers)

    def test_physical_provider_alias(self):
        f = self.f.write()
        providers = {str(path.resolve()): path for path in f.objects}
        providers[str(f.objects[2].resolve())] = f.objects[1]
        with self.assertRaisesRegex(reader.Rejected, "ORIGIN:physical provider alias"):
            f.image(provider_objects=providers)

    def test_root_provider_bytes(self):
        f = self.f.write()
        other = f.directory / "other-port.o"
        other.write_bytes(f.prelink.read_bytes() + b"changed-provider")
        providers = {str(path.resolve()): path for path in f.objects}
        providers[str(f.prelink.resolve())] = other
        with self.assertRaisesRegex(reader.Rejected, "ORIGIN:root provider differs"):
            f.image(provider_objects=providers).function(FIRST)

    def test_map_membership(self):
        f = self.f.write()
        lines = f.link_map.read_text().splitlines()
        f.link_map.write_text("\n".join(lines[:-1]) + "\n", encoding="ascii")
        with self.assertRaisesRegex(reader.Rejected, "ORIGIN:map must place"):
            f.image()

    def test_callee_and_slot_need_same_provider(self):
        self.f.slot_owner = 2
        with self.assertRaisesRegex(reader.Rejected, "ORIGIN:fixed port/provider"):
            self.f.write().image().function(SVC)

    def test_same_both_twins_nobits_overlap(self):
        self.f.bss_address = BASE
        f = self.f.write()
        with self.assertRaisesRegex(reader.Rejected, "ELF:overlapping allocated sections"):
            reader.compare_load_images(f.plain, f.final)

    def test_same_both_twins_ram_without_write(self):
        self.f.ram_flags = 4
        f = self.f.write()
        with self.assertRaisesRegex(reader.Rejected, "ELF:writable allocated section owner lacks PF_W"):
            reader.compare_load_images(f.plain, f.final)


def positive(mode):
    def control(self):
        f = Fixture(self.temp.name, mode).write()
        image = f.image()
        proofs = [image.function(name) for name in ADDRESSES]
        tail = int(mode == "O0")
        self.assertEqual(sum(p["Size"] for p in proofs), 136 + 6 * tail)
        self.assertEqual(sum(p["InstructionCount"] for p in proofs), 39 + 3 * tail)
        self.assertEqual(sum(len(p["References"]) for p in proofs), 3)
        self.assertTrue(reader.compare_load_images(f.plain, f.final)["Identical"])
        for proof in proofs:
            self.assertTrue(proof["Complete"] and proof["PrelinkBoundRootPreservation"])
            self.assertEqual(proof["OutsideFunctionAlignmentBytes"], "00bf" if tail else "")
            self.assertEqual(proof["InputSectionSize"], (proof["Size"] + 3) & ~3)
            self.assertEqual(image.read(proof["Address"], proof["Size"]), bytes(f.after[proof["Name"]]))
            for key in ("SourcePinBindingVerified", "CohortBindingVerified", "ModeBindingVerified",
                        "RequiredCellSatisfied", "FinalParity", "KernelRuntimeProof", "CPUProof", "GlobalProof"):
                self.assertIs(proof[key], False)
    control.__name__ = "test_positive_" + mode
    setattr(ReferenceTests, control.__name__, control)


def both(f, name, offset, raw):
    for body in (f.before[name], f.after[name]):
        body[offset:offset + len(raw)] = raw


def negative(name, mutate, root, expected, *, fixture_mode="O2", **selection):
    def control(self):
        self.f = Fixture(self.temp.name, fixture_mode)
        mutate(self.f)
        f = self.f.write()
        self.assertTrue(reader.compare_load_images(f.plain, f.final)["Identical"])
        with self.assertRaisesRegex(reader.Rejected, expected):
            f.image(**selection).function(root)
    control.__name__ = "test_reject_" + name
    setattr(ReferenceTests, control.__name__, control)


for _mode in MODES:
    positive(_mode)
for _root in ADDRESSES:
    for _stage, _attr in (("prelink", "bindings"), ("final", "final_bindings")):
        for _binding in ((1, 2) if _root == FIRST else (0, 2)):
            negative("%s_%s_binding_%d" % (_root, _stage, _binding),
                lambda f, r=_root, a=_attr, b=_binding: getattr(f, a).__setitem__(r, b), _root, "SYMBOL:")
for _foreign in ("fiber_port_start_first_context", "SVC_Handler", "PendSV_Handler", CALLEE, SLOT, "vPortEnableVFP"):
    negative("foreign_" + _foreign, lambda f: None, _foreign, "SCOPE:")

negative("ordinary_final_byte", lambda f: f.after[FIRST].__setitem__(slice(10, 12), bytes.fromhex("72b6")), FIRST, "PRESERVATION:non-relocation")
negative("BL_destination", lambda f: f.after[PENDSV].__setitem__(slice(28, 32), bl(ADDRESSES[PENDSV] + 28, BASE + 258)), PENDSV, "RELOC:applied BL destination")
negative("BL_addend", lambda f: f.before[PENDSV].__setitem__(slice(28, 32), bl(28, 30)), PENDSV, "RELOC:only original BL addend")
negative("BL_kind", lambda f: f.final_relocs[PENDSV].__setitem__(0, (28, 30, CALLEE)), PENDSV, "RELOC:relocation kind/identity")
negative("BL_target", lambda f: f.final_relocs[PENDSV].__setitem__(0, (28, 10, "xTaskIncrementTick")), PENDSV, "RELOC:relocation kind/identity")
negative("slot_applied", lambda f: f.after[SVC].__setitem__(slice(32, 36), struct.pack("<I", RAM + 4)), SVC, "RELOC:applied ABS32")
negative("slot_addend", lambda f: f.before[SVC].__setitem__(slice(32, 36), struct.pack("<I", 4)), SVC, "RELOC:only current-slot ABS32")
negative("slot_kind", lambda f: f.final_relocs[SVC].__setitem__(0, (32, 10, SLOT)), SVC, "RELOC:relocation kind/identity")
negative("slot_target", lambda f: f.final_relocs[SVC].__setitem__(0, (32, 2, CALLEE)), SVC, "RELOC:relocation kind/identity")
negative("missing_rel", lambda f: f.final_relocs[PENDSV].pop(), PENDSV, "RELOC:relocation membership")
negative("foreign_rel", lambda f: f.relocs[FIRST].append((28, 2, SLOT)), FIRST, "RELOC:relocation membership")
negative("size", lambda f: f.final_sizes.__setitem__(FIRST, 30), FIRST, "PRESERVATION:root extent")
negative("VTOR", lambda f: both(f, FIRST, 28, struct.pack("<I", 0xE000ED0C)), FIRST, "PROTOCOL:original literal")
negative("first_padding", lambda f: both(f, FIRST, 26, b"\x01\x00"), FIRST, "PROTOCOL:original literal")
negative("pend_padding", lambda f: both(f, PENDSV, 62, b"\x01\x00"), PENDSV, "PROTOCOL:original literal")
negative("ORR_value", lambda f: both(f, SVC, 26, bytes.fromhex("4ef0090e")), SVC, "PROTOCOL:original instruction")
negative("SVC_frame_includes_LR", lambda f: both(f, SVC, 6, bytes.fromhex("b0e8f04f")), SVC, "PROTOCOL:original instruction")
negative("PendSV_frame_includes_LR", lambda f: both(f, PENDSV, 12, bytes.fromhex("20e9f04f")), PENDSV, "PROTOCOL:original instruction")
negative("PendSV_restore_includes_LR", lambda f: both(f, PENDSV, 48, bytes.fromhex("b0e8f04f")), PENDSV, "PROTOCOL:original instruction")
negative("BASEPRI_threshold", lambda f: both(f, PENDSV, 20, bytes.fromhex("4ff02000")), PENDSV, "PROTOCOL:original instruction")
negative("BASEPRI_clear", lambda f: both(f, PENDSV, 32, bytes.fromhex("4ff01000")), PENDSV, "PROTOCOL:original instruction")
negative("missing_barrier", lambda f: both(f, FIRST, 14, bytes.fromhex("aff30080")), FIRST, "PROTOCOL:original instruction")
negative("register_jump", lambda f: both(f, SVC, 30, bytes.fromhex("1047")), SVC, "DECODE:only BX LR")
negative("missing_instruction", lambda f: f.omitted.add((SVC, 26)), SVC, "DECODE:missing/mismatched")
negative("ORR_text", lambda f: f.text.__setitem__((SVC, 26), ("orr.w", "lr, lr, #9")), SVC, "PROTOCOL:instruction operands")
negative("BL_text", lambda f: f.text.__setitem__((PENDSV, 28), ("bl", "%x" % (BASE + 258))), PENDSV, "DECODE:branch disassembly")
negative("callee_padding_retarget", lambda f: (setattr(f, "callee_address", BASE + 258),
    f.after[PENDSV].__setitem__(slice(28, 32), bl(ADDRESSES[PENDSV] + 28, BASE + 258))), PENDSV, "ORIGIN:original section/offset/size")
negative("slot_origin_retarget", lambda f: (setattr(f, "slot_address", RAM + 4),
    f.after[SVC].__setitem__(slice(32, 36), struct.pack("<I", RAM + 4))), SVC, "SYMBOL:definition bounds|ORIGIN:")
negative("callee_alias", lambda f: f.extra_final_symbols.append(symbol("callee_alias", ".text", (BASE + 258) | 1, 2, 1, 2)), PENDSV, "SYMBOL:overlapping function/alias")
negative("root_alias", lambda f: f.extra_final_symbols.append(symbol("root_alias", ".text", BASE | 1, 2, 1, 2)), FIRST, "SYMBOL:overlapping function/alias")

for _root, _index in ((FIRST, 1), (PENDSV, 1)):
    for _stage, _attrs in (("prelink", ("maps",)), ("final", ("final_maps",)), ("both", ("maps", "final_maps"))):
        negative("%s_%s_pool_boundary" % (_root, _stage),
            lambda f, r=_root, i=_index, attrs=_attrs: [getattr(f, attr)[r].pop(i) for attr in attrs],
            _root, "PRESERVATION:mapping/layout")
negative("shifted_pool_boundary", lambda f: f.final_maps[FIRST].__setitem__(1, 30), FIRST, "PRESERVATION:mapping/layout")
for _mode in ("Og", "O2", "Os", "O3"):
    negative("%s_as_O0" % _mode, lambda f: None, FIRST, "PRESERVATION:root extent", fixture_mode=_mode, mode="O0")
    negative("O0_as_%s" % _mode, lambda f: None, FIRST, "PRESERVATION:root extent", fixture_mode="O0", mode=_mode)
negative("O0_tail_alias", lambda f: both(f, FIRST, 32, bytes.fromhex("c046")), FIRST, "PROTOCOL:original instruction", fixture_mode="O0")
negative("O0_missing_tail_mapping", lambda f: f.final_tail_maps.__setitem__(FIRST, None), FIRST, "PRESERVATION:mapping/layout", fixture_mode="O0")
negative("O0_section_alignment", lambda f: f.final_suffix.__setitem__(FIRST, bytes.fromhex("c046")), FIRST, "PRESERVATION:owning section bytes", fixture_mode="O0")

for _name, _flags in (("hard", 0x05000400), ("neither", 0x05000000), ("both", 0x05000600)):
    negative("final_ABI_" + _name, lambda f, v=_flags: setattr(f, "final_flags", v), FIRST, "ELF:prelink/final ABI")
negative("prelink_hard", lambda f: setattr(f, "source_flags", 0x05000400), FIRST, "ELF:prelink/final ABI")
negative("provider_ABI", lambda f: setattr(f, "provider_flags", 0x05000400), FIRST, "ORIGIN:provider ABI")


class ModeEnum(Enum):
    O2 = "O2"


class StringModeEnum(str, Enum):
    O2 = "O2"


def invalid_mode(name, value):
    def control(self):
        with self.assertRaisesRegex(reader.Rejected, "SCOPE:mode must be"):
            reader.ReferenceCM3FinalImage(None, None, None, mode=value)
    control.__name__ = "test_invalid_mode_" + name
    setattr(ReferenceTests, control.__name__, control)


for _name, _value in (("true", True), ("false", False), ("none", None), ("integer", 0),
                      ("float", 0.0), ("bytes", b"O2"), ("list", ["O2"]), ("dict", {"mode": "O2"}),
                      ("enum", ModeEnum.O2), ("string_enum", StringModeEnum.O2),
                      ("O1", "O1"), ("case", "o2"), ("flag", "-O2"), ("empty", "")):
    invalid_mode(_name, _value)


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    repo = HERE.parents[2].resolve()
    output = args.output_dir.resolve()
    if output.exists() or output.is_relative_to(repo) or repo.is_relative_to(output):
        parser.error("fresh external non-overlapping output required")
    output.mkdir(parents=True)
    paths = [HERE / "reference_elf.py", HERE / "test_reference_elf.py", HERE / "CONTRACT.md",
             CLASSIC / "elf.py", CLASSIC / "reference_elf.py", CLASSIC / "test_reference_elf.py"]
    hashes = {str(path): hashlib.sha256(path.read_bytes()).hexdigest().upper() for path in paths}
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__]))
    report = dict(Status="PASS" if result.wasSuccessful() else "FAIL", PureControls=result.testsRun,
        Failures=len(result.failures), Errors=len(result.errors), SourceHashes=hashes,
        SourceDrift=[str(path) for path in paths if hashlib.sha256(path.read_bytes()).hexdigest().upper() != hashes[str(path)]],
        Scope="SYNTHETIC_PINNED_CM3_REFERENCE_FINAL_READER_ONLY", ExpectedFreeRTOSPin=reader.PIN,
        ActualWitnessTested=False, RequiredCellSatisfied=False, FinalParity=False, KernelRuntimeProof=False,
        CPUProof=False, GlobalProof=False)
    if report["SourceDrift"]:
        report["Status"] = "FAIL"
    target = output / "results.json"
    target.write_text(json.dumps(report, indent=2) + "\n", encoding="ascii", newline="\n")
    print(json.dumps(report, sort_keys=True))
    print("Receipt:", target, hashlib.sha256(target.read_bytes()).hexdigest().upper())
    return 0 if report["Status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
