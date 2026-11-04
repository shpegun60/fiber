"""Pure fixed CM0 reference-reader controls; no tools, compiler or target.

The parent owns actual retained-ELF mutants and witness qualification. These
controls exercise public admission and small instruction/protocol helpers;
they do not infer source, compiler-mode or CPU identity from function bytes.
"""

import argparse
import ast
from enum import Enum
import hashlib
import importlib.util
import inspect
import json
from pathlib import Path
import struct
import sys
import tempfile
import traceback
from types import SimpleNamespace
import unittest
from unittest.mock import patch


sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
PIN = "a50edad08b29052631aa469d4df6e6ec7ff68878"
MODES = ("O0", "Og", "O2", "Os", "O3")
ROOT_OWNERS = {"vStartFirstTask": 1, "SVC_Handler": 1, "vPortSVCHandler_C": 0,
               "vRestoreContextOfFirstTask": 1, "PendSV_Handler": 1}
reader = None


# Independent instruction descriptions for pin ARM_CM0/portasm.c:138,
# 222,392,498 and non-MPU port.c:842-905. Register transfer, stack geometry,
# SVC100, every conditional/failure edge and padding remain explicit. The
# three ordinary C layouts also retain their prologues and epilogues.
ASM_ROWS = {
    "vStartFirstTask": """
62b6 cpsie i
bff34f8f dsb #15
bff36f8f isb #15
64df svc 100
c046 nop -
c046 nop -
""",
    "SVC_Handler": """
0420 movs r0,#4
7146 mov r1,lr
0842 tst r0,r1
03d0 beq @16
eff30980 mrs r0,psp
044b ldr literal
1847 bx r3
eff30880 mrs r0,msp
024b ldr literal
1847 bx r3
c046 nop -
c046 nop -
c046 nop -
c046 nop -
""",
    "vRestoreContextOfFirstTask": """
074a ldr literal
1168 ldr r1,[r2,#0]
0868 ldr r0,[r1,#0]
04c8 ldmia r0!,{r2}
0221 movs r1,#2
81f31488 msr control,r1
2030 adds r0,#32
80f30988 msr psp,r0
bff36f8f isb #15
1047 bx r2
c046 nop -
c046 nop -
c046 nop -
""",
    "PendSV_Handler": """
eff30980 mrs r0,psp
0e4a ldr literal
1168 ldr r1,[r2,#0]
2438 subs r0,#36
0860 str r0,[r1,#0]
7346 mov r3,lr
f8c0 stmia r0!,{r3,r4,r5,r6,r7}
4446 mov r4,r8
4d46 mov r5,r9
5646 mov r6,r10
5f46 mov r7,r11
f0c0 stmia r0!,{r4,r5,r6,r7}
72b6 cpsid i
fff7feff bl vTaskSwitchContext
62b6 cpsie i
074a ldr literal
1168 ldr r1,[r2,#0]
0868 ldr r0,[r1,#0]
1430 adds r0,#20
f0c8 ldmia r0!,{r4,r5,r6,r7}
a046 mov r8,r4
a946 mov r9,r5
b246 mov r10,r6
bb46 mov r11,r7
80f30988 msr psp,r0
2438 subs r0,#36
f8c8 ldmia r0!,{r3,r4,r5,r6,r7}
1847 bx r3
c046 nop -
""",
}
C_ROWS = {
    "O0": """
80b5 push {r7,lr}
84b0 sub sp,#16
00af add r7,sp,#0
7860 str r0,[r7,#4]
7b68 ldr r3,[r7,#4]
9b69 ldr r3,[r3,#24]
fb60 str r3,[r7,#12]
fb68 ldr r3,[r7,#12]
023b subs r3,#2
1a00 movs r2,r3
0b21 movs r1,#11
7b18 adds r3,r7,r1
1278 ldrb r2,[r2,#0]
1a70 strb r2,[r3,#0]
7b18 adds r3,r7,r1
1b78 ldrb r3,[r3,#0]
642b cmp r3,#100
02d1 bne @42
fff7feff bl vRestoreContextOfFirstTask
01e0 b @46
c046 nop -
fde7 b @42
c046 nop -
bd46 mov sp,r7
04b0 add sp,#16
80bd pop {r7,pc}
""",
    "Os": """
10b5 push {r4,lr}
8369 ldr r3,[r0,#24]
023b subs r3,#2
1b78 ldrb r3,[r3,#0]
642b cmp r3,#100
02d1 bne @18
fff7feff bl vRestoreContextOfFirstTask
10bd pop {r4,pc}
fee7 b @18
""",
    "speed": """
10b5 push {r4,lr}
8369 ldr r3,[r0,#24]
023b subs r3,#2
1b78 ldrb r3,[r3,#0]
642b cmp r3,#100
00d0 beq @14
fee7 b @12
fff7feff bl vRestoreContextOfFirstTask
10bd pop {r4,pc}
""",
}
# Root extent, full owning-section extent, external pool, mapping boundaries,
# exact count of assembler/compiler tail NOPs. Pools never enlarge a root.
ASM_LAYOUTS = {
    "vStartFirstTask": ((16, 16, None, ((0, "t"),), 2), (18, 20, None, ((0, "t"),), 3)),
    "SVC_Handler": ((32, 36, 32, ((0, "t"), (32, "d")), 4),
                    (34, 40, 36, ((0, "t"), (34, "d"), (36, "d")), 5)),
    "vRestoreContextOfFirstTask": ((32, 36, 32, ((0, "t"), (32, "d")), 3),
                                   (34, 40, 36, ((0, "t"), (34, "d"), (36, "d")), 4)),
    "PendSV_Handler": ((64, 68, 64, ((0, "t"), (64, "d")), 1),
                       (66, 72, 68, ((0, "t"), (66, "d"), (68, "d")), 2)),
}


def expected_rows(name, mode):
    text = (C_ROWS[mode if mode in ("O0", "Os") else "speed"]
            if name == "vPortSVCHandler_C" else ASM_ROWS[name])
    result = []
    offset = 0
    for line in text.splitlines():
        if not line.strip():
            continue
        raw_text, mnemonic, operands = line.split(maxsplit=2)
        raw = bytes.fromhex(raw_text)
        if name != "vPortSVCHandler_C" and mode == "O0" and operands == "literal":
            # T1 LDR literal's unsigned imm8 advances one word at O0.
            raw = struct.pack("<H", struct.unpack("<H", raw)[0] + 1)
        result.append((offset, raw, mnemonic, operands))
        offset += len(raw)
    if name != "vPortSVCHandler_C" and mode == "O0":
        result.append((offset, bytes.fromhex("c046"), "nop", "-"))
    return tuple(result)


def load_reader():
    spec = importlib.util.spec_from_file_location("cm0_reference_final_reader_controls", HERE / "reference_elf.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def output_directory(value):
    path = Path(value).resolve()
    if path.exists() or path.is_relative_to(REPO) or REPO.is_relative_to(path):
        raise ValueError("fresh external output directory disjoint from repository required")
    return path


class _Mode(Enum):
    O2 = "O2"


class _StringMode(str, Enum):
    O2 = "O2"


class _Dictionary(dict):
    pass


class AdmissionTests(unittest.TestCase):
    def test_fixed_pin_roots_and_modes(self):
        self.assertEqual(reader.PIN, PIN)
        self.assertEqual(reader.MODES, MODES)
        self.assertEqual(list(reader.ROOT_OWNERS.items()), list(ROOT_OWNERS.items()))
        self.assertEqual(reader.ROOTS, frozenset(ROOT_OWNERS))
        self.assertEqual(reader.ReferenceCM0FinalImage.ROOTS, frozenset(ROOT_OWNERS))

    def test_constructor_interface_and_default(self):
        parameters = inspect.signature(reader.ReferenceCM0FinalImage).parameters
        self.assertEqual(tuple(parameters), ("port_object", "portasm_object", "final_elf", "disassembly",
                                            "provider_objects", "link_map", "mode"))
        self.assertEqual(parameters["mode"].default, "O2")
        for name in ("provider_objects", "link_map", "mode"):
            self.assertIs(parameters[name].kind, inspect.Parameter.KEYWORD_ONLY)
        for name in ("provider_objects", "link_map"):
            self.assertIs(parameters[name].default, inspect.Parameter.empty)

    def test_fixed_class_cannot_be_subclassed_into_another_contract(self):
        class Other(reader.ReferenceCM0FinalImage):
            pass
        with self.assertRaisesRegex(reader.Rejected, "REJECT:SCOPE:"):
            Other(None, None, None, None, provider_objects={}, link_map=None)

    def test_missing_map_rejects_before_input_reads(self):
        providers = {"provider-%d" % index: None for index in range(5)}
        with patch.object(Path, "read_bytes", side_effect=AssertionError("unexpected input read")):
            with self.assertRaisesRegex(reader.Rejected, "REJECT:ORIGIN:"):
                reader.ReferenceCM0FinalImage(None, None, None, None, provider_objects=providers, link_map=None)

    def test_caller_cannot_supply_a_protocol_or_architecture_override(self):
        for name in ("profile", "roots", "protocol", "callees", "float_abi", "cpu", "vtor"):
            with self.subTest(option=name), self.assertRaises(TypeError):
                reader.ReferenceCM0FinalImage(None, None, None, None,
                    provider_objects={}, link_map=None, **{name: "arbitrary"})

    def test_no_process_execution_or_shared_core_patching(self):
        tree = ast.parse((HERE / "reference_elf.py").read_text())
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                modules = ([item.name.split(".")[0] for item in node.names]
                           if isinstance(node, ast.Import) else [(node.module or "").split(".")[0]])
                self.assertFalse(set(modules) & {"subprocess", "os", "ctypes"})
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                self.assertNotIn(node.func.id, ("exec", "eval", "compile"))
            if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for target in targets:
                    self.assertFalse(isinstance(target, ast.Attribute) and
                                     isinstance(target.value, ast.Name) and target.value.id == "core")


def invalid_mode(name, value):
    def control(self):
        with patch.object(Path, "read_bytes", side_effect=AssertionError("unexpected input read")):
            with self.assertRaisesRegex(reader.Rejected, "REJECT:SCOPE:"):
                reader.ReferenceCM0FinalImage(None, None, None, None,
                    provider_objects={}, link_map=None, mode=value)
    control.__name__ = "test_invalid_mode_" + name
    setattr(AdmissionTests, control.__name__, control)


for _name, _value in (("true", True), ("false", False), ("none", None), ("integer", 0),
                      ("bytes", b"O2"), ("list", ["O2"]), ("enum", _Mode.O2),
                      ("string_enum", _StringMode.O2), ("O1", "O1"), ("flag", "-O2"),
                      ("case", "o2"), ("empty", "")):
    invalid_mode(_name, _value)


def invalid_providers(name, value):
    def control(self):
        with patch.object(Path, "read_bytes", side_effect=AssertionError("unexpected input read")):
            with self.assertRaisesRegex(reader.Rejected, "REJECT:ORIGIN:"):
                reader.ReferenceCM0FinalImage(None, None, None, None,
                    provider_objects=value, link_map="not-opened.map")
    control.__name__ = "test_invalid_providers_" + name
    setattr(AdmissionTests, control.__name__, control)


for _name, _value in (("none", None), ("duplicate_list", [None] * 5), ("empty", {}),
                      ("four", {str(i): None for i in range(4)}),
                      ("six", {str(i): None for i in range(6)}),
                      ("dict_subclass", _Dictionary({str(i): None for i in range(5)}))):
    invalid_providers(_name, _value)


def foreign_root(name, value):
    def control(self):
        image = reader.ReferenceCM0FinalImage.__new__(reader.ReferenceCM0FinalImage)
        with self.assertRaisesRegex(reader.Rejected, "REJECT:SCOPE:"):
            image.function(value)
    control.__name__ = "test_foreign_root_" + name
    setattr(AdmissionTests, control.__name__, control)


for _name, _value in (("true", True), ("none", None), ("bytes", b"SVC_Handler"),
                      ("list", ["SVC_Handler"]), ("empty", ""), ("native_start", "fiber_port_start_first_context"),
                      ("constructor", "pxPortInitialiseStack"), ("scheduler_start", "xPortStartScheduler"),
                      ("SysTick", "SysTick_Handler"), ("kernel", "vTaskSwitchContext"), ("slot", "pxCurrentTCB")):
    foreign_root(_name, _value)


class ContractTests(unittest.TestCase):
    pass


def contract_control(name, mode):
    def control(self):
        actual = reader._contract(name, mode)
        expected = expected_rows(name, mode)
        self.assertEqual(actual["Rows"], expected)
        self.assertEqual(sum(len(row[1]) for row in expected), actual["Size"])
        self.assertEqual([row[0] for row in expected],
                         [sum(len(previous[1]) for previous in expected[:i]) for i in range(len(expected))])
        if name == "vPortSVCHandler_C":
            size = 54 if mode == "O0" else 20
            layout = (size, size, None, ((0, "t"),), 0)
            relocs = {36 if mode == "O0" else 12 if mode == "Os" else 14: (10, "vRestoreContextOfFirstTask")}
        else:
            layout = ASM_LAYOUTS[name][int(mode == "O0")]
            pool = layout[2]
            relocs = {} if pool is None else {pool: (2, "vPortSVCHandler_C" if name == "SVC_Handler" else "pxCurrentTCB")}
            if name == "PendSV_Handler":
                relocs[28] = (10, "vTaskSwitchContext")
        self.assertEqual(tuple(actual[key] for key in ("Size", "SectionSize", "Pool", "Mappings", "TailNops")), layout)
        self.assertEqual(actual["Relocations"], relocs)
        if layout[2] is not None:
            self.assertGreaterEqual(layout[2], actual["Size"])
    control.__name__ = "test_contract_" + name + "_" + mode
    setattr(ContractTests, control.__name__, control)


for _root in ROOT_OWNERS:
    for _mode in MODES:
        contract_control(_root, _mode)


def section_case(name, mode):
    """Parsed-image unit double, deliberately not an ELF/parser qualification."""
    contract = reader._contract(name, mode)
    before = bytearray(contract["SectionSize"])
    for offset, raw, _, _ in expected_rows(name, mode):
        before[offset:offset + len(raw)] = raw
    if name == "vStartFirstTask" and mode == "O0":
        before[18:20] = bytes.fromhex("c046")
    after = bytearray(before)
    start = 0x1000
    def mappings(base):
        return [dict(name="$" + kind + ".%d" % offset, section=1, value=base + offset,
                     kind="STT_NOTYPE", binding="STB_LOCAL", size=0)
                for offset, kind in contract["Mappings"]]
    source = SimpleNamespace(final=False, symbols=mappings(0), relocations={},
        sections=[None, SimpleNamespace(header=SimpleNamespace(sh_size=len(before), sh_addr=0))],
        section_read=lambda section, offset, size: bytes(before[offset:offset + size]))
    final = SimpleNamespace(final=True, symbols=mappings(start), relocations={},
        sections=[None, SimpleNamespace(header=SimpleNamespace(sh_size=len(after), sh_addr=start))],
        read=lambda address, size: bytes(after[address - start:address - start + size]))
    image = reader.ReferenceCM0FinalImage.__new__(reader.ReferenceCM0FinalImage)
    image.mode, image.owners, image.final, image.instructions = mode, (source, source), final, {}
    image._origin = lambda root, definition: dict(SectionAddress=start, SectionSize=len(before))
    original = dict(name=name, section=1, size=contract["Size"])
    definition = dict(original, value=start | 1)
    return image, original, definition, contract, source, before, after, start


def check_section(case, name):
    image, original, definition, contract, *_ = case
    return image._section(name, original, definition, contract)


class SectionTests(unittest.TestCase):
    def test_complete_fixed_sections_all_twenty_five_layouts(self):
        for name in ROOT_OWNERS:
            for mode in MODES:
                with self.subTest(root=name, mode=mode):
                    case = section_case(name, mode)
                    source, _, start, before, after = check_section(case, name)
                    self.assertIs(source, case[4])
                    self.assertEqual(start, case[7])
                    self.assertEqual(before, after)
                    self.assertEqual(len(before), case[3]["SectionSize"])

    def test_original_instruction_mutation_is_not_hidden_by_identical_twins(self):
        for name in ROOT_OWNERS:
            for mode in MODES:
                case = section_case(name, mode)
                case[5][0] ^= 1
                case[6][0] ^= 1
                with self.subTest(root=name, mode=mode), self.assertRaisesRegex(reader.Rejected, "PRESERVATION:original fixed"):
                    check_section(case, name)

    def test_external_alignment_and_section_nop_are_not_discarded(self):
        for name in ASM_ROWS:
            for mode in ("O0", "O2"):
                contract = reader._contract(name, mode)
                pool = contract["Pool"]
                end = contract["SectionSize"] if pool is None else pool
                reason = "original section padding" if pool is None else "original external pool alignment"
                for offset in range(contract["Size"], end):
                    case = section_case(name, mode)
                    case[5][offset] ^= 1
                    with self.subTest(root=name, mode=mode, offset=offset), self.assertRaisesRegex(
                            reader.Rejected, "PRESERVATION:" + reason):
                        check_section(case, name)

    def test_missing_moved_or_duplicate_mapping_rejects(self):
        for variant in ("missing", "moved", "duplicate", "global", "nonzero_size"):
            case = section_case("SVC_Handler", "O0")
            symbols = case[0].final.symbols
            if variant == "missing":
                symbols.pop()
            elif variant == "moved":
                symbols[-1]["value"] += 2
            elif variant == "duplicate":
                symbols.append(dict(symbols[-1], name="$d.other"))
            elif variant == "global":
                symbols[-1]["binding"] = "STB_GLOBAL"
            else:
                symbols[-1]["size"] = 2
            with self.subTest(variant=variant), self.assertRaisesRegex(reader.Rejected, "MAPPING:"):
                check_section(case, "SVC_Handler")

    def test_foreign_function_inside_external_pool_rejects(self):
        case = section_case("SVC_Handler", "O2")
        case[4].symbols.append(dict(name="foreign", section=1, value=33, size=2, kind="STT_FUNC"))
        with self.assertRaisesRegex(reader.Rejected, "SYMBOL:foreign function overlaps whole root section"):
            check_section(case, "SVC_Handler")

    def test_extra_disassembly_record_must_be_mapped_data_not_an_instruction(self):
        case = section_case("SVC_Handler", "O2")
        image, _, definition, contract, _, _, after, start = case
        boundaries = {row[0] for row in expected_rows("SVC_Handler", "O2")}
        image.instructions[(1, start + 32)] = (".word", "0", bytes(after[32:36]))
        image._disassembly_extent("SVC_Handler", definition, contract, start, after, boundaries)
        for offset, raw in ((32, bytes(after[32:34])), (1, bytes(after[1:3]))):
            image.instructions = {(1, start + offset): ("nop", "", raw)}
            with self.subTest(offset=offset), self.assertRaisesRegex(reader.Rejected, "DECODE:unowned instruction"):
                image._disassembly_extent("SVC_Handler", definition, contract, start, after, boundaries)

    def test_only_exact_first_O0_out_of_function_nop_is_admitted(self):
        case = section_case("vStartFirstTask", "O0")
        image, _, definition, contract, _, _, after, start = case
        boundaries = {row[0] for row in expected_rows("vStartFirstTask", "O0")}
        image.instructions = {(1, start + 18): ("nop", "", bytes.fromhex("c046"))}
        image._disassembly_extent("vStartFirstTask", definition, contract, start, after, boundaries)
        for record in (("mov", "r8,r8", bytes.fromhex("c046")), ("nop", "", bytes.fromhex("00bf"))):
            image.instructions[(1, start + 18)] = record
            with self.subTest(record=record), self.assertRaisesRegex(reader.Rejected, "DECODE:"):
                image._disassembly_extent("vStartFirstTask", definition, contract, start, after, boundaries)


class AddressFormTests(unittest.TestCase):
    def test_exact_register_transfer_sites_and_registers(self):
        for root, offset, raw, register in (("SVC_Handler", 14, "1847", 3), ("SVC_Handler", 22, "1847", 3),
                ("vRestoreContextOfFirstTask", 24, "1047", 2), ("PendSV_Handler", 60, "1847", 3)):
            with self.subTest(root=root, offset=offset):
                self.assertEqual(reader.ReferenceCM0FinalImage._form(bytes.fromhex(raw), 0x1000 + offset, root, offset),
                                 ("bx", None, register, None))
        for root, offset, raw in (("SVC_Handler", 14, "1047"), ("SVC_Handler", 12, "1847"),
                ("vRestoreContextOfFirstTask", 24, "1847"), ("PendSV_Handler", 60, "7047")):
            with self.subTest(root=root, offset=offset, raw=raw), self.assertRaisesRegex(reader.Rejected, "DECODE:"):
                reader.ReferenceCM0FinalImage._form(bytes.fromhex(raw), 0x1000 + offset, root, offset)

    def test_literal_bits_preserve_register_and_external_pool_address(self):
        for mode in MODES:
            o0 = int(mode == "O0")
            for root, offset, base_halfword, register, pool in (("SVC_Handler", 12, 0x4B04, 3, 32),
                    ("SVC_Handler", 20, 0x4B02, 3, 32), ("vRestoreContextOfFirstTask", 0, 0x4A07, 2, 32),
                    ("PendSV_Handler", 4, 0x4A0E, 2, 64), ("PendSV_Handler", 34, 0x4A07, 2, 64)):
                form = reader.ReferenceCM0FinalImage._form(struct.pack("<H", base_halfword + o0), 0x1000 + offset, root, offset)
                with self.subTest(mode=mode, root=root, offset=offset):
                    self.assertEqual(form[:3], ("ldr", 0x1000 + pool + 4 * o0, register))

    def test_original_BL_placeholder_has_addend_minus_four(self):
        form = reader.ReferenceCM0FinalImage._form(bytes.fromhex("fff7feff"), 28, "PendSV_Handler", 28)
        self.assertEqual(form, ("bl", 28, None, -4))


def literal_case(mode="O2"):
    case = section_case("SVC_Handler", mode)
    image, _, _, contract, source, _, after, _ = case
    target = dict(name="vPortSVCHandler_C", section="SHN_UNDEF", value=0, size=0,
                  kind="STT_NOTYPE", binding="STB_GLOBAL", visibility="STV_DEFAULT")
    definition = dict(name="vPortSVCHandler_C", section=2, value=0x2001, size=54 if mode == "O0" else 20,
                      kind="STT_FUNC", binding="STB_GLOBAL", visibility="STV_DEFAULT")
    source.relocations[(1, contract["Pool"])] = (2, target)
    image.final.relocations[(1, contract["Pool"])] = (2, definition)
    image.final.symbol = lambda name, kind, **kwargs: definition
    struct.pack_into("<I", after, contract["Pool"], definition["value"])
    return case, target, definition


def check_references(case, name):
    image, original, definition, contract, source, before, after, start = case
    return image._references(name, original, definition, contract, source, start, bytes(before), bytes(after))


class RelocationTests(unittest.TestCase):
    def test_collection_accounts_for_final_section_address_and_bounds(self):
        for final, address in ((False, 0), (True, 0x1000)):
            relocation = (2, {"name": "external"})
            image = SimpleNamespace(final=final, sections=[None, SimpleNamespace(header=SimpleNamespace(sh_addr=address))],
                                    relocations={(1, 4): relocation, (2, 4): relocation})
            self.assertEqual(reader.ReferenceCM0FinalImage._relocations(image, 1, address, 8), {4: relocation})
            image.relocations[(1, 6)] = relocation
            with self.assertRaisesRegex(reader.Rejected, "RELOC:relocation crosses owning-section extent"):
                reader.ReferenceCM0FinalImage._relocations(image, 1, address, 8)

    def test_external_function_pointer_keeps_addend_zero_and_thumb_tag(self):
        case, _, definition = literal_case()
        references = check_references(case, "SVC_Handler")
        self.assertEqual(len(references), 1)
        self.assertEqual((references[0]["Offset"], references[0]["Kind"], references[0]["Addend"], references[0]["ResolvedValue"]),
                         (32, 2, 0, definition["value"]))

    def test_malformed_literal_relocation_inputs_reject(self):
        for mode in MODES:
            for variant in ("addend", "applied", "thumb_bit", "weak_original", "missing_original", "foreign_final"):
                case, target, definition = literal_case(mode)
                image, _, _, contract, source, before, after, _ = case
                pool = contract["Pool"]
                if variant == "addend":
                    struct.pack_into("<I", before, pool, 4)
                elif variant == "applied":
                    struct.pack_into("<I", after, pool, definition["value"] + 2)
                elif variant == "thumb_bit":
                    definition["value"] &= ~1
                    struct.pack_into("<I", after, pool, definition["value"])
                elif variant == "weak_original":
                    target["binding"] = "STB_WEAK"
                elif variant == "missing_original":
                    source.relocations.clear()
                else:
                    image.final.relocations[(1, pool)] = (2, dict(definition, name="vTaskSwitchContext"))
                with self.subTest(mode=mode, variant=variant):
                    # Section validation leaves pool values to REL addend/application checks.
                    check_section(case, "SVC_Handler")
                    reason = "RELOC:applied ABS32 differs" if variant == "addend" else "RELOC:"
                    with self.assertRaisesRegex(reader.Rejected, reason):
                        check_references(case, "SVC_Handler")


class MalformedElfTests(unittest.TestCase):
    def constructor_rejects(self, data, reason):
        with tempfile.TemporaryDirectory(prefix="cm0-reference-malformed-") as directory:
            root = Path(directory)
            port = root / "port.o"
            port.write_bytes(data)
            providers = {str(root / ("provider-%d.o" % i)): root / ("provider-%d.o" % i) for i in range(5)}
            with self.assertRaisesRegex(reader.Rejected, reason):
                reader.ReferenceCM0FinalImage(port, root / "portasm.o", root / "final.elf", root / "final.dis",
                    provider_objects=providers, link_map=root / "final.map")


def elf_header(*, machine=40, kind=1, byte_order=1):
    ident = b"\x7fELF\x01" + bytes((byte_order, 1)) + bytes(9)
    return struct.pack(("<" if byte_order == 1 else ">") + "16sHHIIIIIHHHHHH",
                       ident, kind, machine, 1, 0, 0, 0, 0x05000000, 52, 0, 0, 40, 0, 0)


def malformed_elf(name, data, reason):
    def control(self):
        self.constructor_rejects(data, reason)
    control.__name__ = "test_reject_" + name
    setattr(MalformedElfTests, control.__name__, control)


for _name, _data, _reason in (("empty", b"", "REJECT:ELF:"), ("truncated", b"\x7fELF", "REJECT:ELF:"),
                              ("bad_magic", b"not-an-elf" + bytes(64), "REJECT:ELF:"),
                              ("foreign_machine", elf_header(machine=3), "REJECT:ELF:expected ARM ELF32LE"),
                              ("ET_EXEC_as_owner", elf_header(kind=2), "REJECT:ELF:expected ARM ELF32LE"),
                              ("big_endian", elf_header(byte_order=2), "REJECT:ELF:expected ARM ELF32LE"),
                              ("missing_symtab", elf_header(), "REJECT:ELF:one static symbol table")):
    malformed_elf(_name, _data, _reason)


class OperandTests(unittest.TestCase):
    def test_register_aliases_and_whitespace_only(self):
        self.assertEqual(reader._operand("mov", " R14, SL "), "lr,r10")
        self.assertEqual(reader._operand("mov", " FP, R8 "), "r11,r8")
        self.assertEqual(reader._operand("ldmia", " r0!, {r4, r5, r6, r7} "), "r0!,{r4,r5,r6,r7}")

    def test_barrier_sy_alias_is_operation_specific(self):
        for op in ("dsb", "isb"):
            self.assertEqual(reader._operand(op, " sy "), "#15")
            self.assertEqual(reader._operand(op, "#14"), "#14")
        self.assertEqual(reader._operand("mov", "sy"), "sy")

    def test_no_semantic_or_number_rewriting(self):
        for op, text in (("svc", "#100"), ("svc", "#101"), ("bx", "r2"),
                         ("bx", "r3"), ("ldr", "r3,[pc,#24]"), ("movs", "r1,#02")):
            self.assertEqual(reader._operand(op, text), text)


class OutputTests(unittest.TestCase):
    def test_repo_and_existing_directories_reject(self):
        for path in (REPO, HERE, REPO / "not-created-controls", REPO.parent):
            with self.subTest(path=path), self.assertRaises(ValueError):
                output_directory(path)

    def test_fresh_external_path_is_not_created_by_validation(self):
        with tempfile.TemporaryDirectory(prefix="cm0-reader-output-guard-") as directory:
            path = Path(directory) / "fresh"
            self.assertEqual(output_directory(path), path.resolve())
            self.assertFalse(path.exists())


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        output = output_directory(args.output_dir)
    except ValueError as error:
        parser.error(str(error))
    output.mkdir(parents=True, exist_ok=False)
    paths = (Path(__file__).resolve(), HERE / "reference_elf.py",
             HERE.parent / "classic_final_image/elf.py")
    report = dict(Status="FAIL", PureControls=0, Failures=0, Errors=0, Skipped=0,
        SourceHashes={}, SourceDrift=[], Scope="PURE_CM0_REFERENCE_FINAL_ROOT_READER_CONTROLS_ONLY",
        ParsedImageHelpersUseSyntheticDoubles=True,
        ExpectedFreeRTOSPin=PIN, ActualElfMutants=0, ToolInvocations=0, RequiredCellsSatisfied=0,
        RequiredCellSatisfied=False, FinalParity=False, WholeObjectProof=False, KernelRuntimeProof=False,
        SourcePinBindingVerified=False, CohortBindingVerified=False, ModeBindingVerified=False,
        CPUProof=False, BoardExecution=False, GlobalProof=False, Error=None)
    try:
        if sys.flags.optimize or not __debug__:
            raise RuntimeError("optimized Python unsupported")
        report["SourceHashes"] = {str(path): hashlib.sha256(path.read_bytes()).hexdigest().upper() for path in paths}
        with patch("subprocess.Popen", side_effect=AssertionError("process execution forbidden in pure controls")):
            global reader
            reader = load_reader()
            suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
            expected = suite.countTestCases()
            result = unittest.TextTestRunner(verbosity=2).run(suite)
        report.update(PureControls=result.testsRun, Failures=len(result.failures), Errors=len(result.errors),
                      Skipped=len(result.skipped),
                      FailureDetails=[dict(Test=str(case), Detail=detail) for case, detail in result.failures + result.errors])
        report["SourceDrift"] = [str(path) for path in paths if not path.is_file() or
            hashlib.sha256(path.read_bytes()).hexdigest().upper() != report["SourceHashes"][str(path)]]
        if result.wasSuccessful() and result.testsRun == expected > 0 and not result.skipped and not report["SourceDrift"]:
            report["Status"] = "PASS"
    except Exception:
        report.update(Status="FAIL", Errors=report["Errors"] + 1, Error=traceback.format_exc())
    receipt = output / "results.json"
    receipt.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="ascii")
    print("Receipt:", receipt, hashlib.sha256(receipt.read_bytes()).hexdigest().upper())
    return 0 if report["Status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
