"""Synthetic CM3 LTO runtime bindings; no real ELF or target execution."""

import argparse
import ast
import copy
import hashlib
import importlib.util
import json
import os
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
SUBJECT = HERE / "bindings.py"
OLD_TEST = HERE.with_name("cm3_lto_link_contract") / "test_audit.py"
OLD_AUDIT = OLD_TEST.with_name("audit.py")
CORE = HERE.with_name("classic_final_image") / "elf.py"
PINS = {
    OLD_TEST: "3E215D413CC4ADBA6DE85901B394EE1550804EA0A714604AF0269C64D6B68B9D",
    OLD_AUDIT: "9D6B4E1694A8C0A2D7F2E1C7B6D108B58B103131DD7C19D45CD08238E4CED759",
    CORE: "3A8F4E42B42189CDDAE44DE6AFA4468F24781B6EDFD13F02491C96C1E0729809",
}
SELECT = "fiber_internal_runtime_select_scheduler_candidate"
PUBLISH = "fiber_internal_runtime_publish_current_context"
CURRENT = "fiber_internal_runtime_require_current_context"
RETURN = "fiber_internal_task_return"
ANCHOR = "fiber_internal_runtime_port_abi_v1_anchor"
REVERSE = (SELECT, PUBLISH, CURRENT, RETURN)
CALLS = (("fiber_port_runtime_schedule", CURRENT),
         ("fiber_port_scheduler_pick_first_from_start", SELECT),
         ("fiber_port_scheduler_pick_next_from_pendsv", SELECT),
         ("fiber_port_scheduler_pick_next_from_pendsv", PUBLISH))
COLD = ("fiber_port_runtime_prepare_start", "fiber_port_context_init")
FRAME = "fiber_port_init_context_frame"
VECTORS = ((4, "Reset_Handler"), (44, "SVC_Handler"), (56, "PendSV_Handler"))
EXPECTED_METHODS = 18
subject = old = audit = core = None


def sha(raw):
    return hashlib.sha256(raw).hexdigest().upper()


def load(name, path, raw):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    exec(compile(raw, str(path), "exec"), module.__dict__)
    return module


def core_primitives(raw):
    """Load only unchanged pure byte helpers, never pyelftools or an ELF reader."""
    tree = ast.parse(raw, filename=str(CORE))
    functions = {"require", "sha256", "_signed", "_width", "_address_form"}
    nodes = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in functions]
    nodes += [node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "Rejected"]
    conditions = next(node for node in tree.body if isinstance(node, ast.Assign)
                      and any(isinstance(target, ast.Name) and target.id == "CONDITIONS" for target in node.targets))
    nodes.append(conditions)
    body = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "FinalImage")
    method = next(node for node in body.body if isinstance(node, ast.FunctionDef) and node.name == "_body")
    namespace = dict(struct=struct, hashlib=hashlib)
    exec(compile(ast.Module(body=nodes + [method], type_ignores=[]), str(CORE), "exec"), namespace)
    namespace["FinalImage"] = SimpleNamespace(_body=namespace["_body"])
    return SimpleNamespace(**{key: value for key, value in namespace.items() if key != "__builtins__"})


def bl(place, target):
    """Independently construct Thumb BL T1 test bytes, including negative REL -4."""
    delta = target - (place + 4)
    if delta % 2 or not -(1 << 24) <= delta < 1 << 24:
        raise ValueError("synthetic BL extent")
    value = delta & ((1 << 25) - 1)
    sign, i1, i2 = (value >> 24) & 1, (value >> 23) & 1, (value >> 22) & 1
    first = 0xF000 | (sign << 10) | ((value >> 12) & 1023)
    second = 0xD000 | ((1 ^ i1 ^ sign) << 13) | ((1 ^ i2 ^ sign) << 11) | ((value >> 1) & 2047)
    return struct.pack("<HH", first, second)


class Fixture:
    """Extend the frozen model with nonzero function offsets in one merged text."""

    def __init__(self, emit=True):
        base = old.Fixture(emit)
        self.emit, self.image = emit, base.image
        self.machine, self.startup, self.final = base.machine, base.startup, base.final
        machine, startup, final = self.machine, self.startup, self.final
        machine.data += bytes(0xA3C - len(machine.data))
        final.data += bytes(0x123C - len(final.data))
        machine.sections[1].header.sh_size = 0x900
        machine.sections[2].header.sh_offset = 0xA00
        machine.sections[3].header.sh_offset = 0xA20
        machine.sections[4].header.sh_offset = 0xA20
        machine.sections[5].header.sh_offset = 0xA34
        final.sections[2].header.sh_size = 0xA00
        for index, address, offset in ((3, 0xE00, 0x1200), (4, 0xE20, 0x1220), (5, 0xE34, 0x1234)):
            final.sections[index].header.sh_addr = address
            final.sections[index].header.sh_offset = offset
        final.sections[6].header.sh_offset = 0x123C
        final.loads[0].update(FileSize=0xE3C, MemorySize=0xE3C)
        final.loads[1]["Offset"] = 0x123C
        self.image.placements.update({("machine.o", ".text"): (0x440, 0x900),
            ("machine.o", ".rodata"): (0xE00, 0x20), ("machine.o", ".pilot_roots"): (0xE20, 20),
            ("machine.o", old.EXPECT): (0xE34, 8)})
        for name in (*REVERSE, "fiber_port_scheduler_pick_first_from_start",
                     "fiber_port_scheduler_pick_next_from_pendsv", FRAME):
            machine.add(name, 1, 1, 4)
            final.add(name, 2, 0x441, 4)
        functions = [row for row in machine.symbols if row["kind"] == "STT_FUNC"]
        for index, symbol in enumerate(functions, 1):
            offset = index * 32
            symbol.update(value=offset | 1, size=4)
            final.symbol(symbol["name"]).update(value=(0x440 + offset) | 1, size=4)
            self.write_function(symbol["name"], b"\x00\xbf\x70\x47")
        for name in (old.PRIVATE, old.STORAGE, ANCHOR):
            before, after = machine.symbol(name), final.symbol(name)
            after["value"] = 0xE00 + before["value"]
            machine.write(0xA00 + before["value"], b"\x01")
            final.write(0x1200 + before["value"], b"\x01")
        for index, name in enumerate(old.EXPECT_NAMES):
            final.symbol(name)["value"] = 0xE34 + index * 4
        final.symbol("pilot_context_roots")["value"] = 0xE20
        machine.relocations.clear()
        final.relocations.clear()
        for section, names in ((4, old.PUBLIC), (5, (old.STORAGE, old.PRIVATE))):
            for index, name in enumerate(names):
                machine.write(machine.sections[section].header.sh_offset + index * 4, bytes(4))
                machine.relocations[section, index * 4] = (2, machine.symbol(name))
                if emit:
                    final.relocations[section, index * 4] = (2, final.symbol(name))
                final.write(final.sections[section].header.sh_offset + index * 4,
                            struct.pack("<I", final.symbol(name)["value"]))
        self.section_targets = {}
        for elf, index in ((machine, 1), (machine, 2), (final, 2), (final, 3)):
            symbol = elf.add("", index, elf.sections[index].header.sh_addr, 0, "STT_SECTION", "STB_LOCAL")
            self.section_targets[id(elf), index] = symbol
        self.call_sites = []
        for caller in dict.fromkeys(name for name, _ in CALLS):
            targets = [target for name, target in CALLS if name == caller]
            self.write_function(caller, b"\xff\xf7\xfe\xff" * len(targets) + b"\x70\x47\x00\xbf")
            for index, target in enumerate(targets):
                before = machine.symbol(caller)["value"] & ~1
                after = final.symbol(caller)["value"] & ~1
                offset = before + index * 4
                final_offset = after - final.sections[2].header.sh_addr + index * 4
                machine.relocations[1, offset] = (10, machine.symbol(target))
                if emit:
                    final.relocations[2, final_offset] = (10, final.symbol(target))
                final.write(final.sections[2].header.sh_offset + final_offset,
                            bl(after + index * 4, final.symbol(target)["value"] & ~1))
                self.call_sites.append((caller, target, offset, final_offset))
        self.literal_ranges = {id(machine): [], id(final): []}
        self.cold_sites = []
        for name in COLD:
            # LDR r3,[PC,#4]; LDRB r3,[r3]; BX LR; NOP; .word anchor.
            self.write_function(name, bytes.fromhex("014b1b78704700bf") + bytes(4))
            start = machine.symbol(name)["value"] & ~1
            last = final.symbol(name)["value"] & ~1
            original_offset, final_offset = start + 8, last - 0x400 + 8
            machine.write(0x100 + original_offset, struct.pack("<I", machine.symbol(ANCHOR)["value"]))
            final.write(0x800 + final_offset, struct.pack("<I", final.symbol(ANCHOR)["value"]))
            machine.relocations[1, original_offset] = (2, self.section_targets[id(machine), 2])
            if emit:
                final.relocations[2, final_offset] = (2, self.section_targets[id(final), 3])
            self.literal_ranges[id(machine)].append((start + 8, start + 12))
            self.literal_ranges[id(final)].append((last + 8, last + 12))
            self.cold_sites.append((name, original_offset, final_offset))
        self.write_function(FRAME, bytes.fromhex("004b7047") + bytes(4))
        first = machine.symbol(FRAME)["value"] & ~1
        last = final.symbol(FRAME)["value"] & ~1
        self.return_site = (first + 4, last - 0x400 + 4)
        machine.write(0x100 + first + 4, bytes(4))
        final.write(0x800 + self.return_site[1], struct.pack("<I", final.symbol(RETURN)["value"]))
        machine.relocations[1, first + 4] = (2, machine.symbol(RETURN))
        if emit:
            final.relocations[2, self.return_site[1]] = (2, final.symbol(RETURN))
        self.literal_ranges[id(machine)].append((first + 4, first + 8))
        self.literal_ranges[id(final)].append((last + 4, last + 8))
        for elf in (machine, final):
            elf.mapping = lambda section, address, selected=elf: self.mapping(selected, section, address)
            elf.section_read = lambda section, offset, size, selected=elf: self.section_read(selected, section, offset, size)
            elf.read = lambda address, size, selected=elf: self.read(selected, address, size)
        self.image.read = final.read
        self.image._body = lambda elf, symbol: core.FinalImage._body(self.image, elf, symbol)
        for offset, name in VECTORS:
            startup.write(0x400 + offset, bytes(4))
            target = startup.symbol("Reset_Handler") if name == "Reset_Handler" else \
                     startup.add(name, "SHN_UNDEF", 0, 0, "STT_NOTYPE")
            startup.relocations[1, offset] = (2, target)
            if emit:
                final.relocations[1, offset] = (2, final.symbol(name))
        words = [final.symbol("pilot_fault")["value"]] * 256
        words[0] = 0x20010000
        for index in (7, 8, 9, 10, 13):
            words[index] = 0
        for offset, name in VECTORS:
            words[offset // 4] = final.symbol(name)["value"]
        final.write(0x400, struct.pack("<256I", *words))
        for elf in (machine, startup, final):
            for index, symbol in enumerate(elf.symbols):
                symbol["index"] = index
        startup.mapping = lambda section, address: ("d", 1024) if section == 1 else ("t", 4)
        self.refresh_disassembly()

    def refresh_disassembly(self):
        """Synthetic text records for selected bytes, not an ELF/disassembly parser."""
        records = {}
        for _, target, _, offset in self.call_sites:
            address = 0x400 + offset
            records[2, address] = ("bl", "%x <%s>" % (self.final.symbol(target)["value"] & ~1, target),
                                   self.final.data[0x800 + offset:0x800 + offset + 4])
        for name, _, _ in self.cold_sites:
            start = self.final.symbol(name)["value"] & ~1
            for relative in (0, 2, 4, 6):
                offset = start - 0x400 + relative
                raw = self.final.data[0x800 + offset:0x800 + offset + 2]
                half = struct.unpack("<H", raw)[0]
                if half & 0xF800 == 0x4800:
                    record = ("ldr", "r%d, [pc, #%d]" % ((half >> 8) & 7, (half & 255) * 4), raw)
                elif half & 0xF800 == 0x7800:
                    record = ("ldrb", "r%d, [r%d, #%d]" % (half & 7, (half >> 3) & 7, (half >> 6) & 31), raw)
                else:
                    record = ("nop", "", raw)
                records[2, start + relative] = record
        self.image.instructions = records

    def write_function(self, name, raw):
        for elf, index in ((self.machine, 1), (self.final, 2)):
            symbol = elf.symbol(name)
            symbol["size"] = len(raw)
            address = symbol["value"] & ~1
            h = elf.sections[index].header
            offset = address - (h.sh_addr if elf.final else 0)
            elf.write(h.sh_offset + offset, raw)

    def mapping(self, elf, section, address):
        if elf.final and section == 1:
            return "d", 1024
        end = elf.sections[section].header.sh_addr + elf.sections[section].header.sh_size
        if not elf.final:
            end = elf.sections[section].header.sh_size
        ranges = self.literal_ranges.get(id(elf), []) if section == (2 if elf.final else 1) else []
        for low, high in sorted(ranges):
            if low <= address < high:
                return "d", high
            if address < low:
                end = min(end, low)
        return "t", end

    @staticmethod
    def section_read(elf, section, offset, size):
        h = elf.sections[section].header
        if h.sh_type != "SHT_PROGBITS" or offset < 0 or size <= 0 or offset + size > h.sh_size:
            raise ValueError("synthetic section read bounds")
        return elf.data[h.sh_offset + offset:h.sh_offset + offset + size]

    @staticmethod
    def read(elf, address, size):
        rows = [row for row in elf.loads if row["Vaddr"] <= address
                and address + size <= row["Vaddr"] + row["FileSize"]]
        if len(rows) != 1:
            raise ValueError("synthetic unique file-backed load required")
        offset = rows[0]["Offset"] + address - rows[0]["Vaddr"]
        return elf.data[offset:offset + size]

    def check(self, **kwargs):
        options = dict(emit_relocs=self.emit, machine_attributes_text=old.ATTRS)
        options.update(kwargs)
        return subject.inspect(self.image, core, audit, old.ATTRS, **options)


class BindingTests(unittest.TestCase):
    def rejects(self, fixture, **options):
        kinds = [audit.Rejected, core.Rejected, ValueError]
        own = getattr(subject, "Rejected", None)
        if isinstance(own, type) and issubclass(own, Exception):
            kinds.append(own)
        with self.assertRaises(tuple(kinds)):
            fixture.check(**options)

    def test_emit_and_ordinary_accept_nonzero_merged_offsets_and_exact_roles(self):
        for emit in (True, False):
            f = Fixture(emit)
            with self.subTest(emit=emit):
                self.assertTrue(all(f.machine.symbol(name)["value"] > 1 for name in REVERSE))
                result = f.check()
                self.assertIsInstance(result, dict)
                self.assertEqual(result["Status"], "CM3-LTO-RUNTIME-BINDINGS-PASS-NOT-QUALIFIED")
                self.assertEqual((result["Profile"], result["Mode"], result["Linkage"]), ("CM3", "O2-lto", "direct"))
                self.assertEqual(len(result["LinkContract"]["Symbols"]), 26)
                for key, expected in (("ForwardProviderCount", 8), ("ReverseProviderCount", 4),
                        ("ReverseReferenceCount", 5), ("ReverseBLReferences", 4),
                        ("TaskReturnABS32References", 1), ("ColdAnchorReadCount", 2),
                        ("StartupVectorReferenceCount", 3), ("OriginalBindingRelocations", 10),
                        ("AppliedBindingRelocations", 10 if emit else 0)):
                    self.assertIs(type(result[key]), int)
                    self.assertEqual(result[key], expected)
                self.assertEqual([row["Name"] for row in result["ForwardProviders"]], list(old.FORWARD))
                self.assertEqual([row["Name"] for row in result["ReverseProviders"]], list(REVERSE))
                self.assertCountEqual([(row["Consumer"], row["Symbol"], row["Kind"], row["Addend"])
                    for row in result["ReverseReferences"]],
                    [(caller, target, 10, -4) for caller, target in CALLS] + [(FRAME, RETURN, 2, 0)])
                self.assertEqual([row["Function"] for row in result["ColdAnchorReads"]], list(COLD))
                self.assertEqual([(row["Offset"], row["Symbol"], row["Kind"], row["Addend"])
                    for row in result["StartupVectors"]], [(offset, name, 2, 0) for offset, name in VECTORS])
                for key, raw in (("MachineSha256", f.machine.data), ("FinalSha256", f.final.data),
                                 ("StartupSha256", f.startup.data)):
                    self.assertEqual(result[key], sha(raw))
                self.assertIs(type(result["RequiredCellsSatisfied"]), int)
                self.assertEqual(result["RequiredCellsSatisfied"], 0)

    def test_unchanged_link_audit_is_recomputed_once_with_actual_inputs(self):
        for emit in (True, False):
            f = Fixture(emit)
            real = audit.audit
            delegated = Mock(wraps=real)
            proxy = SimpleNamespace(**vars(audit))
            proxy.audit = delegated
            subject.inspect(f.image, core, proxy, old.ATTRS, emit_relocs=emit,
                            machine_attributes_text=old.ATTRS)
            delegated.assert_called_once_with(f.image, old.ATTRS, emit_relocs=emit,
                                             machine_attributes_text=old.ATTRS)
        for options in (dict(emit_relocs=1), dict(machine_attributes_text=None)):
            with self.subTest(options=options):
                self.rejects(Fixture(), **options)

    def test_four_reverse_definitions_missing_wrong_kind_or_binding_reject(self):
        for name in REVERSE:
            for side in ("machine", "final"):
                for change in ("missing", "kind", "binding"):
                    f = Fixture()
                    elf = getattr(f, side)
                    row = elf.symbol(name)
                    if change == "missing":
                        elf.symbols.remove(row)
                    else:
                        row[change] = "STT_OBJECT" if change == "kind" else "STB_LOCAL"
                    with self.subTest(name=name, side=side, change=change):
                        self.rejects(f)

    def test_reverse_definition_provider_substitution_and_duplicate_owner_reject(self):
        for change in ("startup-definition", "third-provider", "provider-bytes"):
            f = Fixture()
            if change == "startup-definition":
                f.startup.symbols.append(dict(f.machine.symbol(SELECT)))
            elif change == "third-provider":
                f.image.providers["foreign.o"] = copy.deepcopy(f.machine)
            else:
                f.image.providers["machine.o"] = copy.deepcopy(f.machine)
                f.image.providers["machine.o"].write(0x100, b"\x01")
            with self.subTest(change=change):
                self.rejects(f)

    def test_reverse_function_alias_duplicate_and_non_thumb_mapping_reject(self):
        for side in ("machine", "final"):
            for change in ("duplicate", "alias", "thumb", "size", "data-map"):
                f = Fixture()
                elf = getattr(f, side)
                row = elf.symbol(PUBLISH)
                if change in ("duplicate", "alias"):
                    elf.symbols.append(dict(row, name=PUBLISH if change == "duplicate" else "foreign_alias"))
                elif change == "thumb":
                    row["value"] &= ~1
                elif change == "size":
                    row["size"] = 0
                else:
                    elf.mapping = lambda section, address: ("d", address + 8)
                with self.subTest(side=side, change=change):
                    self.rejects(f)

    def test_whole_merged_section_origin_size_or_final_definition_drift_reject(self):
        for change in ("address", "extent", "definition", "section", "map-hash"):
            f = Fixture()
            if change in ("address", "extent"):
                f.image.placements["machine.o", ".text"] = (0x444, 0x900) if change == "address" else (0x440, 0x8FC)
            elif change == "definition":
                f.final.symbol(SELECT)["value"] += 2
            elif change == "section":
                f.final.symbol(SELECT)["section"] = 3
            else:
                f.image.link_map_hash = "unknown"
            with self.subTest(change=change):
                self.rejects(f)

    def test_each_reverse_reference_missing_or_duplicated_rejects(self):
        for index in range(4):
            for change in ("missing", "duplicate"):
                f = Fixture()
                _, _, original, _ = f.call_sites[index]
                if change == "missing":
                    del f.machine.relocations[1, original]
                else:
                    f.machine.relocations[1, original + 2] = f.machine.relocations[1, original]
                with self.subTest(index=index, change=change):
                    self.rejects(f)

    def test_reference_in_wrong_caller_or_foreign_reverse_provider_rejects(self):
        for change in ("caller", "target"):
            f = Fixture()
            _, _, original, _ = f.call_sites[0]
            kind, symbol = f.machine.relocations.pop((1, original))
            if change == "caller":
                offset = f.machine.symbol("ctxrt_v1_init")["value"] & ~1
                f.machine.relocations[1, offset] = (kind, symbol)
            else:
                f.machine.relocations[1, original] = (kind, f.machine.symbol(SELECT))
            with self.subTest(change=change):
                self.rejects(f)

    def test_reverse_original_kind_metadata_and_boolean_aliases_reject(self):
        for change in ("kind", "metadata", "index-bool", "value-float"):
            f = Fixture()
            _, _, original, _ = f.call_sites[0]
            kind, symbol = f.machine.relocations[1, original]
            symbol = dict(symbol)
            if change == "kind":
                kind = 2
            elif change == "metadata":
                symbol["size"] += 2
            elif change == "index-bool":
                symbol["index"] = True
            else:
                symbol["value"] = float(symbol["value"])
            f.machine.relocations[1, original] = (kind, symbol)
            with self.subTest(change=change):
                self.rejects(f)

    def test_original_bl_addend_zero_minus_two_or_non_bl_rejects(self):
        for raw in (bl(0, 4), bl(0, 2), bytes.fromhex("00bf00bf")):
            f = Fixture()
            _, _, original, _ = f.call_sites[0]
            f.machine.write(0x100 + original, raw)
            with self.subTest(raw=raw.hex()):
                self.rejects(f)

    def test_applied_bl_raw_destination_interior_or_unrelated_function_rejects(self):
        for emit in (True, False):
            for change in ("interior", "foreign"):
                f = Fixture(emit)
                _, target, _, at = f.call_sites[0]
                place = 0x400 + at
                destination = ((f.final.symbol(target)["value"] & ~1) + 2 if change == "interior"
                               else f.final.symbol(SELECT)["value"] & ~1)
                f.final.write(0x800 + at, bl(place, destination))
                with self.subTest(emit=emit, change=change):
                    self.rejects(f)

    def test_emitted_rel_metadata_missing_extra_wrong_kind_or_target_rejects(self):
        for change in ("missing", "extra", "kind", "target", "ordinary"):
            f = Fixture(change != "ordinary")
            _, target, _, at = f.call_sites[0]
            if change == "missing":
                del f.final.relocations[2, at]
            elif change == "extra":
                f.final.relocations[2, at + 2] = f.final.relocations[2, at]
            else:
                f.final.relocations[2, at] = (2 if change == "kind" else 10,
                    f.final.symbol(SELECT if change == "target" else target))
            with self.subTest(change=change):
                self.rejects(f)
        for change in ("missing", "raw", "target", "mnemonic", "interior"):
            f = Fixture()
            _, _, _, at = f.call_sites[0]
            key = (2, 0x400 + at)
            mnemonic, operand, raw = f.image.instructions[key]
            if change == "missing":
                del f.image.instructions[key]
            elif change == "interior":
                f.image.instructions[2, key[1] + 2] = ("nop", "", bytes.fromhex("00bf"))
            else:
                f.image.instructions[key] = ("b" if change == "mnemonic" else mnemonic,
                    "0 <foreign>" if change == "target" else operand,
                    bytes.fromhex("00bf00bf") if change == "raw" else raw)
            with self.subTest(disassembly=change):
                self.rejects(f)

    def test_task_return_pointer_kind_original_addend_target_and_applied_word_reject(self):
        for change in ("missing", "kind", "original-addend", "target", "applied", "interior"):
            f = Fixture()
            first, last = f.return_site
            if change == "missing":
                del f.machine.relocations[1, first]
            elif change == "kind":
                f.machine.relocations[1, first] = (10, f.machine.symbol(RETURN))
            elif change == "original-addend":
                f.machine.write(0x100 + first, struct.pack("<I", 4))
            elif change == "target":
                f.machine.relocations[1, first] = (2, f.machine.symbol(CURRENT))
            else:
                value = f.final.symbol(RETURN)["value"] + (2 if change == "interior" else 4)
                f.final.write(0x800 + last, struct.pack("<I", value))
            with self.subTest(change=change):
                self.rejects(f)

    def test_local_anchor_section_addend_and_byte_displacement_combine_exactly(self):
        f = Fixture()
        for name, first, last in f.cold_sites:
            start = f.machine.symbol(name)["value"] & ~1
            final = f.final.symbol(name)["value"] & ~1
            # Independent positive: base is one byte before the anchor and is
            # retained in r7 across MOVS r0,#0 before LDRB r2,[r7,#1].
            f.machine.write(0x100 + start, bytes.fromhex("014f00207a787047"))
            f.final.write(0x800 + final - 0x400, bytes.fromhex("014f00207a787047"))
            f.machine.write(0x100 + first, struct.pack("<I", f.machine.symbol(ANCHOR)["value"] - 1))
            f.final.write(0x800 + last, struct.pack("<I", f.final.symbol(ANCHOR)["value"] - 1))
        f.refresh_disassembly()
        f.check()
        for name, _, _ in f.cold_sites:
            broken = Fixture()
            for item, first, last in broken.cold_sites:
                start = broken.machine.symbol(item)["value"] & ~1
                final = broken.final.symbol(item)["value"] & ~1
                # Same literal and LDRB, but MOVS r7,#0 kills their base link.
                raw = bytes.fromhex("014f00277a787047") if item == name else bytes.fromhex("014f00207a787047")
                broken.machine.write(0x100 + start, raw)
                broken.final.write(0x800 + final - 0x400, raw)
                broken.machine.write(0x100 + first, struct.pack("<I", broken.machine.symbol(ANCHOR)["value"] - 1))
                broken.final.write(0x800 + last, struct.pack("<I", broken.final.symbol(ANCHOR)["value"] - 1))
            broken.refresh_disassembly()
            with self.subTest(clobbered_cold_base=name):
                self.rejects(broken)
        name, first, last = f.cold_sites[0]
        f.final.write(0x800 + last, struct.pack("<I", f.final.symbol(ANCHOR)["value"]))
        self.rejects(f)

    def test_cold_load_literal_alone_or_unlinked_register_is_not_byte_read_proof(self):
        for change in ("nop", "word-read", "wrong-base", "wrong-width", "source-only", "final-only"):
            f = Fixture()
            name, _, _ = f.cold_sites[0]
            before = f.machine.symbol(name)["value"] & ~1
            after = (f.final.symbol(name)["value"] & ~1) - 0x400
            raw = {"nop": bytes.fromhex("00bf"), "word-read": bytes.fromhex("1b68"),
                   "wrong-base": bytes.fromhex("1378"), "wrong-width": bytes.fromhex("5b78"),
                   "source-only": bytes.fromhex("00bf"), "final-only": bytes.fromhex("00bf")}[change]
            if change != "final-only":
                f.machine.write(0x100 + before + 2, raw)
            if change != "source-only":
                f.final.write(0x800 + after + 2, raw)
            with self.subTest(change=change):
                self.rejects(f)

    def test_cold_anchor_membership_mapping_literal_and_actual_load_bytes_reject(self):
        for change in ("missing", "extra", "literal", "applied", "data-map", "load-read"):
            f = Fixture()
            name, first, last = f.cold_sites[0]
            if change == "missing":
                del f.machine.relocations[1, first]
            elif change == "extra":
                f.machine.relocations[1, first + 2] = f.machine.relocations[1, first]
            elif change == "literal":
                f.machine.write(0x100 + first, struct.pack("<I", 3))
            elif change == "applied":
                f.final.write(0x800 + last, struct.pack("<I", f.final.symbol(ANCHOR)["value"] + 1))
            elif change == "data-map":
                f.literal_ranges[id(f.machine)] = []
            else:
                f.final.loads[0]["Offset"] += 2
            with self.subTest(change=change):
                self.rejects(f)

    def test_three_original_startup_vector_roles_addends_targets_and_emitted_metadata(self):
        for offset, name in VECTORS:
            for change in ("missing", "kind", "addend", "target", "emitted"):
                f = Fixture()
                if change == "missing":
                    del f.startup.relocations[1, offset]
                elif change == "kind":
                    _, symbol = f.startup.relocations[1, offset]
                    f.startup.relocations[1, offset] = (10, symbol)
                elif change == "addend":
                    f.startup.write(0x400 + offset, struct.pack("<I", 4))
                elif change == "target":
                    f.startup.relocations[1, offset] = (2, dict(f.startup.relocations[1, offset][1], name="foreign"))
                else:
                    del f.final.relocations[1, offset]
                with self.subTest(offset=offset, target=name, change=change):
                    self.rejects(f)

    def test_pure_inputs_unchanged_and_broad_credit_flags_false(self):
        f = Fixture()
        before = {name: (elf.data, copy.deepcopy(elf.symbols), copy.deepcopy(elf.relocations))
                  for name, elf in (("machine", f.machine), ("startup", f.startup), ("final", f.final))}
        placements = copy.deepcopy(f.image.placements)
        with patch("builtins.open", side_effect=AssertionError("pure inspector opened a file")), \
                patch.object(Path, "read_bytes", side_effect=AssertionError("pure inspector read a path")), \
                patch.object(Path, "read_text", side_effect=AssertionError("pure inspector read text")), \
                patch.object(Path, "write_bytes", side_effect=AssertionError("pure inspector wrote a path")), \
                patch("subprocess.Popen", side_effect=AssertionError("pure inspector spawned a process")):
            result = f.check()
        for name, elf in (("machine", f.machine), ("startup", f.startup), ("final", f.final)):
            self.assertEqual((elf.data, elf.symbols, elf.relocations), before[name])
        self.assertEqual(f.image.placements, placements)
        self.assertFalse(hasattr(f.image, "_contract_machine_owner"))
        for name in ("Qualification", "FullABIProof", "SourceIRProof", "SourceToMachineSemanticProof",
                     "OriginalTranslationUnitOwnership", "CanonicalProtocolValidated", "FinalReferenceParity",
                     "CompleteObjectProof", "CpuExecution", "BoardExecution", "GlobalFreezeQualified", "RequiredCellSatisfied"):
            with self.subTest(nonclaim=name):
                self.assertIs(result[name], False)
        self.assertIs(type(result["RequiredCellsSatisfied"]), int)
        self.assertEqual(result["RequiredCellsSatisfied"], 0)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    output, temporary = args.output_dir.resolve(), Path(tempfile.gettempdir()).resolve()
    if (output.exists() or args.output_dir.is_symlink() or not output.is_relative_to(temporary)
            or output.is_relative_to(REPO) or REPO.is_relative_to(output)):
        parser.error("fresh external TEMP output directory required")
    paths = (Path(__file__).resolve(), SUBJECT, OLD_TEST, OLD_AUDIT, CORE)
    report = dict(Status="FAIL", Tests=0, ExpectedTestMethods=EXPECTED_METHODS, Failures=0, Errors=0,
        Skipped=0, SourceHashes={}, SourceDrift=[], SourceClosureVerified=False, ClosingFilesVerified=0,
        Scope="PURE_SYNTHETIC_CM3_O2_LTO_RUNTIME_BINDINGS_CONTROLS_ONLY", SyntheticInputs=True,
        ActualELFTested=False, ActualFinalLinkTested=False, ActualCaptureRead=False,
        FrozenPureBytePrimitivesUsed=False, NativeCommandsExecuted=0, ToolInvocations=0,
        Qualification=False, FullABIProof=False, FullSemanticABIProof=False, SourceIRProof=False,
        SourceToMachineSemanticProof=False, CanonicalProtocolValidated=False, FinalReferenceParity=False,
        CompleteObjectProof=False, CpuExecution=False, BoardExecution=False, GlobalFreezeQualified=False,
        RequiredCellSatisfied=False, RequiredCellsSatisfied=0)
    try:
        if sys.flags.optimize or not __debug__:
            raise ValueError("unoptimized host Python required")
        buffers = {path: path.read_bytes() for path in paths}
        report["SourceHashes"] = {str(path): sha(raw) for path, raw in buffers.items()}
        for path, expected in PINS.items():
            if sha(buffers[path]) != expected:
                raise ValueError("unchanged fixture/audit/byte-helper source required: " + str(path))
        global subject, old, audit, core
        with patch("subprocess.Popen", side_effect=AssertionError("synthetic controls cannot execute processes")), \
                patch("os.system", side_effect=AssertionError("synthetic controls cannot execute commands")):
            old = load("_runtime_binding_legacy_fixture", OLD_TEST, buffers[OLD_TEST])
            audit = load("_runtime_binding_unchanged_audit", OLD_AUDIT, buffers[OLD_AUDIT])
            core = core_primitives(buffers[CORE])
            subject = load("_runtime_binding_subject", SUBJECT, buffers[SUBJECT])
            report["FrozenPureBytePrimitivesUsed"] = True
            suite = unittest.defaultTestLoader.loadTestsFromTestCase(BindingTests)
            if suite.countTestCases() != EXPECTED_METHODS:
                raise ValueError("exact eighteen implemented synthetic methods required")
            result = unittest.TextTestRunner(verbosity=2).run(suite)
        report.update(Tests=result.testsRun, Failures=len(result.failures), Errors=len(result.errors),
            Skipped=len(result.skipped), FailureDetails=[dict(Test=str(case), Detail=detail)
                for case, detail in result.failures + result.errors])
        if result.wasSuccessful() and result.testsRun == EXPECTED_METHODS and not result.skipped:
            report["Status"] = "PASS"
    except Exception:
        report.update(Status="FAIL", Error=traceback.format_exc(), Errors=report["Errors"] + 1)
    finally:
        for path, value in report["SourceHashes"].items():
            try:
                if sha(Path(path).read_bytes()) == value:
                    report["ClosingFilesVerified"] += 1
                else:
                    report["SourceDrift"].append(path)
            except OSError:
                report["SourceDrift"].append(path)
        report["SourceClosureVerified"] = len(report["SourceHashes"]) == len(paths) and not report["SourceDrift"]
        if not report["SourceClosureVerified"]:
            report["Status"] = "FAIL"
    output.mkdir(parents=True, exist_ok=False)
    target = output / "results.json"
    target.write_bytes((json.dumps(report, indent=2, sort_keys=True) + "\n").encode("ascii"))
    print("Receipt:", target, sha(target.read_bytes()))
    return 0 if report["Status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
