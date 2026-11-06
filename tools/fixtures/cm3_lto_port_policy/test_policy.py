"""Synthetic pure policy controls; no compiler, target or ELF-parser execution."""

import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys
from types import SimpleNamespace
import unittest


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SPEC = importlib.util.spec_from_file_location("port_policy_under_test", HERE / "policy.py")
p = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(p)


def ir_rows():
    groups = {"runtime": p.RUNTIME, "boot": p.BOOT, "exception": p.EXCEPTION}
    result = {role: [dict(Name=name, Kind="W" if name == "fiber_fallback_initial_msp" else "T", Value=0, Size=None)
                     for name in names] for role, names in groups.items()}
    result["runtime"] += [dict(Name=name, Kind="D", Value=0, Size=None) for name in (p.PRIVATE, p.STORAGE)]
    return result


def base_flags():
    return ["-mcpu=cortex-m3", "-mthumb", "-mfloat-abi=soft", "-O2", "-flto", "-fno-fat-lto-objects"]


def sym(name, section, value=0, size=0, kind="STT_FUNC", binding="STB_GLOBAL"):
    return dict(name=name, section=section, value=value, size=size, kind=kind,
                binding=binding, visibility="STV_DEFAULT", index=0)


class SyntheticELF:
    def __init__(self, *, final=False, whole=False, stress=False, padding=b"", pool=False, extra=None, transfers=False):
        self.final = final
        self.names = ["", ".text", ".rodata", ".isr_vector"]
        self.symbols, self.relocations, self.maps = [], {}, [(0, "t")]
        self.instructions = {}
        names = ["ctxrt_attribute_stress"] if stress else list(p.RUNTIME + p.BOOT + p.EXCEPTION + p.LOCAL)
        if final:
            names += ["Reset_Handler", "pilot_fault"]
        if extra:
            names.append(extra)
        origin = 0x08000000 if final else 0
        text = bytearray()
        for name in names:
            offset = len(text)
            transfer = transfers and name in names[:2]
            raw = bytes.fromhex("fff7feff" if name == names[0] else "fff7febf") if transfer else bytes.fromhex("00bf")
            text += raw
            item = sym(name, 1, origin + offset + 1, len(raw), binding="STB_LOCAL" if name in p.LOCAL or name == extra else
                       "STB_WEAK" if name == "fiber_fallback_initial_msp" else "STB_GLOBAL")
            self.symbols.append(item)
            self.instructions[1, origin + offset] = ("bl" if name == names[0] else "b", "0", raw) if transfer else ("nop", "", raw)
        if transfers:
            for index, kind in enumerate((10, 30)):
                self.relocations[1, (self.symbols[index]["value"] & ~1) - origin] = kind, self.symbols[2]
        for offset in range(0, len(padding), 2):
            at = len(text)
            raw = padding[offset:offset + 2]
            text += raw
            self.instructions[1, origin + at] = ("nop", "", raw)
        if pool:
            if len(text) % 4:
                at = len(text)
                text += bytes.fromhex("00bf")
                self.instructions[1, origin + at] = ("nop", "", bytes.fromhex("00bf"))
            at = len(text)
            self.maps.append((at, "d"))
            text += struct.pack("<I", 0xE000ED04)
            self.instructions[1, origin + at] = (".word", "0xe000ed04", struct.pack("<I", 0xE000ED04))
            literal = 0x4800 | ((at - 4) // 4)
            text[:2] = struct.pack("<H", literal)
            self.instructions[1, origin] = ("ldr", "r0, [pc]", bytes(text[:2]))
        rodata = bytearray(64)
        if not stress:
            for offset, name in enumerate((p.PRIVATE, p.STORAGE)):
                self.symbols.append(sym(name, 2, (0x08001000 if final else 0) + offset, 1, "STT_OBJECT"))
            if not final:
                for index, name in enumerate(p.FINAL_WORKER_UNDEFINED if whole else p.UNDEFINED):
                    target = sym(name, "SHN_UNDEF", kind="STT_NOTYPE")
                    self.symbols.append(target)
                    self.relocations[2, 4 + index * 4] = 2, target
        vectors = bytearray(1024)
        entry = 0
        if final:
            for index, name in ((1, "Reset_Handler"), (11, "SVC_Handler"), (14, "PendSV_Handler")):
                value = next(x["value"] for x in self.symbols if x["name"] == name)
                struct.pack_into("<I", vectors, index * 4, value)
            entry = struct.unpack_from("<I", vectors, 4)[0]
            self.symbols.append(sym("pilot_vectors", 3, 0x08003000, 1024, "STT_OBJECT"))
        header = bytearray(52)
        header[:7] = b"\x7fELF\x01\x01\x01"
        struct.pack_into("<HHI", header, 16, 2 if final else 1, 40, 1)
        self.data = bytes(header)
        self.elf = SimpleNamespace(header=SimpleNamespace(e_entry=entry))
        self.sections = [SimpleNamespace(header=SimpleNamespace(sh_flags=0, sh_size=0, sh_type="SHT_NULL", sh_addr=0))]
        for index, raw in enumerate((bytes(text), bytes(rodata), bytes(vectors)), 1):
            self.sections.append(SimpleNamespace(header=SimpleNamespace(sh_offset=len(self.data), sh_size=len(raw),
                sh_type="SHT_PROGBITS", sh_flags=6 if index == 1 else 2,
                sh_addr=(origin if index == 1 else 0x08000000 + index * 0x1000) if final else 0)))
            self.data += raw
        for index, item in enumerate(self.symbols):
            item["index"] = index

    def mapping(self, section, address):
        origin = self.sections[section].header.sh_addr if self.final else 0
        offsets = [(origin + offset, kind) for offset, kind in self.maps]
        index = max(i for i, (start, _) in enumerate(offsets) if start <= address)
        return offsets[index][1], offsets[index + 1][0] if index + 1 < len(offsets) else origin + self.sections[section].header.sh_size

    def section_read(self, section, offset, size):
        h = self.sections[section].header
        if not (0 <= offset and size > 0 and offset + size <= h.sh_size):
            raise ValueError("synthetic bounds")
        return self.data[h.sh_offset + offset:h.sh_offset + offset + size]

    def dis(self):
        lines = ["Disassembly of section .text:"]
        for (_, address), (op, args, raw) in sorted(self.instructions.items()):
            words = ("%08x" % struct.unpack("<I", raw)[0] if op == ".word" else
                     " ".join("%04x" % struct.unpack_from("<H", raw, i)[0] for i in range(0, len(raw), 2)))
            lines.append(" %x: %s %s %s" % (address, words, op, args))
        return ("\n".join(lines) + "\n").encode("ascii")


def width(first):
    return 4 if first >> 11 in (29, 30, 31) else 2


def literal(raw, position):
    first = struct.unpack("<H", raw)[0]
    if first & 0xF800 != 0x4800:
        raise ValueError("synthetic fixture literal only")
    return "ldr", ((position + 4) & ~3) + (first & 255) * 4, 0, (first & 255) * 4


CORE = SimpleNamespace(_ELF=SyntheticELF, _width=width, _address_form=literal)


class PolicyTests(unittest.TestCase):
    def scan(self, image=None, dis=None, *, whole=False):
        image = image or SyntheticELF()
        return p.inspect_lowered(image, CORE, image.dis() if dis is None else dis,
                                 p.inspect_ir_definitions(ir_rows()), whole_image=whole)

    def test_exact_seven_counter_recipe_and_no_input_mutation(self):
        original = base_flags()
        before = list(original)
        result = p.supported_flags(original)
        self.assertEqual(original, before)
        self.assertEqual(result, original + list(p.RAW_FLAGS) + list(p.COUNTER_FLAGS))
        self.assertEqual(p.COUNTER_FLAGS[-2:], ("-fno-sanitize-coverage=trace-pc", "-mgeneral-regs-only"))
        with self.assertRaises(p.Rejected):
            p.supported_flags(result)

    def test_effective_negative_order_not_positive_occurrence(self):
        good = p.supported_flags(base_flags())
        self.assertTrue(p.require_effective_options(good, supported=True)["SupportedPolicy"])
        canonical = [x for x in good if x not in p.RAW_FLAGS[:4]]
        self.assertTrue(p.require_effective_options(canonical, supported=True)["EffectiveOptionsVerified"])
        for bad in (*(good + [flag] for flag in p.RAW_FLAGS), good[:-2] + [good[-1]],
                    base_flags() + list(p.COUNTER_FLAGS) + list(p.RAW_FLAGS)):
            with self.assertRaises(p.Rejected):
                p.require_effective_options(bad, supported=True)

    def test_worker_target_grouping_preserves_effective_counter_policy(self):
        good = p.supported_flags(base_flags())
        grouped = [p.COUNTER_FLAGS[-1]] + [x for x in good if x != p.COUNTER_FLAGS[-1]]
        self.assertTrue(p.require_effective_options(grouped, supported=True)["EffectiveOptionsVerified"])
        for bad in (grouped + ["-mno-general-regs-only"],
                    [x for x in grouped if x != p.COUNTER_FLAGS[-1]]):
            with self.assertRaises(p.Rejected):
                p.require_effective_options(bad, supported=True)

    def test_raw_stress_six_uncancelled_and_target_types(self):
        good = base_flags() + list(p.RAW_FLAGS)
        self.assertFalse(p.require_effective_options(good, supported=False)["SupportedPolicy"])
        for bad in (good + [p.COUNTER_FLAGS[5]], good[1:], good + ["-mcpu=cortex-m7"], good + ["-Os"],
                    good + ["-fsanitize=address"], good + ["-finstrument-functions-exclude-file-list=context"],
                    good + ["-mfpu=fpv4-sp-d16"]):
            with self.assertRaises(p.Rejected):
                p.require_effective_options(bad, supported=False)
        with self.assertRaises(p.Rejected):
            p.require_effective_options(good, supported=1)

    def test_ir_exact_source_surface(self):
        rows = ir_rows()
        proof = p.inspect_ir_definitions(rows)
        self.assertEqual(len(proof["Definitions"]), 31)
        self.assertEqual(proof["PublicFunctions"], 29)
        self.assertEqual(rows, ir_rows())
        for change in ("duplicate", "missing", "foreign", "bool", "weak", "private"):
            bad = ir_rows()
            if change == "duplicate":
                bad["runtime"].append(dict(bad["runtime"][0]))
            elif change == "missing":
                bad["boot"].pop()
            elif change == "foreign":
                bad["exception"][0]["Name"] = "unrelated"
            elif change == "bool":
                bad["runtime"][0]["Value"] = False
            elif change == "weak":
                next(x for x in bad["boot"] if x["Name"] == "fiber_fallback_initial_msp")["Kind"] = "T"
            else:
                bad["runtime"][-2]["Name"] = p.PRIVATE.replace("_u00010000_", "_u00100000_")
            with self.subTest(change=change), self.assertRaises(p.Rejected):
                p.inspect_ir_definitions(bad)

    def test_complete_selected_function_census(self):
        image = SyntheticELF(extra="cmsis_emitted_helper")
        before = copy.deepcopy((image.symbols, image.relocations, image.data))
        proof = self.scan(image)
        self.assertEqual(proof["FunctionsAudited"], 50)
        self.assertEqual(proof["ExecutableInstructionBytes"], 100)
        self.assertEqual(proof["Undefined"], sorted(p.UNDEFINED))
        self.assertTrue(proof["CompleteExecutableCensus"])
        self.assertEqual(before, (image.symbols, image.relocations, image.data))
        self.assertEqual(proof["RequiredCellsSatisfied"], 0)
        for key in ("FullInstructionSemantics", "SourceIRSemantics", "OriginalTranslationUnitOwnership",
                    "AttributeOnlyProtection", "GeneralRegistersOnlyEffectProved", "CPUExecution", "BoardExecution", "GlobalQualification"):
            self.assertIs(proof[key], False)

    def test_missing_private_or_abi_and_weak_handler(self):
        for name in (p.LOCAL[0], p.FORWARD[0], "SVC_Handler"):
            image = SyntheticELF()
            item = next(x for x in image.symbols if x["name"] == name)
            if name == "SVC_Handler":
                item["binding"] = "STB_WEAK"
            else:
                image.symbols.remove(item)
            with self.subTest(name=name), self.assertRaises(p.Rejected):
                self.scan(image)

    def test_symbol_alias_and_literal_numeric_fields(self):
        image = SyntheticELF()
        image.symbols.append(dict(image.symbols[0], name="overlap"))
        with self.assertRaises(p.Rejected):
            self.scan(image)
        image = SyntheticELF()
        image.symbols[0]["size"] = True
        with self.assertRaises(p.Rejected):
            self.scan(image)

    def test_import_and_defined_runtime_rejection(self):
        for name in ("__stack_chk_fail", "__aeabi_dadd", "__aeabi_i2f", "__aeabi_ui2f",
                     "__aeabi_l2d", "__aeabi_ul2d", "__floatsisf", "__gcov0.hidden", "memmove"):
            image = SyntheticELF()
            target = sym(name, "SHN_UNDEF", kind="STT_NOTYPE")
            image.symbols.append(target)
            image.relocations[2, 60] = 2, target
            with self.subTest(name=name), self.assertRaises(p.Rejected):
                self.scan(image)
        for name in ("__cyg_profile_func_enter", "__aeabi_i2f", "__aeabi_ul2d"):
            image = SyntheticELF(extra=name)
            with self.subTest(defined=name), self.assertRaises(p.Rejected):
                self.scan(image)

    def test_disassembly_exact_bytes_membership_and_duplicates(self):
        image = SyntheticELF()
        original = image.dis()
        for bad in (original.replace(b"bf00", b"bf01", 1), original.replace(b" 0:", b" 1:", 1),
                    original + original.splitlines()[1] + b"\n", original.replace(original.splitlines()[1] + b"\n", b"", 1),
                    original + b" ffff: 00bf nop\n"):
            with self.assertRaises(p.Rejected):
                self.scan(image, bad)

    def test_raw_extended_domains_and_mnemonic_register_forms(self):
        for first in (0xEC00, 0xED00, 0xEFFF, 0xFC00, 0xFFFF):
            with self.subTest(first=first), self.assertRaises(p.Rejected):
                p._forms("ordinary", "r0, r1", struct.pack("<HH", first, 0))
        for op, args in (("vldr", "s0,[r0]"), ("vmrs", "r0,fpscr"), ("mrc", "p10,0,r0,c0,c0"),
                         ("dlstp", "lr,r0"), ("mov", "r0,s31"), ("mov", "r0,q15")):
            with self.subTest(op=op), self.assertRaises(p.Rejected):
                p._forms(op, args, bytes.fromhex("00bf"))
        p._forms("bl", "100 <valid_d0_name>", bytes.fromhex("fff7feff"))

    def test_wide_objdump_inline_relocation_is_not_a_branch_operand(self):
        image = SyntheticELF(transfers=True)
        dis = image.dis().replace(b" bl 0\n", b" bl 0 <callee>\t0: R_ARM_THM_CALL\tcallee\n", 1)
        self.scan(image, dis)
        for suffix in (b"\t2: R_ARM_THM_CALL\tcallee", b"\t0: R_ARM_THM_CALL\tcallee garbage",
                       b"\t0: R_ARM_THM_CALL\tcallee\t0: R_ARM_THM_CALL\tcallee"):
            bad = image.dis().replace(b" bl 0\n", b" bl 0 <callee>" + suffix + b"\n", 1)
            with self.assertRaises(p.Rejected):
                self.scan(image, bad)

    def test_direct_branch_hex_addresses_are_not_extended_registers(self):
        for op, operands in (("bne", "d0 <fiber_port_boot_record_fast_check+0x20>"),
                             ("bne", "d6 <fiber_port_boot_record_fast_check+0x26>"),
                             ("bpl", "d0 <fiber_port_boot_check+0x20>"),
                             ("bhi", "d6 <fiber_port_boot_check+0x26>"),
                             ("bcc", "d8 <fiber_port_context_init+0x28>"),
                             ("b", "d0"), ("bl", "d6 <callee>"),
                             ("cbz", "r0, d0 <done>"), ("cbnz", "r7, 0xd8 <done>")):
            with self.subTest(op=op, operands=operands):
                p._forms(op, operands, bytes.fromhex("00bf"))
        for op, operands in (("mov", "r0,d0"), ("mov", "r0,d6"), ("mov", "r0,d8"),
                             ("bne", "r0"), ("bl", "d0,r1"), ("b", "q0"),
                             ("cbz", "d0, d6"), ("cbnz", "r0, d0,r1"),
                             ("vldr", "d0 <not_a_branch>")):
            with self.subTest(op=op, operands=operands), self.assertRaises(p.Rejected):
                p._forms(op, operands, bytes.fromhex("00bf"))

    def test_closed_relocation_kinds_bounds_alignment_and_sites(self):
        for change in ("unknown", "straddle", "misaligned", "transfer-data", "abs32-code", "orphan-instruction"):
            image = SyntheticELF(padding=bytes.fromhex("00bf"))
            old = (2, 4)
            kind, target = image.relocations.pop(old)
            if change == "unknown":
                image.relocations[old] = 255, target
            elif change == "straddle":
                image.relocations[2, image.sections[2].header.sh_size - 1] = kind, target
            elif change == "misaligned":
                image.relocations[2, 5] = kind, target
            elif change == "transfer-data":
                image.relocations[old] = 10, target
            elif change == "abs32-code":
                image.relocations[1, 0] = 2, target
            else:
                image.relocations[1, image.sections[1].header.sh_size - 2] = 10, target
            with self.subTest(change=change), self.assertRaises(p.Rejected):
                self.scan(image)

    def test_actual_thumb_transfer_sites_and_kind_binding(self):
        image = SyntheticELF(transfers=True)
        proof = self.scan(image)
        self.assertEqual([row["SiteForm"] for row in proof["References"][:2]], ["THM_CALL-BL", "THM_JUMP24-B.W"])
        final = SyntheticELF(final=True, transfers=True)
        p.inspect_final(final, CORE, final.dis(), p.inspect_ir_definitions(ir_rows()))
        for change in ("wrong-kind", "interior", "misaligned", "wrong-encoding", "overlap"):
            image = SyntheticELF(transfers=True)
            kind, target = image.relocations.pop((1, 0))
            if change == "wrong-kind":
                image.relocations[1, 0] = 30, target
            elif change == "interior":
                image.relocations[1, 2] = kind, target
            elif change == "misaligned":
                image.relocations[1, 1] = kind, target
            elif change == "wrong-encoding":
                h = image.sections[1].header
                raw = bytes.fromhex("aff30080")
                image.data = image.data[:h.sh_offset] + raw + image.data[h.sh_offset + 4:]
                image.instructions[1, 0] = "bl", "0", raw
                image.relocations[1, 0] = kind, target
            else:
                image.relocations[1, 0] = kind, target
                image.relocations[1, 2] = 30, target
            with self.subTest(change=change), self.assertRaises(p.Rejected):
                self.scan(image)

    def test_padding_and_unowned_literal_pool_are_retained(self):
        proof = self.scan(SyntheticELF(padding=bytes.fromhex("00bf00bf")))
        self.assertEqual(len(proof["Padding"]), 2)
        proof = self.scan(SyntheticELF(pool=True))
        self.assertEqual(len(proof["UnownedMappedPools"]), 1)
        image = SyntheticELF(pool=True)
        image.instructions[1, 0] = ("nop", "", bytes.fromhex("00bf"))
        h = image.sections[1].header
        image.data = image.data[:h.sh_offset] + bytes.fromhex("00bf") + image.data[h.sh_offset + 2:]
        with self.assertRaises(p.Rejected):
            self.scan(image)
        with self.assertRaises(p.Rejected):
            self.scan(SyntheticELF(padding=bytes.fromhex("7047")))

    def test_whole_lower_and_final_vector_binding(self):
        proof = self.scan(SyntheticELF(whole=True), whole=True)
        self.assertEqual(proof["Undefined"], sorted(p.FINAL_WORKER_UNDEFINED))
        for change in ('missing', 'compiler-import'):
            image = SyntheticELF(whole=True)
            target = next(row for row in image.symbols if row['name'] == p.FINAL_WORKER_UNDEFINED[0])
            if change == 'missing':
                image.symbols.remove(target)
            else:
                target['name'] = '__sanitizer_cov_trace_pc'
            with self.subTest(change=change), self.assertRaises(p.Rejected):
                self.scan(image, whole=True)
        image = SyntheticELF(final=True)
        proof = p.inspect_final(image, CORE, image.dis(), p.inspect_ir_definitions(ir_rows()))
        self.assertEqual(proof["FinalRootVectorBindings"]["Words"], 256)
        h = image.sections[3].header
        start = h.sh_offset + 11 * 4
        image.data = image.data[:start] + bytes(4) + image.data[start + 4:]
        with self.assertRaises(p.Rejected):
            p.inspect_final(image, CORE, image.dis(), p.inspect_ir_definitions(ir_rows()))

    def test_fake_surface_boolean_cannot_grant_admission(self):
        with self.assertRaises(p.Rejected):
            image = SyntheticELF()
            p.inspect_lowered(image, CORE, image.dis(), dict(IRDefinitionsValidated=True, Definitions=[]))

    def test_stress_dependency_is_explicit_and_source_identical(self):
        source = b"ordinary unchanged fixture"
        attrs = SimpleNamespace(stress_sources=lambda: dict(Unprotected=source, Function="ctxrt_attribute_stress", RequiredFamilies={}))
        pair = p.stress_source(attrs)
        self.assertEqual(pair["Source"], source)
        self.assertFalse(pair["SourceAnnotationDifference"])
        image = SyntheticELF(stress=True)
        calls = []
        def inspect(image, core, *, stress, mutation):
            calls.append((stress, mutation))
            return dict(StressFamiliesActivated=False, StressCounterEvidence=None)
        attrs.inspect_lowered, attrs.STRESS = inspect, "ctxrt_attribute_stress"
        proof = p.inspect_stress(image, CORE, image.dis(), attrs, supported=True)
        self.assertEqual(proof["Status"], "CM3-LTO-PORT-POLICY-STRESS-CLEAN")
        self.assertEqual(calls, [(True, None)])
        with self.assertRaises(p.Rejected):
            p.inspect_stress(image, CORE, image.dis(), attrs, supported=False)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    output = args.output_dir.absolute()
    if output.exists() or output == ROOT or ROOT in output.parents:
        raise SystemExit("fresh external output directory required")
    sources = [Path(__file__), HERE / "policy.py"]
    opening = {str(path): hashlib.sha256(path.read_bytes()).hexdigest().upper() for path in sources}
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__]))
    closing = {str(path): hashlib.sha256(path.read_bytes()).hexdigest().upper() for path in sources}
    report = dict(Status="PASS" if result.wasSuccessful() and opening == closing else "FAIL", Tests=result.testsRun,
                  Failures=len(result.failures), Errors=len(result.errors), Skipped=len(result.skipped),
                  SourceHashes=opening, SourceDrift=opening != closing, SyntheticControlsOnly=True,
                  CompilerInvoked=False, ActualELFQualified=False, CPUExecution=False, RequiredCellsSatisfied=0)
    output.mkdir(parents=True)
    (output / "results.json").write_text(json.dumps(report, indent=2) + "\n", encoding="ascii")
    print(json.dumps(report), flush=True)
    return 0 if report["Status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
