"""Pure synthetic controls and actual source-anchor checks; no native tools."""

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
SPEC = importlib.util.spec_from_file_location("context_lto_attributes_under_test", HERE / "attributes.py")
a = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(a)


def digest(data):
    return hashlib.sha256(data).hexdigest().upper()


def symbol(name, section="SHN_UNDEF", *, value=0, size=0, kind="STT_NOTYPE", binding="STB_GLOBAL", index=1):
    return dict(name=name, section=section, value=value, size=size, kind=kind,
                binding=binding, visibility="STV_DEFAULT", index=index)


class SyntheticELF:
    """Metadata fixture, not a substitute claim about a genuine ELF parser."""

    def __init__(self, *, stress=False, instrumented_stress=False):
        self.final = False
        self.names = ["", ".text", a.THREAD_SECTION, ".bss", ".rodata"]
        names = [a.STRESS] if stress else list(a.PROTECTED) + [a.COLD]
        if not stress or instrumented_stress:
            names += ["_sub_I_00100_0", "_sub_D_00100_1"]
        self.symbols, self.relocations = [], {}
        contents = {1: bytearray(), 2: bytearray(), 3: bytearray(8), 4: bytearray(64)}
        self.maps = {1: [(0, "t")], 2: [(0, "t")]}
        for name in names:
            section = 2 if name in a.THREAD else 1
            offset = len(contents[section])
            contents[section] += bytes.fromhex("00bf") * 16
            self.maps[section].append((offset, "t"))
            self.symbols.append(symbol(name, section, value=offset | 1, size=32, kind="STT_FUNC",
                                       binding="STB_WEAK" if name == a.PANIC else "STB_GLOBAL"))
        self.header = bytearray(52)
        self.header[:7] = b"\x7fELF\x01\x01\x01"
        struct.pack_into("<HHI", self.header, 16, 1, 40, 1)
        self.sections = [SimpleNamespace(header=SimpleNamespace(sh_size=0, sh_offset=0,
                                                                sh_flags=0, sh_type="SHT_NULL"))]
        self.data = bytes(self.header)
        for index in range(1, 5):
            content = bytes(contents[index])
            self.sections.append(SimpleNamespace(header=SimpleNamespace(
                sh_offset=len(self.data), sh_size=len(content), sh_flags=6 if index < 3 else 3 if index == 3 else 2,
                sh_type="SHT_NOBITS" if index == 3 else "SHT_PROGBITS")))
            self.data += content
        if not stress:
            for offset, name in enumerate(a.FORWARD):
                self.reference(4, offset * 4, 2, name)
            cold = self.function(a.COLD)
            start = cold["value"] & ~1
            for offset, name in ((0, "__cyg_profile_func_enter"), (4, "__cyg_profile_func_exit"),
                                 (8, "__stack_chk_fail"), (12, "__sanitizer_cov_trace_pc")):
                self.put(cold["section"], start + offset, bytes.fromhex("fff7feff"))
                self.reference(cold["section"], start + offset, 10, name)
            counter = symbol("__gcov0." + a.COLD, 3, size=8, kind="STT_OBJECT", binding="STB_LOCAL")
            self.symbols.append(counter)
            self.put(cold["section"], start + 24, bytes(8))
            self.maps[cold["section"]].append((start + 24, "d"))
            self.relocations[cold["section"], start + 24] = (2, counter)
            self.reference(cold["section"], start + 28, 2, "__stack_chk_guard")
            self.reference(4, 32, 2, "__gcov_merge_add")
            for function, name in (("_sub_I_00100_0", "__gcov_init"), ("_sub_D_00100_1", "__gcov_exit")):
                item = self.function(function)
                offset = item["value"] & ~1
                self.put(item["section"], offset, bytes.fromhex("fff7feff"))
                self.reference(item["section"], offset, 10, name)
        if instrumented_stress:
            item = self.function(a.STRESS)
            start = item["value"] & ~1
            for offset, name in enumerate(("__cyg_profile_func_enter", "__cyg_profile_func_exit",
                                           "__stack_chk_fail", "__ubsan_handle_add_overflow",
                                           "__ubsan_handle_out_of_bounds", "__sanitizer_cov_trace_pc")):
                self.put(item["section"], start + offset * 4, bytes.fromhex("fff7feff"))
                self.reference(item["section"], start + offset * 4, 10, name)
            self.maps[item["section"]].append((start + 24, "d"))
            self.put(item["section"], start + 24, bytes(8))
            self.reference(item["section"], start + 24, 2, "__stack_chk_guard")
            counter = symbol("__gcov0." + a.STRESS, 3, size=8, kind="STT_OBJECT", binding="STB_LOCAL")
            self.symbols.append(counter)
            self.relocations[item["section"], start + 28] = (2, counter)
            self.reference(4, 32, 2, "__gcov_merge_add")
            for function, name in (("_sub_I_00100_0", "__gcov_init"), ("_sub_D_00100_1", "__gcov_exit")):
                ctor = self.function(function)
                offset = ctor["value"] & ~1
                self.put(ctor["section"], offset, bytes.fromhex("fff7feff"))
                self.reference(ctor["section"], offset, 10, name)
        for index, item in enumerate(self.symbols):
            item["index"] = index

    def function(self, name):
        return next(item for item in self.symbols if item["name"] == name)

    def reference(self, section, offset, kind, name):
        target = next((item for item in self.symbols if item["name"] == name), None)
        if target is None:
            target = symbol(name, index=len(self.symbols))
            self.symbols.append(target)
        self.relocations[section, offset] = (kind, target)

    def put(self, section, offset, raw):
        start = self.sections[section].header.sh_offset + offset
        self.data = self.data[:start] + raw + self.data[start + len(raw):]

    def section_read(self, section, offset, size):
        h = self.sections[section].header
        if not (0 <= offset and 0 < size and offset + size <= h.sh_size):
            raise ValueError("synthetic section bounds")
        return self.data[h.sh_offset + offset:h.sh_offset + offset + size]

    def mapping(self, section, position):
        rows = sorted(self.maps[section])
        starts = [value for value, _ in rows]
        index = max(i for i, value in enumerate(starts) if value <= position)
        return rows[index][1], starts[index + 1] if index + 1 < len(starts) else self.sections[section].header.sh_size

    def instrument(self, name):
        item = self.function(name)
        start = item["value"] & ~1
        for offset, target in ((0, "__cyg_profile_func_enter"), (4, "__cyg_profile_func_exit")):
            self.put(item["section"], start + offset, bytes.fromhex("fff7feff"))
            self.reference(item["section"], start + offset, 10, target)


def synthetic_width(first):
    return 4 if first >> 11 in (29, 30, 31) else 2


def synthetic_call(raw, place):
    if raw != bytes.fromhex("fff7feff"):
        raise ValueError("synthetic fixture admits only original BL -4")
    return "bl", place, None, -4


CORE = SimpleNamespace(_ELF=SyntheticELF, _width=synthetic_width, _address_form=synthetic_call)


class SourcePlanTests(unittest.TestCase):
    def test_catalog_is_fixed_and_fresh(self):
        first = a.catalog()
        self.assertEqual(len(first["ProtectedFunctions"]), 14)
        self.assertEqual(len(first["ThreadFunctions"]), 3)
        self.assertEqual(len(first["AggregateExpectedUndefined"]), 8)
        first["ProtectedFunctions"].clear()
        self.assertEqual(len(a.catalog()["ProtectedFunctions"]), 14)
        self.assertIs(type(first["RequiredCellCount"]), int)

    def test_plugin_ir_exact_surfaces(self):
        sets = {
            "engine": (set(a.FORWARD) - {a.FORWARD[1], a.FORWARD[2]})
                      | {a.PANIC, a.STATE[0], a.STATE[2], a.STATE[4], a.STATE[5], a.COLD},
            "state": {a.PANIC, a.FORWARD[1]} | set(a.GCOV_IMPORTS),
            "panic": {a.FORWARD[1], a.FORWARD[2]},
        }
        for role, names in sets.items():
            with self.subTest(role=role):
                self.assertTrue(a.inspect_ir_undefined(sorted(names), role)["UndefinedValidated"])
                for bad in ([], sorted(names) + ["memcpy"], sorted(names) + [sorted(names)[0]], [False]):
                    with self.assertRaises(a.Rejected):
                        a.inspect_ir_undefined(bad, role)
        with self.assertRaises(a.Rejected):
            a.inspect_ir_undefined([a.PANIC, a.FORWARD[1]], "state")
        early_mutant = sorted(sets["panic"] | set(a.GCOV_IMPORTS) | {"__cyg_profile_func_enter"})
        self.assertTrue(a.inspect_ir_undefined(early_mutant, "panic", mutation=True)["UndefinedValidated"])

    def source_map(self):
        paths = set(a.SOURCES.values()) | {item[1] for item in a.MUTATIONS.values()}
        paths.add("context/context_runtime_port_abi.h")
        return {path: (ROOT / path).read_bytes() for path in paths}

    def test_all_fourteen_actual_protected_source_pairs(self):
        sources = self.source_map()
        proof = a.inspect_sources(sources)
        self.assertEqual(proof["ProtectedDefinitions"], 14)
        self.assertEqual(proof["ProtectedDeclarations"], 14)
        self.assertEqual(len(proof["Records"]), 28)
        for role in a.MUTATIONS:
            with self.subTest(role=role):
                changed = a.annotation_mutant(role, sources)
                with self.assertRaises(a.Rejected):
                    a.inspect_sources(changed["Sources"])

    def test_specs_adapter_is_one_exact_byte_edit(self):
        condition = b"%{fprofile-arcs|fcondition-coverage|fprofile-generate*|coverage:-lgcov}"
        raw = b"*startfile:\nuntouched\r\n*lib:\n" + condition + b"\n*endfile:\nKEEP"
        proof = a.adapt_specs(raw)
        self.assertEqual(proof["Specs"], raw.replace(condition, condition.replace(b"-lgcov", b"")))
        self.assertEqual(proof["OriginalSha256"], digest(raw))
        self.assertEqual(proof["AdaptedSha256"], digest(proof["Specs"]))
        self.assertFalse(proof["InstrumentationCounterFlagsAdded"])
        for bad in (raw + condition, b"missing", raw.replace(b"coverage:-lgcov", b"coverage: -lgcov"), raw + b"\x00", "text"):
            with self.assertRaises(a.Rejected):
                a.adapt_specs(bad)

    def test_actual_stage_options_not_wrapper_only_intent(self):
        flags = list(a.HOSTILE_FLAGS) + ["-mcpu=cortex-m3", "-mthumb", "-mfloat-abi=soft", "-O2",
                                       "-flto-partition=one", "-nostdlib", "-r", "-flinker-output=nolto-rel"]
        wpa = ("\n".join(flags + ["-fwpa"]) + "\n").encode()
        trans = ("\n".join(flags + ["-fltrans"]) + "\n").encode()
        self.assertTrue(a.require_hostile_options(wpa, trans)["ActualHostileOptionsVerified"])
        for flag in a.HOSTILE_FLAGS:
            with self.subTest(missing=flag):
                with self.assertRaises(a.Rejected):
                    a.require_hostile_options(wpa, trans.replace(flag.encode() + b"\n", b""))
        for extra in ("-fno-instrument-functions", "-finstrument-functions-exclude-function-list=ctxrt",
                      "-fno-stack-protector", "-fno-profile-arcs", "-fno-test-coverage", "-fno-sanitize=all",
                      "-fstack-protector", "-mcpu=cortex-m7", "-mfloat-abi=hard", "-mfpu=fpv4-sp-d16",
                      "-Os", "-lgcov", "-fsanitize=undefined,address", "-flto-partition=none", "-ffat-lto-objects"):
            with self.subTest(extra=extra):
                with self.assertRaises(a.Rejected):
                    a.require_hostile_options(wpa, trans + extra.encode() + b"\n")

    def test_all_three_actual_declaration_definition_anchors(self):
        original = self.source_map()
        saved = copy.deepcopy(original)
        for role in a.MUTATIONS:
            with self.subTest(role=role):
                result = a.annotation_mutant(role, original)
                self.assertEqual(len(result["Edits"]), 2)
                changed = {path for path in original if result["Sources"][path] != original[path]}
                self.assertEqual(changed, {a.SOURCES[role], a.MUTATIONS[role][1]})
                for path in changed:
                    self.assertEqual(original[path].count(b"CTXRT_API_ATTR_SENSITIVE") - 1,
                                     result["Sources"][path].count(b"CTXRT_API_ATTR_SENSITIVE"))
                self.assertEqual([row["Site"] for row in result["Edits"]], ["Declaration", "Definition"])
                self.assertFalse(result["CompiledMutantRejected"])
        self.assertEqual(original, saved)

    def test_anchor_failures_are_not_annotation_controls(self):
        original = self.source_map()
        path = a.MUTATIONS["engine"][1]
        variants = [dict(original), dict(original), dict(original), dict(original)]
        del variants[0][path]
        variants[1][path] += original[path]
        variants[2][path] = original[path].replace(b"ctxrt_v1_current(void)", b"wrong_current(void)")
        variants[3][path] = original[path].replace(b"CTXRT_API_ATTR_SENSITIVE", b"REMOVED")
        for value in variants:
            with self.subTest(value=list(value)):
                with self.assertRaises(a.Rejected):
                    a.annotation_mutant("engine", value)

    def test_mutations_preserve_line_endings_and_unrelated_bytes(self):
        original = {path: data.replace(b"\r\n", b"\n") for path, data in self.source_map().items()}
        original["extra/sentinel.h"] = b"untouched\x00\xff"
        for role in a.MUTATIONS:
            value = a.annotation_mutant(role, original)
            self.assertEqual(value["Sources"]["extra/sentinel.h"], b"untouched\x00\xff")
            self.assertEqual(set(value["Sources"]), set(original))
            for row in value["Edits"]:
                self.assertEqual(value["Sources"][row["Path"]].count(b"\n"), original[row["Path"]].count(b"\n"))

    def test_source_aliases_types_and_foreign_roles_reject(self):
        for path, data in (("../escape.h", b"x"), ("C:/escape.h", b"x"), ("x\\y.h", b"x"), ("ok.h", "text")):
            with self.subTest(path=path):
                with self.assertRaises(a.Rejected):
                    a.annotation_mutant("engine", {path: data})
        with self.assertRaises(a.Rejected):
            a.annotation_mutant("CM7", self.source_map())

    def test_stress_pair_exact_body_and_all_raw_families(self):
        value = a.stress_sources()
        self.assertEqual(value["Protected"].replace(b"CTXRT_DISPATCH_ATTR\n", b""), value["Unprotected"])
        for token in (b"volatile char scratch[32]", b"volatile int", b"input[1] + input[2]", b"scratch[index]"):
            self.assertIn(token, value["Protected"])
        self.assertEqual(len(value["RequiredFamilies"]), 5)
        self.assertEqual(len(a.HOSTILE_FLAGS), 6)
        self.assertFalse(any(flag.startswith("-fno-") for flag in a.HOSTILE_FLAGS))


class LoweredMetadataTests(unittest.TestCase):
    def inspect(self, image=None, **kwargs):
        return a.inspect_lowered(image or SyntheticELF(), CORE, **kwargs)

    def test_synthetic_clean_catalog_and_nonpromotions(self):
        proof = self.inspect()
        self.assertEqual(proof["ProtectedFunctions"], 14)
        self.assertTrue(proof["AllProtectedBodiesClean"])
        self.assertEqual(len(proof["RootEvidence"]), 14)
        self.assertTrue(proof["OrdinaryColdActivityValidated"])
        for field in ("TransitiveProtection", "FullABI", "FullIRSemantics", "CPUExecution", "BoardExecution", "GlobalQualification"):
            self.assertIs(proof[field], False)
        self.assertIs(type(proof["RequiredCellCount"]), int)
        self.assertEqual(proof["RequiredCellCount"], 0)

    def test_mutant_has_actual_named_carrier_calls(self):
        for role, spec in a.MUTATIONS.items():
            with self.subTest(role=role):
                image = SyntheticELF()
                image.instrument(spec[0])
                proof = self.inspect(image, mutation=spec[0])
                self.assertTrue(proof["CompiledAnnotationMutantDetected"])
                self.assertFalse(proof["AllProtectedBodiesClean"])
        with self.assertRaises(a.Rejected):
            self.inspect(mutation="ctxrt_v1_current")
        image = SyntheticELF()
        image.instrument(a.PANIC)
        item = image.function(a.PANIC)
        del image.relocations[item["section"], (item["value"] & ~1) + 4]
        value = self.inspect(image, mutation=a.PANIC)
        self.assertTrue(value["CompiledAnnotationMutantDetected"])
        with self.assertRaises(a.Rejected):
            self.inspect(SyntheticELF(), mutation=a.PANIC)

    def test_unprotected_other_body_is_not_a_mutant_or_positive(self):
        for function in ("ctxrt_v1_current", a.STATE[2], a.PANIC):
            with self.subTest(function=function):
                image = SyntheticELF()
                image.instrument(function)
                with self.assertRaises(a.Rejected):
                    self.inspect(image)
        image = SyntheticELF()
        image.instrument(a.STATE[2])
        with self.assertRaises(a.Rejected):
            self.inspect(image, mutation="ctxrt_v1_current")

    def test_setter_effects_remain_pending_not_inferred_from_cold_identity(self):
        image = SyntheticELF()
        image.instrument(a.SETTER)
        value = self.inspect(image)
        self.assertEqual(value["Status"], "CONTEXT-LTO-ATTRIBUTES-ATTRIBUTION-PENDING")
        self.assertFalse(value["AllProtectedBodiesClean"])
        self.assertFalse(value["ColdInlineAttributionValidated"])
        self.assertEqual(len(value["UnresolvedAttribution"]), 1)
        self.assertFalse(value["UnresolvedAttribution"][0]["AttributionValidated"])

    def test_no_mutation_of_input_metadata_or_bytes(self):
        image = SyntheticELF()
        before = copy.deepcopy((image.symbols, image.relocations, image.data, image.maps))
        self.inspect(image)
        self.assertEqual(before, (image.symbols, image.relocations, image.data, image.maps))

    def test_header_kind_endian_hard_float_and_ir_reject(self):
        for offset, raw in ((4, b"\x02"), (5, b"\x02"), (16, b"\x02\x00"), (18, b"\x3e\x00"), (36, b"\x00\x04\x00\x05")):
            with self.subTest(offset=offset):
                image = SyntheticELF()
                image.data = image.data[:offset] + raw + image.data[offset + len(raw):]
                with self.assertRaises(a.Rejected):
                    self.inspect(image)
        image = SyntheticELF()
        image.names[4] = ".gnu.lto_something"
        with self.assertRaises(a.Rejected):
            self.inspect(image)

    def test_exact_catalog_alias_and_thread_section(self):
        variants = []
        missing = SyntheticELF()
        missing.symbols.remove(missing.function("ctxrt_v1_init"))
        variants.append(missing)
        alias = SyntheticELF()
        extra = dict(alias.function("ctxrt_v1_init"), name="alias")
        alias.symbols.append(extra)
        variants.append(alias)
        thread = SyntheticELF()
        thread.names[2] = ".text.wrong"
        variants.append(thread)
        for image in variants:
            with self.assertRaises(a.Rejected):
                self.inspect(image)

    def test_constructor_numeric_lto_suffixes(self):
        for suffix in ("", ".lto_priv.0", ".lto_priv.1", ".0", ".1"):
            with self.subTest(suffix=suffix):
                image = SyntheticELF()
                for base in ("_sub_I_00100_0", "_sub_D_00100_1"):
                    image.function(base)["name"] += suffix
                value = self.inspect(image)
                self.assertEqual({row["Name"] for row in value["CompilerConstructors"]},
                                 {"_sub_I_00100_0" + suffix, "_sub_D_00100_1" + suffix})
                self.assertTrue(value["AllProtectedBodiesClean"])

    def test_constructor_suffix_does_not_admit_arbitrary_names(self):
        for suffix in (".lto_priv", ".lto_priv.", ".lto_priv.x", ".lto_priv.-1", ".x", ".",
                       ".1.2", ".lto_priv.0.1", ".lto_priv.0.cold", ".0.lto_priv.1"):
            with self.subTest(suffix=suffix):
                image = SyntheticELF()
                image.function("_sub_I_00100_0")["name"] += suffix
                with self.assertRaisesRegex(a.Rejected, "exact lowered function catalog"):
                    self.inspect(image)

    def test_constructor_suffix_retains_per_body_validation(self):
        image = SyntheticELF()
        name = "_sub_I_00100_0.lto_priv.0"
        image.function("_sub_I_00100_0")["name"] = name
        item = image.function(name)
        start = item["value"] & ~1
        for offset, target in ((8, "__cyg_profile_func_enter"), (12, "__cyg_profile_func_exit")):
            image.put(item["section"], start + offset, bytes.fromhex("fff7feff"))
            image.reference(item["section"], start + offset, 10, target)
        with self.assertRaisesRegex(a.Rejected, "compiler constructor hook family"):
            self.inspect(image)

    def test_literal_integer_symbol_and_relocation_fields(self):
        for field in ("value", "size", "index", "section"):
            with self.subTest(field=field):
                image = SyntheticELF()
                image.function("ctxrt_v1_init")[field] = False
                with self.assertRaises(a.Rejected):
                    self.inspect(image)
        image = SyntheticELF()
        pair = image.relocations.pop((4, 0))
        image.relocations[4, False] = pair
        with self.assertRaises(a.Rejected):
            self.inspect(image)

    def test_foreign_undefined_and_unreferenced_import(self):
        for name in ("memcpy", "__ubsan_unclassified", "__ubsan_handle_pointer_overflow"):
            with self.subTest(name=name):
                image = SyntheticELF()
                image.symbols.append(symbol(name, index=len(image.symbols)))
                with self.assertRaises(a.Rejected):
                    self.inspect(image)

    def test_cold_activity_and_counter_ownership_required(self):
        image = SyntheticELF()
        cold = image.function(a.COLD)
        del image.relocations[cold["section"], (cold["value"] & ~1)]
        with self.assertRaises(a.Rejected):
            self.inspect(image)
        image = SyntheticELF()
        image.function("__gcov0." + a.COLD)["name"] = "__gcov0.ctxrt_v1_current"
        with self.assertRaises(a.Rejected):
            self.inspect(image)

    def test_wrong_hook_addend_or_instruction_boundary(self):
        image = SyntheticELF()
        cold = image.function(a.COLD)
        image.put(cold["section"], cold["value"] & ~1, bytes.fromhex("00bf00bf"))
        with self.assertRaises((a.Rejected, ValueError)):
            self.inspect(image)
        image = SyntheticELF()
        cold = image.function(a.COLD)
        start = cold["value"] & ~1
        pair = image.relocations.pop((cold["section"], start))
        image.relocations[cold["section"], start + 2] = pair
        with self.assertRaises(a.Rejected):
            self.inspect(image)

    def test_original_hook_tail_template_and_changed_template_reject(self):
        image = SyntheticELF()
        cold = image.function(a.COLD)
        offset = (cold["value"] & ~1) + 4
        image.put(cold["section"], offset, bytes.fromhex("fff7febf"))
        _, target = image.relocations[cold["section"], offset]
        image.relocations[cold["section"], offset] = (30, target)
        value = self.inspect(image)
        self.assertTrue(next(row for row in value["OrdinaryEvidence"] if row["Offset"] == offset)["OriginalHookTransferValidated"])
        image.put(cold["section"], offset, bytes.fromhex("fff7fcbf"))
        with self.assertRaises(a.Rejected):
            self.inspect(image)

    def test_bad_mapping_extent_and_arm_mapping(self):
        for rows in ([(0, "a")], [(0, "t"), (1, "d")]):
            image = SyntheticELF()
            image.maps[1] = rows
            with self.assertRaises(a.Rejected):
                self.inspect(image)

    def test_stress_requires_family_effects_not_any_annotation_failure(self):
        image = SyntheticELF(stress=True)
        proof = self.inspect(image, stress=True)
        self.assertEqual(proof["ProtectedFunctions"], 1)
        self.assertFalse(proof["StressFamiliesActivated"])
        image.instrument(a.STRESS)
        with self.assertRaises(a.Rejected):
            self.inspect(image, stress=True, mutation=a.STRESS)
        with self.assertRaises(a.Rejected):
            self.inspect(SyntheticELF(stress=True), stress=1)

    def test_unprotected_stress_all_families_with_carrier_counter(self):
        image = SyntheticELF(stress=True, instrumented_stress=True)
        proof = self.inspect(image, stress=True, mutation=a.STRESS)
        self.assertTrue(proof["StressFamiliesActivated"])
        self.assertEqual(proof["Status"], "CONTEXT-LTO-ANNOTATION-MUTANT-DETECTED")
        counters = [row for row in proof["RootEvidence"][0]["References"] if row["CompilerCounter"]]
        self.assertEqual(len(counters), 1)
        self.assertEqual(counters[0]["ResolvedABS32"]["Symbol"], "__gcov0." + a.STRESS)

    def test_stress_ctor_metadata_cannot_replace_carrier_counter(self):
        for remove_definition in (False, True):
            with self.subTest(remove_definition=remove_definition):
                image = SyntheticELF(stress=True, instrumented_stress=True)
                item = image.function(a.STRESS)
                del image.relocations[item["section"], (item["value"] & ~1) + 28]
                if remove_definition:
                    image.symbols.remove(image.function("__gcov0." + a.STRESS))
                with self.assertRaisesRegex(a.Rejected, "stress profiling carrier"):
                    self.inspect(image, stress=True, mutation=a.STRESS)

    def test_stress_counter_requires_actual_resolved_reference(self):
        for change in ("wrong-kind", "past-counter", "outside-storage"):
            with self.subTest(change=change):
                image = SyntheticELF(stress=True, instrumented_stress=True)
                item = image.function(a.STRESS)
                site = item["section"], (item["value"] & ~1) + 28
                kind, target = image.relocations[site]
                if change == "wrong-kind":
                    image.relocations[site] = (3, target)
                elif change == "past-counter":
                    image.put(*site, struct.pack("<I", 8))
                else:
                    target["value"] = image.sections[target["section"]].header.sh_size
                with self.assertRaisesRegex(a.Rejected, "stress profiling carrier"):
                    self.inspect(image, stress=True, mutation=a.STRESS)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    output = args.output_dir.absolute()
    if not output.is_absolute() or output.exists() or output == ROOT or ROOT in output.parents:
        raise SystemExit("fresh external output directory required")
    watched = [Path(__file__), HERE / "attributes.py"]
    watched += [ROOT / path for path in set(a.SOURCES.values()) | {item[1] for item in a.MUTATIONS.values()}]
    watched.append(ROOT / "context/context_runtime_port_abi.h")
    opening = {str(path): digest(path.read_bytes()) for path in watched}
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__]))
    closing = {str(path): digest(path.read_bytes()) for path in watched}
    report = dict(Status="PASS" if result.wasSuccessful() and opening == closing else "FAIL",
                  Tests=result.testsRun, Failures=len(result.failures), Errors=len(result.errors),
                  Skipped=len(result.skipped), SourceHashes=opening, SourceDrift=opening != closing,
                  SyntheticMetadataControls=True, ActualSourceAnchors=True, ActualCompilerInvoked=False,
                  ActualLoweredELFQualified=False, CPUExecution=False, RequiredCellCount=0)
    output.mkdir(parents=True)
    (output / "results.json").write_text(json.dumps(report, indent=2) + "\n", encoding="ascii")
    print(json.dumps(report), flush=True)
    return 0 if report["Status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
