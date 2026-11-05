"""Pure synthetic link-contract controls; no real ELF parsing or execution."""
import argparse
import copy
import hashlib
import importlib.util
import json
import struct
import sys
import tempfile
import traceback
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
AUDIT = HERE / "audit.py"
EXPECTED_METHODS = 20
PUBLIC = ("ctxrt_v1_init", "ctxrt_v1_current", "ctxrt_v1_set_dispatcher", "ctxrt_v1_start", "ctxrt_v1_yield")
FORWARD = ("fiber_port_context_init", "fiber_port_runtime_memory_barrier", "fiber_port_panic_wait",
           "fiber_port_require_scheduler_configuration_environment", "fiber_port_runtime_prepare_start",
           "fiber_port_runtime_select_first", "fiber_port_runtime_start_first", "fiber_port_runtime_schedule")
ANCHOR = "fiber_internal_runtime_port_abi_v1_anchor"
SLOT = "fiber_internal_runtime_current_context_slot"
PRIVATE = ("fiber_port_context_cohort_armv7m_p0x434D3033u_l0x00010001u_f0_e0_h1_j1_v1_d0_r0_z8u_y0_w2_g4_"
           "u00010000_i0_o0xFFFFFFFDu_c0_s0_x0_m0_a0_b0_t0_n0_k0_q0")
STORAGE = "fiber_port_storage_cohort_arm_cm3_v1_r0"
EXPECT = ".fiber_port_context_cohort_expectation"
EXPECT_NAMES = ("fiber_port_storage_cohort_consumer_expectation", "fiber_port_context_cohort_build_expectation")
ATTRS = ('Attribute Section: aeabi\nFile Attributes\n  Tag_CPU_name: "7-M"\n'
         '  Tag_CPU_arch: v7\n  Tag_CPU_arch_profile: Microcontroller\n  Tag_THUMB_ISA_use: Thumb-2\n')
a = None


def sha(data):
    return hashlib.sha256(data).hexdigest().upper()


class Header(SimpleNamespace):
    def __getitem__(self, key):
        return getattr(self, key)


class Section:
    def __init__(self, owner, name, address, offset, size, flags, kind="SHT_PROGBITS", alignment=4):
        self.owner, self.name = owner, name
        self.header = Header(sh_addr=address, sh_offset=offset, sh_size=size, sh_flags=flags,
                             sh_type=kind, sh_addralign=alignment)

    def data(self):
        h = self.header
        return self.owner.data[h.sh_offset:h.sh_offset + h.sh_size]


class FakeELF:
    """Explicit metadata plus actual backing bytes, not a qualified parser."""
    def __init__(self, final, length):
        self.final, self.data = final, bytes(length)
        self.sections, self.symbols, self.relocations, self.loads = [], [], {}, []
        self.mapping_kind = "t"
        self.elf = SimpleNamespace(header=Header(e_entry=0x401 if final else 0,
                                                  e_flags=0x05000200 if final else 0x05000000),
                                   get_section_by_name=self.get_section_by_name)
        self.write(0, b"\x7fELF\x01\x01\x01" + bytes(9))
        self.write(16, struct.pack("<HHII", 2 if final else 1, 40, 1, self.elf.header.e_entry))
        self.write(36, struct.pack("<IH", self.elf.header.e_flags, 52))
        self.section("", 0, 0, 0, 0, "SHT_NULL", 0)

    @property
    def names(self):
        return [row["name"] for row in self.symbols]

    def write(self, offset, data):
        raw = bytearray(self.data)
        raw[offset:offset + len(data)] = data
        self.data = bytes(raw)

    def section(self, name, address, offset, size, flags, kind="SHT_PROGBITS", alignment=4):
        self.sections.append(Section(self, name, address, offset, size, flags, kind, alignment))
        return len(self.sections) - 1

    def get_section_by_name(self, name):
        return next((row for row in self.sections if row.name == name), None)

    def mapping(self, section, address):
        h = self.sections[section].header
        return self.mapping_kind, h.sh_addr + h.sh_size

    def symbol(self, name):
        return next(row for row in self.symbols if row["name"] == name)

    def add(self, name, section, value, size, kind="STT_FUNC", binding="STB_GLOBAL"):
        row = dict(name=name, section=section, value=value, size=size, kind=kind,
                   binding=binding, visibility="STV_DEFAULT", index=len(self.symbols) + 1)
        self.symbols.append(row)
        return row


class Fixture:
    def __init__(self, emit=True):
        self.emit = emit
        machine, startup, final = FakeELF(False, 0x33C), FakeELF(False, 0x804), FakeELF(True, 0xC3C)
        self.machine, self.startup, self.final = machine, startup, final
        machine.section(".text", 0, 0x100, 0x200, 6)
        machine.section(".rodata", 0, 0x300, 0x20, 2)
        machine.section(".bss.fiber_runtime_current_context_slot", 0, 0x320, 4, 3, "SHT_NOBITS")
        machine.section(".pilot_roots", 0, 0x320, 20, 2)
        machine.section(EXPECT, 0, 0x334, 8, 2)
        startup.section(".isr_vector", 0, 0x400, 1024, 2, alignment=1024)
        startup.section(".text.Reset_Handler", 0, 0x800, 4, 6)
        final.section(".isr_vector", 0, 0x400, 1024, 2, alignment=1024)
        final.section(".text", 0x400, 0x800, 0x400, 6)
        final.section(".rodata", 0x800, 0xC00, 0x20, 2)
        final.section(".pilot_roots", 0x820, 0xC20, 20, 2)
        final.section(EXPECT, 0x834, 0xC34, 8, 2)
        final.section(".bss", 0x20000000, 0xC3C, 0x20, 3, "SHT_NOBITS")
        final.loads = [dict(Vaddr=0, Offset=0x400, FileSize=0x83C, MemorySize=0x83C, Flags=5),
                       dict(Vaddr=0x20000000, Offset=0xC3C, FileSize=0, MemorySize=0x20, Flags=6)]
        functions = (*PUBLIC, *FORWARD, "SVC_Handler", "PendSV_Handler", "pilot_fault", "fiber_panic",
                     "fiber_port_start_first_context")
        for index, name in enumerate(functions):
            offset = index * 8
            machine.add(name, 1, offset | 1, 4)
            final.add(name, 2, (0x440 + offset) | 1, 4)
        startup.add("Reset_Handler", 2, 1, 4)
        final.add("Reset_Handler", 2, 0x401, 4)
        for name, offset, binding in ((PRIVATE, 0, "STB_GLOBAL"), (ANCHOR, 2, "STB_LOCAL"),
                                      (STORAGE, 4, "STB_GLOBAL")):
            machine.add(name, 2, offset, 1, "STT_OBJECT", binding)
            final.add(name, 3, 0x800 + offset, 1, "STT_OBJECT", binding)
            machine.write(0x300 + offset, b"\x01")
            final.write(0xC00 + offset, b"\x01")
        machine.add(SLOT, 3, 0, 4, "STT_OBJECT", "STB_LOCAL")
        final.add(SLOT, 6, 0x20000010, 4, "STT_OBJECT", "STB_LOCAL")
        for index, name in enumerate(EXPECT_NAMES):
            machine.add(name, 5, index * 4, 4, "STT_OBJECT", "STB_LOCAL")
            final.add(name, 5, 0x834 + index * 4, 4, "STT_OBJECT", "STB_LOCAL")
        machine.add("pilot_context_roots", 4, 0, 20, "STT_OBJECT")
        final.add("pilot_context_roots", 4, 0x820, 20, "STT_OBJECT")
        startup.add("pilot_vectors", 1, 0, 1024, "STT_OBJECT")
        final.add("pilot_vectors", 1, 0, 1024, "STT_OBJECT")
        for section, names in ((4, PUBLIC), (5, (STORAGE, PRIVATE))):
            h = final.sections[section].header
            for index, name in enumerate(names):
                machine.relocations[section, index * 4] = (2, machine.symbol(name))
                if emit:
                    final.relocations[section, index * 4] = (2, final.symbol(name))
                final.write(h.sh_offset + index * 4, struct.pack("<I", final.symbol(name)["value"]))
        words = [final.symbol("pilot_fault")["value"]] * 256
        words[0] = 0x20010000
        for index in (7, 8, 9, 10, 13):
            words[index] = 0
        for index, name in ((1, "Reset_Handler"), (11, "SVC_Handler"), (14, "PendSV_Handler")):
            words[index] = final.symbol(name)["value"]
        final.write(0x400, struct.pack("<256I", *words))
        self.image = SimpleNamespace(prelink=machine, final=final,
            providers={"machine.o": machine, "startup.o": startup}, float_abi="soft", link_map_hash="A" * 64,
            placements={("machine.o", ".text"): (0x440, 0x200),
                        ("machine.o", ".rodata"): (0x800, 0x20),
                        ("machine.o", ".bss.fiber_runtime_current_context_slot"): (0x20000010, 4),
                        ("machine.o", ".pilot_roots"): (0x820, 20),
                        ("machine.o", EXPECT): (0x834, 8),
                        ("startup.o", ".isr_vector"): (0, 1024),
                        ("startup.o", ".text.Reset_Handler"): (0x400, 4)})

    def check(self, **kwargs):
        options = dict(emit_relocs=self.emit, machine_attributes_text=ATTRS)
        options.update(kwargs)
        return a.audit(self.image, ATTRS, **options)


class AuditTests(unittest.TestCase):
    def rejects(self, fixture, **kwargs):
        with self.assertRaises(a.Rejected):
            fixture.check(**kwargs)

    def test_emit_positive(self):
        result = Fixture().check()
        self.assertIs(result["FinalLinkContractValidated"], True)
        self.assertEqual(result["OriginalPointerRelocations"], 7)
        self.assertEqual(result["AppliedPointerRelocations"], 7)

    def test_ordinary_positive_and_requires_original_rels(self):
        fixture = Fixture(False)
        self.assertEqual(fixture.check()["AppliedPointerRelocations"], 0)
        fixture.machine.relocations.clear()
        self.rejects(fixture)

    def test_anchor_and_slot_global_on_both_sides_reject(self):
        for name in (ANCHOR, SLOT):
            fixture = Fixture()
            for elf in (fixture.machine, fixture.final):
                elf.symbol(name)["binding"] = "STB_GLOBAL"
            with self.subTest(name=name):
                self.rejects(fixture)

    def test_public_five_missing_extra_or_wrong_binding_reject(self):
        for name in PUBLIC:
            fixture = Fixture()
            fixture.final.symbols.remove(fixture.final.symbol(name))
            with self.subTest(missing=name):
                self.rejects(fixture)
        fixture = Fixture()
        fixture.final.add("ctxrt_v1_foreign", 2, 0x701, 4)
        self.rejects(fixture)
        fixture = Fixture()
        fixture.final.symbol(PUBLIC[0])["binding"] = "STB_LOCAL"
        self.rejects(fixture)

    def test_forward_eight_missing_or_wrong_type_reject(self):
        for name in FORWARD:
            fixture = Fixture()
            fixture.machine.symbol(name)["kind"] = "STT_OBJECT"
            with self.subTest(name=name):
                self.rejects(fixture)

    def test_handler_definition_ambiguity_thumb_and_size_reject(self):
        for change in ("duplicate", "thumb", "size", "mapping"):
            fixture = Fixture()
            row = fixture.final.symbol("SVC_Handler")
            if change == "duplicate":
                fixture.final.symbols.append(dict(row))
            elif change == "thumb":
                row["value"] &= ~1
            elif change == "size":
                row["size"] += 2
            else:
                fixture.final.mapping_kind = "d"
            with self.subTest(change=change):
                self.rejects(fixture)

    def test_provider_origin_map_and_cross_name_alias_reject(self):
        for change in ("placement", "provider", "alias", "hash"):
            fixture = Fixture()
            if change == "placement":
                fixture.image.placements["machine.o", ".text"] = (0x444, 0x200)
            elif change == "provider":
                fixture.startup.symbols.append(dict(fixture.machine.symbol(PUBLIC[0])))
            elif change == "alias":
                row = dict(fixture.final.symbol("PendSV_Handler"), name="foreign_alias")
                fixture.final.symbols.append(row)
            else:
                fixture.image.link_map_hash = "not-a-hash"
            with self.subTest(change=change):
                self.rejects(fixture)

    def test_legacy_undefined_and_foreign_cohort_reject(self):
        for name, section in (("fiber_init", 2), ("fiber_v1_new", 2), ("unresolved", "SHN_UNDEF"),
                              ("fiber_port_context_cohort_foreign", 3)):
            fixture = Fixture()
            fixture.final.add(name, section, 0x701, 4)
            with self.subTest(name=name):
                self.rejects(fixture)

    def test_vector_geometry_entry_msp_and_all_template_slots_reject(self):
        for index in (0, 1, 2, 7, 11, 13, 14, 255):
            fixture = Fixture()
            at = 0x400 + index * 4
            value = struct.unpack_from("<I", fixture.final.data, at)[0]
            fixture.final.write(at, struct.pack("<I", value ^ 2))
            with self.subTest(index=index):
                self.rejects(fixture)
        fixture = Fixture()
        fixture.final.write(24, struct.pack("<I", 0x403))
        self.rejects(fixture)
        fixture = Fixture()
        fixture.final.sections[1].header.sh_addralign = 4
        self.rejects(fixture)

    def test_pointer_order_and_applied_word_reject(self):
        for section in (4, 5):
            fixture = Fixture()
            offset = fixture.final.sections[section].header.sh_offset
            raw = fixture.final.data[offset:offset + 8]
            fixture.final.write(offset, raw[4:8] + raw[:4])
            with self.subTest(section=section):
                self.rejects(fixture)

    def test_original_relocation_addend_kind_target_and_membership_reject(self):
        for section in (4, 5):
            for change in ("addend", "kind", "target", "missing", "extra"):
                fixture = Fixture()
                key = (section, 0)
                if change == "addend":
                    fixture.machine.write(fixture.machine.sections[section].header.sh_offset, b"\x04\0\0\0")
                elif change == "kind":
                    fixture.machine.relocations[key] = (10, fixture.machine.relocations[key][1])
                elif change == "target":
                    fixture.machine.relocations[key] = (2, fixture.machine.symbol("pilot_fault"))
                elif change == "missing":
                    del fixture.machine.relocations[key]
                else:
                    fixture.machine.relocations[section, 2] = fixture.machine.relocations[key]
                with self.subTest(section=section, change=change):
                    self.rejects(fixture)

    def test_applied_relocation_kind_target_missing_extra_and_ordinary_reject(self):
        for change in ("kind", "target", "missing", "extra"):
            fixture = Fixture()
            if change == "kind":
                fixture.final.relocations[4, 0] = (10, fixture.final.symbol(PUBLIC[0]))
            elif change == "target":
                fixture.final.relocations[4, 0] = (2, fixture.final.symbol(PUBLIC[1]))
            elif change == "missing":
                del fixture.final.relocations[4, 0]
            else:
                fixture.final.relocations[4, 2] = fixture.final.relocations[4, 0]
            with self.subTest(change=change):
                self.rejects(fixture)
        fixture = Fixture(False)
        fixture.final.relocations[4, 0] = (2, fixture.final.symbol(PUBLIC[0]))
        self.rejects(fixture)

    def test_readonly_anchor_cohorts_and_tables_reject(self):
        for name in (ANCHOR, PRIVATE, STORAGE):
            fixture = Fixture()
            fixture.final.write(0xC00 + fixture.machine.symbol(name)["value"], b"\x02")
            with self.subTest(name=name):
                self.rejects(fixture)
        for section in (3, 4, 5):
            fixture = Fixture()
            fixture.final.sections[section].header.sh_flags |= 1
            with self.subTest(section=section):
                self.rejects(fixture)

    def test_slot_dedicated_extent_zero_fill_and_load_permissions_reject(self):
        for change in ("size", "section", "nobits", "writable", "executable", "filebacked"):
            fixture = Fixture()
            if change == "size":
                fixture.machine.sections[3].header.sh_size = 8
            elif change == "section":
                fixture.machine.sections[3].name = ".bss.foreign"
            elif change == "nobits":
                fixture.final.sections[6].header.sh_type = "SHT_PROGBITS"
            elif change == "writable":
                fixture.final.loads[1]["Flags"] = 4
            elif change == "executable":
                fixture.final.loads[1]["Flags"] = 7
            else:
                fixture.final.loads[1]["FileSize"] = 0x20
            with self.subTest(change=change):
                self.rejects(fixture)

    def test_machine_and_final_attributes_required_exact_soft_profile(self):
        bad = (None, b"attributes", ATTRS.replace("v7", "v6-M"), ATTRS.replace('"7-M"', '"Cortex-M7"'),
               ATTRS + "  Tag_FP_arch: VFPv4\n", ATTRS + "  Tag_ABI_HardFP_use: SP only\n",
               ATTRS + "  tag_cpu_arch: v7\n", ATTRS + "  Tag_CPU_arch: v7\n", ATTRS + "\0")
        for value in bad:
            with self.subTest(machine=value), self.assertRaises(a.Rejected):
                a.audit(Fixture().image, ATTRS, machine_attributes_text=value)
            with self.subTest(final=value), self.assertRaises(a.Rejected):
                a.audit(Fixture().image, value, machine_attributes_text=ATTRS)

    def test_raw_headers_abi_flags_and_literal_selector_reject(self):
        for which, offset, data in (("machine", 18, b"\x03\0"), ("final", 16, b"\x01\0"),
                                    ("machine", 36, struct.pack("<I", 0x05000400)),
                                    ("final", 36, struct.pack("<I", 0x05000600)),
                                    ("final", 4, b"\x02")):
            fixture = Fixture()
            getattr(fixture, which).write(offset, data)
            with self.subTest(which=which, offset=offset):
                self.rejects(fixture)
        for value in (0, 1, None, "true"):
            with self.subTest(selector=value):
                self.rejects(Fixture(), emit_relocs=value)
        fixture = Fixture()
        fixture.image.float_abi = "hard"
        self.rejects(fixture)

    def test_symbol_numeric_bool_and_float_aliases_reject(self):
        for field in ("section", "value", "size", "index"):
            for value in (True, False, 1.0):
                fixture = Fixture()
                fixture.final.symbol(PUBLIC[0])[field] = value
                with self.subTest(field=field, value=value):
                    self.rejects(fixture)

    def test_section_load_and_relocation_numeric_aliases_reject(self):
        for field in ("sh_addr", "sh_offset", "sh_size", "sh_flags", "sh_addralign"):
            fixture = Fixture()
            setattr(fixture.final.sections[4].header, field, True)
            with self.subTest(section_field=field):
                self.rejects(fixture)
        for field in ("Vaddr", "MemorySize", "FileSize", "Flags", "Offset"):
            fixture = Fixture()
            fixture.final.loads[0][field] = False
            with self.subTest(load_field=field):
                self.rejects(fixture)
        fixture = Fixture()
        fixture.machine.relocations[4, 0] = (2.0, fixture.machine.symbol(PUBLIC[0]))
        self.rejects(fixture)
        fixture = Fixture()
        row = dict(fixture.machine.symbol(PUBLIC[0]), index=True)
        fixture.machine.relocations[4, 0] = (2, row)
        self.rejects(fixture)

    def test_report_counters_and_nonclaims_are_typed(self):
        result = Fixture().check()
        self.assertEqual(result["Status"], "CM3-LTO-DIRECT-LINK-CONTRACT-PASS-NOT-QUALIFIED")
        for name in ("Qualification", "FullABIProof", "SourceIRProof", "SourceToMachineSemanticProof",
                     "OriginalTranslationUnitOwnership", "CanonicalProtocolValidated", "InstructionEquivalence",
                     "PolicyEquivalence", "FinalReferenceParity", "CompleteObjectProof", "KernelRuntimeProof",
                     "CpuExecution", "BoardExecution", "GlobalFreezeQualified", "RequiredCellSatisfied"):
            with self.subTest(name=name):
                self.assertIs(result[name], False)
        for name, expected in (("OriginalPointerRelocations", 7), ("AppliedPointerRelocations", 7),
                               ("RequiredCellsSatisfied", 0)):
            self.assertIs(type(result[name]), int)
            self.assertEqual(result[name], expected)
        self.assertEqual(result["Vectors"]["Words"], 256)
        self.assertIs(result["Vectors"]["OriginalVectorRelocationsAudited"], False)

    def test_pure_audit_does_not_mutate_inputs_or_access_files(self):
        fixture = Fixture()
        before = copy.deepcopy(fixture.image)
        with patch("builtins.open", side_effect=AssertionError("pure audit opened file")), \
                patch.object(Path, "open", side_effect=AssertionError("pure audit opened path")), \
                patch.object(Path, "read_bytes", side_effect=AssertionError("pure audit read path")), \
                patch.object(Path, "read_text", side_effect=AssertionError("pure audit read text")), \
                patch("subprocess.Popen", side_effect=AssertionError("pure audit spawned process")):
            fixture.check()
        for name in ("prelink", "final"):
            original, current = getattr(before, name), getattr(fixture.image, name)
            self.assertEqual(original.data, current.data)
            self.assertEqual(original.symbols, current.symbols)
            self.assertEqual(original.relocations, current.relocations)
            self.assertEqual([vars(s.header) for s in original.sections], [vars(s.header) for s in current.sections])
        self.assertEqual(before.placements, fixture.image.placements)
        self.assertFalse(hasattr(fixture.image, "_contract_machine_owner"))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    output, temporary = args.output_dir.resolve(), Path(tempfile.gettempdir()).resolve()
    if (output.exists() or args.output_dir.is_symlink() or output.is_relative_to(REPO)
            or REPO.is_relative_to(output) or not output.is_relative_to(temporary)):
        parser.error("fresh external TEMP output directory required")
    report = dict(Status="FAIL", Tests=0, ExpectedTestMethods=EXPECTED_METHODS, Failures=0, Errors=0, Skipped=0,
        SourceHashes={}, SourceDrift=[], SourceClosureVerified=False, ClosingFilesVerified=0,
        Scope="PURE_SYNTHETIC_CM3_LTO_DIRECT_LINK_CONTRACT_CONTROLS_ONLY", SyntheticInputs=True,
        ActualELFTested=False, ActualMachineDecoderTested=False, ActualFinalLinkTested=False,
        Qualification=False, NativeCommandsExecuted=0, ToolInvocations=0, FullABIProof=False,
        SourceIRProof=False, SourceToMachineSemanticProof=False, OriginalTranslationUnitOwnership=False,
        CanonicalProtocolValidated=False, InstructionEquivalence=False, PolicyEquivalence=False,
        FinalReferenceParity=False, CompleteObjectProof=False, KernelRuntimeProof=False,
        CpuExecution=False, BoardExecution=False, GlobalFreezeQualified=False,
        RequiredCellSatisfied=False, RequiredCellsSatisfied=0)
    paths = (Path(__file__).resolve(), AUDIT)
    try:
        if sys.flags.optimize or not __debug__:
            raise ValueError("optimized interpreter unsupported")
        buffers = {item: item.read_bytes() for item in paths}
        report["SourceHashes"] = {str(item): sha(data) for item, data in buffers.items()}
        global a
        with patch("subprocess.Popen", side_effect=AssertionError("pure controls cannot execute processes")), \
                patch("os.system", side_effect=AssertionError("pure controls cannot execute processes")):
            spec = importlib.util.spec_from_file_location("synthetic_cm3_lto_link_audit", AUDIT)
            a = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = a
            exec(compile(buffers[AUDIT], str(AUDIT), "exec"), a.__dict__)
            suite = unittest.defaultTestLoader.loadTestsFromTestCase(AuditTests)
            count = suite.countTestCases()
            if count != EXPECTED_METHODS:
                raise ValueError("exact 20 synthetic control methods required")
            result = unittest.TextTestRunner(verbosity=2).run(suite)
        report.update(Tests=result.testsRun, Failures=len(result.failures), Errors=len(result.errors),
            Skipped=len(result.skipped), FailureDetails=[dict(Test=str(case), Detail=detail)
            for case, detail in result.failures + result.errors])
        if result.wasSuccessful() and result.testsRun == count and not result.skipped:
            report["Status"] = "PASS"
    except Exception:
        report.update(Status="FAIL", Error=traceback.format_exc(), Errors=report["Errors"] + 1)
    finally:
        for item, digest in report["SourceHashes"].items():
            try:
                if sha(Path(item).read_bytes()) != digest:
                    report["SourceDrift"].append(item)
                else:
                    report["ClosingFilesVerified"] += 1
            except OSError:
                report["SourceDrift"].append(item)
        report["SourceClosureVerified"] = len(report["SourceHashes"]) == 2 and not report["SourceDrift"]
        if not report["SourceClosureVerified"]:
            report["Status"] = "FAIL"
    output.mkdir(parents=True, exist_ok=False)
    target = output / "results.json"
    target.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="ascii")
    print("Receipt:", target, sha(target.read_bytes()))
    return 0 if report["Status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
