"""Pure synthetic CM3 policy-aware link-contract controls; no ELF/tool runs."""
import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys
import tempfile
import traceback
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
AUDIT = HERE / "audit.py"
OLD_AUDIT = HERE.with_name("cm3_lto_link_contract") / "audit.py"
OLD_FIXTURE = HERE.with_name("cm3_lto_link_contract") / "test_audit.py"
IDENTITY = HERE.with_name("cm3_lto_cohort_controls") / "identity.py"
EXPECTED_METHODS = 20
PRIVATE16 = ("fiber_port_context_cohort_armv7m_p0x434D3033u_l0x00010001u_"
    "f0_e0_h1_j1_v1_d0_r0_z8u_y0_w2_g4_u00010000_i0_"
    "o0xFFFFFFFDu_c0_s0_x0_m0_a0_b0_t0_n0_k0_q0")
PRIVATE32 = PRIVATE16.replace("_u00010000_", "_u00100000_")
STORAGE = "fiber_port_storage_cohort_arm_cm3_v1_r0"
ANCHOR = "fiber_internal_runtime_port_abi_v1_anchor"
SLOT = "fiber_internal_runtime_current_context_slot"
a = None
b = None
frozen = None
ident = None


def sha(data):
    return hashlib.sha256(data).hexdigest().upper()


def rename(elf, before, after):
    for row in elf.symbols:
        if row["name"] == before:
            row["name"] = after
    for kind, target in elf.relocations.values():
        if target["name"] == before:
            target["name"] = after


class Fixture:
    def __init__(self, basepri=16, emit=True):
        self.basepri, self.emit = basepri, emit
        self.original = b.Fixture(emit)
        self.image = self.original.image
        self.machine, self.final, self.startup = self.original.machine, self.original.final, self.original.startup
        if basepri == 32:
            rename(self.machine, PRIVATE16, PRIVATE32)
            rename(self.final, PRIVATE16, PRIVATE32)

    def check(self, **kwargs):
        options = dict(basepri=self.basepri, emit_relocs=self.emit, machine_attributes_text=b.ATTRS,
                       frozen_audit=frozen, identity=ident)
        options.update(kwargs)
        return a.audit(self.image, b.ATTRS, **options)


class PolicyAuditTests(unittest.TestCase):
    def rejects(self, fixture, **kwargs):
        with self.assertRaisesRegex((ValueError, RuntimeError), r"REJECT|cm3-lto"):
            fixture.check(**kwargs)

    def test_valid_policy16_emit_complete_surface(self):
        result = Fixture().check()
        self.assertIs(result["FinalLinkContractValidated"], True)
        self.assertEqual(result["OriginalPointerRelocations"], 7)
        self.assertEqual(result["AppliedPointerRelocations"], 7)
        self.assertIn(PRIVATE16, result["Symbols"])
        self.assertIn(STORAGE, result["Symbols"])

    def test_valid_policy32_renames_all_metadata_not_pointer_values(self):
        baseline, variant = Fixture(16), Fixture(32)
        self.assertEqual(variant.machine.data, baseline.machine.data)
        self.assertEqual(variant.final.data, baseline.final.data)
        for elf in (variant.machine, variant.final):
            self.assertFalse(any(row["name"] == PRIVATE16 for row in elf.symbols))
            self.assertTrue(any(row["name"] == PRIVATE32 for row in elf.symbols))
            self.assertFalse(any(target["name"] == PRIVATE16 for kind, target in elf.relocations.values()))
        result = variant.check()
        self.assertIn(PRIVATE32, result["Symbols"])
        self.assertNotIn(PRIVATE16, result["Symbols"])
        self.assertEqual(result["Symbols"][PRIVATE32]["Final"]["value"], baseline.final.symbol(PRIVATE16)["value"])
        self.assertEqual(result["OriginalPointerRelocations"], 7)
        self.assertEqual(result["AppliedPointerRelocations"], 7)

    def test_both_ordinary_policies_require_original_not_applied_rels(self):
        for policy in (16, 32):
            fixture = Fixture(policy, False)
            result = fixture.check()
            self.assertEqual(result["OriginalPointerRelocations"], 7)
            self.assertEqual(result["AppliedPointerRelocations"], 0)
            self.assertIs(result["EmitRelocs"], False)
            fixture.machine.relocations.clear()
            with self.subTest(policy=policy):
                self.rejects(fixture)

    def test_policy_selector_is_exact_literal_sixteen_or_thirtytwo(self):
        for policy in (None, True, False, 0, 1, 17, 31, 64, 16.0, 32.0, "16", "32", [], {}):
            with self.subTest(policy=policy):
                self.rejects(Fixture(), basepri=policy)
        for emit in (0, 1, None, "true"):
            with self.subTest(emit=emit):
                self.rejects(Fixture(), emit_relocs=emit)

    def test_policy_mismatch_and_foreign_full_private_identity_reject(self):
        self.rejects(Fixture(16), basepri=32)
        self.rejects(Fixture(32), basepri=16)
        for before in (PRIVATE16, PRIVATE32):
            for after in (before.replace("_g4_", "_g3_"), before.replace("_v1_", "_v0_"),
                          before.replace("_u00010000_", "_u00110000_") if before == PRIVATE16
                          else before.replace("_u00100000_", "_u00110000_")):
                fixture = Fixture(16 if before == PRIVATE16 else 32)
                rename(fixture.machine, before, after)
                rename(fixture.final, before, after)
                with self.subTest(before=before, after=after):
                    self.rejects(fixture)

    def test_storage_identity_unchanged_and_no_extra_cohort_definitions(self):
        for policy in (16, 32):
            fixture = Fixture(policy)
            rename(fixture.machine, STORAGE, "fiber_port_storage_cohort_arm_cm3_v2_r0")
            rename(fixture.final, STORAGE, "fiber_port_storage_cohort_arm_cm3_v2_r0")
            with self.subTest(policy=policy):
                self.rejects(fixture)
        fixture = Fixture(32)
        fixture.final.add(PRIVATE16, 3, 0x810, 1, "STT_OBJECT")
        self.rejects(fixture)

    def test_anchor_must_stay_local_on_both_sides(self):
        for policy in (16, 32):
            fixture = Fixture(policy)
            fixture.machine.symbol(ANCHOR)["binding"] = "STB_GLOBAL"
            fixture.final.symbol(ANCHOR)["binding"] = "STB_GLOBAL"
            with self.subTest(policy=policy):
                self.rejects(fixture)

    def test_slot_local_dedicated_writable_zero_fill_geometry(self):
        for change in ("global", "extent", "type", "readonly", "executable"):
            fixture = Fixture(32)
            if change == "global":
                fixture.machine.symbol(SLOT)["binding"] = "STB_GLOBAL"
                fixture.final.symbol(SLOT)["binding"] = "STB_GLOBAL"
            elif change == "extent":
                fixture.machine.sections[3].header.sh_size = 8
            elif change == "type":
                fixture.final.sections[6].header.sh_type = "SHT_PROGBITS"
            elif change == "readonly":
                fixture.final.loads[1]["Flags"] = 4
            else:
                fixture.final.loads[1]["Flags"] = 7
            with self.subTest(change=change):
                self.rejects(fixture)

    def test_five_public_eight_forward_and_handler_definitions_exact(self):
        for name in (*b.PUBLIC, *b.FORWARD, "Reset_Handler", "SVC_Handler", "PendSV_Handler"):
            fixture = Fixture(32)
            fixture.final.symbols.remove(fixture.final.symbol(name))
            with self.subTest(missing=name):
                self.rejects(fixture)
        fixture = Fixture(32)
        fixture.final.add("ctxrt_v1_foreign", 2, 0x701, 4)
        self.rejects(fixture)

    def test_undefined_legacy_and_optional_configuration_reject(self):
        for name, section in (("undefined_dependency", "SHN_UNDEF"), ("fiber_init", 2), ("fiber_v1_foreign", 2),
                              ("fiber_internal_runtime_context_configuration_abi_v1_anchor", 3)):
            fixture = Fixture(32)
            fixture.final.add(name, section, 0x701, 4)
            with self.subTest(name=name):
                self.rejects(fixture)

    def test_machine_final_attributes_remain_exact_soft_cm3(self):
        for bad in (None, b.ATTRS.replace('"7-M"', '"Cortex-M7"'), b.ATTRS.replace("v7", "v6-M"),
                    b.ATTRS + "  Tag_FP_arch: VFPv4\n", b.ATTRS + "  Tag_ABI_HardFP_use: SP only\n",
                    b.ATTRS + "  Tag_MVE_arch: MVE Integer\n", b.ATTRS + "  Tag_CPU_arch: v7\n"):
            fixture = Fixture(32)
            with self.subTest(machine=bad):
                self.rejects(fixture, machine_attributes_text=bad)
            with self.subTest(final=bad), self.assertRaisesRegex((ValueError, RuntimeError), r"REJECT|cm3-lto"):
                a.audit(fixture.image, bad, basepri=32, emit_relocs=True, machine_attributes_text=b.ATTRS,
                        frozen_audit=frozen, identity=ident)

    def test_vector_raw_words_alignment_and_entry_reject(self):
        for index in (0, 1, 2, 7, 11, 13, 14, 255):
            fixture = Fixture(32)
            offset = 0x400 + 4 * index
            value = struct.unpack_from("<I", fixture.final.data, offset)[0]
            fixture.final.write(offset, struct.pack("<I", value ^ 2))
            with self.subTest(index=index):
                self.rejects(fixture)
        fixture = Fixture(32)
        fixture.final.sections[1].header.sh_addralign = 4
        self.rejects(fixture)
        fixture = Fixture(32)
        fixture.final.write(24, struct.pack("<I", 0x403))
        self.rejects(fixture)

    def test_readonly_anchor_cohorts_and_table_flags(self):
        for name in (ANCHOR, PRIVATE32, STORAGE):
            fixture = Fixture(32)
            fixture.final.write(0xC00 + fixture.machine.symbol(name)["value"], b"\x02")
            with self.subTest(name=name):
                self.rejects(fixture)
        for section in (3, 4, 5):
            fixture = Fixture(32)
            fixture.final.sections[section].header.sh_flags |= 1
            with self.subTest(section=section):
                self.rejects(fixture)

    def test_exact_pointer_values_order_and_full_table_extent(self):
        for section in (4, 5):
            fixture = Fixture(32)
            start = fixture.final.sections[section].header.sh_offset
            raw = fixture.final.data[start:start + 8]
            fixture.final.write(start, raw[4:] + raw[:4])
            with self.subTest(section=section):
                self.rejects(fixture)
        fixture = Fixture(32)
        fixture.final.sections[4].header.sh_size -= 4
        self.rejects(fixture)

    def test_original_rel_zero_addends_kind_targets_and_membership(self):
        for change in ("addend", "kind", "target", "missing", "extra"):
            fixture = Fixture(32)
            key = (5, 4)
            if change == "addend":
                fixture.machine.write(0x338, b"\x04\0\0\0")
            elif change == "kind":
                fixture.machine.relocations[key] = (10, fixture.machine.symbol(PRIVATE32))
            elif change == "target":
                fixture.machine.relocations[key] = (2, fixture.machine.symbol(STORAGE))
            elif change == "missing":
                del fixture.machine.relocations[key]
            else:
                fixture.machine.relocations[5, 2] = fixture.machine.relocations[key]
            with self.subTest(change=change):
                self.rejects(fixture)

    def test_applied_rel_exact_kind_target_membership_and_ordinary_absence(self):
        for change in ("kind", "target", "missing", "extra", "stale-policy-name"):
            fixture = Fixture(32)
            key = (5, 4)
            if change == "kind":
                fixture.final.relocations[key] = (10, fixture.final.symbol(PRIVATE32))
            elif change == "target":
                fixture.final.relocations[key] = (2, fixture.final.symbol(STORAGE))
            elif change == "missing":
                del fixture.final.relocations[key]
            elif change == "extra":
                fixture.final.relocations[5, 2] = fixture.final.relocations[key]
            else:
                fixture.final.relocations[key] = (2, dict(fixture.final.symbol(PRIVATE32), name=PRIVATE16))
            with self.subTest(change=change):
                self.rejects(fixture)
        fixture = Fixture(32, False)
        fixture.final.relocations[5, 4] = (2, fixture.final.symbol(PRIVATE32))
        self.rejects(fixture)

    def test_map_provider_alias_and_function_shape_changes_reject(self):
        for change in ("missing-map", "partial-map", "shifted-map", "provider", "alias", "thumb", "size"):
            fixture = Fixture(32)
            if change == "missing-map":
                del fixture.image.placements["machine.o", ".text"]
            elif change == "partial-map":
                fixture.image.placements["machine.o", ".text"] = (0x440, 0x100)
            elif change == "shifted-map":
                fixture.image.placements["machine.o", ".text"] = (0x444, 0x200)
            elif change == "provider":
                fixture.startup.symbols.append(dict(fixture.machine.symbol(b.PUBLIC[0])))
            elif change == "alias":
                fixture.final.symbols.append(dict(fixture.final.symbol("SVC_Handler"), name="foreign_alias"))
            elif change == "thumb":
                fixture.final.symbol("SVC_Handler")["value"] &= ~1
            else:
                fixture.final.symbol("SVC_Handler")["size"] += 2
            with self.subTest(change=change):
                self.rejects(fixture)

    def test_literal_integer_fields_and_raw_soft_elf_headers(self):
        for key, value in (("value", True), ("size", 4.0), ("section", 2.0), ("index", False)):
            fixture = Fixture(32)
            fixture.final.symbol(b.PUBLIC[0])[key] = value
            with self.subTest(key=key):
                self.rejects(fixture)
        for change in ("section", "load", "kind", "flags", "type"):
            fixture = Fixture(32)
            if change == "section":
                fixture.final.sections[4].header.sh_size = 20.0
            elif change == "load":
                fixture.final.loads[0]["Flags"] = True
            elif change == "kind":
                fixture.machine.relocations[5, 4] = (2.0, fixture.machine.symbol(PRIVATE32))
            elif change == "flags":
                fixture.final.write(36, struct.pack("<I", 0x05000400))
            else:
                fixture.final.write(16, b"\x01\0")
            with self.subTest(change=change):
                self.rejects(fixture)

    def test_audit_purity_input_detachment_and_no_frozen_global_patching(self):
        for policy in (16, 32):
            fixture = Fixture(policy)
            before = copy.deepcopy((fixture.machine.data, fixture.final.data, fixture.machine.symbols,
                fixture.final.symbols, fixture.machine.relocations, fixture.final.relocations, fixture.image.placements))
            with patch("builtins.open", side_effect=AssertionError("pure audit opened file")), \
                    patch.object(Path, "read_bytes", side_effect=AssertionError("pure audit read file")), \
                    patch.object(Path, "read_text", side_effect=AssertionError("pure audit read text")), \
                    patch("subprocess.Popen", side_effect=AssertionError("pure audit spawned process")):
                result = fixture.check()
            result["Symbols"]["SVC_Handler"]["Final"]["name"] = "changed-output"
            after = (fixture.machine.data, fixture.final.data, fixture.machine.symbols, fixture.final.symbols,
                     fixture.machine.relocations, fixture.final.relocations, fixture.image.placements)
            self.assertEqual(before, after)
            self.assertEqual(b.PRIVATE, PRIVATE16)
            self.assertEqual(frozen.PRIVATE, PRIVATE16)
            self.assertEqual(frozen.STORAGE, STORAGE)
            self.assertFalse(hasattr(fixture.image, "_contract_machine_owner"))

    def test_report_exact_typed_counters_and_broad_false_claims(self):
        for policy in (16, 32):
            for emit in (False, True):
                result = Fixture(policy, emit).check()
                self.assertEqual(result["Status"], "CM3-LTO-COHORT-LINK-CONTRACT-PASS-NOT-QUALIFIED")
                self.assertEqual(result["Scope"], "NATIVE_CM3_O2_LTO_POLICY_COHORT_DIRECT_LINK_CONTRACT_ONLY")
                self.assertEqual(result["PrivateCohort"], PRIVATE16 if policy == 16 else PRIVATE32)
                self.assertEqual(result["StorageCohort"], STORAGE)
                self.assertEqual(result["Basepri"], policy)
                self.assertIs(type(result["Basepri"]), int)
                self.assertIs(result["PolicyCohortLinkContractValidated"], True)
                self.assertIs(result["FrozenPredicatesReused"], True)
                self.assertIs(result["FrozenAuditDelegated"], policy == 16)
                self.assertEqual(len(result["Symbols"]), 26)
                for key, expected in (("OriginalPointerRelocations", 7), ("AppliedPointerRelocations", 7 if emit else 0),
                                       ("RequiredCellsSatisfied", 0), ("DefinitionCount", 26)):
                    self.assertIs(type(result[key]), int)
                    self.assertEqual(result[key], expected)
                self.assertIs(result["FinalLinkContractValidated"], True)
                self.assertIs(result["EmitRelocs"], emit)
                for key in ("Qualification", "FullABIProof", "SourceIRProof", "SourceToMachineSemanticProof",
                            "OriginalTranslationUnitOwnership", "CanonicalProtocolValidated", "InstructionEquivalence",
                            "PolicyEquivalence", "FinalReferenceParity", "CompleteObjectProof", "KernelRuntimeProof",
                            "CpuExecution", "BoardExecution", "GlobalFreezeQualified", "RequiredCellSatisfied"):
                    with self.subTest(policy=policy, emit=emit, key=key):
                        self.assertIs(result[key], False)


def load_module(name, path, data):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    exec(compile(data, str(path), "exec"), module.__dict__)
    return module


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
        Scope="PURE_SYNTHETIC_CM3_LTO_POLICY_LINK_AUDIT_CONTROLS_ONLY", SyntheticInputs=True,
        ActualELFTested=False, ActualMachineDecoderTested=False, ActualLinkTested=False, Qualification=False,
        NativeCommandsExecuted=0, ToolInvocations=0, FullABIProof=False, SourceIRProof=False,
        SourceToMachineSemanticProof=False, OriginalTranslationUnitOwnership=False, CanonicalProtocolValidated=False,
        InstructionEquivalence=False, PolicyEquivalence=False, FinalReferenceParity=False, CompleteObjectProof=False,
        KernelRuntimeProof=False, CpuExecution=False, BoardExecution=False, GlobalFreezeQualified=False,
        RequiredCellSatisfied=False, RequiredCellsSatisfied=0)
    paths = (Path(__file__).resolve(), AUDIT, OLD_AUDIT, OLD_FIXTURE, IDENTITY)
    try:
        if sys.flags.optimize or not __debug__:
            raise ValueError("optimized interpreter unsupported")
        buffers = {item: item.read_bytes() for item in paths}
        report["SourceHashes"] = {str(item): sha(data) for item, data in buffers.items()}
        global a, b, frozen, ident
        with patch("subprocess.Popen", side_effect=AssertionError("pure controls cannot execute processes")), \
                patch("os.system", side_effect=AssertionError("pure controls cannot execute processes")):
            def read_source(path):
                if path not in buffers:
                    raise AssertionError("unexpected audit module input: " + str(path))
                return buffers[path]
            with patch.object(Path, "read_bytes", read_source):
                frozen = load_module("synthetic_cm3_policy_frozen_audit", OLD_AUDIT, buffers[OLD_AUDIT])
                ident = load_module("synthetic_cm3_policy_identity", IDENTITY, buffers[IDENTITY])
                a = load_module("synthetic_cm3_policy_audit", AUDIT, buffers[AUDIT])
                b = load_module("synthetic_cm3_policy_link_fixture", OLD_FIXTURE, buffers[OLD_FIXTURE])
            suite = unittest.defaultTestLoader.loadTestsFromTestCase(PolicyAuditTests)
            count = suite.countTestCases()
            if count != EXPECTED_METHODS:
                raise ValueError("exact twenty synthetic policy audit methods required")
            result = unittest.TextTestRunner(verbosity=2).run(suite)
        report.update(Tests=result.testsRun, Failures=len(result.failures), Errors=len(result.errors),
            Skipped=len(result.skipped), FailureDetails=[dict(Test=str(case), Detail=detail)
            for case, detail in result.failures + result.errors])
        if result.wasSuccessful() and result.testsRun == count and not result.skipped:
            report["Status"] = "PASS"
    except Exception:
        report.update(Status="FAIL", Error=traceback.format_exc(), Errors=report["Errors"] + 1)
    finally:
        for path, expected in report["SourceHashes"].items():
            try:
                if sha(Path(path).read_bytes()) != expected:
                    report["SourceDrift"].append(path)
                else:
                    report["ClosingFilesVerified"] += 1
            except OSError:
                report["SourceDrift"].append(path)
        report["SourceClosureVerified"] = len(report["SourceHashes"]) == 5 and not report["SourceDrift"]
        if not report["SourceClosureVerified"]:
            report["Status"] = "FAIL"
    output.mkdir(parents=True, exist_ok=False)
    target = output / "results.json"
    target.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="ascii")
    print("Receipt:", target, sha(target.read_bytes()))
    return 0 if report["Status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
