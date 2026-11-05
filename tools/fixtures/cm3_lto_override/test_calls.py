"""Synthetic machine-to-final panic call controls; no ELF parser or tool runs."""
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
from unittest.mock import patch

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
CALLS = HERE / "calls.py"
LINK_AUDIT = HERE.with_name("cm3_lto_link_contract") / "audit.py"
LINK_FIXTURE = HERE.with_name("cm3_lto_link_contract") / "test_audit.py"
PANIC = "fiber_panic"
CALLERS = (("ctxrt_v1_init", 10), ("fiber_port_runtime_schedule", 10),
           ("SVC_Handler", 10), ("PendSV_Handler", 10), ("fiber_port_start_first_context", 10))
EXPECTED_METHODS = 18
c = None
base = None


def sha(data):
    return hashlib.sha256(data).hexdigest().upper()


def branch_bytes(kind, displacement):
    """Independent T32 BL/B.W bit construction, not a decoder oracle."""
    if kind not in (10, 30) or type(displacement) is not int or displacement % 2 or not -(1 << 24) <= displacement < (1 << 24):
        raise ValueError("bad synthetic branch")
    bits = displacement & 0x1FFFFFF
    sign, i1, i2 = (bits >> 24) & 1, (bits >> 23) & 1, (bits >> 22) & 1
    j1, j2 = 1 ^ i1 ^ sign, 1 ^ i2 ^ sign
    first = 0xF000 | sign << 10 | (bits >> 12) & 0x3FF
    last = (0xD000 if kind == 10 else 0x9000) | j1 << 13 | j2 << 11 | (bits >> 1) & 0x7FF
    return struct.pack("<HH", first, last)


class Fixture:
    """Reuse only the explicit pure synthetic generic-image fixture."""
    def __init__(self, emit=True, tail=False):
        self.emit = emit
        self.link = base.Fixture(emit)
        self.image = self.link.image
        self.machine, self.final = self.link.machine, self.link.final
        self.sites = []
        self.image.instructions = {}
        for name, kind in CALLERS:
            if tail and name == "fiber_port_runtime_schedule":
                kind = 30
            before, after = self.machine.symbol(name), self.final.symbol(name)
            source = before["value"] & ~1
            address = after["value"] & ~1
            section = self.final.sections[after["section"]]
            offset = address - section.header.sh_addr
            original = branch_bytes(kind, -4)
            applied = branch_bytes(kind, (self.final.symbol(PANIC)["value"] & ~1) - address - 4)
            self.machine.write(self.machine.sections[before["section"]].header.sh_offset + source, original)
            self.final.write(section.header.sh_offset + offset, applied)
            self.machine.relocations[before["section"], source] = (kind, dict(self.machine.symbol(PANIC)))
            if emit:
                self.final.relocations[after["section"], offset] = (kind, dict(self.final.symbol(PANIC)))
            self.image.instructions[after["section"], address] = (
                "bl" if kind == 10 else "b", "%x <fiber_panic>" % (self.final.symbol(PANIC)["value"] & ~1), applied)
            self.sites.append(dict(Name=name, Kind=kind, OriginalSection=before["section"], OriginalOffset=source,
                                   FinalSection=after["section"], FinalOffset=offset, Address=address))
        for elf in (self.machine, self.final):
            elf.section_read = lambda section, offset, size, elf=elf: elf.data[
                elf.sections[section].header.sh_offset + offset:elf.sections[section].header.sh_offset + offset + size]
            elf.read = lambda address, size, elf=elf: self.read(elf, address, size)
        self.image.read = self.final.read
        self.image.origin_evidence = {}
        self.proof = self.link.check()

    @staticmethod
    def read(elf, address, size):
        for section in elf.sections:
            h = section.header
            if h.sh_type == "SHT_PROGBITS" and h.sh_addr <= address and address + size <= h.sh_addr + h.sh_size:
                return elf.section_read(elf.sections.index(section), address - h.sh_addr, size)
        raise ValueError("synthetic unmapped read")

    def raw(self, side, site, data):
        elf = self.machine if side == "Original" else self.final
        section = site[side + "Section"]
        offset = site[side + "Offset"]
        elf.write(elf.sections[section].header.sh_offset + offset, data)

    def check(self, **kwargs):
        self.image.hashes = dict(PrelinkSha256=sha(self.machine.data), FinalSha256=sha(self.final.data),
                                 DisassemblySha256=sha(b"synthetic disassembly metadata only"))
        return c.audit_calls(self.image, self.proof, emit_relocs=kwargs.get("emit_relocs", self.emit))

    def retarget(self, site, target):
        raw = branch_bytes(site["Kind"], target - site["Address"] - 4)
        self.raw("Final", site, raw)
        self.image.instructions[site["FinalSection"], site["Address"]] = (
            "bl" if site["Kind"] == 10 else "b", "%x <fiber_panic>" % target, raw)


class CallTests(unittest.TestCase):
    def rejects(self, fixture, **kwargs):
        with self.assertRaises(c.Rejected) as raised:
            fixture.check(**kwargs)
        self.assertTrue(str(raised.exception).startswith("REJECT:CM3-LTO-OVERRIDE-CALLS:"))

    def test_emit_positive_includes_c_and_all_three_assembly_callers(self):
        fixture = Fixture()
        result = fixture.check()
        self.assertEqual(result["CallCount"], 5)
        self.assertEqual(result["CallerCount"], 5)
        self.assertEqual(result["OriginalNamedRelocations"], 5)
        self.assertEqual(result["AppliedNamedRelocations"], 5)
        for key in ("CallCount", "CallerCount", "OriginalNamedRelocations", "AppliedNamedRelocations"):
            self.assertIs(type(result[key]), int)
        self.assertIs(result["AllNamedPanicCallsValidated"], True)
        self.assertIs(result["EmitRelocs"], True)
        self.assertEqual(result["SupportedRelocationKinds"], [10])
        self.assertEqual({site["Caller"] for site in result["CallSites"]}, {name for name, _ in CALLERS})
        for site in result["CallSites"]:
            self.assertEqual(site["Transfer"], "BL")
            self.assertEqual(site["OriginalAddend"], -4)
            self.assertIs(type(site["OriginalAddend"]), int)
            self.assertIs(type(site["Kind"]), int)
            self.assertIs(site["InstructionBoundaryValidated"], True)
            self.assertIs(site["CallerBodySemanticsProven"], False)

    def test_ordinary_positive_with_original_rel_authority(self):
        result = Fixture(False).check()
        self.assertEqual(result["OriginalNamedRelocations"], 5)
        self.assertEqual(result["AppliedNamedRelocations"], 0)
        self.assertEqual(result["CallCount"], 5)
        for key in ("CallCount", "CallerCount", "OriginalNamedRelocations", "AppliedNamedRelocations"):
            self.assertIs(type(result[key]), int)
        self.assertIs(result["EmitRelocs"], False)
        self.assertTrue(all(site["FinalRelocationSymbol"] is None for site in result["CallSites"]))

    def test_original_named_target_definition_metadata_is_exact(self):
        for key, value in (("value", 3), ("size", 6), ("section", 2), ("index", 999),
                           ("binding", "STB_WEAK"), ("kind", "STT_NOTYPE"), ("visibility", "STV_HIDDEN")):
            fixture = Fixture()
            site = fixture.sites[0]
            kind, target = fixture.machine.relocations[site["OriginalSection"], site["OriginalOffset"]]
            fixture.machine.relocations[site["OriginalSection"], site["OriginalOffset"]] = (kind, dict(target, **{key: value}))
            with self.subTest(key=key):
                self.rejects(fixture)

    def test_original_rel_addend_minus_four_only_for_all_named_bl_callers(self):
        for index in (0, 1):
            for addend in (0, -2, -8, 4):
                fixture = Fixture()
                site = fixture.sites[index]
                fixture.raw("Original", site, branch_bytes(site["Kind"], addend))
                with self.subTest(index=index, addend=addend):
                    self.rejects(fixture)

    def test_unsupported_relocation_and_instruction_forms_fail_closed(self):
        self.rejects(Fixture(tail=True))
        for kind in (2, 28, 30, 51, 10.0, True):
            fixture = Fixture()
            site = fixture.sites[0]
            fixture.machine.relocations[site["OriginalSection"], site["OriginalOffset"]] = (
                kind, dict(fixture.machine.symbol(PANIC)))
            with self.subTest(kind=kind):
                self.rejects(fixture)
        for raw in (b"\x70\x47\x00\xbf", b"\0\xf0\0\xc0", b"\0\xe0\0\xbf", b"\0\0\0\0"):
            fixture = Fixture()
            fixture.raw("Original", fixture.sites[0], raw)
            with self.subTest(raw=raw.hex()):
                self.rejects(fixture)
        fixture = Fixture()
        fixture.raw("Final", fixture.sites[0], branch_bytes(30, 0))
        self.rejects(fixture)

    def test_full_caller_section_map_and_final_definition_required(self):
        for change in ("missing", "partial", "moved", "size", "local", "type"):
            fixture = Fixture()
            if change == "missing":
                del fixture.image.placements["machine.o", ".text"]
            elif change == "partial":
                fixture.image.placements["machine.o", ".text"] = (0x440, 0x100)
            elif change == "moved":
                fixture.image.placements["machine.o", ".text"] = (0x444, 0x200)
            elif change == "size":
                fixture.final.symbol("ctxrt_v1_init")["size"] = 2
            elif change == "local":
                fixture.final.symbol("ctxrt_v1_init")["binding"] = "STB_LOCAL"
            else:
                fixture.machine.symbol("ctxrt_v1_init")["kind"] = "STT_OBJECT"
            with self.subTest(change=change):
                self.rejects(fixture)

    def test_caller_and_panic_cross_name_positive_size_aliases_reject(self):
        for side in ("machine", "final"):
            for name in ("ctxrt_v1_init", PANIC):
                fixture = Fixture()
                elf = getattr(fixture, side)
                elf.symbols.append(dict(elf.symbol(name), name="unexpected_alias"))
                with self.subTest(side=side, name=name):
                    self.rejects(fixture)

    def test_thumb_mapping_and_complete_four_byte_boundary_required(self):
        for side in ("machine", "final"):
            for mapping in ("d", "a", "crosses"):
                fixture = Fixture()
                elf = getattr(fixture, side)
                site = fixture.sites[0]
                start = site["OriginalOffset"] if side == "machine" else site["Address"]
                elf.mapping = lambda section, address, mapping=mapping, start=start: (
                    "t" if mapping == "crosses" else mapping, start + 2 if mapping == "crosses" else 0xFFFFFFFF)
                with self.subTest(side=side, mapping=mapping):
                    self.rejects(fixture)

    def test_relocation_site_alignment_and_complete_caller_extent(self):
        for offset in (1, 2, 4, 0x200):
            fixture = Fixture()
            site = fixture.sites[0]
            value = fixture.machine.relocations.pop((site["OriginalSection"], site["OriginalOffset"]))
            fixture.machine.relocations[site["OriginalSection"], offset] = value
            with self.subTest(offset=offset):
                self.rejects(fixture)

    def test_final_bl_destinations_exact_named_panic_entry(self):
        for index in (0, 1):
            for displacement in (-2, 2, 4):
                fixture = Fixture()
                fixture.retarget(fixture.sites[index], (fixture.final.symbol(PANIC)["value"] & ~1) + displacement)
                with self.subTest(index=index, displacement=displacement):
                    self.rejects(fixture)

    def test_applied_rel_kind_and_complete_named_target_metadata(self):
        for change in ("kind", "name", "value", "size", "binding", "index"):
            fixture = Fixture()
            site = fixture.sites[0]
            key = (site["FinalSection"], site["FinalOffset"])
            kind, target = fixture.final.relocations[key]
            target = dict(target)
            if change == "kind":
                kind = 30
            elif change == "name":
                target = dict(fixture.final.symbol("pilot_fault"))
            elif change == "value":
                target["value"] += 2
            elif change == "size":
                target["size"] += 2
            elif change == "binding":
                target["binding"] = "STB_WEAK"
            else:
                target["index"] += 1
            fixture.final.relocations[key] = (kind, target)
            with self.subTest(change=change):
                self.rejects(fixture)

    def test_exact_emit_membership_and_no_extra_final_panic_relocations(self):
        for change in ("missing", "extra", "ordinary"):
            fixture = Fixture(change != "ordinary")
            site = fixture.sites[0]
            key = (site["FinalSection"], site["FinalOffset"])
            if change == "missing":
                del fixture.final.relocations[key]
            else:
                fixture.final.relocations[key[0], key[1] + 2] = (10, dict(fixture.final.symbol(PANIC)))
            with self.subTest(change=change):
                self.rejects(fixture)

    def test_nonempty_original_named_machine_panic_coverage_required(self):
        for emit in (False, True):
            fixture = Fixture(emit)
            for site in fixture.sites:
                del fixture.machine.relocations[site["OriginalSection"], site["OriginalOffset"]]
            with self.subTest(emit=emit):
                self.rejects(fixture)

    def test_c_callers_outside_three_assembly_roots_are_not_ignored(self):
        for index in (0, 1):
            fixture = Fixture()
            fixture.retarget(fixture.sites[index], (fixture.final.symbol(PANIC)["value"] & ~1) + 2)
            with self.subTest(caller=fixture.sites[index]["Name"]):
                self.rejects(fixture)

    def test_typed_selector_proof_and_numeric_metadata_no_bool_float_aliases(self):
        for value in (0, 1, None, "true"):
            with self.subTest(selector=value):
                self.rejects(Fixture(), emit_relocs=value)
        for flag, value in (("FinalLinkContractValidated", 1), ("EmitRelocs", 1), ("Status", "PASS"),
                             ("Scope", "arbitrary-contract"), ("Profile", "CM7"), ("Mode", "O2"),
                             ("Linkage", "archive"), ("LinkMapSha256", "0" * 64)):
            fixture = Fixture()
            fixture.proof[flag] = value
            with self.subTest(flag=flag):
                self.rejects(fixture)
        for key, value in (("value", True), ("size", 4.0), ("section", 1.0), ("index", True)):
            fixture = Fixture()
            site = fixture.sites[0]
            kind, target = fixture.machine.relocations[site["OriginalSection"], site["OriginalOffset"]]
            fixture.machine.relocations[site["OriginalSection"], site["OriginalOffset"]] = (kind, dict(target, **{key: value}))
            with self.subTest(key=key, value=value):
                self.rejects(fixture)

    def test_panic_definition_strong_thumb_positive_size_and_origin(self):
        for side in ("machine", "final"):
            for field, value in (("binding", "STB_WEAK"), ("size", 0), ("kind", "STT_NOTYPE")):
                fixture = Fixture()
                getattr(fixture, side).symbol(PANIC)[field] = value
                with self.subTest(side=side, field=field):
                    self.rejects(fixture)
        fixture = Fixture()
        fixture.final.symbol(PANIC)["value"] &= ~1
        self.rejects(fixture)

    def test_bit_construction_known_raw_fields_and_relocation_addends(self):
        self.assertEqual(branch_bytes(10, -4), b"\xff\xf7\xfe\xff")
        self.assertEqual(branch_bytes(30, -4), b"\xff\xf7\xfe\xbf")
        self.assertEqual(branch_bytes(10, 0), b"\0\xf0\0\xf8")
        self.assertEqual(branch_bytes(30, 0), b"\0\xf0\0\xb8")
        for kind in (10, 30):
            for displacement in (1, 1 << 24, -(1 << 24) - 2, True):
                with self.subTest(kind=kind, displacement=displacement), self.assertRaises(ValueError):
                    branch_bytes(kind, displacement)
        for change in ("interior", "wrong-text", "wrong-raw", "wrong-op"):
            fixture = Fixture()
            site = fixture.sites[0]
            key = (site["FinalSection"], site["Address"])
            op, operands, raw = fixture.image.instructions[key]
            if change == "interior":
                fixture.image.instructions[key[0], key[1] + 2] = ("nop", "", b"\0\xbf")
            elif change == "wrong-text":
                fixture.image.instructions[key] = (op, "0 <fiber_panic>", raw)
            elif change == "wrong-raw":
                fixture.image.instructions[key] = (op, operands, b"\0\0\0\0")
            else:
                fixture.image.instructions[key] = ("b", operands, raw)
            with self.subTest(disassembly=change):
                self.rejects(fixture)

    def test_pure_audit_no_input_mutation_file_access_or_claim_promotion(self):
        fixture = Fixture()
        before = copy.deepcopy((fixture.machine.data, fixture.final.data, fixture.machine.symbols,
                                fixture.final.symbols, fixture.machine.relocations, fixture.final.relocations,
                                fixture.image.placements, fixture.proof))
        with patch("builtins.open", side_effect=AssertionError("pure audit opened file")), \
                patch.object(Path, "open", side_effect=AssertionError("pure audit opened path")), \
                patch.object(Path, "read_bytes", side_effect=AssertionError("pure audit read file")), \
                patch("subprocess.Popen", side_effect=AssertionError("pure audit spawned process")):
            result = fixture.check()
        after = (fixture.machine.data, fixture.final.data, fixture.machine.symbols, fixture.final.symbols,
                 fixture.machine.relocations, fixture.final.relocations, fixture.image.placements, fixture.proof)
        self.assertEqual(before, after)
        self.assertEqual(result["MachineSha256"], sha(fixture.machine.data))
        self.assertEqual(result["FinalSha256"], sha(fixture.final.data))
        for name in ("Qualification", "CpuExecution", "BoardExecution", "GlobalFreezeQualified", "RequiredCellSatisfied",
                     "SourceToMachineSemanticProof", "OriginalTranslationUnitOwnership", "CanonicalProtocolValidated",
                     "CallerBodySemanticsProven", "CallerBodyPreservationProven", "UnrelocatedTransfersAudited",
                     "PanicResolutionSelectionProven", "CalleeBodyProof"):
            with self.subTest(name=name):
                self.assertIs(result[name], False)
        self.assertIs(type(result["RequiredCellsSatisfied"]), int)
        self.assertEqual(result["RequiredCellsSatisfied"], 0)


def load_module(name, source, data):
    spec = importlib.util.spec_from_file_location(name, source)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    exec(compile(data, str(source), "exec"), module.__dict__)
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
        Scope="PURE_SYNTHETIC_CM3_LTO_PANIC_CALL_CONTROLS_ONLY", SyntheticInputs=True,
        ActualELFTested=False, ActualMachineDecoderTested=False, ActualLinkTested=False,
        Qualification=False, NativeCommandsExecuted=0, ToolInvocations=0, FullABIProof=False,
        SourceIRProof=False, SourceToMachineSemanticProof=False, OriginalTranslationUnitOwnership=False,
        CanonicalProtocolValidated=False, InstructionEquivalence=False, PolicyEquivalence=False,
        FinalReferenceParity=False, CompleteObjectProof=False, KernelRuntimeProof=False,
        CpuExecution=False, BoardExecution=False, GlobalFreezeQualified=False,
        RequiredCellSatisfied=False, RequiredCellsSatisfied=0)
    paths = (Path(__file__).resolve(), CALLS, LINK_AUDIT, LINK_FIXTURE)
    try:
        if sys.flags.optimize or not __debug__:
            raise ValueError("optimized interpreter unsupported")
        buffers = {item: item.read_bytes() for item in paths}
        report["SourceHashes"] = {str(item): sha(data) for item, data in buffers.items()}
        global c, base
        with patch("subprocess.Popen", side_effect=AssertionError("pure controls cannot execute processes")), \
                patch("os.system", side_effect=AssertionError("pure controls cannot execute processes")):
            c = load_module("synthetic_cm3_override_calls", CALLS, buffers[CALLS])
            audit = load_module("synthetic_cm3_override_link_audit", LINK_AUDIT, buffers[LINK_AUDIT])
            base = load_module("synthetic_cm3_override_link_fixture", LINK_FIXTURE, buffers[LINK_FIXTURE])
            base.a = audit
            suite = unittest.defaultTestLoader.loadTestsFromTestCase(CallTests)
            count = suite.countTestCases()
            if count != EXPECTED_METHODS:
                raise ValueError("exact synthetic call control method count required")
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
        report["SourceClosureVerified"] = len(report["SourceHashes"]) == 4 and not report["SourceDrift"]
        if not report["SourceClosureVerified"]:
            report["Status"] = "FAIL"
    output.mkdir(parents=True, exist_ok=False)
    target = output / "results.json"
    target.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="ascii")
    print("Receipt:", target, sha(target.read_bytes()))
    return 0 if report["Status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
