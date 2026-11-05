"""Synthetic archive grammar and recipe controls; no compiler or ELF execution."""

import argparse
import hashlib
import importlib.util
import json
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
PROBE = HERE / "probe.py"
COMMON = HERE.with_name("cm3_lto_transport") / "probe.py"
EXPECTED_METHODS = 11
subject = common = None


def sha(data):
    return hashlib.sha256(data).hexdigest().upper()


def ar_header(name, size, mode="100644"):
    fields = ((name, 16), ("0", 12), ("0", 6), ("0", 6), (mode, 8), (str(size), 10))
    if any(len(value) > width for value, width in fields):
        raise ValueError("synthetic header field overflow")
    return "".join(value.ljust(width) for value, width in fields).encode("ascii") + b"`\n"


def ar_member(name, data, mode="100644"):
    return ar_header(name, len(data), mode) + data + (b"\n" if len(data) % 2 else b"")


def archive_fixture(names=None, longnames=True, symbols=None, index_padding=b""):
    """Invented member bytes and independently constructed GNU32 index offsets."""
    if names is None:
        names = ["%02d-long-synthetic-source-object.o" % index for index in range(6)]
    members = [(name, ("synthetic slim IR member %d" % index).encode("ascii") + bytes([index]))
               for index, name in enumerate(names)]
    if symbols is None:
        symbols = [("synthetic_symbol_%02d" % index).encode("ascii") for index in range(len(members))]
    symbol_names = b"".join(symbol + b"\0" for symbol in symbols) + index_padding
    index_size = 4 + 4 * len(members) + len(symbol_names)
    table, table_offsets = b"", []
    for name, _ in members:
        table_offsets.append(len(table))
        table += name.encode("ascii") + b"/\n"
    table_record = ar_member("//", table, "0") if longnames else b""
    position = 8 + 60 + index_size + index_size % 2 + len(table_record)
    offsets, records = [], []
    for index, (name, data) in enumerate(members):
        offsets.append(position)
        label = "/" + str(table_offsets[index]) if longnames else name + "/"
        record = ar_member(label, data)
        records.append(record)
        position += len(record)
    index_data = struct.pack(">I", len(members)) + b"".join(struct.pack(">I", offset) for offset in offsets) + symbol_names
    raw = b"!<arch>\n" + ar_member("/", index_data, "0") + table_record + b"".join(records)
    return SimpleNamespace(raw=raw, members=members, symbols=symbols, offsets=offsets,
                           index_data=68, index_size=index_size,
                           table_header=8 + 60 + index_size + index_size % 2,
                           table_offsets=table_offsets)


def changed(raw, offset, replacement):
    return raw[:offset] + replacement + raw[offset + len(replacement):]


class ProbeTests(unittest.TestCase):
    """The parent runs these controls after the archive probe API is frozen."""

    def test_indexed_long_names_bind_offsets_order_and_complete_bytes(self):
        fixture = archive_fixture()
        result = subject.archive_records(fixture.raw)
        self.assertEqual(result["Format"], "GNU-ar-regular-32bit-index")
        self.assertIs(result["DeterministicHeaderMetadata"], True)
        self.assertEqual(result["Size"], len(fixture.raw))
        self.assertEqual(result["Sha256"], sha(fixture.raw))
        self.assertEqual(len(result["Members"]), 6)
        for index, ((name, data), row) in enumerate(zip(fixture.members, result["Members"])):
            self.assertEqual(row["Name"], name)
            self.assertEqual(row["Ordinal"], index)
            self.assertEqual(row["HeaderOffset"], fixture.offsets[index])
            self.assertEqual(row["DataOffset"], fixture.offsets[index] + 60)
            self.assertEqual(row["Size"], len(data))
            self.assertEqual(row["Sha256"], sha(data))
            self.assertEqual(fixture.raw[row["DataOffset"]:row["DataOffset"] + row["Size"]], data)
        self.assertEqual(result["Index"], [dict(Name=symbol.decode("ascii"), HeaderOffset=offset, Member=name)
            for symbol, offset, (name, _) in zip(fixture.symbols, fixture.offsets, fixture.members)])

    def test_short_names_and_required_single_index_alignment_nul(self):
        symbols = [("synthetic_symbol_%02d" % index).encode("ascii") for index in range(6)]
        symbols[0] += b"x"
        consumed = 4 + 4 * 6 + sum(len(symbol) + 1 for symbol in symbols)
        self.assertEqual(consumed % 2, 1)
        names = ["m%d.o" % index for index in range(6)]
        fixture = archive_fixture(names, longnames=False, symbols=symbols, index_padding=b"\0")
        self.assertEqual(fixture.index_size, consumed + 1)
        self.assertEqual(fixture.raw[fixture.index_data + consumed:fixture.index_data + consumed + 1], b"\0")
        result = subject.archive_records(fixture.raw)
        self.assertEqual([row["Name"] for row in result["Members"]], [name for name, _ in fixture.members])
        self.assertEqual(len(result["Records"]), 7)
        for row, (_, data) in zip(result["Members"], fixture.members):
            self.assertEqual(row["Sha256"], sha(data))
            self.assertEqual(fixture.raw[row["DataOffset"]:row["DataOffset"] + row["Size"]], data)
        self.assertEqual({row["HeaderOffset"] for row in result["Index"]}, set(fixture.offsets))
        self.assertEqual([row["Name"] for row in result["Index"]], [symbol.decode("ascii") for symbol in symbols])
        for padding in (b"\x01", b"\0\0", b"\n"):
            with self.subTest(padding=padding.hex()):
                raw = archive_fixture(names, longnames=False, symbols=symbols, index_padding=padding).raw
                with self.assertRaises(ValueError):
                    subject.archive_records(raw)
        even = [("synthetic_symbol_%02d" % index).encode("ascii") for index in range(6)]
        self.assertEqual((4 + 4 * 6 + sum(len(symbol) + 1 for symbol in even)) % 2, 0)
        with self.assertRaises(ValueError):
            subject.archive_records(archive_fixture(names, longnames=False, symbols=even, index_padding=b"\0").raw)

    def test_magic_types_header_bounds_determinism_padding_and_tail_reject(self):
        fixture = archive_fixture()
        raw, first = fixture.raw, fixture.offsets[0]
        odd_pad = first + 60 + len(fixture.members[0][1])
        self.assertEqual(len(fixture.members[0][1]) % 2, 1)
        invalid = [None, True, bytearray(raw), memoryview(raw), "!<arch>\n", b"", b"!<thin>\n" + raw[8:],
            b"!<arch>\nshort", changed(raw, 8 + 58, b"??"),
            changed(raw, 8 + 48, b"01        "), changed(raw, first + 16, b"1".ljust(12)),
            changed(raw, first + 28, b"1".ljust(6)), changed(raw, first + 40, b"100648  "),
            changed(raw, first + 48, b"9999999999"), changed(raw, odd_pad, b"\0"), raw[:-3], raw + b"\n"]
        for index, mutant in enumerate(invalid):
            with self.subTest(case=index):
                with self.assertRaises(ValueError):
                    subject.archive_records(mutant)

    def test_long_name_boundaries_and_duplicate_expected_member_reject(self):
        fixture = archive_fixture()
        raw, first, last = fixture.raw, fixture.offsets[0], fixture.offsets[-1]
        invalid = [changed(raw, first, b"/1".ljust(16)), changed(raw, first, b"/999999".ljust(16)),
            changed(raw, first, b"#1/8".ljust(16)), changed(raw, fixture.table_header + 60, b"/"),
            changed(raw, fixture.table_header + 60 + len(fixture.members[0][0]) - 1, b"*"),
            changed(raw, last, b"/0".ljust(16))]
        table = raw[fixture.table_header:fixture.offsets[0]]
        invalid.append(raw + table)
        for index, mutant in enumerate(invalid):
            with self.subTest(case=index):
                with self.assertRaises(ValueError):
                    subject.archive_records(mutant)

    def test_plugin_index_requires_actual_headers_all_members_and_complete_names(self):
        fixture = archive_fixture()
        raw, start = fixture.raw, fixture.index_data
        invalid = [changed(raw, start, struct.pack(">I", 0)),
            changed(raw, start, struct.pack(">I", 999999)),
            changed(raw, start + 4, struct.pack(">I", fixture.offsets[0] + 1)),
            changed(raw, start + 4, struct.pack(">I", fixture.table_header)),
            changed(raw, start + 4, struct.pack(">I", len(raw) + 2)),
            changed(raw, start + 8, struct.pack(">I", fixture.offsets[0])),
            changed(raw, start + fixture.index_size - 1, b"x"),
            changed(raw, start + fixture.index_size - 2, b"\0\x01"),
            changed(raw, start + 4 + 4 * 6, b"9")]
        for index, mutant in enumerate(invalid):
            with self.subTest(case=index):
                with self.assertRaises(ValueError):
                    subject.archive_records(mutant)

    def test_extraction_table_requires_six_bound_unique_actual_members(self):
        fixture = archive_fixture()
        names = [name for name, _ in fixture.members]
        archive = Path("synthetic/libfiber.a")
        heading = "Archive member included to satisfy reference by file (symbol)"
        lines = [str(archive) + "(" + name + ") consumer-%d.o (symbol_%d)" % (index, index)
                 for index, name in enumerate(names)]
        text = "\n".join([heading, "", *lines, "Memory Configuration"])
        result = subject.extraction_rows(text, archive, names)
        self.assertEqual([row["Member"] for row in result], names)
        wrapped = "\n".join([heading, str(archive) + "(" + names[0] + ")",
                             "  consumer-0.o (symbol_0)", *lines[1:], "Discarded input sections"])
        self.assertEqual(subject.extraction_rows(wrapped, archive, names), result)
        invalid = [text.replace(lines[0] + "\n", ""), text.replace(lines[-1], lines[0]),
            text.replace(str(archive), "other/libfiber.a"), text.replace(names[0], "unknown.o"),
            text.replace(lines[0], "unparsed inclusion record"), text.replace("Memory Configuration", ""),
            text + "\0", "\n".join([heading, str(archive) + "(" + names[0] + ")", "Memory Configuration"])]
        for index, mutant in enumerate(invalid):
            with self.subTest(case=index):
                with self.assertRaises(ValueError):
                    subject.extraction_rows(mutant, archive, names)

    def test_exact_six_archive_and_three_explicit_source_roles_in_order(self):
        self.assertEqual(subject.ARCHIVE_INDICES, (0, 1, 2, 3, 4, 5))
        self.assertEqual(subject.EXPLICIT_INDICES, (8, 7, 6))
        self.assertEqual(tuple(common.SOURCES[index] for index in subject.ARCHIVE_INDICES), (
            "context/context_core.c", "context/context_runtime_state.c", "context/context_panic.c",
            "fiber/port/ARM_CM3/fiber_port.c", "fiber/port/ARM_CM3/fiber_port_boot.c",
            "fiber/port/ARM_CM3/fiber_port_exception.c"))
        self.assertEqual(tuple(common.SOURCES[index] for index in subject.EXPLICIT_INDICES), (
            "tools/fixtures/classic_final_image/startup.S", "tools/fixtures/classic_final_image/application.c",
            "fiber/port/fiber_port_context_cohort_expectation.c"))
        self.assertFalse(set(subject.ARCHIVE_INDICES).intersection(subject.EXPLICIT_INDICES))

    def test_link_recipe_has_only_three_direct_objects_then_archive_no_forcing(self):
        objects = [Path("synthetic/objects/%02d.o" % index) for index in range(9)]
        archive, script = Path("synthetic/libfiber.a"), Path("synthetic/link.ld")
        output, map_path = Path("synthetic/image.elf"), Path("synthetic/image.map")
        artifact = dict(compile_flags=["-mcpu=cortex-m3", "-mthumb", "-mfloat-abi=soft"])
        plain = subject.link_flags(common, artifact, objects, archive, script, output, map_path, False)
        emitted = subject.link_flags(common, artifact, objects, archive, script, output, map_path, True)
        providers = [str(objects[index]) for index in (8, 7, 6)] + [str(archive)]
        start = plain.index("-T") + 2
        self.assertEqual(plain[start:start + 4], providers)
        self.assertEqual([value for value in emitted if value != "-Wl,--emit-relocs"], plain)
        self.assertEqual(emitted.count("-Wl,--emit-relocs"), 1)
        for value in ("-O2", "-flto", "-flto-partition=one", "-save-temps=obj", "-Wl,-plugin-opt=-save-temps"):
            self.assertEqual(plain.count(value), 1)
        for index in subject.ARCHIVE_INDICES:
            self.assertNotIn(str(objects[index]), plain)
        for argument in plain:
            self.assertNotIn("whole-archive", argument)
            self.assertNotIn("--undefined", argument)
            self.assertFalse(argument == "-u" or argument.startswith(("-Wl,-u", "-u=")))
        for invalid in (objects[:-1], objects + [Path("extra.o")], objects[:-1] + [objects[0]], "not-objects"):
            with self.subTest(objects=str(invalid)):
                with self.assertRaises(ValueError):
                    subject.link_flags(common, artifact, invalid, archive, script, output, map_path, False)
        for option in ("-Wl,--whole-archive", "-Wl,--undefined=fiber_panic", "-march=armv7-m"):
            with self.subTest(option=option):
                with self.assertRaises(ValueError):
                    subject.link_flags(common, dict(compile_flags=artifact["compile_flags"] + [option]),
                                       objects, archive, script, output, map_path, False)

    def test_member_byte_changes_remain_observable_and_count_is_exact(self):
        fixture = archive_fixture()
        before = subject.archive_records(fixture.raw)
        location = fixture.offsets[2] + 60
        mutant = changed(fixture.raw, location, bytes([fixture.raw[location] ^ 1]))
        after = subject.archive_records(mutant)
        self.assertNotEqual(before["Sha256"], after["Sha256"])
        self.assertEqual(before["Index"], after["Index"])
        self.assertEqual([row["Name"] for row in before["Members"]], [row["Name"] for row in after["Members"]])
        for index, row in enumerate(after["Members"]):
            extracted = mutant[row["DataOffset"]:row["DataOffset"] + row["Size"]]
            self.assertEqual(row["Sha256"], sha(extracted))
            if index == 2:
                self.assertNotEqual(extracted, fixture.members[index][1])
                self.assertNotEqual(row["Sha256"], before["Members"][index]["Sha256"])
            else:
                self.assertEqual(extracted, fixture.members[index][1])
                self.assertEqual(row["Sha256"], before["Members"][index]["Sha256"])
        for count in (5, 7):
            with self.subTest(count=count):
                raw = archive_fixture(["object-%d.o" % index for index in range(count)]).raw
                with self.assertRaises(ValueError):
                    subject.archive_records(raw)

    def test_extract_member_uses_binary_file_not_text_stdout_and_requires_fresh_output(self):
        raw = b"synthetic member\n\r\n\0tail\n"
        text_stdout = raw.replace(b"\n", b"\r\n")
        self.assertNotEqual(raw, text_stdout)
        with tempfile.TemporaryDirectory(prefix="synthetic-archive-extraction-") as temporary:
            root = Path(temporary).resolve()
            ar, plugin, archive = root / "ar.exe", root / "plugin.dll", root / "archive.a"
            name = "synthetic-member.o"
            directory = root / "fresh"
            directory.mkdir()
            calls = []
            regular = Mock(wraps=common.regular)
            api = SimpleNamespace(regular=regular)

            def command(argv, label, *, cwd):
                calls.append(([str(value) for value in argv], label, Path(cwd)))
                (Path(cwd) / name).write_bytes(raw)
                return SimpleNamespace(stdout=text_stdout, stderr=b"", returncode=0)

            result = subject.extract_member(api, command, ar, plugin, archive, name, directory)
            self.assertEqual(result, raw)
            self.assertEqual((directory / name).read_bytes(), raw)
            self.assertNotEqual(result, text_stdout)
            self.assertEqual(len(calls), 1)
            self.assertEqual(calls[0][0], [str(ar), "--plugin", str(plugin), "x", str(archive), name])
            self.assertEqual(calls[0][2], directory)
            self.assertIs(type(calls[0][1]), str)
            self.assertTrue(calls[0][1])
            regular.assert_called_once_with(directory / name)

            existing = root / "existing"
            existing.mkdir()
            target = existing / name
            target.write_bytes(b"preexisting sentinel")
            forbidden = Mock(side_effect=AssertionError("preexisting member must not invoke extraction"))
            with self.assertRaises(ValueError):
                subject.extract_member(api, forbidden, ar, plugin, archive, name, existing)
            forbidden.assert_not_called()
            self.assertEqual(target.read_bytes(), b"preexisting sentinel")

            missing = root / "missing"
            missing.mkdir()
            no_output = Mock(return_value=SimpleNamespace(stdout=raw, stderr=b"", returncode=0))
            with self.assertRaises((ValueError, OSError)):
                subject.extract_member(api, no_output, ar, plugin, archive, name, missing)
            no_output.assert_called_once()
            argv, label = no_output.call_args.args
            self.assertEqual([str(value) for value in argv],
                             [str(ar), "--plugin", str(plugin), "x", str(archive), name])
            self.assertIs(type(label), str)
            self.assertEqual(Path(no_output.call_args.kwargs["cwd"]), missing)
            self.assertFalse((missing / name).exists())

    def test_synthetic_constructor_retains_false_capture_qualification_scope(self):
        class FakeBase:
            def __init__(self, seed, args):
                self.seed, self.args, self.report = seed, args, common.scope_report()

        api = SimpleNamespace(Probe=FakeBase)
        arguments = SimpleNamespace(archiver_sha256="A" * 64)
        probe = subject.probe_type(api)(SimpleNamespace(), arguments)
        self.assertIs(probe.args, arguments)
        self.assertEqual(probe.report["Status"], "FAIL")
        self.assertEqual(probe.report["Scope"], "NATIVE_CM3_O2_LTO_INDEXED_ARCHIVE_CAPTURE_ONLY")
        self.assertEqual(probe.report["Linkage"], "archive")
        self.assertEqual(probe.report["SeedMode"], "O2")
        self.assertEqual(probe.report["ArchiveMemberIndices"], [0, 1, 2, 3, 4, 5])
        self.assertEqual(probe.report["ExplicitObjectIndices"], [8, 7, 6])
        self.assertIs(probe.report["NoForcedExtraction"], True)
        for key in ("ArchiveCaptureComplete", "ArchiveExtraction", "ArchiveExtractionQualified", "Qualification",
                    "FullABIProof", "SourceIRProof", "CanonicalProtocolValidated", "OriginalTranslationUnitOwnership",
                    "WeakAliasPrecedenceProven", "FinalRootRelocationProof", "FinalReferenceParity",
                    "CompleteObjectProof", "SourceToMachineSemanticProof", "OrdinaryOwnerContractSatisfied",
                    "PolicyEquivalence", "ReferenceBuilt", "CpuExecution", "BoardExecution",
                    "RequiredCellSatisfied", "GlobalFreezeQualified"):
            with self.subTest(flag=key):
                self.assertIs(probe.report[key], False)
        self.assertIs(type(probe.report["RequiredCellsSatisfied"]), int)
        self.assertEqual(probe.report["RequiredCellsSatisfied"], 0)

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
    report = dict(
        Status="FAIL", Scope="PURE_SYNTHETIC_CM3_LTO_ARCHIVE_GRAMMAR_AND_RECIPE_ONLY",
        Tests=0, ExpectedTestMethods=EXPECTED_METHODS, Failures=0, Errors=0, Skipped=0,
        SourceHashes={}, SourceDrift=[], SourceClosureVerified=False, ClosingFilesVerified=0,
        SyntheticInputs=True, ActualArchiveTested=False, ActualELFTested=False,
        ToolInvocations=0, NativeCommandsExecuted=0, Qualification=False,
        CaptureExecuted=False, FinalElfProof=False, FinalReferenceParity=False,
        FullABIProof=False, CanonicalProtocolValidated=False, CompleteObjectProof=False,
        KernelRuntimeProof=False, CpuExecution=False, BoardExecution=False,
        GlobalFreezeQualified=False, RequiredCellSatisfied=False, RequiredCellsSatisfied=0)
    try:
        if sys.flags.optimize or not __debug__:
            raise ValueError("optimized interpreter unsupported")
        buffers = {path: path.read_bytes() for path in (Path(__file__).resolve(), PROBE, COMMON)}
        report["SourceHashes"] = {str(path): sha(data) for path, data in buffers.items()}
        global subject, common
        with patch("subprocess.Popen", side_effect=AssertionError("pure archive controls cannot spawn processes")), \
                patch("os.system", side_effect=AssertionError("pure archive controls cannot execute tools")):
            common = load_module("synthetic_archive_common", COMMON, buffers[COMMON])
            subject = load_module("synthetic_cm3_lto_archive_probe", PROBE, buffers[PROBE])
            suite = unittest.defaultTestLoader.loadTestsFromTestCase(ProbeTests)
            if suite.countTestCases() != EXPECTED_METHODS:
                raise ValueError("exact eleven synthetic archive methods required")
            result = unittest.TextTestRunner(verbosity=2).run(suite)
        report.update(Tests=result.testsRun, Failures=len(result.failures), Errors=len(result.errors),
            Skipped=len(result.skipped), FailureDetails=[
                dict(Test=str(case), Detail=detail) for case, detail in result.failures + result.errors])
        if result.wasSuccessful() and result.testsRun == EXPECTED_METHODS and not result.skipped:
            report["Status"] = "PASS"
    except Exception:
        report.update(Status="FAIL", Error=traceback.format_exc(), Errors=report["Errors"] + 1)
    finally:
        for path, expected in report["SourceHashes"].items():
            try:
                if sha(Path(path).read_bytes()) == expected:
                    report["ClosingFilesVerified"] += 1
                else:
                    report["SourceDrift"].append(path)
            except OSError:
                report["SourceDrift"].append(path)
        report["SourceClosureVerified"] = len(report["SourceHashes"]) == 3 and not report["SourceDrift"]
        if not report["SourceClosureVerified"]:
            report["Status"] = "FAIL"
    output.mkdir(parents=True, exist_ok=False)
    target = output / "results.json"
    target.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="ascii")
    print("Receipt:", target, sha(target.read_bytes()))
    return 0 if report["Status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
