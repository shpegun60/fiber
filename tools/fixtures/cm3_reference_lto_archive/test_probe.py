"""Synthetic fixed reference archive capture controls; no tools or targets."""

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
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
PROBE = HERE / "probe.py"
COMMON = HERE.with_name("cm3_lto_transport") / "probe.py"
REFERENCE = HERE.with_name("cm3_reference_lto_transport") / "probe.py"
ARCHIVE_API = HERE.with_name("cm3_lto_archive") / "probe.py"
EXPECTED_METHODS = 10
subject = common = reference_api = archive_api = None
TEST_PLAN = (
    "one member with multiple GNU index symbols, full bytes and header offsets",
    "independently computed symbol-name parity and exact single alignment NUL",
    "malformed magic/header/metadata/payload/name/tail rejection",
    "index bounds/count/name/target rejection and exact one-member count",
    "fresh binary extraction rather than text stdout; missing/preexisting rejection",
    "fixed four source roles with one archived port and explicit order 3/2/1",
    "ordinary/emit archive recipes without whole-archive or forced undefineds",
    "exact single-member GNU map extraction and wrong/extra-record rejection",
    "typed false capture scope and zero qualification/required-cell credit",
    "real reference-archive prepare method on a fake Probe without tools",
)


def sha(data):
    return hashlib.sha256(data).hexdigest().upper()


def ar_member(name, payload, mode="100644"):
    fields = ((name, 16), ("0", 12), ("0", 6), ("0", 6), (mode, 8), (str(len(payload)), 10))
    if any(len(value) > width for value, width in fields):
        raise ValueError("synthetic GNU header overflow")
    header = "".join(value.ljust(width) for value, width in fields).encode("ascii") + b"`\n"
    return header + payload + (b"\n" if len(payload) % 2 else b"")


def one_member_fixture(name="00-port.o", symbols=None, padding=None, optional_table=False):
    """A regular GNU archive, not ELF: multiple symbols may own one member."""
    if symbols is None:
        symbols = [b"vPortSVCHandler", b"xPortPendSVHandler", b"xPortStartScheduler"]
    names = b"".join(symbol + b"\0" for symbol in symbols)
    consumed = 4 + 4 * len(symbols) + len(names)
    if padding is None:
        padding = b"\0" if consumed % 2 else b""
    index_size = consumed + len(padding)
    long_name = len(name) + 1 > 16
    table_payload = name.encode("ascii") + b"/\n" if long_name else b"unused-long-table-name.o/\n"
    table = ar_member("//", table_payload, "0") if long_name or optional_table else b""
    member_header = 8 + 60 + index_size + index_size % 2 + len(table)
    index = struct.pack(">I", len(symbols)) + b"".join(struct.pack(">I", member_header) for _ in symbols) + names + padding
    payload = b"synthetic reference slim IR\n\r\n\0end!"
    record = ar_member("/0" if long_name else name + "/", payload)
    raw = b"!<arch>\n" + ar_member("/", index, "0") + table + record
    return SimpleNamespace(raw=raw, name=name, payload=payload, symbols=symbols,
        member_header=member_header, member_data=member_header + 60, index_data=68,
        index_size=index_size, consumed=consumed, table_header=8 + 60 + index_size + index_size % 2)


def changed(raw, offset, payload):
    return raw[:offset] + payload + raw[offset + len(payload):]


class FakeBaseProbe:
    """Only host file-copy/receipt plumbing; no compiler or inspection methods."""

    def __init__(self, seed, args):
        self.seed, self.args = seed, args
        self.output = getattr(seed, "output", Path(args.output_dir))
        self.report = common.scope_report()
        self.tools, self.tool_hashes = {}, {}
        self.base_prepare_calls = self.base_verify_calls = 0

    def prepare(self):
        self.base_prepare_calls += 1
        self.tool_root = self.output / "toolchain"
        self.tool_root.mkdir(parents=True)
        self.plugin = self.tool_root / self.seed.plugin.relative_to(self.seed.tool_root)
        self.plugin.parent.mkdir(parents=True, exist_ok=True)
        raw = self.seed.closure.read(self.seed.plugin)
        self.plugin.write_bytes(raw)
        self.tool_hashes[self.plugin] = sha(raw)
        self.tools["gcc"] = self.tool_root / "bin/arm-none-eabi-gcc.exe"
        self.verify_tools()

    def verify_tools(self):
        self.base_verify_calls += 1


def fake_api():
    return SimpleNamespace(Probe=FakeBaseProbe, scope_report=common.scope_report,
        regular=common.regular, same=common.same, files_under=common.files_under, save=common.save)


def fake_args(output):
    return SimpleNamespace(reference_build="synthetic-ordinary-reference-seed",
        reference_receipt_sha256="A" * 64, reference_artifacts_sha256="B" * 64,
        archiver_sha256="C" * 64, output_dir=str(output))


class ProbeTests(unittest.TestCase):
    def test_one_member_keeps_all_index_symbols_and_complete_bytes(self):
        for optional_table in (False, True):
            with self.subTest(optional_table=optional_table):
                name = "00-port.o"
                fixture = one_member_fixture(name, optional_table=optional_table)
                result = subject.archive_records(fixture.raw)
                self.assertEqual(result["Sha256"], sha(fixture.raw))
                self.assertEqual(result["Size"], len(fixture.raw))
                self.assertIs(result["DeterministicHeaderMetadata"], True)
                self.assertEqual(len(result["Members"]), 1)
                row = result["Members"][0]
                self.assertEqual(row["Name"], name)
                self.assertEqual(row["Ordinal"], 0)
                self.assertEqual(row["HeaderOffset"], fixture.member_header)
                self.assertEqual(row["DataOffset"], fixture.member_data)
                self.assertEqual(row["Size"], len(fixture.payload))
                self.assertEqual(row["Sha256"], sha(fixture.payload))
                self.assertEqual(fixture.raw[row["DataOffset"]:row["DataOffset"] + row["Size"]], fixture.payload)
                self.assertEqual(result["Index"], [dict(Name=symbol.decode("ascii"),
                    HeaderOffset=fixture.member_header, Member=name) for symbol in fixture.symbols])
                self.assertEqual([item["RawName"] for item in result["Records"]],
                                 ["/", "//", "00-port.o/"] if optional_table else ["/", "00-port.o/"])

    def test_index_padding_is_exact_for_independently_calculated_name_parity(self):
        for symbol, expected_parity in ((b"even", 1), (b"odd", 0)):
            with self.subTest(symbol=symbol):
                consumed = 4 + 4 + len(symbol) + 1
                self.assertEqual(consumed % 2, expected_parity)
                fixture = one_member_fixture(symbols=[symbol])
                self.assertEqual(fixture.consumed, consumed)
                self.assertEqual(fixture.index_size, consumed + expected_parity)
                result = subject.archive_records(fixture.raw)
                self.assertEqual(result["Index"][0]["Name"], symbol.decode("ascii"))
        for padding in (b"", b"\n", b"\x01", b"\0\0"):
            with self.subTest(odd_padding=padding.hex()):
                with self.assertRaises(ValueError):
                    subject.archive_records(one_member_fixture(symbols=[b"even"], padding=padding).raw)
        for padding in (b"\0", b"\0\0"):
            with self.subTest(even_padding=padding.hex()):
                with self.assertRaises(ValueError):
                    subject.archive_records(one_member_fixture(symbols=[b"odd"], padding=padding).raw)

    def test_malformed_archive_headers_names_metadata_bounds_and_tails_reject(self):
        fixture = one_member_fixture()
        raw, header = fixture.raw, fixture.member_header
        self.assertEqual(len(fixture.payload) % 2, 1)
        invalid = [None, True, bytearray(raw), memoryview(raw), "!<arch>\n", b"", b"!<thin>\n" + raw[8:],
            b"!<arch>\nshort", changed(raw, 8 + 58, b"??"), changed(raw, 8 + 48, b"01        "),
            changed(raw, header + 16, b"1".ljust(12)), changed(raw, header + 28, b"1".ljust(6)),
            changed(raw, header + 40, b"100648  "), changed(raw, header + 48, b"9999999999"),
            changed(raw, header, b"/1".ljust(16)), changed(raw, header, b"/999999".ljust(16)),
            changed(raw, header, b"../foreign.o/".ljust(16)),
            changed(raw, header, b"foreign.o/".ljust(16)), one_member_fixture("00-long-reference-port.o").raw,
            changed(raw, fixture.member_data + len(fixture.payload), b"\0"), raw[:-3], raw + b"\n"]
        optional = one_member_fixture(optional_table=True)
        table = optional.raw[optional.table_header:optional.member_header]
        invalid.extend((
            optional.raw[:optional.member_header] + table + optional.raw[optional.member_header:],
            changed(optional.raw, optional.table_header, b"foreign.o/".ljust(16)),
            changed(optional.raw, optional.member_header, b"foreign.o/".ljust(16)),
            changed(optional.raw, optional.member_header, b"/0".ljust(16)),
            optional.raw[:optional.member_header] + ar_member("foreign.o/", b"foreign")
            + optional.raw[optional.member_header:]))
        for index, mutant in enumerate(invalid):
            with self.subTest(case=index):
                with self.assertRaises(ValueError):
                    subject.archive_records(mutant)

    def test_index_requires_exact_member_header_targets_names_and_one_member(self):
        fixture = one_member_fixture()
        raw, start = fixture.raw, fixture.index_data
        invalid = [changed(raw, start, struct.pack(">I", 0)), changed(raw, start, struct.pack(">I", 999999)),
            changed(raw, start + 4, struct.pack(">I", fixture.member_header + 1)),
            changed(raw, start + 4, struct.pack(">I", 8)),
            changed(raw, start + 4, struct.pack(">I", len(raw) + 2)),
            changed(raw, start + 4 + 4 * len(fixture.symbols), b"9"),
            changed(raw, start + fixture.consumed - 1, b"?"),
            raw + ar_member("foreign.o/", b"foreign synthetic IR"),
            raw + ar_member(fixture.name + "/", fixture.payload)]
        optional = one_member_fixture(optional_table=True)
        invalid.append(changed(optional.raw, optional.index_data + 4, struct.pack(">I", optional.table_header)))
        for index, mutant in enumerate(invalid):
            with self.subTest(case=index):
                with self.assertRaises(ValueError):
                    subject.archive_records(mutant)

    def test_binary_extraction_ignores_text_stdout_and_refuses_existing_or_missing_file(self):
        raw = b"reference member\n\r\n\0unchanged\n"
        translated = raw.replace(b"\n", b"\r\n")
        self.assertNotEqual(raw, translated)
        with tempfile.TemporaryDirectory(prefix="synthetic-reference-ar-extract-") as temporary:
            root = Path(temporary).resolve()
            ar, plugin, library = root / "ar.exe", root / "plugin.dll", root / "reference.a"
            name = "00-port.o"
            directory = root / "fresh"
            directory.mkdir()
            api = SimpleNamespace(regular=common.regular)
            calls = []

            def command(argv, label, *, cwd):
                calls.append(([str(value) for value in argv], label, Path(cwd)))
                (Path(cwd) / name).write_bytes(raw)
                return SimpleNamespace(stdout=translated, stderr=b"", returncode=0)

            extracted = archive_api.extract_member(api, command, ar, plugin, library, name, directory)
            self.assertEqual(extracted, raw)
            self.assertEqual((directory / name).read_bytes(), raw)
            self.assertEqual(calls, [([str(ar), "--plugin", str(plugin), "x", str(library), name],
                                      "extract archive member " + name, directory)])
            forbidden = Mock(side_effect=AssertionError("existing member must not invoke a tool"))
            with self.assertRaises(ValueError):
                archive_api.extract_member(api, forbidden, ar, plugin, library, name, directory)
            forbidden.assert_not_called()
            self.assertEqual((directory / name).read_bytes(), raw)
            missing = root / "missing"
            missing.mkdir()
            no_file = Mock(return_value=SimpleNamespace(stdout=raw, stderr=b"", returncode=0))
            with self.assertRaises((ValueError, OSError)):
                archive_api.extract_member(api, no_file, ar, plugin, library, name, missing)
            no_file.assert_called_once()
            self.assertFalse((missing / name).exists())

    def test_four_object_roles_keep_only_three_two_one_then_archive(self):
        objects = [Path("/synthetic/objects/" + name) for name in
                   ("00-port.o", "01-providers.o", "02-consumer.o", "03-startup.o")]
        library = Path("/synthetic/archive/libreference.a")
        before = list(objects)
        self.assertEqual(subject.ARCHIVE_INDICES, (0,))
        self.assertEqual(subject.EXPLICIT_INDICES, (3, 2, 1))
        self.assertEqual(subject.required_provider_order(objects, library),
                         [str(objects[3]), str(objects[2]), str(objects[1]), str(library)])
        self.assertEqual(objects, before)
        for candidate, target in ((objects[:-1], library), (objects + [Path("extra.o")], library),
                (objects[:-1] + [objects[0]], library), (objects[:-1] + [True], library),
                (objects[:-1] + [""], library), (objects, objects[0]), (objects, ""),
                (objects, None), ({"objects": objects}, library)):
            with self.subTest(objects=str(candidate), archive=str(target)):
                with self.assertRaises(ValueError):
                    subject.required_provider_order(candidate, target)

    def test_link_recipe_is_genuine_lto_without_whole_archive_or_forced_undefineds(self):
        objects = [Path("/synthetic/%02d.o" % index) for index in range(4)]
        library, script = Path("/synthetic/reference.a"), Path("/synthetic/link.ld")
        image, map_path = Path("/synthetic/image.elf"), Path("/synthetic/image.map")
        artifact = dict(compile_flags=["-mcpu=cortex-m3", "-mthumb", "-mfloat-abi=soft"])
        plain = subject.link_flags(common, artifact, objects, library, script, image, map_path, False)
        emitted = subject.link_flags(common, artifact, objects, library, script, image, map_path, True)
        self.assertEqual(plain[plain.index("-T") + 2:plain.index("-T") + 6],
                         [str(objects[3]), str(objects[2]), str(objects[1]), str(library)])
        self.assertNotIn(str(objects[0]), plain)
        self.assertEqual([value for value in emitted if value != "-Wl,--emit-relocs"], plain)
        self.assertEqual(emitted.count("-Wl,--emit-relocs"), 1)
        for flag in ("-O2", "-flto", "-flto-partition=one", "-save-temps=obj", "-Wl,-plugin-opt=-save-temps"):
            self.assertEqual(plain.count(flag), 1)
        self.assertFalse(any("whole-archive" in value or "--undefined" in value or value == "-u"
                             or value.startswith(("-Wl,-u", "-u=")) for value in plain))
        for flag in ("-Wl,--whole-archive", "-Wl,--undefined=vPortSVCHandler", "-mcpu=cortex-m4"):
            with self.subTest(flag=flag):
                with self.assertRaises(ValueError):
                    subject.link_flags(common, dict(compile_flags=artifact["compile_flags"] + [flag]),
                                       objects, library, script, image, map_path, False)
        for emit in (0, 1, None, "True"):
            with self.subTest(emit=emit):
                with self.assertRaises(ValueError):
                    subject.link_flags(common, artifact, objects, library, script, image, map_path, emit)

    def test_map_extraction_is_exactly_the_bound_archive_port(self):
        library = Path("/synthetic/reference.a")
        heading = "Archive member included to satisfy reference by file (symbol)"
        line = str(library) + "(00-port.o) consumer.o (vPortSVCHandler)"
        text = "\n".join([heading, "", line, "Memory Configuration"])
        expected = [dict(Member="00-port.o", ReferenceBy="consumer.o", Symbol="vPortSVCHandler")]
        self.assertEqual(subject.extraction_rows(text, library, ["00-port.o"]), expected)
        wrapped = "\n".join([heading, str(library) + "(00-port.o)",
                              "  consumer.o (vPortSVCHandler)", "Discarded input sections"])
        self.assertEqual(subject.extraction_rows(wrapped, library, ["00-port.o"]), expected)
        invalid = [text.replace(line, ""), text.replace(line, line + "\n" + line),
            text.replace(str(library), "/foreign/reference.a"), text.replace("00-port.o", "foreign.o"),
            text.replace(line, "unparsed inclusion"), text.replace("Memory Configuration", ""),
            text + "\0", "\n".join([heading, str(library) + "(00-port.o)", "Memory Configuration"])]
        for index, mutant in enumerate(invalid):
            with self.subTest(case=index):
                with self.assertRaises(ValueError):
                    subject.extraction_rows(mutant, library, ["00-port.o"])

    def test_fake_probe_constructor_retains_four_tu_reference_capture_nonclaims(self):
        api = fake_api()
        arguments = fake_args(Path("/synthetic/output"))
        probe = subject.probe_type(api, reference_api, archive_api)(SimpleNamespace(), arguments)
        self.assertEqual(probe.report["Status"], "FAIL")
        self.assertEqual(probe.report["Scope"], "PINNED_REFERENCE_CM3_O2_LTO_INDEXED_ARCHIVE_CAPTURE_ONLY")
        self.assertEqual(probe.report["ReferenceCommit"], "a50edad08b29052631aa469d4df6e6ec7ff68878")
        self.assertEqual(probe.report["Mode"], "O2-lto")
        self.assertEqual(probe.report["Linkage"], "archive")
        self.assertEqual(probe.report["ArchiveMemberIndices"], [0])
        self.assertEqual(probe.report["ExplicitObjectIndices"], [3, 2, 1])
        self.assertIs(probe.report["NoForcedExtraction"], True)
        for key in ("ArchiveExtraction", "ArchiveExtractionQualified", "ArchiveCaptureComplete",
                    "WeakAliasPrecedenceProven", "Qualification", "FullABIProof", "SourceIRProof",
                    "OriginalTranslationUnitOwnership", "CompleteObjectProof", "NativeBuilt", "ReferenceBuilt",
                    "ReferenceKernelAvailable", "SchedulerSemanticsProven", "CSourceSemanticProof",
                    "HandlerRoutingProven", "CanonicalProtocolValidated", "FinalRootRelocationProof",
                    "FinalReferenceParity", "PolicyEquivalence", "CpuExecution", "BoardExecution",
                    "GlobalFreezeQualified", "RequiredCellSatisfied"):
            with self.subTest(flag=key):
                self.assertIs(probe.report[key], False)
        for key in ("TranslationUnits", "SlimIRObjects", "RequiredCellsSatisfied"):
            self.assertIs(type(probe.report[key]), int)
            self.assertEqual(probe.report[key], 0)

    def test_prepare_uses_reference_base_and_clones_archiver_without_super_type_error(self):
        with tempfile.TemporaryDirectory(prefix="synthetic-reference-ar-prepare-") as temporary:
            root = Path(temporary).resolve()
            tools, output = root / "seed-tools", root / "output"
            (tools / "bin").mkdir(parents=True)
            (tools / "lib").mkdir()
            output.mkdir()
            ar, plugin = tools / "bin/arm-none-eabi-ar.exe", tools / "lib/lto_plugin.dll"
            ar.write_bytes(b"synthetic ar\n\r\n\0not executable")
            plugin.write_bytes(b"synthetic plugin, never loaded")
            info = ar.stat()
            seed = SimpleNamespace(output=output, tool_root=tools, plugin=plugin, closure=common.Closure(),
                result=dict(ReferenceFileBindings=[dict(Path="synthetic/reference.h", Sha256="B" * 64)]),
                archive_tool=dict(Path=str(ar), Sha256=sha(ar.read_bytes()),
                    Identity=dict(Device=info.st_dev, FileId=info.st_ino, Links=info.st_nlink)))
            probe = subject.probe_type(fake_api(), reference_api, archive_api)(seed, fake_args(output))
            probe.command = Mock(side_effect=AssertionError("prepare smoke cannot run tools"))
            probe.prepare()
            self.assertEqual(probe.base_prepare_calls, 1)
            self.assertGreaterEqual(probe.base_verify_calls, 1)
            captured = probe.tool_root / ar.relative_to(tools)
            self.assertEqual(probe.tools["ar"], captured)
            self.assertNotEqual(captured, ar)
            self.assertEqual(captured.read_bytes(), ar.read_bytes())
            self.assertEqual(probe.tool_hashes[captured], seed.archive_tool["Sha256"])
            self.assertEqual(probe.report["Archiver"]["Captured"], str(captured))
            self.assertEqual(probe.report["Archiver"]["Sha256"], seed.archive_tool["Sha256"])
            self.assertEqual(probe.report["SeedSide"], "Reference")
            self.assertEqual(probe.report["ReferenceFileBindings"], seed.result["ReferenceFileBindings"])
            self.assertIs(probe.report["ReferenceKernelAvailable"], False)
            probe.command.assert_not_called()


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
        Status="FAIL", Scope="PURE_SYNTHETIC_CM3_REFERENCE_ARCHIVE_GRAMMAR_RECIPE_AND_SCOPE_ONLY",
        Tests=0, ExpectedTestMethods=EXPECTED_METHODS, Failures=0, Errors=0, Skipped=0,
        SourceHashes={}, SourceDrift=[], SourceClosureVerified=False, ClosingFilesVerified=0,
        TestPlan=list(TEST_PLAN), SyntheticInputs=True, ActualArchiveTested=False,
        ActualELFTested=False, CaptureExecuted=False, ToolInvocations=0, NativeCommandsExecuted=0,
        Qualification=False, FinalElfProof=False, FinalReferenceParity=False,
        CanonicalProtocolValidated=False, FullABIProof=False, CompleteObjectProof=False,
        SourceToMachineSemanticProof=False, OriginalTranslationUnitOwnership=False,
        KernelRuntimeProof=False, CpuExecution=False, BoardExecution=False,
        GlobalFreezeQualified=False, RequiredCellSatisfied=False, RequiredCellsSatisfied=0)
    try:
        if sys.flags.optimize or not __debug__:
            raise ValueError("optimized interpreter unsupported")
        paths = (Path(__file__).resolve(), PROBE, COMMON, REFERENCE, ARCHIVE_API)
        buffers = {path: path.read_bytes() for path in paths}
        report["SourceHashes"] = {str(path): sha(data) for path, data in buffers.items()}
        global subject, common, reference_api, archive_api
        with patch("subprocess.Popen", side_effect=AssertionError("pure reference archive controls cannot spawn processes")), \
                patch("os.system", side_effect=AssertionError("pure reference archive controls cannot execute tools")):
            common = load_module("synthetic_reference_archive_common", COMMON, buffers[COMMON])
            reference_api = load_module("synthetic_reference_archive_reference", REFERENCE, buffers[REFERENCE])
            archive_api = load_module("synthetic_reference_archive_native_helpers", ARCHIVE_API, buffers[ARCHIVE_API])
            subject = load_module("synthetic_reference_archive_probe", PROBE, buffers[PROBE])
            suite = unittest.defaultTestLoader.loadTestsFromTestCase(ProbeTests)
            if suite.countTestCases() != EXPECTED_METHODS:
                raise ValueError("exact ten implemented reference archive controls required")
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
        report["SourceClosureVerified"] = len(report["SourceHashes"]) == 5 and not report["SourceDrift"]
        if not report["SourceClosureVerified"]:
            report["Status"] = "FAIL"
    output.mkdir(parents=True, exist_ok=False)
    target = output / "results.json"
    target.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="ascii")
    print("Receipt:", target, sha(target.read_bytes()))
    return 0 if report["Status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
