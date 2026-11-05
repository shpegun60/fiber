"""Pure fake-tool Os-LTO transport controls; no compiler, target or witness."""
import argparse
from contextlib import ExitStack
import hashlib
import importlib.util
import json
from pathlib import Path
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
EXPECTED_METHODS = 14
p = common = reference = None
TARGET = ["-mcpu=cortex-m3", "-mthumb", "-mfloat-abi=soft"]
BASE_FLAGS = [*TARGET, "-O2", "-ffunction-sections", "-fdata-sections"]


def sha(data):
    return hashlib.sha256(data).hexdigest().upper()


class Closure:
    def __init__(self):
        self.hashes, self.memberships = {}, {}
        self.failure = None

    def read(self, path, expected=None):
        path = Path(path)
        data = path.read_bytes()
        value = sha(data)
        if expected is not None and expected != value:
            raise ValueError("synthetic expected source hash mismatch")
        if path in self.hashes and self.hashes[path] != value:
            raise ValueError("synthetic closing input drift")
        self.hashes[path] = value
        return data

    def tree(self, root, expected):
        paths = {path.relative_to(root).as_posix(): path for path in root.rglob("*") if path.is_file()}
        if set(paths) != set(expected):
            raise ValueError("synthetic tree membership mismatch")
        self.memberships[root] = set(paths)
        for name, path in paths.items():
            self.read(path, expected[name])

    def close(self):
        if self.failure:
            raise self.failure
        for path, value in tuple(self.hashes.items()):
            self.read(path, value)


def sections(text):
    native = "startup" in text or "ltrans0.ltrans.o" in text
    return [dict(Index=0, Name="", Size=0, Flags=""),
            dict(Index=1, Name=".text" if native else ".gnu.lto_synthetic", Size=4, Flags="AX" if native else "")]


class CompileFixture:
    """Small real temp files and invented metadata; never genuine ELF or IR."""
    def __init__(self, root, cls, count):
        self.root = root
        self.output = root / "output"
        self.output.mkdir()
        self.dependencies, self.commands = {}, []
        self.dependency_change = None
        self.command_failure = None
        self.inspect_change = None
        self.header = root / "input.h"
        self.header.write_bytes(b"/* synthetic shared header */\n")
        closure, rows = Closure(), []
        closure.read(self.header)
        for index in range(count):
            source = root / ("startup.S" if index == count - 1 else "source-%02d.c" % index)
            source.write_bytes(("/* synthetic source %d, never compiled */\n" % index).encode("ascii"))
            closure.read(source)
            rows.append(dict(Source=str(source), SourceSha256=sha(source.read_bytes()), CompileFlags=list(BASE_FLAGS),
                Dependencies=[dict(Path=str(source), Sha256=sha(source.read_bytes())),
                              dict(Path=str(self.header), Sha256=sha(self.header.read_bytes()))]))
        self.seed = SimpleNamespace(output=self.output, closure=closure, sources=rows, tool_root=root / "seed-tools",
            artifact=dict(compile_flags=list(TARGET)), script=root / "link.ld",
            native=SimpleNamespace(read_dependencies=self.read_dependencies))
        self.seed.script.write_bytes(b"/* synthetic linker input, never linked */\n")
        side = "native" if count == 9 else "reference"
        arguments = SimpleNamespace(**{side + "_build": str(root / "seed"),
            side + "_receipt_sha256": "A" * 64, side + "_artifacts_sha256": "B" * 64,
            "output_dir": str(self.output)})
        self.probe = cls(self.seed, arguments)
        self.probe.tool_root = root / "copied-tools"
        self.probe.tools = dict(gcc="synthetic-gcc-never-executed")
        self.probe.command = self.command
        self.probe.inspect = self.inspect

    def read_dependencies(self, path):
        result = list(self.dependencies[Path(path)])
        return self.dependency_change(result) if self.dependency_change else result

    def command(self, argv, label, *, cwd=None, timeout=120):
        argv = [str(value) for value in argv]
        self.commands.append(dict(Argv=argv, Label=label, Cwd=str(cwd or self.output)))
        self.probe.report["Commands"].append(dict(Label=label, Argv=argv,
            Status="FAIL" if self.command_failure else "PASS", Exit=1 if self.command_failure else 0, TimedOut=False))
        if self.command_failure:
            raise self.command_failure
        obj = Path(argv[argv.index("-o") + 1])
        obj.write_bytes(b"synthetic object bytes, not ELF or IR")
        source = Path(argv[argv.index("-c") + 1])
        dependency = Path(argv[argv.index("-MF") + 1])
        dependency.write_bytes(b"synthetic dependency record consumed through the fake parser\n")
        self.dependencies[dependency] = [source, self.header]
        return SimpleNamespace(stdout=b"", stderr=b"")

    def inspect(self, path):
        text = "Type: REL\nMachine: ARM\n" + str(path)
        return self.inspect_change(path, text) if self.inspect_change else text

    def metadata(self):
        stack = ExitStack()
        stack.enter_context(patch.object(common, "require_elf32le", return_value=dict(SectionCount=2)))
        stack.enter_context(patch.object(common, "section_records", side_effect=sections))
        return stack


def capture_class(side):
    return p.probe_type(common, side, reference)


def build_fixture(fixture, *, link_failure=None, extra_partition=False):
    probe = fixture.probe
    probe.prepare, probe.compile = Mock(), Mock()
    verify = probe.verify_objects
    probe.verify_objects = Mock(wraps=verify)
    probe.verify_tools = Mock()
    probe.trace_identities = Mock(return_value=dict(Synthetic=True))
    def command(argv, label, *, cwd=None, timeout=120):
        argv = [str(value) for value in argv]
        fixture.commands.append(dict(Argv=argv, Label=label, Cwd=str(cwd)))
        probe.report["Commands"].append(dict(Label=label, Argv=argv,
            Status="FAIL" if link_failure else "PASS", Exit=1 if link_failure else 0, TimedOut=False))
        if link_failure:
            raise link_failure
        image = Path(argv[argv.index("-o") + 1])
        image.write_bytes(b"synthetic final, not ELF")
        image.with_suffix(".map").write_bytes(b"synthetic map, not linker output")
        for suffix in (".ltrans0.ltrans.o", ".res", ".ltrans.out", ".ltrans0.o", ".ltrans0.ltrans.s"):
            Path(str(image) + suffix).write_bytes(b"synthetic transport bytes, never generated by GCC")
        if extra_partition:
            Path(str(image) + ".ltrans1.ltrans.o").write_bytes(b"synthetic extra machine")
        return SimpleNamespace(stdout=b"", stderr=b"synthetic trace, not tool execution")
    probe.command = command
    def compare():
        evidence = dict(Identical=True, Synthetic=True)
        target = probe.output / "load-image.json"
        target.write_text(json.dumps(evidence, sort_keys=True) + "\n", encoding="ascii")
        probe.seed.closure.read(target)
        probe.report.update(TwinLoadImageCompared=True, TwinLoadImageIdentical=True,
            TwinAllocatedSectionsIdentical=True, TwinLoadImages=evidence,
            TwinLoadImagesPath=str(target), TwinLoadImagesSha256=sha(target.read_bytes()))
        probe.twins_verified = True
    probe.compare_twins = Mock(side_effect=compare)
    return probe


def synthetic_build_metadata(fixture):
    stack = fixture.metadata()
    stack.enter_context(patch.object(common, "symbol_records", return_value=[dict(Name="synthetic-native-fact")]))
    stack.enter_context(patch.object(reference, "symbol_records", return_value=[dict(Name="synthetic-reference-fact")]))
    return stack


class ProbeTests(unittest.TestCase):
    def test_sole_o2_to_os_transform_keeps_all_other_flags_and_input(self):
        original = list(BASE_FLAGS)
        self.assertEqual(p.startup_flags(original), ["-Os" if value == "-O2" else value for value in original])
        self.assertEqual(p.mode_flags(original), ["-Os" if value == "-O2" else value for value in original]
                         + ["-flto", "-fno-fat-lto-objects"])
        self.assertEqual(original, BASE_FLAGS)
        self.assertIsNot(p.startup_flags(original), original)

    def test_transform_rejects_missing_repeated_or_foreign_optimization(self):
        bad = (None, True, False, "-O2", tuple(BASE_FLAGS), [16], [], [*BASE_FLAGS, "-O2"],
               [*BASE_FLAGS, "-O3"], [value for value in BASE_FLAGS if value != "-O2"])
        for flags in bad:
            with self.subTest(flags=flags), self.assertRaises(ValueError):
                p.mode_flags(flags)
        for optimization in ("-O0", "-Og", "-Os", "-O3", "-Ofast", "-O2=1"):
            with self.subTest(optimization=optimization), self.assertRaises(ValueError):
                p.startup_flags([optimization if value == "-O2" else value for value in BASE_FLAGS])

    def test_preexisting_lto_and_fat_object_counteroverrides_reject(self):
        for flag in ("-flto", "-flto=2", "-flto=auto", "-fno-lto", "-ffat-lto-objects", "-fno-fat-lto-objects"):
            for function in (p.mode_flags, p.startup_flags):
                with self.subTest(flag=flag, function=function.__name__), self.assertRaises(ValueError):
                    function([*BASE_FLAGS, flag])

    def test_link_recipe_changes_only_optimization_for_both_twins(self):
        artifact = dict(compile_flags=list(TARGET))
        objects = [Path("synthetic-input-0.o"), Path("synthetic-startup.o")]
        for emit in (False, True):
            original = common.link_flags(artifact, objects, Path("link.ld"), Path("image.elf"), Path("image.map"), emit)
            actual = p.link_flags(common, artifact, objects, Path("link.ld"), Path("image.elf"), Path("image.map"), emit)
            self.assertEqual(actual, ["-Os" if value == "-O2" else value for value in original])
            self.assertEqual([value for value in actual if value.startswith("-O")], ["-Os"])
            for required in ("-flto", "-flto-partition=one", "-save-temps=obj", "-Wl,-plugin-opt=-save-temps", "-v"):
                self.assertIn(required, actual)
        with self.assertRaises(ValueError):
            p.link_flags(common, artifact, objects, Path("link.ld"), Path("image.elf"), Path("image.map"), 1)

    def test_exact_side_translation_and_initial_scope_nonclaims(self):
        for side, count in (("native", 9), ("reference", 4)):
            args = SimpleNamespace(side=side, seed_build="synthetic-seed", seed_receipt_sha256="A" * 64,
                seed_artifacts_sha256="B" * 64, output_dir="synthetic-output")
            translated = p.seed_args(args)
            self.assertEqual(vars(translated), {side + "_build": "synthetic-seed", side + "_receipt_sha256": "A" * 64,
                side + "_artifacts_sha256": "B" * 64, "output_dir": "synthetic-output"})
            with tempfile.TemporaryDirectory() as directory:
                fixture = CompileFixture(Path(directory), capture_class(side), count)
                result = fixture.probe.report
                self.assertEqual(result["Mode"], "Os-lto")
                self.assertEqual(result["SeedMode"], "O2")
                self.assertEqual(result["SeedSide"], side.capitalize())
                for key in ("Qualification", "FullABIProof", "SourceIRProof", "SourceToMachineSemanticProof",
                            "OriginalTranslationUnitOwnership", "CanonicalProtocolValidated", "FinalRootRelocationProof",
                            "FinalReferenceParity", "PolicyEquivalence", "CompleteObjectProof", "CpuExecution",
                            "BoardExecution", "GlobalFreezeQualified", "RequiredCellSatisfied"):
                    self.assertIs(result[key], False)
                self.assertIs(type(result["RequiredCellsSatisfied"]), int)
                self.assertEqual(result["RequiredCellsSatisfied"], 0)
        for side in (None, True, 0, "Native", "REFERENCE", "other"):
            with self.subTest(side=side), self.assertRaises(ValueError):
                p.probe_type(common, side, reference)

    def test_compile_both_exact_groups_c_slim_and_native_startup(self):
        for side, count in (("native", 9), ("reference", 4)):
            with tempfile.TemporaryDirectory() as directory:
                fixture = CompileFixture(Path(directory), capture_class(side), count)
                with fixture.metadata():
                    fixture.probe.compile()
                result = fixture.probe.report
                self.assertEqual(len(fixture.commands), count)
                self.assertEqual(len(result["Sources"]), count)
                self.assertEqual(result["TranslationUnits"], count)
                self.assertEqual(result["SlimIRObjects"], count - 1)
                self.assertIs(type(result["TranslationUnits"]), int)
                self.assertIs(type(result["SlimIRObjects"]), int)
                for index, row in enumerate(result["Sources"]):
                    self.assertIs(row["SlimIR"], index != count - 1)
                    self.assertIs(row["CompileDependenciesVerified"], True)
                    self.assertEqual([flag for flag in row["CompileFlags"] if flag.startswith("-O")], ["-Os"])
                    self.assertEqual("-flto" in row["CompileFlags"], index != count - 1)
                    self.assertEqual(row["SeedCompileFlags"], BASE_FLAGS)
                    argv = fixture.commands[index]["Argv"]
                    self.assertEqual(argv[1:1 + len(row["CompileFlags"])], row["CompileFlags"])
                    self.assertEqual(argv[argv.index("-MT") + 1], "pilot-source-" + str(index))

    def test_missing_or_extra_source_group_fails_before_any_fake_command(self):
        for side, count in (("native", 9), ("reference", 4)):
            for extra in (False, True):
                with tempfile.TemporaryDirectory() as directory:
                    fixture = CompileFixture(Path(directory), capture_class(side), count)
                    if extra:
                        fixture.seed.sources.append(dict(fixture.seed.sources[0]))
                    else:
                        fixture.seed.sources.pop()
                    with self.subTest(side=side, extra=extra), self.assertRaises(ValueError):
                        fixture.probe.compile()
                    self.assertEqual(fixture.commands, [])

    def test_actual_compile_dependencies_missing_extra_and_changed_bytes_reject(self):
        for side, count in (("native", 9), ("reference", 4)):
            for change in ("missing", "extra", "changed"):
                with tempfile.TemporaryDirectory() as directory:
                    fixture = CompileFixture(Path(directory), capture_class(side), count)
                    if change == "missing":
                        fixture.dependency_change = lambda values: values[:1]
                    elif change == "extra":
                        foreign = fixture.root / "foreign.h"
                        foreign.write_bytes(b"synthetic foreign header")
                        fixture.dependency_change = lambda values, foreign=foreign: [*values, foreign]
                    else:
                        fixture.dependency_change = lambda values: (fixture.header.write_bytes(b"changed"), values)[1]
                    with self.subTest(side=side, change=change), fixture.metadata(), self.assertRaises(ValueError):
                        fixture.probe.compile()
                    self.assertFalse(fixture.probe.complete)

    def test_c_fat_fallback_missing_ir_and_lto_startup_reject(self):
        for side, count in (("native", 9), ("reference", 4)):
            for change in ("fat-c", "missing-ir", "lto-startup", "wrong-machine", "section-count"):
                with tempfile.TemporaryDirectory() as directory:
                    fixture = CompileFixture(Path(directory), capture_class(side), count)
                    def altered(text, change=change):
                        result = sections(text)
                        startup = "startup" in text
                        if change == "fat-c" and not startup:
                            result[1]["Flags"] = "AX"
                        elif change == "missing-ir" and not startup:
                            result[1]["Name"] = ".data"
                        elif change == "lto-startup" and startup:
                            result[1].update(Name=".gnu.lto_bad", Flags="")
                        return result
                    if change == "wrong-machine":
                        fixture.inspect_change = lambda path, text: text.replace("Machine: ARM", "Machine: X86")
                    with self.subTest(side=side, change=change), fixture.metadata() as stack:
                        stack.enter_context(patch.object(common, "section_records", side_effect=altered))
                        if change == "section-count":
                            stack.enter_context(patch.object(common, "require_elf32le", return_value=dict(SectionCount=3)))
                        with self.assertRaises(ValueError):
                            fixture.probe.compile()
                    self.assertFalse(fixture.probe.complete)

    def test_exact_object_count_hash_and_missing_file_checks(self):
        for side, count in (("native", 9), ("reference", 4)):
            for change in ("partial", "extra-hash", "changed", "missing"):
                with tempfile.TemporaryDirectory() as directory:
                    fixture = CompileFixture(Path(directory), capture_class(side), count)
                    with fixture.metadata():
                        fixture.probe.compile()
                    probe = fixture.probe
                    if change == "partial":
                        probe.objects.pop()
                    elif change == "extra-hash":
                        probe.object_hashes[fixture.root / "foreign.o"] = "C" * 64
                    elif change == "changed":
                        probe.objects[0].write_bytes(b"changed synthetic object")
                    else:
                        probe.objects[0].unlink()
                    with self.subTest(side=side, change=change), self.assertRaises((ValueError, OSError)):
                        probe.verify_objects("synthetic-mutation")

    def test_build_invokes_two_distinct_link_commands_with_own_artifacts(self):
        for side, count in (("native", 9), ("reference", 4)):
            with tempfile.TemporaryDirectory() as directory:
                fixture = CompileFixture(Path(directory), capture_class(side), count)
                with fixture.metadata():
                    fixture.probe.compile()
                probe = build_fixture(fixture)
                with synthetic_build_metadata(fixture):
                    probe.build()
                links = [row for row in fixture.commands if row["Label"].startswith("link ")]
                self.assertEqual([row["Label"] for row in links], ["link ordinary", "link emit-relocs"])
                self.assertNotEqual(links[0]["Cwd"], links[1]["Cwd"])
                self.assertEqual([row["Kind"] for row in probe.report["Links"]], ["ordinary", "emit-relocs"])
                self.assertEqual(probe.report["FinalExecutableLinks"], 2)
                self.assertEqual(probe.report["SavedMachineObjects"], 2)
                self.assertEqual([row["Argv"].count("-Os") for row in links], [1, 1])
                self.assertIs(probe.complete, True)
                self.assertIs(probe.twins_verified, True)
                probe.compare_twins.assert_called_once()
                self.assertEqual([call.args[0] for call in probe.verify_objects.call_args_list],
                    ["before-link-ordinary", "after-link-ordinary", "before-link-emit-relocs", "after-link-emit-relocs", "closing"])

    def test_link_failure_or_extra_machine_partition_never_completes(self):
        for side, count in (("native", 9), ("reference", 4)):
            for change in ("link-failure", "extra-partition"):
                with tempfile.TemporaryDirectory() as directory:
                    fixture = CompileFixture(Path(directory), capture_class(side), count)
                    with fixture.metadata():
                        fixture.probe.compile()
                    probe = build_fixture(fixture,
                        link_failure=ValueError("synthetic link failure") if change == "link-failure" else None,
                        extra_partition=change == "extra-partition")
                    with self.subTest(side=side, change=change), synthetic_build_metadata(fixture), self.assertRaises(ValueError):
                        probe.build()
                    self.assertFalse(probe.complete)
                    self.assertEqual(probe.report["Links"], [])
                    probe.compare_twins.assert_not_called()
                    self.assertIn("after-link-ordinary", [call.args[0] for call in probe.verify_objects.call_args_list])

    def test_compile_error_and_incomplete_build_cannot_promote_at_finish(self):
        for side, count in (("native", 9), ("reference", 4)):
            with tempfile.TemporaryDirectory() as directory:
                fixture = CompileFixture(Path(directory), capture_class(side), count)
                fixture.command_failure = ValueError("synthetic compile failure")
                with fixture.metadata(), self.assertRaisesRegex(ValueError, "synthetic compile failure"):
                    fixture.probe.compile()
                self.assertEqual(fixture.probe.report["Commands"][0]["Status"], "FAIL")
                self.assertFalse(fixture.probe.complete)
                self.assertEqual(fixture.probe.report["Links"], [])
                fixture.probe.verify_tools = Mock()
                self.assertIs(fixture.probe.finish(fixture.command_failure), False)
                self.assertEqual(fixture.probe.report["Status"], "FAIL")
            with tempfile.TemporaryDirectory() as directory:
                fixture = CompileFixture(Path(directory), capture_class(side), count)
                with fixture.metadata():
                    fixture.probe.compile()
                probe = build_fixture(fixture)
                with synthetic_build_metadata(fixture):
                    probe.build()
                probe.report["Links"].pop()
                self.assertIs(probe.finish(), False)
                self.assertEqual(probe.report["Status"], "FAIL")

    def test_successful_synthetic_finish_and_late_close_failure_nonpromotion(self):
        for side, count in (("native", 9), ("reference", 4)):
            for fail_late in (False, True):
                with tempfile.TemporaryDirectory() as directory:
                    fixture = CompileFixture(Path(directory), capture_class(side), count)
                    with fixture.metadata():
                        fixture.probe.compile()
                    probe = build_fixture(fixture)
                    with synthetic_build_metadata(fixture):
                        probe.build()
                    if fail_late:
                        original_close = probe.close_inputs
                        calls = []
                        def closing():
                            calls.append(None)
                            if len(calls) == 2:
                                raise ValueError("synthetic late closing failure")
                            original_close()
                        probe.close_inputs = closing
                    self.assertIs(probe.finish(), not fail_late)
                    self.assertEqual(probe.report["Status"], "FAIL" if fail_late else "PASS")
                    self.assertIs(probe.report["GlobalFreezeQualified"], False)
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
    report = dict(Status="FAIL", Tests=0, ExpectedTestMethods=EXPECTED_METHODS, Failures=0, Errors=0, Skipped=0,
        SourceHashes={}, SourceDrift=[], SourceClosureVerified=False, ClosingFilesVerified=0,
        Scope="PURE_SYNTHETIC_CM3_OS_LTO_CAPTURE_CONTROLS_ONLY", SyntheticInputs=True,
        ActualELFTested=False, ActualCompileTested=False, ActualLinkTested=False, ActualWitnessTested=False,
        Qualification=False, NativeCommandsExecuted=0, ToolInvocations=0, FullABIProof=False, SourceIRProof=False,
        SourceToMachineSemanticProof=False, OriginalTranslationUnitOwnership=False, CanonicalProtocolValidated=False,
        InstructionEquivalence=False, PolicyEquivalence=False, FinalReferenceParity=False, CompleteObjectProof=False,
        KernelRuntimeProof=False, CpuExecution=False, BoardExecution=False, GlobalFreezeQualified=False,
        RequiredCellSatisfied=False, RequiredCellsSatisfied=0)
    paths = (Path(__file__).resolve(), PROBE, COMMON, REFERENCE)
    try:
        if sys.flags.optimize or not __debug__:
            raise ValueError("optimized interpreter unsupported")
        buffers = {item: item.read_bytes() for item in paths}
        report["SourceHashes"] = {str(item): sha(data) for item, data in buffers.items()}
        global p, common, reference
        with patch("subprocess.Popen", side_effect=AssertionError("pure controls cannot execute processes")), \
                patch("os.system", side_effect=AssertionError("pure controls cannot execute processes")):
            def source_read(path):
                if path not in buffers:
                    raise AssertionError("unexpected producer source input: " + str(path))
                return buffers[path]
            with patch.object(Path, "read_bytes", source_read):
                common = load_module("synthetic_os_lto_common", COMMON, buffers[COMMON])
                reference = load_module("synthetic_os_lto_reference", REFERENCE, buffers[REFERENCE])
                p = load_module("synthetic_os_lto_probe", PROBE, buffers[PROBE])
            suite = unittest.defaultTestLoader.loadTestsFromTestCase(ProbeTests)
            count = suite.countTestCases()
            if count != EXPECTED_METHODS:
                raise ValueError("exact fourteen synthetic Os-LTO control methods required")
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
