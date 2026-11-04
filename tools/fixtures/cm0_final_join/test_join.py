"""Pure CM0 join helper controls using synthetic files, never ELF or tools."""
import argparse
import builtins
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("cm0_join_helper_controls", HERE / "join.py")
join = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(join)


def sha(data):
    return hashlib.sha256(data).hexdigest().upper()


def put(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


class TemporaryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="cm0-join-helpers-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name).resolve()
        self.output = self.directory / "join output"
        self.output.mkdir()
        self.watch = join.Watch(self.output)


class SharedBufferTests(TemporaryTests):
    def invoke(self, captured_bytes):
        path = put(self.directory / "shared.py", captured_bytes)
        with patch.object(join, "_SHARED_PATH", path), \
                patch.object(join, "_SHARED_BYTES", b"executed helper buffer\n"), \
                patch.object(join, "bind_parser", side_effect=LookupError("parser boundary")) as parser:
            join.load_api(self.watch, self.directory)

    def test_matching_executed_buffer_reaches_parser_boundary(self):
        with self.assertRaisesRegex(LookupError, "parser boundary"):
            self.invoke(b"executed helper buffer\n")
        path = self.directory / "shared.py"
        self.assertEqual(self.watch.hashes[path], sha(b"executed helper buffer\n"))
        self.assertEqual(self.watch.copies[path].read_bytes(), b"executed helper buffer\n")
        self.watch.close()

    def test_stable_different_buffer_rejects_before_parser(self):
        path = put(self.directory / "shared.py", b"stable replacement buffer\n")
        with patch.object(join, "_SHARED_PATH", path), \
                patch.object(join, "_SHARED_BYTES", b"executed helper buffer\n"), \
                patch.object(join, "bind_parser") as parser:
            with self.assertRaisesRegex(ValueError, "input hash mismatch"):
                join.load_api(self.watch, self.directory)
            parser.assert_not_called()
        self.assertEqual(self.watch.hashes, {})


class CoverageFixture:
    def __init__(self, directory, side="Reference"):
        self.root, self.side = directory / "build with spaces", side
        self.rows, self.generated, self.keys = [], {}, {}
        source = self.add("port.c", self.root / "freertos/portable/GCC/ARM_CM0/port.c")
        dependency = self.add("task.h", self.root / "freertos/include/task.h")
        self.add("gcc.exe", original=directory / "toolchain/bin/gcc.exe")
        self.add("python.exe")
        self.result = dict(Sources=[dict(Source=source, Dependencies=[dict(Path=dependency, Sha256=self.rows[1]["Sha256"])])],
                           Interpreter=dict(ModulePath=self.keys["python.exe"]["Original"]),
                           Commands=[dict(Label="compile port", Argv=[self.keys["gcc.exe"]["Original"], "-c", source])])
        self.add("host.dll", original=directory / "toolchain/bin/host.dll")
        for worker in ("cc1", "collect2", "as", "ld", "lto1", "lto-wrapper"):
            self.add(worker + ".exe", original=directory / "toolchain/libexec" / (worker + ".exe"))
            index = len(self.result["Commands"])
            self.result["Commands"].append(dict(Label="resolve " + worker,
                Argv=[self.keys["gcc.exe"]["Original"], "-print-prog-name=" + worker]))
            put(self.root / ("command-%04d.stdout" % index),
                (self.keys[worker + ".exe"]["Original"] + "\n").encode("utf-8"))
        inventory = directory / "inventory"
        self.add("inventory-payload", original=inventory / "payload.bin")
        manifest = json.dumps(dict(Artifacts={"payload.bin": self.keys["inventory-payload"]["Sha256"]})).encode("ascii")
        self.add("inventory-manifest", original=inventory / "artifacts.json", data=manifest)
        self.result["SourceInventoryReceipt"] = str(inventory)
        self.add("parser.py", self.root / "python/elftools/__init__.py")
        fixture = self.root / "source/tools/fixtures" / (
            "classic_final_image" if side == "Native" else "cm0_final_image/reference")
        self.add("link.ld", fixture / "link.ld")
        if side == "Reference":
            self.add("base-config", fixture / "freeze_base_FreeRTOSConfig.h")
            self.config = self.generate(fixture / "FreeRTOSConfig.h", b"synthetic generated config\n")
            blob = self.generate(self.root / "reference-blobs/include/task.h", b"synthetic task.h\n")
            self.result["ReferenceFileBindings"] = [dict(Captured=dependency,
                Original=self.keys["task.h"]["Original"], GitBlob=blob)]
        self.inputs = dict(Files=self.rows, Generated=self.generated)
        # Native also needs a nonempty generated inventory, without a FreeRTOS config.
        if not self.generated:
            self.generate(self.root / "generated/main.h", b"synthetic main\n")

    def add(self, name, captured=None, *, original=None, data=None):
        data = data if data is not None else ("synthetic " + name + "\n").encode("ascii")
        original = original or self.root.parent / "originals" / name
        captured = captured or self.root / "input-bytes" / name
        put(original, data)
        put(captured, data)
        row = dict(Original=str(original), Captured=str(captured), Sha256=sha(data))
        self.rows.append(row)
        self.keys[name] = row
        return str(captured)

    def generate(self, path, data):
        put(path, data)
        self.generated[str(path)] = sha(data)
        return str(path)

    def omit(self, key):
        self.rows.remove(self.keys[key])

    def seal(self):
        put(self.root / "inputs.json", json.dumps(self.inputs).encode("ascii"))
        artifacts = {path.relative_to(self.root).as_posix(): sha(path.read_bytes())
                     for path in self.root.rglob("*") if path.is_file() and path.name != "artifacts.json"}
        put(self.root / "artifacts.json", json.dumps(dict(Artifacts=artifacts)).encode("ascii"))


class CoverageTests(TemporaryTests):
    def setUp(self):
        super().setUp()
        self.fixture = CoverageFixture(self.directory)

    def verify(self):
        fixture = self.fixture
        fixture.seal()
        artifacts = join.close_build(self.watch, fixture.root)
        join.require_input_coverage(self.watch, fixture.root, fixture.result, artifacts, fixture.side)
        self.watch.close()

    def reject_omission(self, key, reason):
        self.fixture.omit(key)
        with self.assertRaisesRegex(ValueError, reason):
            self.verify()

    def test_complete_reference_inputs_pass(self):
        self.verify()

    def test_native_inputs_allow_equal_content_addressed_capture(self):
        self.fixture = CoverageFixture(self.directory / "native", side="Native")
        data = b"equal shared bytes\n"
        captured = self.fixture.root / "input-bytes" / (sha(data) + "-shared.h")
        first = self.fixture.add("shared.h", captured, data=data)
        self.fixture.add("alias/shared.h", Path(first), data=b"equal shared bytes\n")
        self.fixture.add("git.exe")
        self.fixture.result["Commands"].append(dict(Label="git identity", Argv=[
            self.fixture.keys["git.exe"]["Original"], "-c", "core.fsmonitor=false", "status"]))
        self.verify()

    def test_absent_consumed_source_rejects(self):
        self.reject_omission("port.c", "consumed source capture coverage")

    def test_absent_dependency_rejects(self):
        self.reject_omission("task.h", "compile dependency input coverage")

    def test_absent_interpreter_rejects(self):
        self.reject_omission("python.exe", "tool input coverage")

    def test_absent_command_executable_rejects(self):
        self.reject_omission("gcc.exe", "tool input coverage")

    def test_absent_resolved_worker_rejects(self):
        self.reject_omission("cc1.exe", "worker input coverage")

    def test_absent_dll_rejects(self):
        self.reject_omission("host.dll", "DLL input coverage")

    def test_absent_inventory_member_rejects(self):
        self.reject_omission("inventory-payload", "inventory input coverage")

    def test_absent_parser_capture_rejects(self):
        self.reject_omission("parser.py", "parser input coverage")

    def test_absent_generated_config_rejects(self):
        del self.fixture.generated[self.fixture.config]
        with self.assertRaisesRegex(ValueError, "reference config input coverage"):
            self.verify()

    def test_pinned_binding_to_wrong_valid_original_rejects(self):
        self.fixture.result["ReferenceFileBindings"][0]["Original"] = self.fixture.keys["gcc.exe"]["Original"]
        with self.assertRaisesRegex(ValueError, "pinned binding input coverage"):
            self.verify()


class LinkCommandsTests(TemporaryTests):
    def recipe(self, side="Reference"):
        root = self.directory / "build with spaces"
        artifact = dict(compile_flags=["-mcpu=cortex-m0", "-mthumb", "-mfloat-abi=soft"])
        sources = [dict(Source=str(root / ("source-%d.c" % index)), Object=str(root / ("object-%d.o" % index)),
                        CompileFlags=[*artifact["compile_flags"], "-O2", "-g0"],
                        CompileDependencyFile=str(root / ("actual-%d.d" % index)))
                   for index in range(9 if side == "Native" else 5)]
        gcc = str(self.directory / "toolchain/bin/gcc.exe")
        commands = [dict(Label="compile %d" % index, Argv=[gcc, *source["CompileFlags"], "-MD", "-MF",
                    source["CompileDependencyFile"], "-MT", "pilot-source-" + str(index),
                    "-c", source["Source"], "-o", source["Object"]]) for index, source in enumerate(sources)]
        fixture = "classic_final_image" if side == "Native" else "cm0_final_image/reference"
        links = []
        for kind in ("ordinary", "emit-relocs"):
            link = dict(Kind=kind, Path=str(root / (kind + ".elf")), Map=str(root / (kind + ".map")))
            argv = [gcc, *artifact["compile_flags"], "-O2", "-nostdlib",
                    "-Wl,--gc-sections,--no-undefined,--fatal-warnings,--build-id=none,-z,noexecstack",
                    "-T", str(root / "source/tools/fixtures" / fixture / "link.ld"),
                    *(source["Object"] for source in sources)]
            if kind == "emit-relocs":
                argv.append("-Wl,--emit-relocs")
            argv.extend(("-Wl,-Map=" + link["Map"], "-o", link["Path"]))
            commands.append(dict(Label="link " + kind, Argv=argv))
            links.append(link)
        return dict(Sources=sources, Commands=commands, Links=links), artifact, root

    def reject(self, mutate, kind="ordinary"):
        result, artifact, root = self.recipe()
        command = next(row["Argv"] for row in result["Commands"] if row["Label"] == "link " + kind)
        mutate(command, result)
        with self.assertRaisesRegex(ValueError, "exact ordered twin link command"):
            join.require_link_commands(result, artifact, root, "Reference", "O2")

    def test_exact_native_and_reference_compile_and_link_commands_pass(self):
        for side in ("Native", "Reference"):
            with self.subTest(side=side):
                result, artifact, root = self.recipe(side)
                join.require_codegen_records(result, artifact, "O2")
                join.require_link_commands(result, artifact, root, side, "O2")

    def test_missing_provider_rejects(self):
        self.reject(lambda argv, row: argv.remove(row["Sources"][-1]["Object"]))

    def test_reordered_providers_rejects(self):
        def swap(argv, row):
            first = argv.index(row["Sources"][0]["Object"])
            argv[first:first + 2] = reversed(argv[first:first + 2])
        self.reject(swap)

    def test_wrong_linker_script_rejects(self):
        self.reject(lambda argv, row: argv.__setitem__(argv.index("-T") + 1, str(self.directory / "other.ld")))

    def test_wrong_map_output_rejects(self):
        self.reject(lambda argv, row: argv.__setitem__(-3, "-Wl,-Map=" + str(self.directory / "other.map")))

    def test_emit_flag_on_ordinary_link_rejects(self):
        self.reject(lambda argv, row: argv.insert(-3, "-Wl,--emit-relocs"))

    def test_missing_emit_flag_rejects(self):
        self.reject(lambda argv, row: argv.remove("-Wl,--emit-relocs"), "emit-relocs")

    def test_compile_tail_extra_argument_rejects(self):
        result, artifact, _ = self.recipe()
        result["Commands"][0]["Argv"].append("-fsyntax-only")
        with self.assertRaisesRegex(ValueError, "actual compiler flag/source/object binding"):
            join.require_codegen_records(result, artifact, "O2")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args(argv)
    output = args.report.resolve()
    if sys.flags.optimize or output.exists() or not output.is_relative_to(Path(tempfile.gettempdir()).resolve()):
        parser.error("fresh TEMP report / unoptimized Python required")
    sources = (Path(__file__).resolve(), HERE / "join.py", join._SHARED_PATH)
    hashes = {str(path): sha(path.read_bytes()) for path in sources}
    actual_import = builtins.__import__

    def guarded_import(name, *args, **kwargs):
        if name == "elftools" or name.startswith("elftools."):
            raise AssertionError("parser execution forbidden")
        return actual_import(name, *args, **kwargs)

    suite = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(case)
                               for case in (SharedBufferTests, CoverageTests, LinkCommandsTests))
    with patch.object(subprocess, "Popen", side_effect=AssertionError("process execution forbidden")), \
            patch("builtins.__import__", side_effect=guarded_import):
        result = unittest.TextTestRunner(verbosity=2).run(suite)
    drift = [name for name, expected in hashes.items() if sha(Path(name).read_bytes()) != expected]
    report = dict(Status="PASS" if result.wasSuccessful() and not result.skipped and not drift else "FAIL",
        Scope="PURE_CM0_FINAL_JOIN_HELPER_CONTROLS_ONLY", Tests=result.testsRun,
        Failures=len(result.failures), Errors=len(result.errors), Skipped=len(result.skipped),
        SourceHashes=hashes, SourceDrift=drift, SyntheticFixturesOnly=True, ParserExecution=False,
        ToolInvocations=0, NativeCommandsExecuted=0, RequiredCellsSatisfied=0,
        FinalReferenceParity=False, InstructionEquivalence=False, PolicyEquivalence=False,
        CpuExecution=False, BoardExecution=False, GlobalFreezeQualified=False,
        FailureDetails=[dict(Test=str(case), Detail=detail) for case, detail in result.failures + result.errors])
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="ascii") as stream:
        stream.write(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(report["Status"], report["Tests"], str(output))
    return 0 if report["Status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
