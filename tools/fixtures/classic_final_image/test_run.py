"""Pure controls for the final-image pilot's command envelope and claim scope."""
import argparse
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

if sys.flags.optimize or not __debug__:
    raise SystemExit("REJECT:PYTHON:optimization is unsupported")

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("classic_final_pilot_controls", HERE / "run.py")
r = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = r
SPEC.loader.exec_module(r)


class CommandControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="classic-final-command-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.pilot = r.Pilot.__new__(r.Pilot)
        self.pilot.output = self.root
        self.pilot.inputs = {}
        self.pilot.environment = {"PILOT_TEST": "bounded"}
        self.pilot.commands = []
        self.tool = self.root / "tool.exe"
        self.tool.write_bytes(b"not executed by these pure controls")
        self.pilot.inputs[str(self.tool.resolve())] = {"Sha256": r.sha(self.tool.read_bytes())}
        self.result = SimpleNamespace(returncode=0, timed_out=False, elapsed=0.1,
                                      stdout=b"out\x00\xff", stderr=b"err\xfe")
        self.events = []
        self.pilot.process = SimpleNamespace(run=self.invoke)

    def invoke(self, argv, **kwargs):
        self.events.append((argv, kwargs))
        record = json.loads((self.root / "command-0000.json").read_text())
        self.assertEqual(record["Status"], "ATTEMPT")
        self.assertIsNone(record["Exit"])
        self.assertIsNone(record["TimedOut"])
        self.assertEqual(record["Argv"], argv)
        if isinstance(self.result, BaseException):
            raise self.result
        return self.result

    def record(self):
        record = json.loads((self.root / "command-0000.json").read_text())
        self.assertEqual(json.loads((self.root / "commands.json").read_text()), [record])
        self.assertEqual(self.pilot.commands, [record])
        return record

    def test_attempt_precedes_launch_and_binary_output_is_preserved(self):
        result = self.pilot.command([self.tool, "argument with spaces", "--literal=1"], "control", timeout=2)
        self.assertIs(result, self.result)
        argv, kwargs = self.events[0]
        self.assertEqual(argv, [str(self.tool), "argument with spaces", "--literal=1"])
        self.assertEqual(kwargs, {"cwd": str(self.root), "env": self.pilot.environment, "timeout": 2})
        self.assertEqual(self.record()["Status"], "PASS")
        self.assertEqual((self.root / "command-0000.stdout").read_bytes(), b"out\x00\xff")
        self.assertEqual((self.root / "command-0000.stderr").read_bytes(), b"err\xfe")

    def test_timeout_is_failure_even_with_zero_root_exit(self):
        self.result.timed_out = True
        with self.assertRaisesRegex(RuntimeError, "tool failed/timeout"):
            self.pilot.command([self.tool], "timeout")
        record = self.record()
        self.assertEqual(record["Status"], "FAIL")
        self.assertEqual(record["Exit"], 0)
        self.assertIs(record["TimedOut"], True)
        self.assertEqual((self.root / "command-0000.stdout").read_bytes(), self.result.stdout)

    def test_nonzero_and_runner_failure_are_not_success(self):
        for code in (1, -1, 125):
            with self.subTest(code=code):
                self.pilot.commands.clear()
                self.result.returncode = code
                with self.assertRaises(RuntimeError):
                    self.pilot.command([self.tool], "failure")
                self.assertEqual(self.record()["Status"], "FAIL")

    def test_boolean_exit_and_timeout_fields_are_rejected(self):
        for code, timeout in ((False, False), (0, 0), (True, False), (0, None)):
            with self.subTest(code=code, timeout=timeout):
                self.pilot.commands.clear()
                self.result.returncode, self.result.timed_out = code, timeout
                with self.assertRaises(RuntimeError):
                    self.pilot.command([self.tool], "malformed-result")
                self.assertEqual(self.record()["Status"], "FAIL")

    def test_launch_exception_keeps_failure_record(self):
        self.result = OSError("blocked launch")
        with self.assertRaisesRegex(OSError, "blocked launch"):
            self.pilot.command([self.tool], "launch exception")
        record = self.record()
        self.assertEqual(record["Status"], "FAIL")
        self.assertIn("blocked launch", record["Error"])
        self.assertIsNone(record["Exit"])

    def test_tool_change_fails_before_launch(self):
        self.tool.write_bytes(b"changed")
        with self.assertRaisesRegex(RuntimeError, "tool drift before launch"):
            self.pilot.command([self.tool], "drift")
        self.assertEqual(self.events, [])
        self.assertEqual(self.record()["Status"], "FAIL")

    def test_untracked_and_missing_executable_fail_before_launch(self):
        for missing in (False, True):
            with self.subTest(missing=missing):
                self.pilot.commands.clear()
                self.pilot.inputs.clear()
                if missing:
                    self.tool.unlink()
                with self.assertRaises((RuntimeError, FileNotFoundError)):
                    self.pilot.command([self.tool], "untracked")
                self.assertEqual(self.events, [])
                self.assertEqual(self.record()["Status"], "FAIL")

    def test_interrupt_is_recorded_before_propagation(self):
        self.result = KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):
            self.pilot.command([self.tool], "interrupt")
        self.assertEqual(self.record()["Status"], "FAIL")


class ScopeControls(unittest.TestCase):
    def test_no_required_global_or_execution_claim(self):
        report = r.scope_report()
        self.assertEqual(report["Verdict"], "FAIL")
        self.assertEqual(report["Cohort"], r.COHORT)
        self.assertEqual(report["Mode"], "O2")
        self.assertEqual(report["Linkage"], "direct")
        self.assertIs(type(report["RequiredCellsSatisfied"]), int)
        self.assertEqual(report["RequiredCellsSatisfied"], 0)
        for key in ("ReferenceBuilt", "LTO", "RequiredCellSatisfied", "FinalElfProof",
                    "FinalRootRelocationProof", "CompleteObjectProof", "PolicyEquivalence",
                    "CpuExecution", "BoardExecution", "GlobalFreezeQualified"):
            self.assertIs(report[key], False)

    def test_scope_reports_do_not_share_mutable_state(self):
        first, second = r.scope_report(), r.scope_report()
        first["Commands"].append("mutated")
        first["Sources"].append("mutated")
        first["InputDrift"].append("mutated")
        self.assertEqual(second["Commands"], [])
        self.assertEqual(second["Sources"], [])
        self.assertEqual(second["InputDrift"], [])

    def test_source_groups_are_exactly_context_plus_concrete_cm4(self):
        self.assertEqual(r.COMMON_SOURCES,
                         ("context/context_core.c", "context/context_runtime_state.c", "context/context_panic.c"))
        self.assertEqual(r.PORT_SOURCES, tuple("fiber/port/ARM_CM4/" + name for name in
                         ("fiber_port.c", "fiber_port_boot.c", "fiber_port_exception.c")))

    def test_fresh_output_admission_is_before_creation(self):
        with tempfile.TemporaryDirectory(prefix="classic-final-admission-") as directory:
            path = Path(directory)
            with self.assertRaisesRegex(RuntimeError, "fresh external output"):
                r.Pilot(SimpleNamespace(output_dir=str(path)))
            self.assertEqual(list(path.iterdir()), [])
        repo = HERE.parents[2]
        candidate = repo / "pilot-control-must-not-create"
        self.assertFalse(candidate.exists())
        with self.assertRaisesRegex(RuntimeError, "fresh external output"):
            r.Pilot(SimpleNamespace(output_dir=str(candidate)))
        self.assertFalse(candidate.exists())

    def test_import_does_not_launch_process_or_create_output(self):
        spec = importlib.util.spec_from_file_location("classic_final_import_control", HERE / "run.py")
        module = importlib.util.module_from_spec(spec)
        with patch("subprocess.Popen", side_effect=AssertionError("must not spawn")), \
                patch.object(Path, "mkdir", side_effect=AssertionError("must not create")), \
                patch.object(Path, "write_bytes", side_effect=AssertionError("must not write")):
            spec.loader.exec_module(module)

    def test_parent_path_alias_cannot_bypass_repo_output_guard(self):
        repo = HERE.parents[2]
        candidate = repo.parent / "uncreated-parent" / ".." / repo.name / "must-not-create-pilot"
        with patch.object(Path, "mkdir", side_effect=AssertionError("admission reached mkdir")):
            with self.assertRaisesRegex(RuntimeError, "fresh external output"):
                r.Pilot(SimpleNamespace(output_dir=str(candidate)))

    def test_finish_cannot_promote_an_unbuilt_pilot(self):
        with tempfile.TemporaryDirectory(prefix="classic-final-unbuilt-") as directory:
            pilot = r.Pilot.__new__(r.Pilot)
            pilot.output = Path(directory)
            pilot.inputs, pilot.generated, pilot.commands = {}, {}, []
            pilot.report = r.scope_report()
            self.assertFalse(pilot.finish(None))
            self.assertEqual(pilot.report["Verdict"], "FAIL")

    def test_process_environment_does_not_capture_credentials(self):
        source = {"Path": "toolchain", "SystemRoot": "windows", "TEMP": "temporary",
                  "GH_TOKEN": "secret-one", "AWS_SECRET_ACCESS_KEY": "secret-two",
                  "PRIVATE_SETTING": "secret-three", "PYTHONPATH": "not-inherited"}
        self.assertEqual(r.process_environment(source),
                         {"Path": "toolchain", "SystemRoot": "windows", "TEMP": "temporary"})
        self.assertEqual(source["GH_TOKEN"], "secret-one")

    def test_compiler_overrides_are_rejected_before_filtering(self):
        for key in ("GCC_EXEC_PREFIX", "COMPILER_PATH", "LIBRARY_PATH", "CPATH",
                    "C_INCLUDE_PATH", "CPLUS_INCLUDE_PATH", "OBJC_INCLUDE_PATH",
                    "DEPENDENCIES_OUTPUT", "SUNPRO_DEPENDENCIES", "GCC_SPECS", "LD_PRELOAD"):
            for spelling in (key, key.lower()):
                with self.subTest(key=spelling):
                    with self.assertRaisesRegex(RuntimeError, "ambient compiler override"):
                        r.process_environment({"PATH": "toolchain", spelling: "injected"})
        self.assertEqual(r.process_environment({"PATH": "toolchain", "CPATH": ""}), {"PATH": "toolchain"})


class ObjectControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="classic-final-object-controls-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.pilot = r.Pilot.__new__(r.Pilot)
        self.pilot.output = self.root
        self.pilot.report = r.scope_report()
        self.pilot.objects = []
        for index in range(9):
            path = self.root / ("object-%d.o" % index)
            path.write_bytes(bytes([index]) * 16)
            self.pilot.objects.append(path)
            self.pilot.report["Sources"].append(dict(Object=str(path), ObjectSha256=r.sha(path.read_bytes()),
                                                       CompileDependenciesVerified=True))

    def freeze(self):
        self.pilot.freeze_objects()
        self.pilot.verify_objects("test-initial")

    def test_exact_object_freeze_and_recheck(self):
        self.freeze()
        self.assertEqual(len(self.pilot.object_hashes), 9)
        self.assertEqual(self.pilot.report["ObjectChecks"][-1]["Status"], "PASS")
        with self.assertRaisesRegex(RuntimeError, "already frozen"):
            self.pilot.freeze_objects()

    def test_incomplete_or_duplicate_inventory_rejected(self):
        self.pilot.objects.pop()
        with self.assertRaisesRegex(RuntimeError, "nine-object"):
            self.pilot.freeze_objects()
        self.pilot.objects.append(self.pilot.objects[0])
        with self.assertRaisesRegex(RuntimeError, "nine-object"):
            self.pilot.freeze_objects()

    def test_unverified_compile_dependencies_rejected(self):
        self.pilot.report["Sources"][0]["CompileDependenciesVerified"] = False
        with self.assertRaisesRegex(RuntimeError, "actual compilation dependencies"):
            self.pilot.freeze_objects()

    def test_object_identity_cannot_change_at_freeze(self):
        self.pilot.report["Sources"][0]["Object"] = str(self.root / "unrelated.o")
        with self.assertRaisesRegex(RuntimeError, "object/source identity"):
            self.pilot.freeze_objects()

    def test_changed_object_is_failure_with_terminal_record(self):
        self.freeze()
        self.pilot.objects[3].write_bytes(b"different object")
        with self.assertRaisesRegex(RuntimeError, "frozen object drift"):
            self.pilot.verify_objects("changed")
        self.assertEqual(self.pilot.report["ObjectChecks"][-1]["Status"], "FAIL")
        self.assertEqual(json.loads((self.root / "object-checks.json").read_text()),
                         self.pilot.report["ObjectChecks"])

    def test_membership_change_is_failure(self):
        self.freeze()
        self.pilot.objects.reverse()
        with self.assertRaisesRegex(RuntimeError, "membership"):
            self.pilot.verify_objects("reordered")

    def test_missing_object_is_failure(self):
        self.freeze()
        self.pilot.objects[2].unlink()
        with self.assertRaises((RuntimeError, FileNotFoundError)):
            self.pilot.verify_objects("missing")
        self.assertEqual(self.pilot.report["ObjectChecks"][-1]["Status"], "FAIL")

    def test_drift_prevents_link_invocation(self):
        self.freeze()
        self.pilot.objects[0].write_bytes(b"changed before link")
        self.pilot.command = unittest.mock.Mock(side_effect=AssertionError("must not launch"))
        with self.assertRaisesRegex(RuntimeError, "frozen object drift"):
            self.pilot.link_twin("ordinary", ["not executed"])
        self.pilot.command.assert_not_called()

    def test_link_time_object_change_is_detected(self):
        self.freeze()
        def command(*args):
            self.pilot.objects[0].write_bytes(b"changed during link")
            return "apparent success"
        self.pilot.command = command
        with self.assertRaisesRegex(RuntimeError, "frozen object drift"):
            self.pilot.link_twin("emit-relocs", ["not executed"])
        self.assertEqual(self.pilot.report["ObjectChecks"][-1]["Stage"], "after-link-emit-relocs")
        self.assertEqual(self.pilot.report["ObjectChecks"][-1]["Status"], "FAIL")

    def test_failed_link_still_rechecks_objects(self):
        self.freeze()
        self.pilot.command = unittest.mock.Mock(side_effect=RuntimeError("link failed"))
        with self.assertRaisesRegex(RuntimeError, "link failed"):
            self.pilot.link_twin("ordinary", ["not executed"])
        self.assertEqual(self.pilot.report["ObjectChecks"][-1]["Stage"], "after-link-ordinary")
        self.assertEqual(self.pilot.report["ObjectChecks"][-1]["Status"], "PASS")

    def test_exact_actual_dependency_inventory(self):
        expected = [dict(Path="source.c", Sha256="A" * 64), dict(Path="header.h", Sha256="B" * 64)]
        r.require_compile_dependencies(expected, [dict(item) for item in expected])
        mutants = (expected[:1], [*expected, dict(Path="extra.h", Sha256="C" * 64)],
                   [dict(expected[0]), dict(expected[1], Sha256="D" * 64)], list(reversed(expected)))
        for actual in mutants:
            with self.subTest(actual=actual):
                with self.assertRaisesRegex(RuntimeError, "actual compilation dependencies differ"):
                    r.require_compile_dependencies(expected, actual)
        for discovered, actual in (([], []), (expected, []), (None, expected), (tuple(expected), expected)):
            with self.subTest(discovered=discovered, actual=actual):
                with self.assertRaisesRegex(RuntimeError, "empty actual/discovery"):
                    r.require_compile_dependencies(discovered, actual)

    def test_dependency_parser_retains_escaped_space_and_hash(self):
        paths = [self.root / "source with space.c", self.root / "header#one.h"]
        for path in paths:
            path.write_bytes(b"bound input")
        dep = self.root / "source.d"
        escaped = [str(path).replace("\\", "/").replace(" ", "\\ ").replace("#", "\\#") for path in paths]
        dep.write_text("pilot-source-0: " + escaped[0] + " \\\n " + escaped[1] + "\n", encoding="utf-8")
        self.assertEqual(r.read_dependencies(dep), tuple(sorted(path.resolve() for path in paths)))
        dep.write_text("pilot-source-0: " + escaped[0] + " " + escaped[0] + "\n", encoding="utf-8")
        self.assertEqual(r.read_dependencies(dep), (paths[0].resolve(),))
        dep.write_text("pilot-source-0: \n", encoding="utf-8")
        with self.assertRaisesRegex(RuntimeError, "empty dependency"):
            r.read_dependencies(dep)

    def test_distinct_include_spellings_bind_one_physical_dependency(self):
        header = self.root / "header.h"
        header.write_bytes(b"one physical header")
        alias_directory = self.root / "include-alias"
        alias_directory.mkdir()
        alias = str(alias_directory) + "/../header.h"
        dep = self.root / "alias.d"
        dep.write_text("pilot-source-1: " + header.as_posix() + " " + alias.replace("\\", "/") + "\n",
                       encoding="utf-8")
        self.assertEqual(r.read_dependencies(dep), (header.resolve(),))


def main():
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--report", required=True)
    args = parser.parse_args()
    path = Path(args.report).resolve()
    if path.exists() or not path.is_relative_to(Path(tempfile.gettempdir()).resolve()):
        raise SystemExit("requires a fresh report inside TEMP")
    suite = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(case)
                              for case in (CommandControls, ScopeControls, ObjectControls))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    report = dict(Status="PASS" if result.wasSuccessful() else "FAIL", Tests=result.testsRun,
                  Failures=len(result.failures), Errors=len(result.errors), Skipped=len(result.skipped),
                  ToolInvocations=0, CpuExecution=False, BoardExecution=False,
                  FailureDetails=[dict(Test=str(case), Detail=detail)
                                  for case, detail in result.failures + result.errors])
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2) + "\n", encoding="ascii")
    print(json.dumps(report, sort_keys=True))
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
