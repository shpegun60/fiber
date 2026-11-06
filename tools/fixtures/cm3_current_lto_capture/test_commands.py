"""Pure fault-injection controls: no real seed, filesystem command or process."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import patch


HERE = Path(__file__).absolute().parent
SUBJECT = HERE / "commands.py"
REPO = HERE.parents[2]
subject = None
SOURCE = b""


def need(ok, message):
    if not ok:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest().upper()


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")


def load_source(raw):
    module = ModuleType("cm3_current_lto_commands_under_test")
    module.__file__ = str(SUBJECT)
    exec(compile(raw, str(SUBJECT), "exec"), module.__dict__)
    return module


class Fixture:
    def __init__(self):
        self.output = Path(tempfile.gettempdir()).absolute() / "cm3-command-synthetic-never-created"
        self.gcc = self.output / "toolchain/gcc.exe"
        self.result = SimpleNamespace(returncode=0, timed_out=False, elapsed=0.125,
                                      stdout=b"partial stdout\n", stderr=b"partial stderr\n")
        self.faults, self.events, self.files, self.history = {}, [], {}, []
        self.runner_error = None
        self.run_calls = self.verify_calls = 0
        self.stream_primaries = []
        self.api = SimpleNamespace(need=need, regular=lambda p: Path(p), checked_path=lambda p: Path(p), save=self.save)
        self.probe = SimpleNamespace(output=self.output, report=dict(Commands=[], ClosingErrors=[], PrimaryError=None),
            tool_hashes={self.gcc: "synthetic tool hash"}, verify_tools=self.verify,
            environment={"PATH": "synthetic admitted tool path"},
            seed=SimpleNamespace(process=SimpleNamespace(run=self.run)))

    def trip(self, event):
        self.events.append(event)
        failures = self.faults.get(event, [])
        if failures:
            error = failures.pop(0)
            if error is not None:
                raise error

    def run(self, argv, **kwargs):
        self.run_calls += 1
        self.events.append("run")
        self.runner_arguments = (argv, kwargs)
        if self.runner_error is not None:
            raise self.runner_error
        return self.result

    def verify(self):
        self.verify_calls += 1
        self.trip("verify-" + str(self.verify_calls))

    def save(self, path, value):
        state = value[-1]["State"] if isinstance(value, list) else value["State"]
        event = "command list" if Path(path).name == "commands.json" else (
            "initial journal" if state == "ATTEMPT" else "terminal journal")
        self.trip(event)
        snapshot = json.loads(encoded(value))
        self.files[Path(path)] = snapshot
        self.history.append((event, copy.deepcopy(snapshot)))

    def write(self, path, raw):
        event = "stdout write" if Path(path).suffix == ".stdout" else "stderr write"
        self.stream_primaries.append(self.probe.report["PrimaryError"])
        self.trip(event)
        self.files[Path(path)] = raw
        return len(raw)

    def invoke(self, *, cwd=None, timeout=120, argv=None):
        with patch.object(Path, "write_bytes", autospec=True, side_effect=self.write), \
             patch.object(Path, "mkdir", side_effect=AssertionError("unexpected directory creation")), \
             patch("subprocess.Popen", side_effect=AssertionError("real process forbidden")), \
             patch("subprocess.run", side_effect=AssertionError("real process forbidden")):
            return subject.command(self.probe, self.api, [self.gcc, "-c", "input.c"] if argv is None else argv,
                                   "compile synthetic", cwd=cwd, timeout=timeout)

    @property
    def record(self):
        return self.probe.report["Commands"][0]

    def assert_terminal(self, case, status):
        case.assertEqual(self.record["State"], "TERMINAL")
        case.assertEqual(self.record["Status"], status)
        case.assertEqual(self.files[self.output / "command-0000.json"], self.record)
        case.assertEqual(self.files[self.output / "commands.json"], [self.record])


class CommandTests(unittest.TestCase):
    def test_success_exact_runner_arguments_and_terminal_streams(self):
        f = Fixture()
        result = f.invoke(cwd=f.output / "ordinary", timeout=7)
        self.assertIs(result, f.result)
        f.assert_terminal(self, "PASS")
        self.assertEqual(f.events, ["initial journal", "verify-1", "run", "stdout write", "stderr write",
                                   "verify-2", "terminal journal", "command list"])
        argv, options = f.runner_arguments
        self.assertEqual(argv, [str(f.gcc), "-c", "input.c"])
        self.assertEqual(options, dict(cwd=str(f.output / "ordinary"), env=f.probe.environment, timeout=7))
        self.assertIs(options["env"], f.probe.environment)
        self.assertEqual((f.run_calls, f.verify_calls), (1, 2))
        self.assertEqual(f.files[f.output / "command-0000.stdout"], f.result.stdout)
        self.assertEqual(f.files[f.output / "command-0000.stderr"], f.result.stderr)
        self.assertEqual(f.probe.report["ClosingErrors"], [])

    def test_nonzero_primary_survives_terminal_write_error(self):
        f = Fixture()
        f.result.returncode = 1
        f.faults["terminal journal"] = [OSError("terminal write")]
        with self.assertRaisesRegex(ValueError, "command failed/timeout"):
            f.invoke()
        f.assert_terminal(self, "FAIL")
        self.assertEqual(f.record["Exit"], 1)
        self.assertEqual(f.record["Seconds"], 0.125)
        self.assertIn("command failed/timeout", f.record["Error"])
        self.assertTrue(all("command failed/timeout" in v for v in f.stream_primaries))
        self.assertEqual(len(f.record["ClosingErrors"]), 1)
        self.assertIn("terminal write", f.record["ClosingErrors"][0])
        self.assertEqual(f.probe.report["PrimaryError"], f.record["Error"])
        self.assertEqual(f.run_calls, 1)

    def test_success_with_either_journal_fault_revokes_terminal_pass(self):
        for event in ("terminal journal", "command list"):
            f = Fixture()
            fault = OSError(event)
            f.faults[event] = [fault]
            with self.subTest(event=event), self.assertRaises(OSError) as caught:
                f.invoke()
            self.assertIs(caught.exception, fault)
            f.assert_terminal(self, "FAIL")
            self.assertEqual(f.run_calls, 1)
            if event == "command list":
                states = [row["Status"] for name, row in f.history if name == "terminal journal"]
                self.assertEqual(states, ["PASS", "FAIL"])

    def test_stream_faults_attempt_the_other_stream_and_closing_independently(self):
        for event in ("stdout write", "stderr write"):
            f = Fixture()
            fault = OSError(event)
            f.faults[event] = [fault]
            with self.subTest(event=event), self.assertRaises(OSError) as caught:
                f.invoke()
            self.assertIs(caught.exception, fault)
            f.assert_terminal(self, "FAIL")
            self.assertIn("stdout write", f.events)
            self.assertIn("stderr write", f.events)
            self.assertEqual(f.verify_calls, 2)
            self.assertEqual(f.run_calls, 1)

    def test_success_with_closing_tool_fault_is_failure(self):
        f = Fixture()
        fault = RuntimeError("closing tool changed")
        f.faults["verify-2"] = [fault]
        with self.assertRaises(RuntimeError) as caught:
            f.invoke()
        self.assertIs(caught.exception, fault)
        f.assert_terminal(self, "FAIL")
        self.assertEqual(f.record["FailurePhase"], "closing tool checks")
        self.assertEqual(f.run_calls, 1)

    def test_initial_journal_fault_prevents_launch_but_still_closes_and_journals(self):
        f = Fixture()
        fault = OSError("initial journal blocked")
        f.faults["initial journal"] = [fault]
        with self.assertRaises(OSError) as caught:
            f.invoke()
        self.assertIs(caught.exception, fault)
        f.assert_terminal(self, "FAIL")
        self.assertEqual((f.run_calls, f.verify_calls), (0, 1))
        self.assertFalse(f.record["StdoutCaptured"])
        self.assertFalse(f.record["StderrCaptured"])
        self.assertEqual(f.files[f.output / "command-0000.stdout"], b"")
        self.assertEqual(f.files[f.output / "command-0000.stderr"], b"")

    def test_opening_tool_failure_prevents_launch_and_still_checks_closing(self):
        f = Fixture()
        fault = RuntimeError("opening tool changed")
        f.faults["verify-1"] = [fault]
        with self.assertRaises(RuntimeError) as caught:
            f.invoke()
        self.assertIs(caught.exception, fault)
        f.assert_terminal(self, "FAIL")
        self.assertEqual((f.run_calls, f.verify_calls), (0, 2))

    def test_timeout_precedes_stream_fault_and_retains_partial_streams(self):
        f = Fixture()
        f.result.returncode, f.result.timed_out = 0, True
        f.faults["stdout write"] = [OSError("partial stdout write")]
        with self.assertRaisesRegex(ValueError, "command failed/timeout"):
            f.invoke()
        f.assert_terminal(self, "FAIL")
        self.assertIs(f.record["TimedOut"], True)
        self.assertEqual(f.files[f.output / "command-0000.stderr"], b"partial stderr\n")
        self.assertEqual(f.record["Seconds"], 0.125)
        self.assertIn("partial stdout write", f.record["ClosingErrors"][0])

    def test_runner_cleanup_exception_is_preserved_without_a_retry(self):
        f = Fixture()
        fault = RuntimeError("contained runner cleanup failed")
        f.runner_error = fault
        f.faults["stderr write"] = [OSError("stderr write")]
        f.faults["terminal journal"] = [OSError("terminal write")]
        with self.assertRaises(RuntimeError) as caught:
            f.invoke()
        self.assertIs(caught.exception, fault)
        f.assert_terminal(self, "FAIL")
        self.assertEqual(f.run_calls, 1)
        self.assertFalse(f.record["StdoutCaptured"])
        self.assertEqual(len(f.record["ClosingErrors"]), 2)

    def test_baseexception_preserves_identity_and_attempts_all_terminal_work(self):
        f = Fixture()
        fault = KeyboardInterrupt("synthetic interrupt")
        f.runner_error = fault
        with self.assertRaises(KeyboardInterrupt) as caught:
            f.invoke()
        self.assertIs(caught.exception, fault)
        f.assert_terminal(self, "FAIL")
        self.assertEqual(f.verify_calls, 2)
        self.assertEqual(f.run_calls, 1)

    def test_multiple_cleanup_faults_keep_first_command_failure(self):
        f = Fixture()
        f.result.returncode = 1
        for event in ("stdout write", "stderr write", "verify-2", "terminal journal", "command list"):
            f.faults[event] = [OSError(event)]
        with self.assertRaisesRegex(ValueError, "command failed/timeout"):
            f.invoke()
        f.assert_terminal(self, "FAIL")
        self.assertEqual(len(f.record["ClosingErrors"]), 5)
        self.assertEqual(f.record["ClosingErrors"], f.probe.report["ClosingErrors"])
        self.assertEqual(f.run_calls, 1)

    def test_malformed_results_fail_closed_without_bool_or_nan_metadata(self):
        for field, value in (("returncode", False), ("timed_out", 0), ("elapsed", True),
                             ("elapsed", float("nan")), ("elapsed", -1), ("stdout", "text"), ("stderr", None)):
            f = Fixture()
            setattr(f.result, field, value)
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                f.invoke()
            f.assert_terminal(self, "FAIL")
            encoded(f.record)
            self.assertEqual(f.run_calls, 1)

    def test_unadmitted_executable_never_reaches_runner(self):
        f = Fixture()
        with self.assertRaisesRegex(ValueError, "executable not captured"):
            f.invoke(argv=[f.output / "foreign.exe"])
        f.assert_terminal(self, "FAIL")
        self.assertEqual(f.run_calls, 0)

    def test_cwd_outside_output_is_rejected_before_journal_or_launch(self):
        f = Fixture()
        with self.assertRaisesRegex(ValueError, "working directory outside"):
            f.invoke(cwd=f.output.parent)
        self.assertEqual(f.events, [])
        self.assertEqual(f.probe.report["Commands"], [])

    def test_permanent_journal_failures_have_bounded_repair_and_no_process_retry(self):
        f = Fixture()
        f.result.returncode = 1
        for event in ("terminal journal", "command list"):
            f.faults[event] = [OSError(event), OSError(event + " repair")]
        with self.assertRaisesRegex(ValueError, "command failed/timeout"):
            f.invoke()
        self.assertEqual(f.record["State"], "TERMINAL")
        self.assertEqual(f.record["Status"], "FAIL")
        self.assertEqual(f.events.count("terminal journal"), 2)
        self.assertEqual(f.events.count("command list"), 2)
        self.assertEqual(len(f.record["ClosingErrors"]), 4)
        self.assertEqual(f.run_calls, 1)

    def test_existing_report_primary_is_not_replaced_and_import_has_no_io(self):
        f = Fixture()
        f.probe.report["PrimaryError"] = "earlier primary"
        f.runner_error = RuntimeError("current command failure")
        with self.assertRaisesRegex(RuntimeError, "current command failure"):
            f.invoke()
        self.assertEqual(f.probe.report["PrimaryError"], "earlier primary")
        with patch.object(Path, "read_bytes", side_effect=AssertionError("import read")), \
             patch.object(Path, "write_bytes", side_effect=AssertionError("import write")), \
             patch("subprocess.Popen", side_effect=AssertionError("import process")):
            load_source(SOURCE)


def main(argv=None):
    global subject, SOURCE
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args(argv)
    output = Path(args.output_dir).absolute()
    need(not output.exists() and output.is_relative_to(Path(tempfile.gettempdir()).absolute())
         and not output.is_relative_to(REPO), "fresh external TEMP report directory required")
    paths = (Path(__file__).absolute(), SUBJECT)
    buffers = {path: path.read_bytes() for path in paths}
    hashes = {str(path): sha(raw) for path, raw in buffers.items()}
    SOURCE = buffers[SUBJECT]
    subject = load_source(SOURCE)
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(CommandTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    drift = [str(path) for path in paths if sha(path.read_bytes()) != hashes[str(path)]]
    success = result.wasSuccessful() and not result.skipped and not drift
    report = dict(Status="PASS" if success else "FAIL", TestsRun=result.testsRun,
        Failures=len(result.failures), Errors=len(result.errors), Skipped=len(result.skipped),
        SourceHashes=hashes, SourceDrift=drift, Scope="SYNTHETIC_COMMAND_FAILURE_AND_JOURNAL_CONTROLS_ONLY",
        ActualSeedAdmission=False, ActualCompilerExecution=False, TargetExecution=False,
        ProcessInvocations=0, Qualification=False)
    output.mkdir(parents=True)
    (output / "results.json").write_bytes(encoded(report) + b"\n")
    print(json.dumps(report, sort_keys=True))
    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())
