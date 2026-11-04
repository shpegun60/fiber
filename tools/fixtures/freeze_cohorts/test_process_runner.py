"""Blocked-subprocess controls plus Python-only process-tree controls in fresh TEMP."""
import argparse
import ctypes
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch


MODULE = Path(__file__).with_name("process_runner.py")
SPEC = importlib.util.spec_from_file_location("freeze_process_runner_under_test", MODULE)
r = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = r
SPEC.loader.exec_module(r)
TEMP_ROOT = None
ACTUAL = []


class PureControls(unittest.TestCase):
    def exercise(self, *, timeout=False, failure=None, orphan=False, platform="nt", exitcode=0):
        events = []

        class Tree:
            def __init__(self, *args):
                events.append("job")
                if failure == "setup":
                    raise OSError("blocked job setup")

            def assign(self, pid):
                events.append("assign")
                if failure == "assign":
                    raise OSError("blocked assignment")

            def resume(self, pid):
                events.append("resume")
                if failure == "resume":
                    raise OSError("blocked resume")

            def wait_empty(self, deadline):
                events.append("empty")
                return not orphan or "terminate" in events

            def terminate(self):
                events.append("terminate")
                if failure == "terminate":
                    raise OSError("blocked termination")

            def close(self):
                events.append("close")

        class Process:
            def __init__(self, argv, **kwargs):
                events.append("popen")
                self.kwargs, self.argv, self.pid = kwargs, argv, 12345
                self.stdout, self.stderr = io.BytesIO(b"out\x00\xff"), io.BytesIO(b"err\xfe")
                self.returncode, self.waits = None, 0

            def wait(self, timeout):
                self.waits += 1
                events.append("wait")
                if self.waits == 1 and timeout_control:
                    raise subprocess.TimeoutExpired(self.argv, timeout)
                if failure == "interrupt" and self.waits == 1:
                    raise KeyboardInterrupt()
                self.returncode = exitcode
                return exitcode

            def poll(self):
                return self.returncode

            def kill(self):
                events.append("kill")
                self.returncode = exitcode

        timeout_control = timeout
        instances = []

        def popen(*args, **kwargs):
            if failure == "spawn":
                raise FileNotFoundError("blocked executable")
            value = Process(*args, **kwargs)
            instances.append(value)
            return value

        with patch.object(r, "_platform", return_value=platform), patch.object(r, "_WindowsJob", Tree), \
                patch.object(r, "_PosixGroup", Tree), patch.object(r.subprocess, "Popen", side_effect=popen):
            if failure == "interrupt":
                with self.assertRaises(KeyboardInterrupt):
                    r.run(["tool.exe", "a b"], cwd="synthetic", env={}, timeout=2)
                result = None
            else:
                result = r.run(["tool.exe", "a b"], cwd="synthetic", env={}, timeout=2)
        return result, events, instances

    def test_import_creates_no_job_or_process(self):
        spec = importlib.util.spec_from_file_location("freeze_process_runner_import_control", MODULE)
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        with patch.object(subprocess, "Popen", side_effect=AssertionError("process on import")), \
                patch.object(ctypes, "WinDLL", side_effect=AssertionError("Win32 API on import"), create=True):
            spec.loader.exec_module(module)
        self.assertTrue(callable(module.run))

    def test_schema_bytes_and_windows_order(self):
        result, events, processes = self.exercise()
        self.assertIs(type(result.returncode), int)
        self.assertIs(type(result.timed_out), bool)
        self.assertIs(type(result.elapsed), float)
        self.assertEqual((result.returncode, result.stdout, result.stderr, result.timed_out),
                         (0, b"out\x00\xff", b"err\xfe", False))
        self.assertLess(events.index("job"), events.index("popen"))
        self.assertLess(events.index("assign"), events.index("resume"))
        self.assertNotIn("terminate", events)
        options = processes[0].kwargs
        self.assertEqual(options["creationflags"], 0x08000004)
        self.assertFalse(options["shell"])
        self.assertTrue(options["close_fds"])
        self.assertEqual(options["stdin"], subprocess.DEVNULL)
        self.assertNotIn("text", options)
        self.assertTrue(processes[0].stdout.closed and processes[0].stderr.closed)
        self.assertEqual(events[-1], "close")

    def test_timeout_even_if_root_exits_zero(self):
        result, events, _ = self.exercise(timeout=True)
        self.assertTrue(result.timed_out)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"out\x00\xff")
        self.assertEqual(result.stderr, b"err\xfe")
        self.assertIn("terminate", events)
        self.assertIn("kill", events)

    def test_tool_nonzero_preserved(self):
        result, _, _ = self.exercise(exitcode=7)
        self.assertEqual(result.returncode, 7)
        self.assertFalse(result.timed_out)

    def test_operational_failures_fail_closed(self):
        for failure in ("setup", "spawn", "assign", "resume"):
            with self.subTest(failure=failure):
                result, events, _ = self.exercise(failure=failure)
                self.assertEqual(result.returncode, 125)
                self.assertIn(b"[process-runner]", result.stderr)
                self.assertFalse(result.timed_out)
                if failure == "setup":
                    self.assertNotIn("popen", events)
                if failure == "assign":
                    self.assertNotIn("resume", events)
                if failure in ("assign", "resume"):
                    self.assertIn("terminate", events)
                    self.assertIn("kill", events)
                if failure != "setup":
                    self.assertEqual(events[-1], "close")

    def test_termination_failure_uses_close_fallback(self):
        result, events, _ = self.exercise(timeout=True, failure="terminate")
        self.assertTrue(result.timed_out)
        self.assertEqual(result.returncode, 125)
        self.assertLess(events.index("terminate"), events.index("close"))
        self.assertIn("kill", events)

    def test_zero_exit_orphan_is_not_success(self):
        result, events, _ = self.exercise(orphan=True)
        self.assertEqual(result.returncode, 125)
        self.assertIn(b"outlived root", result.stderr)
        self.assertIn("terminate", events)

    def test_interrupt_cleans_up_before_propagation(self):
        _, events, _ = self.exercise(failure="interrupt")
        self.assertIn("terminate", events)
        self.assertIn("kill", events)
        self.assertEqual(events[-1], "close")

    def test_posix_uses_new_session(self):
        result, _, processes = self.exercise(platform="posix")
        self.assertEqual(result.returncode, 0)
        self.assertTrue(processes[0].kwargs["start_new_session"])
        self.assertNotIn("creationflags", processes[0].kwargs)

    def test_invalid_arguments_never_spawn(self):
        with patch.object(r.subprocess, "Popen", side_effect=AssertionError("invalid launch")):
            for argv in ("tool.exe arg", [], [""], ["bad\0.exe"], ["script.cmd"], ["script.BAT"]):
                with self.subTest(argv=argv), self.assertRaises(ValueError):
                    r.run(argv, cwd=None, env=None, timeout=1)
            for timeout in (0, -1, True, float("nan"), float("inf"), "2"):
                with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                    r.run(["tool.exe"], cwd=None, env=None, timeout=timeout)

    def test_closed_job_never_queries_or_terminates_callers_job(self):
        job = object.__new__(r._WindowsJob)
        job.api, job.handle = Mock(), None
        for action in (job.active, job.terminate):
            with self.assertRaisesRegex(RuntimeError, "job already closed"):
                action()
        self.assertEqual(job.api.mock_calls, [])

    @unittest.skipUnless(os.name == "nt", "Win32 ctypes failure controls")
    def test_job_limits_set_before_any_process(self):
        api = Mock()
        api.CreateJobObjectW.return_value = 17
        api.SetInformationJobObject.return_value = 1
        api.CloseHandle.return_value = 1
        with patch.object(r.ctypes, "WinDLL", return_value=api):
            job = r._WindowsJob()
        api.CreateJobObjectW.assert_called_once_with(None, None)
        arguments = api.SetInformationJobObject.call_args.args
        limits = ctypes.cast(arguments[2], ctypes.POINTER(r._ExtendedLimits)).contents
        self.assertEqual((arguments[0], arguments[1]), (17, 9))
        self.assertEqual(limits.BasicLimitInformation.LimitFlags, 0x2000)
        self.assertEqual(arguments[3], ctypes.sizeof(r._ExtendedLimits))
        job.close()
        api.CloseHandle.assert_called_once_with(17)

    @unittest.skipUnless(os.name == "nt", "Win32 ctypes failure controls")
    def test_resume_requires_exactly_one_suspended_owned_thread(self):
        for previous in (1, 0, 2, 0xFFFFFFFF):
            with self.subTest(previous=previous):
                api = Mock()
                api.CreateToolhelp32Snapshot.return_value = 11
                api.OpenThread.return_value = 12
                api.GetProcessIdOfThread.return_value = 123
                api.ResumeThread.return_value = previous
                api.CloseHandle.return_value = 1

                def first(snapshot, pointer):
                    entry = ctypes.cast(pointer, ctypes.POINTER(r._ThreadEntry)).contents
                    entry.dwSize, entry.th32ThreadID, entry.th32OwnerProcessID = 28, 456, 123
                    return 1

                def last(snapshot, pointer):
                    ctypes.set_last_error(18)
                    return 0

                api.Thread32First.side_effect, api.Thread32Next.side_effect = first, last
                job = object.__new__(r._WindowsJob)
                job.api, job.handle = api, 17
                if previous == 1:
                    job.resume(123)
                else:
                    ctypes.set_last_error(5)
                    with self.assertRaises((RuntimeError, OSError)):
                        job.resume(123)
                api.OpenThread.assert_called_once_with(0x0802, False, 456)
                self.assertEqual([call.args[0] for call in api.CloseHandle.call_args_list], [12, 11])


def assert_dead(test, pid):
    if os.name == "nt":
        api = ctypes.WinDLL("kernel32", use_last_error=True)
        api.OpenProcess.argtypes, api.OpenProcess.restype = [ctypes.c_uint32, ctypes.c_int32, ctypes.c_uint32], ctypes.c_void_p
        api.WaitForSingleObject.argtypes, api.WaitForSingleObject.restype = [ctypes.c_void_p, ctypes.c_uint32], ctypes.c_uint32
        api.CloseHandle.argtypes, api.CloseHandle.restype = [ctypes.c_void_p], ctypes.c_int32
        handle = api.OpenProcess(0x00100000, False, pid)
        if not handle:
            test.assertEqual(ctypes.get_last_error(), 87, "cannot establish child exit")
            return
        try:
            test.assertEqual(api.WaitForSingleObject(handle, 1000), 0, "test process survived cleanup: " + str(pid))
        finally:
            test.assertTrue(api.CloseHandle(handle))
    else:
        with test.assertRaises(ProcessLookupError):
            os.kill(pid, 0)


class PythonProcessControls(unittest.TestCase):
    def setUp(self):
        self.directory = TEMP_ROOT / self._testMethodName
        self.directory.mkdir()

    def invoke(self, code, timeout=10):
        result = r.run([sys.executable, "-I", "-B", "-u", "-c", code],
                       cwd=self.directory, env=dict(os.environ), timeout=timeout)
        ACTUAL.append(dict(Name=self._testMethodName, ReturnCode=result.returncode, TimedOut=result.timed_out,
                           Elapsed=result.elapsed, StdoutHex=result.stdout.hex(), StderrHex=result.stderr.hex()))
        return result

    def test_binary_output_nonzero(self):
        result = self.invoke("import os,sys; os.write(1,b'out\\x00\\xff'); os.write(2,b'err\\xfe'); sys.exit(7)")
        self.assertEqual((result.returncode, result.stdout, result.stderr, result.timed_out),
                         (7, b"out\x00\xff", b"err\xfe", False))

    def test_normal_parent_waits_for_child(self):
        child = "import os; print('CHILD',os.getpid(),flush=True)"
        code = ("import os,subprocess,sys; print('PARENT',os.getpid(),flush=True); "
                "p=subprocess.Popen([sys.executable,'-I','-B','-u','-c'," + repr(child) + "],"
                "stdin=subprocess.DEVNULL,stdout=sys.stdout,stderr=sys.stderr,"
                "creationflags=(0x08000000 if os.name=='nt' else 0)); sys.exit(p.wait())")
        result = self.invoke(code)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(result.timed_out)
        pids = re.findall(rb"(?:PARENT|CHILD) (\d+)", result.stdout)
        self.assertEqual(len(pids), 2)
        for pid in pids:
            assert_dead(self, int(pid))

    def test_timeout_reaps_parent_and_child_with_partial_bytes(self):
        child = ("import os,time; print('CHILD',os.getpid(),flush=True); "
                 "os.write(1,b'child-out\\x00\\xff\\n'); os.write(2,b'child-err\\xfe\\n'); time.sleep(60)")
        code = ("import os,subprocess,sys; print('PARENT',os.getpid(),flush=True); "
                "os.write(2,b'parent-err\\n'); p=subprocess.Popen([sys.executable,'-I','-B','-u','-c'," + repr(child) + "],"
                "stdin=subprocess.DEVNULL,stdout=sys.stdout,stderr=sys.stderr,"
                "creationflags=(0x08000000 if os.name=='nt' else 0)); "
                "print('SPAWNED',p.pid,flush=True); sys.exit(p.wait())")
        result = self.invoke(code, timeout=3)
        self.assertTrue(result.timed_out)
        self.assertIn(b"child-out\x00\xff", result.stdout)
        self.assertIn(b"parent-err", result.stderr)
        self.assertIn(b"child-err\xfe", result.stderr)
        self.assertGreaterEqual(result.elapsed, 2.5)
        self.assertLess(result.elapsed, 12)
        pids = re.findall(rb"(?:PARENT|SPAWNED) (\d+)", result.stdout)
        self.assertEqual(len(pids), 2)
        for pid in pids:
            assert_dead(self, int(pid))

    def test_zero_exit_parent_cannot_leave_child(self):
        child = "import time; time.sleep(60)"
        code = ("import os,subprocess,sys; print('PARENT',os.getpid(),flush=True); "
                "p=subprocess.Popen([sys.executable,'-I','-B','-u','-c'," + repr(child) + "],"
                "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,"
                "creationflags=(0x08000000 if os.name=='nt' else 0)); print('SPAWNED',p.pid,flush=True)")
        result = self.invoke(code)
        self.assertEqual(result.returncode, 125)
        self.assertFalse(result.timed_out)
        self.assertIn(b"outlived root", result.stderr)
        pids = re.findall(rb"(?:PARENT|SPAWNED) (\d+)", result.stdout)
        self.assertEqual(len(pids), 2)
        for pid in pids:
            assert_dead(self, int(pid))

    @unittest.skipUnless(os.name == "nt", "suspended Windows launch control")
    def test_resume_failure_never_executes_suspended_python(self):
        real_popen = subprocess.Popen
        created = []

        def popen(*args, **kwargs):
            process = real_popen(*args, **kwargs)
            created.append(process.pid)
            return process

        with patch.object(r._WindowsJob, "resume", side_effect=OSError("injected resume failure")), \
                patch.object(r.subprocess, "Popen", side_effect=popen):
            result = self.invoke("print('MUST-NOT-EXECUTE',flush=True)")
        self.assertEqual(result.returncode, 125)
        self.assertEqual(result.stdout, b"")
        self.assertIn(b"injected resume failure", result.stderr)
        self.assertEqual(len(created), 1)
        assert_dead(self, created[0])


def main():
    global TEMP_ROOT
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--temp-root", required=True)
    args = parser.parse_args()
    TEMP_ROOT = Path(args.temp_root).resolve()
    parent = Path(tempfile.gettempdir()).resolve()
    if not TEMP_ROOT.is_relative_to(parent) or TEMP_ROOT == parent or TEMP_ROOT.exists():
        raise SystemExit("requires an explicitly fresh directory inside TEMP")
    TEMP_ROOT.mkdir()
    suite = unittest.TestSuite((unittest.defaultTestLoader.loadTestsFromTestCase(PureControls),
                               unittest.defaultTestLoader.loadTestsFromTestCase(PythonProcessControls)))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    report = dict(Status="PASS" if result.wasSuccessful() else "FAIL", Tests=result.testsRun,
                  Failures=len(result.failures), Errors=len(result.errors), Skipped=len(result.skipped),
                  HostPlatform=os.name, ArmExecutions=0, GitExecutions=0, BoardExecutions=0,
                  ActualPythonControls=ACTUAL,
                  FailureDetails=[dict(Test=str(case), Traceback=detail)
                                  for case, detail in result.failures + result.errors])
    (TEMP_ROOT / "results.json").write_text(json.dumps(report, indent=2) + "\n", encoding="ascii")
    print(json.dumps({key: value for key, value in report.items() if key != "ActualPythonControls"}, sort_keys=True))
    print("Report: " + str(TEMP_ROOT / "results.json"))
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
